//! # VanityGPG (default binary)
//!
//! A simple tool for generating and filtering vanity GPG keys, c0nCurr3nt1Y.

extern crate backtrace;
extern crate clap;
extern crate colored;
extern crate indicatif;
extern crate log;
extern crate regex;

extern crate vanity_gpg;

mod logger;

use anyhow::Error;
use backtrace::Backtrace;
use clap::Clap;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, info, set_boxed_logger, set_max_level, Level};
use regex::Regex;
use vanity_gpg::{Ciphers, Key, Params, VanityGPG};

use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::panic;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use logger::{Backend, ProgressLogger};

// Constants
/// Default log level
const PKG_LOG_LEVEL_DEFAULT: Level = Level::Info;
/// Log level with `-v`
const PKG_LOG_LEVEL_VERBOSE_1: Level = Level::Debug;
/// Log level with `-vv` and beyond
const PKG_LOG_LEVEL_VERBOSE_2: Level = Level::Trace;
/// Program version (from `Cargo.toml`)
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Program description (from `Cargo.toml`)
const PKG_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
/// Program repository (from `Cargo.toml`)
const PKG_REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// Commandline option parser with `Clap`
#[derive(Clap, Debug)]
#[clap(version = PKG_VERSION, about = PKG_DESCRIPTION)]
struct Opts {
    /// Concurrent key generation jobs
    #[clap(
        short = 'j',
        long = "jobs",
        about = "Concurrent key generation jobs",
        default_value = "1"
    )]
    concurrent_jobs: usize,
    /// Regex pattern for matching fingerprints
    #[clap(
        short = 'p',
        long = "pattern",
        about = "Regex pattern for matching fingerprints"
    )]
    pattern: String,
    /// Cipher suite
    #[clap(
        short = 'c',
        long = "cipher-suite",
        about = "Cipher suite",
        default_value = "RSA4096"
    )]
    cipher_suite: String,
    /// User ID
    #[clap(short = 'u', long = "user-id", about = "OpenPGP compatible user ID")]
    user_id: Option<String>,
    #[clap(
        short = 'd',
        long = "dry-run",
        about = "Dry run (does not save matched keys)"
    )]
    dry_run: bool,
    /// Verbose level
    #[clap(
        short = 'v',
        long = "verbose",
        about = "Verbose level",
        parse(from_occurrences)
    )]
    verbose: u8,
}

/// Implementing the backend trait for `ProgressBar` from `indicatif`
impl Backend for ProgressBar {
    fn println(&self, content: String) {
        self.println(content)
    }
}

/// Set panic hook with repository information
fn setup_panic_hook(progress_bar: Arc<Mutex<ProgressBar>>) {
    panic::set_hook(Box::new(move |panic_info: &panic::PanicInfo| {
        println!("{:#?}", Backtrace::new());
        progress_bar.lock().unwrap().finish_and_clear();
        if let Some(info) = panic_info.payload().downcast_ref::<&str>() {
            println!("Panic occurred: {:?}", info);
        } else {
            println!("Panic occurred");
        }
        if let Some(location) = panic_info.location() {
            println!(
                r#"In file "{}" at line "{}""#,
                location.file(),
                location.line()
            );
        }
        println!("Please report this panic to {}/issues", PKG_REPOSITORY);
    }));
}

/// Setup logger and return a `ProgressBar` that can be shared between threads
fn setup_logger(verbosity: u8) -> Result<Arc<Mutex<ProgressBar>>, Error> {
    let level = match verbosity {
        0 => PKG_LOG_LEVEL_DEFAULT,
        1 => PKG_LOG_LEVEL_VERBOSE_1,
        _ => PKG_LOG_LEVEL_VERBOSE_2,
    };
    set_max_level(level.to_level_filter());
    let progress_bar = ProgressBar::new_spinner();
    progress_bar.enable_steady_tick(120);
    progress_bar.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["▹▹▹▹▹", "▸▹▹▹▹", "▹▸▹▹▹", "▹▹▸▹▹", "▹▹▹▸▹", "▹▹▹▹▸"])
            .template("{spinner:.blue} {msg}"),
    );
    progress_bar.set_message("Initializing");
    let wrapped_progress_bar = Arc::new(Mutex::new(progress_bar));
    let wrapped_progress_bar_cloned = Arc::clone(&wrapped_progress_bar);
    let progress_logger = ProgressLogger::new(level, wrapped_progress_bar_cloned);
    set_boxed_logger(Box::new(progress_logger))?;
    debug!("Logger initialized");
    Ok(Arc::clone(&wrapped_progress_bar))
}

/// Jobs within each worker threads
fn start_job(
    id: usize,
    dry_run: bool,
    total_counter: Arc<AtomicUsize>,
    found_counter: Arc<AtomicUsize>,
    params: Params,
    pattern: Regex,
) {
    info!("({}): Staring...", id);
    let mut vanity_gpg = VanityGPG::new(id, params).expect("Failed to start");
    // Register a regex hook
    vanity_gpg.register_hook(move |key: &Key| {
        let fingerprint = key.get_fingerprint_hex();
        total_counter.fetch_add(1, Ordering::SeqCst);
        if pattern.is_match(&fingerprint) {
            found_counter.fetch_add(1, Ordering::SeqCst);
            if !dry_run {
                // Save secret key
                let mut secret_key_file = File::create(format!("{}-secret.asc", &fingerprint))
                    .expect("Failed to save secret key");
                secret_key_file
                    .write_all(key.get_tsk_armored().unwrap().as_bytes())
                    .unwrap();
                // Save public key
                let mut public_key_file = File::create(format!("{}-public.asc", &fingerprint))
                    .expect("Failed to save public key");
                public_key_file
                    .write_all(key.get_armored().unwrap().as_bytes())
                    .unwrap();
            }
            true
        } else {
            false
        }
    });
    vanity_gpg.enter_loop().unwrap();
}

/// Start the program
fn main() -> Result<(), Error> {
    // Parse commandline options
    let opts: Opts = Opts::parse();

    // Setup logger and show some messages
    let progress_bar = setup_logger(opts.verbose)?;
    info!("Main: Staring VanityGPG version v{}", PKG_VERSION);
    info!("Main: (So fast, such concurrency, wow)");
    info!("Main: Please report issues to \"{}\"", PKG_REPOSITORY);

    // Setup panic hook
    let progress_bar_cloned = Arc::clone(&progress_bar);
    setup_panic_hook(progress_bar_cloned);

    // Start worker threads
    let mut handles = vec![];
    let params = Params::new(opts.cipher_suite.parse::<Ciphers>()?, opts.user_id);
    let pattern = Regex::new(&opts.pattern)?;
    let total_counter = Arc::new(AtomicUsize::new(0));
    let found_counter = Arc::new(AtomicUsize::new(0));
    info!("Main: Starting {} threads...", opts.concurrent_jobs);
    for id in 0..opts.concurrent_jobs {
        let total_counter = Arc::clone(&total_counter);
        let found_counter = Arc::clone(&found_counter);
        let params_cloned = params.clone();
        let pattern_cloned = pattern.clone();
        let dry_run = opts.dry_run;
        handles.push(thread::spawn(move || {
            start_job(
                id,
                dry_run,
                total_counter,
                found_counter,
                params_cloned,
                pattern_cloned,
            );
        }));
    }

    // Setup spinner updating thread
    let total_counter = Arc::clone(&total_counter);
    let found_counter = Arc::clone(&found_counter);
    handles.push(thread::spawn(move || loop {
        let total = total_counter.load(Ordering::SeqCst);
        let found = found_counter.load(Ordering::SeqCst);
        progress_bar
            .lock()
            .unwrap()
            .set_message(&format!("Summary: {} found ({} generated)", found, total));
        thread::sleep(Duration::from_millis(100));
    }));

    // Join thread handles
    for handle in handles {
        handle.join().unwrap();
    }

    Ok(())
}
