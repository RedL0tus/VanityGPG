//! # VanityGPG (default binary)
//!
//! A simple tool for generating and filtering vanity GPG keys, c0nCurr3nt1Y.

extern crate backtrace;
extern crate clap;
extern crate colored;
extern crate indicatif;
extern crate log;
extern crate rayon;
extern crate regex;

extern crate vanity_gpg;

mod logger;

use anyhow::Error;
use backtrace::Backtrace;
use clap::Clap;
use log::{debug, info, warn, Level};
use rayon::ThreadPoolBuilder;
use regex::Regex;

use std::env;
use std::fmt;
use std::fs::File;
use std::io::prelude::*;
use std::panic;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use vanity_gpg::{Backend, CipherSuite, DefaultBackend, UserID};

use logger::{IndicatifBackend, ProgressLogger, ProgressLoggerBackend};

// Constants
/// Default log level
const PKG_LOG_LEVEL_DEFAULT: Level = Level::Warn;
/// Log level with `-v`
const PKG_LOG_LEVEL_VERBOSE_1: Level = Level::Info;
/// Log level with `-vv` and beyond
const PKG_LOG_LEVEL_VERBOSE_2: Level = Level::Debug;
/// Log level with `-vvv` and beyond
const PKG_LOG_LEVEL_VERBOSE_3: Level = Level::Trace;
/// Program version (from `Cargo.toml`)
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Program description (from `Cargo.toml`)
const PKG_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
/// Program repository (from `Cargo.toml`)
const PKG_REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// Key reshuffle limit
const KEY_RESHUFFLE_LIMIT: usize = 60 * 60 * 24 * 30; // One month ago at worst

/// Commandline option parser with `Clap`
#[derive(Clap, Debug)]
#[clap(version = PKG_VERSION, about = PKG_DESCRIPTION)]
struct Opts {
    /// Concurrent key generation jobs
    #[clap(
        short = 'j',
        long = "jobs",
        about = "Number of threads",
        default_value = "8"
    )]
    jobs: usize,
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
        default_value = "Ed25519",
        possible_values = &[ "Ed25519", "RSA2048", "RSA3072", "RSA4096", "NISTP256", "NISTP384", "NISTP521" ],
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

#[derive(Debug)]
struct Counter {
    total: AtomicUsize,
    success: AtomicUsize,
}

#[derive(Debug)]
struct Key<B: Backend> {
    backend: B,
}

/// Save string to file
fn save_file(file_name: String, content: &str) -> Result<(), Error> {
    let mut file = File::create(file_name)?;
    Ok(file.write_all(content.as_bytes())?)
}

/// Set panic hook with repository information
fn setup_panic_hook() {
    panic::set_hook(Box::new(move |panic_info: &panic::PanicInfo| {
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
        println!("Traceback:");
        println!("{:#?}", Backtrace::new());
        println!();
        println!("Please report this panic to {}/issues", PKG_REPOSITORY);
    }));
}

/// Setup logger and return a `ProgressBar` that can be shared between threads
fn setup_logger<B: 'static + ProgressLoggerBackend>(
    verbosity: u8,
    backend: B,
) -> Result<Arc<Mutex<B>>, Error> {
    let level = match verbosity {
        0 => PKG_LOG_LEVEL_DEFAULT,
        1 => PKG_LOG_LEVEL_VERBOSE_1,
        2 => PKG_LOG_LEVEL_VERBOSE_2,
        _ => PKG_LOG_LEVEL_VERBOSE_3,
    };
    let logger = ProgressLogger::new(level, backend);
    debug!("Logger initialized");
    let cloned_backend = logger.get_backend();
    logger.setup()?;
    Ok(cloned_backend)
}

/// Sub-thread that display status summary
fn setup_summary<B: ProgressLoggerBackend>(logger_backend: Arc<Mutex<B>>, counter: Arc<Counter>) {
    let start = Instant::now();
    loop {
        thread::sleep(Duration::from_millis(100));
        debug!("Updating counter information");
        let secs_elapsed = start.elapsed().as_secs();
        logger_backend.lock().unwrap().set_message(&format!(
            "Summary: {} (avg. {:.2} tries/s)",
            &counter,
            counter.get_total() as f64 / secs_elapsed as f64
        ));
    }
}

impl Counter {
    fn new() -> Self {
        Self {
            total: AtomicUsize::new(0),
            success: AtomicUsize::new(0),
        }
    }

    fn count_total(&self) {
        self.total.fetch_add(1, Ordering::SeqCst);
    }

    fn count_success(&self) {
        self.count_total();
        self.success.fetch_add(1, Ordering::SeqCst);
    }

    fn get_total(&self) -> usize {
        self.total.load(Ordering::SeqCst)
    }

    fn get_success(&self) -> usize {
        self.success.load(Ordering::SeqCst)
    }
}

impl fmt::Display for Counter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} success, {} tries total",
            self.get_success(),
            self.get_total(),
        )
    }
}

impl<B: Backend> Key<B> {
    fn new(backend: B) -> Key<B> {
        Key { backend }
    }

    fn get_fingerprint(&self) -> String {
        self.backend.fingerprint()
    }

    fn shuffle(&mut self) -> Result<(), Error> {
        Ok(self.backend.shuffle()?)
    }

    fn check(&self, pattern: &Regex) -> bool {
        pattern.is_match(&self.backend.fingerprint())
    }

    fn save_key(self, user_id: &UserID, dry_run: bool) -> Result<(), Error> {
        if dry_run {
            return Ok(());
        }
        let fingerprint = self.get_fingerprint();
        info!("saving [{}]", &fingerprint);
        let armored_keys = self.backend.get_armored_results(user_id)?;
        save_file(
            format!("{}-private.asc", &fingerprint),
            armored_keys.get_private_key(),
        )?;
        save_file(
            format!("{}-public.asc", &fingerprint),
            armored_keys.get_public_key(),
        )?;
        Ok(())
    }
}

/// Start the program
fn main() -> Result<(), Error> {
    // Setup panic hook
    setup_panic_hook();

    // Parse commandline options
    let opts: Opts = Opts::parse();

    // Setup logger and show some messages
    let logger_backend = setup_logger(opts.verbose, IndicatifBackend::init())?;
    warn!("Staring VanityGPG version v{}", PKG_VERSION);
    warn!("(So fast, such concurrency, wow)");
    warn!(
        "if you met any issue, please file an issue report to \"{}\"",
        PKG_REPOSITORY
    );
    let counter = Arc::new(Counter::new());

    let pool = ThreadPoolBuilder::new()
        .num_threads(opts.jobs + 1)
        .build()?;
    let user_id = UserID::from(opts.user_id);

    for _index in 0..opts.jobs {
        let user_id_cloned = user_id.clone();
        let pattern = Regex::new(&opts.pattern)?;
        let dry_run = opts.dry_run;
        let cipher_suite = CipherSuite::from_str(&opts.cipher_suite)?;
        let counter_cloned = Arc::clone(&counter);
        pool.spawn(move || {
            let mut key = Key::new(DefaultBackend::new(cipher_suite.clone()).unwrap());
            let mut reshuffle_counter: usize = KEY_RESHUFFLE_LIMIT;
            loop {
                if key.check(&pattern) {
                    warn!("found [{}]", key.get_fingerprint());
                    counter_cloned.count_success();
                    key.save_key(&user_id_cloned, dry_run).unwrap_or(());
                    key = Key::new(DefaultBackend::new(cipher_suite.clone()).unwrap());
                } else {
                    if reshuffle_counter == 0 {
                        key = Key::new(DefaultBackend::new(cipher_suite.clone()).unwrap());
                    } else {
                        reshuffle_counter -= 1;
                        #[cfg(not(feature = "za_warudo"))]
                        thread::sleep(Duration::from_secs(1));
                        key.shuffle().unwrap_or(());
                    }
                    counter_cloned.count_total();
                }
            }
        });
    }

    // Setup summary
    let logger_backend_cloned = Arc::clone(&logger_backend);
    let counter_cloned = Arc::clone(&counter);
    pool.install(move || setup_summary(logger_backend_cloned, counter_cloned));

    Ok(())
}
