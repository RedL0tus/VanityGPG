//! # Logger
//!
//! A simple logger implementation that can be used with random progress bar implementations

mod indicatif_backend;

use colored::*;
use log::{set_boxed_logger, set_max_level, Level, Metadata, Record, SetLoggerError};

pub use indicatif_backend::IndicatifBackend;

use std::sync::{Arc, Mutex};

/// Progress bar backend
pub trait ProgressLoggerBackend: Sync + Send {
    fn println<S: AsRef<str>>(&self, content: S);
    fn set_message<S: AsRef<str>>(&self, content: S);
    fn finish(&self);
}

/// Logger that work with a progress bar implementation
pub struct ProgressLogger<B: ProgressLoggerBackend> {
    max_level: Level,
    backend: Arc<Mutex<B>>,
}

/// Implementing `Log` trait for `ProgressLogger`
impl<B: ProgressLoggerBackend> log::Log for ProgressLogger<B> {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.max_level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let level_name = match record.level() {
            Level::Error => record.level().to_string().red(),
            Level::Warn => record.level().to_string().yellow(),
            Level::Info => record.level().to_string().cyan(),
            Level::Debug => record.level().to_string().purple(),
            Level::Trace => record.level().to_string().normal(),
        };
        let target = if !record.target().is_empty() {
            record.target()
        } else {
            record.module_path().unwrap_or_default()
        };
        self.backend.lock().unwrap().println(format!(
            "{:<5} [{}] {}",
            level_name,
            target,
            record.args()
        ));
    }

    fn flush(&self) {}
}

/// Main impl block of `ProgressLogger`
impl<B: 'static + ProgressLoggerBackend> ProgressLogger<B> {
    /// Create new `ProgressLogger` instance
    pub fn new(max_level: Level, backend: B) -> Self {
        Self {
            max_level,
            backend: Arc::new(Mutex::new(backend)),
        }
    }

    pub fn setup(self) -> Result<(), SetLoggerError> {
        set_max_level(self.max_level.to_level_filter());
        set_boxed_logger(Box::new(self))?;
        Ok(())
    }

    /// Get `Arc<Mutex<ProgressLoggerBackend>>`
    pub fn get_backend(&self) -> Arc<Mutex<B>> {
        self.backend.clone()
    }
}
