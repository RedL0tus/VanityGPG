//! # Logger
//!
//! A simple logger implementation that can be used with random progress bar implementations

use colored::*;
use log::{Level, Metadata, Record};

use std::sync::{Arc, Mutex};

/// Progress bar backend
pub trait Backend: Sync + Send {
    fn println(&self, content: String);
}

/// Logger that work with a progress bar implementation
pub struct ProgressLogger {
    max_level: Level,
    backend: Arc<Mutex<dyn Backend>>,
}

/// Implementing `Log` trait for `ProgressLogger`
impl log::Log for ProgressLogger {
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
impl ProgressLogger {
    /// Create new `ProgressLogger` instance
    pub fn new(max_level: Level, backend: Arc<Mutex<dyn Backend>>) -> Self {
        Self { max_level, backend }
    }
}
