//! Indicatif backend

use indicatif::{ProgressBar, ProgressStyle};

use super::ProgressLoggerBackend;

pub struct IndicatifBackend {
    inner: ProgressBar,
}

/// Implementing the backend trait for `ProgressBar` from `indicatif`
impl ProgressLoggerBackend for IndicatifBackend {
    fn println<S: AsRef<str>>(&self, content: S) {
        self.inner.println(content.as_ref());
    }

    fn set_message<S: AsRef<str>>(&self, content: S) {
        self.inner.set_message(content.as_ref().to_string())
    }

    fn finish(&self) {
        self.inner.finish();
    }
}

impl IndicatifBackend {
    pub fn init() -> Self {
        let progress_bar = ProgressBar::new_spinner();
        progress_bar.enable_steady_tick(100);
        progress_bar.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(&["▹▹▹▹▹", "▸▹▹▹▹", "▹▸▹▹▹", "▹▹▸▹▹", "▹▹▹▸▹", "▹▹▹▹▸"])
                .template("{spinner:.blue} {msg}"),
        );
        progress_bar.set_message("Initializing");
        Self {
            inner: progress_bar,
        }
    }
}
