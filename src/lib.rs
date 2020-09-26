//! # VanityGPG
//!
//! It works.

extern crate anyhow;
extern crate log;
extern crate sequoia_openpgp;
extern crate thiserror;

pub mod gpg;

use anyhow::{bail, Error};
use log::{debug, info};

pub use gpg::{Ciphers, Key, Params};

use std::clone::Clone;
use std::sync::Arc;

/// Hook trait
pub trait Hook: Sync + Send {
    fn process(&self, key: &Key) -> bool;
}

/// Implement `Hook` trait for `Fn(&Key) -> bool`
impl<F> Hook for F
where
    F: Fn(&Key) -> bool + Sync + Send + Clone,
{
    fn process(&self, key: &Key) -> bool {
        debug!("Executing hook function...");
        self(key)
    }
}

/// VanityGPG generator
pub struct VanityGPG {
    id: usize,
    params: Params,
    match_hooks: Vec<Arc<dyn Hook>>,
}

/// Main impl block for the wrapped `VanityGPG`
impl VanityGPG {
    /// Create a new instance of `VanityGPG`
    pub fn new(id: usize, params: Params) -> Result<Self, Error> {
        debug!("Initiating VanityGPG instance");
        Ok(Self {
            id,
            params,
            match_hooks: vec![],
        })
    }

    /// Register a hook
    pub fn register_hook(&mut self, hook: impl Hook + 'static) {
        debug!("({}): Registering hook...", self.id);
        self.match_hooks.push(Arc::new(hook));
    }

    /// Run the generation steps for once
    pub fn try_once(&mut self) -> Result<bool, Error> {
        if self.match_hooks.is_empty() {
            debug!("({}): No hooks available", self.id);
            bail!("({}): No hooks available", self.id);
        }
        let key = Key::generate(&self.params)?;
        let key_cloned = key.clone();
        let fingerprint = key_cloned.get_fingerprint_hex();
        let matched = self
            .match_hooks
            .clone()
            .iter()
            .fold(false, move |acc, hook| hook.process(&key) || acc);
        if matched {
            info!("({}): [{}] Matched", self.id, &fingerprint);
        } else {
            info!("({}): [{}] Not matched", self.id, &fingerprint);
        }
        Ok(matched)
    }

    /// Enter the loop
    pub fn enter_loop(&mut self) -> Result<(), Error> {
        debug!("({}) Entering loop", self.id);
        loop {
            self.try_once()?;
        }
    }
}

#[cfg(test)]
mod test_vanity_gpg {
    #[test]
    fn it_works() {
        assert_eq!(1 + 1, 2);
    }
}
