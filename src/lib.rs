//! # VanityGPG
//!
//! The underlying `GPGME` wrapper and hooking mechanism.
//!
//! ## Examples
//! ```rust
//! extern crate vanity_gpg;
//!
//! use vanity_gpg::{KeyGenerationResult, Protocol, VanityGPG};
//!
//! const ECC_PARAMS: &'static str = r#"
//!     <GnupgKeyParms format="internal">
//!         Key-Type: EdDSA
//!         Key-Curve: ed25519
//!         Key-Usage: sign
//!         Subkey-Type: ECDH
//!         Subkey-Curve: Curve25519
//!         Subkey-Usage: encrypt
//!         Name-Real: Kay Lin
//!         Name-Email: i@v2bv.net
//!         Expire-Date: 0
//!         Passphrase: 114514
//!     </GnupgKeyParms>
//! "#;
//!
//! let mut vanity_gpg =
//!     VanityGPG::new(0, Protocol::OpenPgp, None, Some("./gpg"), ECC_PARAMS).unwrap();
//! vanity_gpg.register_hook(|result: &KeyGenerationResult| {
//!     assert!(result.has_primary_key());
//!     false
//! });
//! vanity_gpg.try_once().unwrap();
//! ```

extern crate anyhow;
extern crate gpgme;
extern crate lazy_static;
extern crate log;

pub mod gpg;

use anyhow::{bail, Error};
use lazy_static::lazy_static;
use log::{debug, info};

use gpg::{DeleteKeyFlags, GPG};

pub use gpg::{KeyGenerationResult, Protocol};

use std::clone::Clone;
use std::sync::Arc;

lazy_static! {
    /// Default flags for deletion
    static ref DELETE_FLAG: DeleteKeyFlags = DeleteKeyFlags::all();
}

/// Hook trait
pub trait Hook: Sync + Send {
    fn process(&self, result: &KeyGenerationResult) -> bool;
}

/// Implement `Hook` trait for `Fn(&KeyGenerationResult) -> bool`
impl<F> Hook for F
where
    F: Fn(&KeyGenerationResult) -> bool + Sync + Send + Clone,
{
    fn process(&self, result: &KeyGenerationResult) -> bool {
        debug!("Executing hook function...");
        self(result)
    }
}

/// VanityGPG generator
pub struct VanityGPG<'a> {
    id: usize,
    gpg: GPG,
    params: &'a str,
    match_hooks: Vec<Arc<dyn Hook>>,
}

/// Main impl block for the wrapped `VanityGPG`
impl<'a> VanityGPG<'a> {
    /// Create a new instance of `VanityGPG`
    pub fn new(
        id: usize,
        protocol: Protocol,
        engine_path: Option<&'a str>,
        home_dir: Option<&'a str>,
        params: &'a str,
    ) -> Result<Self, Error> {
        debug!("Initiating VanityGPG instance");
        Ok(Self {
            id,
            gpg: GPG::new(protocol, engine_path, home_dir)?,
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
        let result = self.gpg.generate_key(self.params)?;
        let cloned_result = result.clone();
        let fingerprint = cloned_result.fingerprint()?;
        info!("({}): [{}] Generated", self.id, &fingerprint);
        let key = self.gpg.get_key(fingerprint)?;
        let matched = self
            .match_hooks
            .clone()
            .iter()
            .fold(false, move |acc, hook| hook.process(&result) || acc);
        if !matched {
            self.gpg.delete_key_with_flags(key, *DELETE_FLAG)?;
            info!("({}): [{}] Deleted", self.id, &fingerprint);
        } else {
            info!("({}): [{}] Matched", self.id, &fingerprint);
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
    use super::{KeyGenerationResult, Protocol, VanityGPG};

    const RSA_PARAMS: &'static str = r#"
        <GnupgKeyParms format="internal">
            Key-Type: RSA
            Key-Length: 4096
            Key-Usage: sign
            Subkey-Type: RSA
            Subkey-Length: 4096
            Subkey-Usage: encrypt
            Name-Real: Kay Lin
            Name-Email: i@v2bv.net
            Expire-Date: 0
            Passphrase: 114514
        </GnupgKeyParms>
    "#;

    const ECC_PARAMS: &'static str = r#"
        <GnupgKeyParms format="internal">
            Key-Type: EdDSA
            Key-Curve: ed25519
            Key-Usage: sign
            Subkey-Type: ECDH
            Subkey-Curve: Curve25519
            Subkey-Usage: encrypt
            Name-Real: Kay Lin
            Name-Email: i@v2bv.net
            Expire-Date: 0
            Passphrase: 114514
        </GnupgKeyParms>
    "#;

    #[test]
    fn no_hook() {
        let mut vanity_gpg =
            VanityGPG::new(0, Protocol::OpenPgp, None, Some("./gpg"), RSA_PARAMS).unwrap();
        assert!(true, vanity_gpg.try_once().is_err());
    }

    #[test]
    fn ecc_generation() {
        let mut vanity_gpg =
            VanityGPG::new(0, Protocol::OpenPgp, None, Some("./gpg"), ECC_PARAMS).unwrap();
        vanity_gpg.register_hook(|result: &KeyGenerationResult| {
            assert!(result.has_primary_key());
            false
        });
        vanity_gpg.try_once().unwrap();
    }

    #[test]
    fn rsa_generation() {
        let mut vanity_gpg =
            VanityGPG::new(0, Protocol::OpenPgp, None, Some("./gpg"), RSA_PARAMS).unwrap();
        vanity_gpg.register_hook(|result: &KeyGenerationResult| {
            assert!(result.has_primary_key());
            false
        });
        vanity_gpg.try_once().unwrap();
    }
}
