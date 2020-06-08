//! # GPGME wrapper
//!
//! Just a simple GPGME Wrapper
//!
//! ## Example
//!
//! ```rust
//! extern crate vanity_gpg;
//!
//! use vanity_gpg::gpg::{GPG, Protocol, DeleteKeyFlags};
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
//! let mut gpg = GPG::new(Protocol::OpenPgp, None, Some("./gpg")).unwrap();
//! let result = gpg.generate_key(ECC_PARAMS).unwrap();
//! let fingerprint = result.fingerprint().unwrap();
//! let key = gpg.get_key(fingerprint).unwrap();
//! let delete_flags = DeleteKeyFlags::all();
//! gpg.delete_key_with_flags(key, delete_flags).unwrap();
//! ```

use gpgme::{Context, Gpgme};
use anyhow::{bail, Error};

pub use gpgme::{DeleteKeyFlags, Key, Protocol};

/// Use `anyhow` to wrap around `GPGME`'s errors
macro_rules! error_wrapper {
    ($e:expr) => {
        match $e {
            Ok(inner) => Ok(inner),
            Err(error) => {
                if error.is_none() {
                    bail!("Error decoding return values from GPGME");
                } else {
                    bail!(error.expect("So cringy, such error, wow"));
                }
            }
        }
    };
}

/// Wrapped `EngineInfo`
#[derive(Debug)]
pub struct EngineInfo<'a> {
    inner: gpgme::EngineInfo<'a>,
}

/// Wrapped `KeyGenerationResult`
#[derive(Clone, Debug)]
pub struct KeyGenerationResult {
    inner: gpgme::results::KeyGenerationResult,
}

/// Wrapped `GPG`
#[derive(Debug)]
pub struct GPG {
    context: Context,
    gpgme: Gpgme,
    protocol: Protocol,
}

/// Conversion from `gpgme::EngineInfo` to wrapped `EngineInfo`
impl<'a> From<gpgme::EngineInfo<'a>> for EngineInfo<'a> {
    fn from(engine_info: gpgme::EngineInfo<'a>) -> Self {
        Self { inner: engine_info }
    }
}

/// Main impl block for the wrapped `EngineInfo`
impl<'a> EngineInfo<'a> {
    /// Get the protocol for which the crypto engine is using
    pub fn protocol(&self) -> Protocol {
        self.inner.protocol()
    }

    /// Get the path of the executable of the crypto engine
    pub fn path(&self) -> Result<&str, Error> {
        error_wrapper!(self.inner.path())
    }

    /// Get the crypto engine’s configuration directory.
    pub fn home_dir(&self) -> Result<&str, Error> {
        error_wrapper!(self.inner.home_dir())
    }

    /// Check the crypto engine's version
    pub fn check_version(&self, version: &str) -> bool {
        self.inner.check_version(version)
    }

    /// Get the version of the crypto engine in use
    pub fn version(&self) -> Result<&str, Error> {
        error_wrapper!(self.inner.version())
    }

    /// Get the minimum required version number of the crypto engine for GPGME to work
    pub fn required_version(&self) -> Result<&str, Error> {
        error_wrapper!(self.inner.required_version())
    }
}

/// Conversion from `gpgme::results::` to wrapped `EngineInfo`
impl From<gpgme::results::KeyGenerationResult> for KeyGenerationResult {
    fn from(result: gpgme::results::KeyGenerationResult) -> Self {
        Self { inner: result }
    }
}

/// Main impl block for the wrapped `EngineInfo`
impl KeyGenerationResult {
    /// Check if the generated key has a primary key
    pub fn has_primary_key(&self) -> bool {
        self.inner.has_primary_key()
    }

    /// Check if the generated key has a subkey
    pub fn has_sub_key(&self) -> bool {
        self.inner.has_sub_key()
    }

    /// Check if the generated key has a uid
    pub fn has_uid(&self) -> bool {
        self.inner.has_uid()
    }

    /// Get the fingerprint of the generated key
    pub fn fingerprint(&self) -> Result<&str, Error> {
        error_wrapper!(self.inner.fingerprint())
    }

    /// Get the short ID of the generated key
    pub fn short_id(&self) -> Result<&str, Error> {
        Ok(&self.fingerprint()?[32..40])
    }

    /// Get the long ID of the generated key
    pub fn long_id(&self) -> Result<&str, Error> {
        Ok(&self.fingerprint()?[24..40])
    }
}

/// Main impl block for the wrapped `GPG`
impl GPG {
    /// Create a new instance of `GPG`
    pub fn new(
        protocol: Protocol,
        engine_path: Option<&str>,
        home_dir: Option<&str>,
    ) -> Result<Self, Error> {
        let gpgme = gpgme::init();
        let mut context = Context::from_protocol(protocol)?;
        gpgme.check_engine_version(protocol)?;
        context.set_engine_info(engine_path, home_dir)?;
        Ok(Self {
            context,
            gpgme,
            protocol,
        })
    }

    /// Get information about the crypto engine in use
    pub fn get_engine_info(&self) -> EngineInfo {
        self.context.engine_info().into()
    }

    /// Generate key with the given params
    pub fn generate_key<'a>(&mut self, params: &'a str) -> Result<KeyGenerationResult, Error> {
        Ok(self
            .context
            .generate_key(params, None::<&'a str>, None::<&'a str>)?
            .into())
    }

    /// Get the matching key with the fingerprint
    pub fn get_key(&mut self, fingerprint: &str) -> Result<Key, Error> {
        Ok(self.context.get_key(fingerprint)?)
    }

    /// Get the matching secret key with the fingerprint
    pub fn get_secret_key(&mut self, fingerprint: &str) -> Result<Key, Error> {
        Ok(self.context.get_secret_key(fingerprint)?)
    }

    /// Delete the key
    pub fn delete_key(&mut self, key: Key) -> Result<(), Error> {
        Ok(self.context.delete_key(&key)?)
    }

    /// Delete the secret key
    pub fn delete_secret_key(&mut self, key: Key) -> Result<(), Error> {
        Ok(self.context.delete_secret_key(&key)?)
    }

    /// Delete the key with flags (`DeleteKeyFlags`)
    pub fn delete_key_with_flags(&mut self, key: Key, flags: DeleteKeyFlags) -> Result<(), Error> {
        Ok(self.context.delete_key_with_flags(&key, flags)?)
    }
}

#[cfg(test)]
mod gpg_test {
    use super::*;

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
    fn ecc_generation_and_deletion() {
        let mut gpg = GPG::new(Protocol::OpenPgp, None, Some("./gpg")).unwrap();
        let result = gpg.generate_key(ECC_PARAMS).unwrap();
        let fingerprint = result.fingerprint().unwrap();
        let key = gpg.get_key(fingerprint).unwrap();
        let delete_flags = DeleteKeyFlags::all();
        gpg.delete_key_with_flags(key, delete_flags).unwrap();
    }

    #[test]
    fn rsa_generation_and_deletion() {
        let mut gpg = GPG::new(Protocol::OpenPgp, None, Some("./gpg")).unwrap();
        let result = gpg.generate_key(RSA_PARAMS).unwrap();
        let fingerprint = result.fingerprint().unwrap();
        let key = gpg.get_key(fingerprint).unwrap();
        let delete_flags = DeleteKeyFlags::all();
        gpg.delete_key_with_flags(key, delete_flags).unwrap();
    }
}
