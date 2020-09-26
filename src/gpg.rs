//! Sequoia-OpenPGP wrapper

use anyhow::Error;
use sequoia_openpgp::armor::{Kind, Writer};
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::cert::CipherSuite;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::Cert;

use std::io::Write;
use std::str::FromStr;

/// Error
#[derive(thiserror::Error, Debug)]
pub enum PGPError {
    #[error("Cipher suite not recognized: {0}")]
    UnrecognizedCipherSuite(String),
}

/// Ciphers
#[derive(Clone, Debug)]
pub enum Ciphers {
    Cv25519,
    P256,
    P384,
    P521,
    RSA2k,
    RSA3k,
    RSA4k,
}

/// Parameters
#[derive(Clone, Debug)]
pub struct Params {
    cipher: Ciphers,
    user_id: Option<String>,
}

/// Generated keys and revocation certifications
#[derive(Clone, Debug)]
pub struct Key {
    key: Cert,
    revocation: Signature,
}

/// Make `Ciphers` be able to convert to Sequoia's `CipherSuite`
impl Into<CipherSuite> for &Ciphers {
    fn into(self) -> CipherSuite {
        match self {
            &Ciphers::Cv25519 => CipherSuite::Cv25519,
            &Ciphers::P256 => CipherSuite::P256,
            &Ciphers::P384 => CipherSuite::P384,
            &Ciphers::P521 => CipherSuite::P521,
            &Ciphers::RSA2k => CipherSuite::RSA2k,
            &Ciphers::RSA3k => CipherSuite::RSA3k,
            &Ciphers::RSA4k => CipherSuite::RSA4k,
        }
    }
}

/// Make `Ciphers` parsable
impl FromStr for Ciphers {
    type Err = PGPError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ed25519" | "cv25519" | "eddsa" => Ok(Ciphers::Cv25519),
            "p256" => Ok(Ciphers::P256),
            "p384" => Ok(Ciphers::P384),
            "p521" => Ok(Ciphers::P521),
            "rsa2048" | "rsa2k" => Ok(Ciphers::RSA4k),
            "rsa3k" => Ok(Ciphers::RSA3k),
            "rsa" | "rsa4096" | "rsa4k" => Ok(Ciphers::RSA4k),
            _ => Err(PGPError::UnrecognizedCipherSuite(String::from(s))),
        }
    }
}

impl Params {
    /// Create a new `Params`
    pub fn new(cipher: Ciphers, user_id: Option<String>) -> Self {
        Self { cipher, user_id }
    }

    /// Get cipher suite
    pub fn get_cipher(&self) -> &Ciphers {
        &self.cipher
    }

    /// Get user ID
    pub fn get_user_id(&self) -> Option<String> {
        self.user_id.clone()
    }
}

impl Key {
    /// Generate a key
    pub fn generate(params: &Params) -> Result<Self, Error> {
        let (cert, revocation) =
            CertBuilder::general_purpose(Some(params.get_cipher().into()), params.get_user_id())
                .generate()?;
        Ok(Self {
            key: cert,
            revocation,
        })
    }

    /// Get fingerprint hex
    pub fn get_fingerprint_hex(&self) -> String {
        self.key.fingerprint().to_hex()
    }

    /// Get armored public key
    pub fn get_armored(&self) -> Result<String, Error> {
        Ok(String::from_utf8(self.key.armored().to_vec()?)?)
    }

    /// Get armored secret key
    pub fn get_tsk_armored(&self) -> Result<String, Error> {
        let mut writer = Writer::new(Vec::new(), Kind::SecretKey)?;
        writer.write(&self.key.as_tsk().to_vec()?)?;
        Ok(String::from_utf8(writer.finalize()?)?)
    }
}

#[cfg(test)]
mod test_gpg {
    use super::{Ciphers, Key, Params};

    #[test]
    fn generate() {
        let key = Key::generate(&Params::new(
            Ciphers::RSA4k,
            Some(String::from("Yajuu Senpai <1145141919810@example.com>")),
        ))
        .unwrap();
        println!("{}", key.get_fingerprint_hex());
    }
}
