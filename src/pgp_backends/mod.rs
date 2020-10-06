#[cfg(feature = "rpgp")]
mod rpgp_backend;
#[cfg(feature = "sequoia")]
mod sequoia_backend;

pub use anyhow::Error as UniversalError;
use thiserror::Error;

#[cfg(feature = "sequoia")]
pub use sequoia_backend::SequoiaBackend;

#[cfg(feature = "rpgp")]
pub use rpgp_backend::RPGPBackend;

use std::str::FromStr;

#[cfg(feature = "sequoia")]
pub type DefaultBackend = SequoiaBackend;

#[cfg(feature = "rpgp")]
pub type DefaultBackend = RPGPBackend;

#[derive(Clone, Debug, Error)]
pub enum PGPError {
    #[error("Cipher suite not supported: {0}")]
    CipherSuiteNotSupported(String),
    #[error("Algorithm is not supported by the current backend: {0}")]
    AlgorithmNotSupportedByTheCurrentBackend(String),
    #[error("Failed to generate key")]
    KeyGenerationFailed,
    #[error("This is a mysterious error, it should never appear")]
    MysteriousError,
    #[error("Invalid key generated")]
    InvalidKeyGenerated,
    #[error("Failed to modify generation time")]
    FailedToModifyGenerationTime,
}

#[derive(Debug, Clone)]
pub enum CipherSuite {
    RSA2048,
    RSA3072,
    RSA4096,
    Curve25519,
    NistP256,
    NistP384,
    NistP521,
}

#[derive(Debug, Clone)]
pub enum RSA {
    RSA2048,
    RSA3072,
    RSA4096,
}

#[derive(Debug, Clone)]
pub enum Curve {
    Cv25519,
    Ed25519,
    NistP256,
    NistP384,
    NistP521,
}

#[derive(Debug, Clone)]
pub enum Algorithms {
    RSA(RSA),
    ECC(Curve),
}

#[derive(Debug, Clone)]
pub struct UserID {
    id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ArmoredKey {
    public: String,
    private: String,
}

pub trait Backend {
    fn fingerprint(&self) -> String;

    fn shuffle(&mut self) -> Result<(), PGPError>;

    fn get_armored_results(self, uid: &UserID) -> Result<ArmoredKey, UniversalError>;
}

impl FromStr for UserID {
    type Err = PGPError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            id: Some(s.to_string()),
        })
    }
}

impl From<String> for UserID {
    fn from(string: String) -> Self {
        Self { id: Some(string) }
    }
}

impl From<Option<String>> for UserID {
    fn from(string: Option<String>) -> Self {
        Self { id: string }
    }
}

impl Default for CipherSuite {
    fn default() -> Self {
        Self::Curve25519
    }
}

impl FromStr for CipherSuite {
    type Err = PGPError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "rsa2048" | "rsa2k" => Ok(CipherSuite::RSA2048),
            "rsa3072" | "rsa3k" => Ok(CipherSuite::RSA3072),
            "rsa4096" | "rsa4k" => Ok(CipherSuite::RSA4096),
            "cv25519" | "ed25519" | "curve25519" => Ok(CipherSuite::Curve25519),
            "nistp256" | "p256" => Ok(CipherSuite::NistP256),
            "nistp384" | "p384" => Ok(CipherSuite::NistP384),
            "nistp521" | "p521" => Ok(CipherSuite::NistP521),
            s => Err(PGPError::CipherSuiteNotSupported(String::from(s))),
        }
    }
}

impl CipherSuite {
    fn get_algorithm(&self, encryption: bool) -> Algorithms {
        match self {
            CipherSuite::RSA2048 => Algorithms::RSA(RSA::RSA2048),
            CipherSuite::RSA3072 => Algorithms::RSA(RSA::RSA3072),
            CipherSuite::RSA4096 => Algorithms::RSA(RSA::RSA4096),
            CipherSuite::Curve25519 => {
                if encryption {
                    Algorithms::ECC(Curve::Cv25519)
                } else {
                    Algorithms::ECC(Curve::Ed25519)
                }
            }
            CipherSuite::NistP256 => Algorithms::ECC(Curve::NistP256),
            CipherSuite::NistP384 => Algorithms::ECC(Curve::NistP384),
            CipherSuite::NistP521 => Algorithms::ECC(Curve::NistP521),
        }
    }

    pub fn get_signing_key_algorithm(&self) -> Algorithms {
        self.get_algorithm(false)
    }

    pub fn get_encryption_key_algorithm(&self) -> Algorithms {
        self.get_algorithm(true)
    }
}

impl UserID {
    pub fn get_id(&self) -> Option<String> {
        self.id.clone()
    }
}

impl ArmoredKey {
    pub fn new<S: Into<String>>(public: S, private: S) -> Self {
        Self {
            public: public.into(),
            private: private.into(),
        }
    }

    pub fn get_public_key(&self) -> &str {
        &self.public
    }

    pub fn get_private_key(&self) -> &str {
        &self.private
    }
}
