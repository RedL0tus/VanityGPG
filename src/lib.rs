//! # VanityGPG
//!
//! It works.

extern crate anyhow;
#[cfg(feature = "rpgp")]
extern crate byteorder;
#[cfg(feature = "rpgp")]
extern crate chrono;
#[cfg(feature = "rpgp")]
extern crate hex;
#[cfg(feature = "rpgp")]
extern crate pgp;
#[cfg(feature = "rpgp")]
extern crate rand;
#[cfg(feature = "sequoia")]
extern crate sequoia_openpgp;
#[cfg(feature = "rpgp")]
extern crate sha1;
#[cfg(feature = "rpgp")]
extern crate smallvec;
extern crate thiserror;

pub mod pgp_backends;

pub use pgp_backends::{ArmoredKey, Backend, CipherSuite, DefaultBackend, UserID};

#[cfg(test)]
mod test {
    #[test]
    fn it_works() {
        assert_eq!(1 + 1, 2);
    }
}
