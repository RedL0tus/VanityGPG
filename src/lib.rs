//! # VanityGPG
//!
//! It works.

extern crate anyhow;
extern crate sequoia_openpgp;
extern crate thiserror;

pub mod pgp;

pub use pgp::{ArmoredKey, Backend, CipherSuite, DefaultBackend, UserID};

#[cfg(test)]
mod test {
    #[test]
    fn it_works() {
        assert_eq!(1 + 1, 2);
    }
}
