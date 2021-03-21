//! Sequoia-OpenPGP backend
//!
//! This is a wrapper of the `Sequoia-OpenPGP` crate for generating vanity OpenPGP keys.

use byteorder::{BigEndian, ByteOrder};
use nettle::hash::insecure_do_not_use::Sha1;
use nettle::hash::Hash;
use sequoia_openpgp::armor::{Kind, Writer};
use sequoia_openpgp::packet::key::{Key4, PrimaryRole, SecretParts};
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::packet::UserID as SequoiaUserID;
use sequoia_openpgp::serialize::{MarshalInto, SerializeInto};
use sequoia_openpgp::types::{
    Curve as SequoiaCurve, Features, HashAlgorithm, KeyFlags, SignatureType, SymmetricAlgorithm,
};
use sequoia_openpgp::{Cert, Packet};

use super::{
    sha1_to_hex, Algorithms, ArmoredKey, Backend, CipherSuite, Curve, PGPError, UniversalError,
    UserID, RSA,
};

use std::io::Write;
use std::time::Duration;
use std::time::UNIX_EPOCH;

/// The `Sequoia-OpenPGP` backend wrapper
pub struct SequoiaBackend {
    primary_key: Key4<SecretParts, PrimaryRole>,
    cipher_suite: CipherSuite,
    timestamp: u32,
    packet_cache: Vec<u8>,
}

/// Generate key with the required `CipherSuite`
fn generate_key(
    algorithm: Algorithms,
    for_signing: bool,
) -> Result<Key4<SecretParts, PrimaryRole>, PGPError> {
    let wrapped_key: Result<Key4<SecretParts, PrimaryRole>, UniversalError> = match algorithm {
        Algorithms::RSA(rsa) => match rsa {
            RSA::RSA2048 => Key4::generate_rsa(2048),
            RSA::RSA3072 => Key4::generate_rsa(3072),
            RSA::RSA4096 => Key4::generate_rsa(4096),
        },
        Algorithms::ECC(curve) => match curve {
            Curve::Ed25519 => Key4::generate_ecc(for_signing, SequoiaCurve::Ed25519),
            Curve::Cv25519 => Key4::generate_ecc(for_signing, SequoiaCurve::Cv25519),
            Curve::NistP256 => Key4::generate_ecc(for_signing, SequoiaCurve::NistP256),
            Curve::NistP384 => Key4::generate_ecc(for_signing, SequoiaCurve::NistP384),
            Curve::NistP521 => Key4::generate_ecc(for_signing, SequoiaCurve::NistP521),
        },
    };
    if let Ok(key) = wrapped_key {
        Ok(key)
    } else {
        Err(PGPError::KeyGenerationFailed)
    }
}

impl Backend for SequoiaBackend {
    fn fingerprint(&self) -> String {
        let mut hasher = Sha1::default();
        hasher.update(&self.packet_cache);
        let mut digest_buffer: Vec<u8> = vec![0; hasher.digest_size()];
        hasher.digest(&mut digest_buffer);
        // hex_string(&digest_buffer).unwrap()
        sha1_to_hex(&digest_buffer)
    }

    fn shuffle(&mut self) -> Result<(), PGPError> {
        self.timestamp -= 1;
        BigEndian::write_u32(&mut self.packet_cache[4..8], self.timestamp);
        Ok(())
    }

    fn get_armored_results(mut self, uid: &UserID) -> Result<ArmoredKey, UniversalError> {
        let creation_time = UNIX_EPOCH.clone() + Duration::from_secs(self.timestamp as u64);
        self.primary_key.set_creation_time(creation_time)?;
        let mut packets = Vec::<Packet>::new();
        let mut signer = self.primary_key.clone().into_keypair()?;
        let primary_key_packet = Key::V4(self.primary_key);

        // Direct key signature and the secret key
        let direct_key_signature = SignatureBuilder::new(SignatureType::DirectKey)
            .set_hash_algo(HashAlgorithm::SHA512)
            .set_features(Features::sequoia())?
            .set_key_flags(KeyFlags::empty().set_certification().set_signing())?
            .set_signature_creation_time(creation_time)?
            .set_key_validity_period(None)?
            .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])?
            .set_preferred_symmetric_algorithms(vec![
                SymmetricAlgorithm::AES256,
                SymmetricAlgorithm::AES128,
            ])?
            .sign_direct_key(&mut signer, Some(primary_key_packet.parts_as_public()))?;
        packets.push(Packet::SecretKey(primary_key_packet));
        packets.push(direct_key_signature.clone().into());

        // Build certificate
        let mut cert = Cert::from_packets(packets.into_iter())?;

        // UID
        if let Some(uid_string) = uid.get_id() {
            let uid_signature_builder = SignatureBuilder::from(direct_key_signature)
                .set_signature_creation_time(creation_time)?
                .set_revocation_key(vec![])? // Remove revocation certificate
                .set_type(SignatureType::PositiveCertification)
                .set_hash_algo(HashAlgorithm::SHA512);
            let uid_packet = SequoiaUserID::from(uid_string);
            let uid_signature = uid_packet.bind(&mut signer, &cert, uid_signature_builder)?;
            cert = cert.insert_packets(vec![Packet::from(uid_packet), uid_signature.into()])?;
        }

        // Encryption subkey
        let mut subkey = generate_key(self.cipher_suite.get_encryption_key_algorithm(), false)?
            .parts_into_secret()?
            .role_into_subordinate();
        subkey.set_creation_time(creation_time)?;
        let subkey_packet = Key::V4(subkey);
        let subkey_signature_builder = SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_signature_creation_time(creation_time)?
            .set_hash_algo(HashAlgorithm::SHA512)
            .set_features(Features::sequoia())?
            .set_key_flags(KeyFlags::empty().set_storage_encryption())?
            .set_key_validity_period(None)?;
        let subkey_signature = subkey_packet.bind(&mut signer, &cert, subkey_signature_builder)?;
        cert = cert.insert_packets(vec![
            Packet::SecretSubkey(subkey_packet),
            subkey_signature.into(),
        ])?;

        if cert.unknowns().next().is_none() {
            // Get armored texts
            let armored_public_key = String::from_utf8(SerializeInto::to_vec(&cert.armored())?)?;
            let private_hex = SerializeInto::to_vec(&cert.as_tsk())?;
            let mut private_key_writer = Writer::new(Vec::new(), Kind::SecretKey)?;
            private_key_writer.write_all(&private_hex)?;
            let armored_private_key =
                String::from_utf8_lossy(&private_key_writer.finalize()?).to_string();

            Ok(ArmoredKey::new(armored_public_key, armored_private_key))
        } else {
            Err(PGPError::InvalidKeyGenerated.into())
        }
    }
}

impl SequoiaBackend {
    /// Create new instance
    pub fn new<C: Into<CipherSuite>>(cipher_suite: C) -> Result<Self, PGPError> {
        let ciphers = cipher_suite.into();
        let primary_key = generate_key(ciphers.get_signing_key_algorithm(), true)?;

        // Build packet cache
        let mut packet_cache: Vec<u8> = vec![0x99, 0, 0, 4, 0, 0, 0, 0];
        let packet_length = 6 + primary_key.mpis().serialized_len() as u16;
        BigEndian::write_u16(&mut packet_cache[1..3], packet_length); // Packet length
        let timestamp = primary_key
            .creation_time()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to get timestamp")
            .as_secs() as u32;
        BigEndian::write_u32(&mut packet_cache[4..8], timestamp); // Timestamp
        packet_cache.push(primary_key.pk_algo().into()); // Algorithm identifier
        let mut public_key_buffer =
            MarshalInto::to_vec(primary_key.mpis()).expect("Failed to serialize public key");
        packet_cache.append(&mut public_key_buffer); // Public key

        Ok(Self {
            primary_key,
            cipher_suite: ciphers,
            timestamp,
            packet_cache,
        })
    }

    /// Get primary key
    #[allow(dead_code)]
    pub(crate) fn get_primary_key(self) -> Key4<SecretParts, PrimaryRole> {
        self.primary_key
    }

    /// Get `u32` timestamp
    // Boo! You've just found something that will go wrong after the year 2038
    #[allow(dead_code)]
    pub(crate) fn get_timestamp(&self) -> u32 {
        self.timestamp
    }
}

#[cfg(test)]
mod sequoia_backend_test {
    use super::{Backend, Cert, CipherSuite, Key, SequoiaBackend, UserID};
    use anyhow::Error;
    use sequoia_openpgp::armor::{Reader, ReaderMode};
    use sequoia_openpgp::packet::Signature;
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::types::PublicKeyAlgorithm;
    use std::io::{Cursor, Read};
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn ed25519_key_generation() {
        let backend = SequoiaBackend::new(CipherSuite::Curve25519).unwrap();
        let key = backend.get_primary_key();
        assert_eq!(key.pk_algo(), PublicKeyAlgorithm::EdDSA);
    }

    #[test]
    fn ed25519_fingerprint_calculation() {
        let backend = SequoiaBackend::new(CipherSuite::Curve25519).unwrap();
        let fingerprint_custom = backend.fingerprint();
        let fingerprint_sequoia = backend.get_primary_key().fingerprint().to_hex();
        assert_eq!(fingerprint_custom, fingerprint_sequoia);
    }

    #[test]
    fn ed25519_shuffle() {
        let mut backend = SequoiaBackend::new(CipherSuite::Curve25519).unwrap();
        let fingerprint_custom_before = backend.fingerprint();
        let timestamp_before = backend.get_timestamp() as u64;
        backend.shuffle().unwrap();
        let fingerprint_custom_after = backend.fingerprint();
        let timestamp_after = backend.get_timestamp() as u64;
        assert_ne!(timestamp_before, timestamp_after);

        let mut primary_key = backend.get_primary_key();
        primary_key
            .set_creation_time(UNIX_EPOCH.clone() + Duration::from_secs(timestamp_before))
            .unwrap();
        let fingerprint_sequoia_before = primary_key.fingerprint().to_hex();
        primary_key
            .set_creation_time(UNIX_EPOCH.clone() + Duration::from_secs(timestamp_after))
            .unwrap();
        let fingerprint_sequoia_after = primary_key.fingerprint().to_hex();

        assert_eq!(fingerprint_custom_before, fingerprint_sequoia_before);
        assert_eq!(fingerprint_custom_after, fingerprint_sequoia_after);
    }

    #[test]
    fn ed25519_export() {
        let mut backend = SequoiaBackend::new(CipherSuite::Curve25519).unwrap();
        backend.shuffle().unwrap();
        let fingerprint_before = backend.fingerprint();
        let uid = UserID::from("Tiansuo Li <114514@example.com>".to_string());
        let results = backend.get_armored_results(&uid).unwrap();
        assert!(!results.get_private_key().is_empty());
        assert!(!results.get_public_key().is_empty());

        let mut cursor = Cursor::new(results.get_private_key());
        let mut reader = Reader::new(&mut cursor, ReaderMode::VeryTolerant);
        let mut content = Vec::new();
        reader.read_to_end(&mut content).unwrap();
        let cert = Cert::from_bytes(&content).unwrap();
        let fingerprint_after = cert.fingerprint().to_hex();
        assert_eq!(fingerprint_before, fingerprint_after);
        assert!(cert.is_tsk());
        assert!(cert
            .bad_signatures()
            .collect::<Vec<&Signature>>()
            .is_empty());
        for uid_after in cert.userids() {
            assert_eq!(
                String::from_utf8_lossy(uid_after.value()),
                "Tiansuo Li <114514@example.com>"
            );
        }
        let pk = match cert.primary_key().key().clone() {
            Key::V4(key_4) => key_4,
            _ => unreachable!(),
        };
        assert_eq!(pk.pk_algo(), PublicKeyAlgorithm::EdDSA);
    }

    #[test]
    fn rsa4096_key_generation() {
        let backend = SequoiaBackend::new(CipherSuite::RSA4096).unwrap();
        let key = backend.get_primary_key();
        assert_eq!(key.pk_algo(), PublicKeyAlgorithm::RSAEncryptSign);
    }

    #[test]
    fn rsa4096_fingerprint_calculation() {
        let backend = SequoiaBackend::new(CipherSuite::RSA4096).unwrap();
        let fingerprint_custom = backend.fingerprint();
        let fingerprint_sequoia = backend.get_primary_key().fingerprint().to_hex();
        assert_eq!(fingerprint_custom, fingerprint_sequoia);
    }

    #[test]
    fn rsa4096_shuffle() {
        let mut backend = SequoiaBackend::new(CipherSuite::RSA4096).unwrap();
        let fingerprint_custom_before = backend.fingerprint();
        let timestamp_before = backend.get_timestamp() as u64;
        backend.shuffle().unwrap();
        let fingerprint_custom_after = backend.fingerprint();
        let timestamp_after = backend.get_timestamp() as u64;
        assert_ne!(timestamp_before, timestamp_after);

        let mut primary_key = backend.get_primary_key();
        primary_key
            .set_creation_time(UNIX_EPOCH.clone() + Duration::from_secs(timestamp_before))
            .unwrap();
        let fingerprint_sequoia_before = primary_key.fingerprint().to_hex();
        primary_key
            .set_creation_time(UNIX_EPOCH.clone() + Duration::from_secs(timestamp_after))
            .unwrap();
        let fingerprint_sequoia_after = primary_key.fingerprint().to_hex();

        assert_eq!(fingerprint_custom_before, fingerprint_sequoia_before);
        assert_eq!(fingerprint_custom_after, fingerprint_sequoia_after);
    }

    #[test]
    fn rsa4096_export() -> Result<(), Error> {
        let mut backend = SequoiaBackend::new(CipherSuite::RSA4096).unwrap();
        backend.shuffle().unwrap();
        let fingerprint_before = backend.fingerprint();
        let uid = UserID::from("Tiansuo Li <114514@example.com>".to_string());
        let results = backend.get_armored_results(&uid).unwrap();
        assert!(!results.get_private_key().is_empty());
        assert!(!results.get_public_key().is_empty());

        let mut cursor = Cursor::new(results.get_private_key());
        let mut reader = Reader::new(&mut cursor, ReaderMode::VeryTolerant);
        let mut content = Vec::new();
        reader.read_to_end(&mut content).unwrap();
        let cert = Cert::from_bytes(&content).unwrap();
        let fingerprint_after = cert.fingerprint().to_hex();
        assert_eq!(fingerprint_before, fingerprint_after);
        assert!(cert.is_tsk());
        assert!(cert
            .bad_signatures()
            .collect::<Vec<&Signature>>()
            .is_empty());
        for uid_after in cert.userids() {
            assert_eq!(
                String::from_utf8_lossy(uid_after.value()),
                "Tiansuo Li <114514@example.com>"
            );
        }
        let pk = match cert.primary_key().key().clone() {
            Key::V4(key_4) => key_4,
            _ => unreachable!(),
        };
        assert_eq!(pk.pk_algo(), PublicKeyAlgorithm::RSAEncryptSign);
        Ok(())
    }
}
