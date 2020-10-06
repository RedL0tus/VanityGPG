//! rPGP backend
//!
//! This is a wrapper of the `rPGP` crate for generating vanity OpenPGP keys.

use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, TimeZone, Utc};
use hex::encode_upper;
use pgp::composed::{KeyDetails, SecretKey, SecretSubkey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::crypto::{ecdh, eddsa, rsa};
use pgp::key::KeyType;
use pgp::packet::{
    KeyFlags, PublicKey as PublicKeyPacket, PublicSubkey as PublicSubkeyPacket,
    SecretKey as SecretKeyPacket, SecretSubkey as SecretSubkeyPacket, UserId as UserIDPacket,
};
use pgp::ser::Serialize;
use pgp::types::{
    CompressionAlgorithm, KeyVersion, PublicParams, SecretKeyTrait, SecretParams, Version,
};
use rand::thread_rng;
use sha1::{Digest, Sha1};
use smallvec::smallvec;

use super::{ArmoredKey, Backend, CipherSuite, PGPError, UniversalError, UserID};

/// Converter for transmuting to struct with private fields
#[allow(dead_code)]
struct PublicKeyPacketConverter {
    packet_version: Version,
    version: KeyVersion,
    algorithm: PublicKeyAlgorithm,
    created_at: DateTime<Utc>,
    expiration: Option<u16>,
    public_params: PublicParams,
}

/// Converter for transmuting to struct with private fields
#[allow(dead_code)]
struct SecretKeyPacketConverter {
    details: PublicKeyPacket,
    secret_params: SecretParams,
}

/// Converter for transmuting to struct with private fields
#[allow(dead_code)]
struct SecretSubkeyPacketConverter {
    details: PublicSubkeyPacket,
    secret_params: SecretParams,
}

/// VanityGPG backend powered by rPGP
pub struct RPGPBackend {
    public_params: PublicParams,
    secret_params: SecretParams,
    key_type: KeyType,
    cipher_suite: CipherSuite,
    timestamp: u32,
    packet_cache: Vec<u8>,
}

/// Generate key with the required `CipherSuite`
// So messy, wow
fn generate_key(
    cipher_suite: &CipherSuite,
    for_signing: bool,
) -> Result<(KeyType, PublicParams, SecretParams), PGPError> {
    let mut rng = thread_rng();
    match {
        match cipher_suite {
            &CipherSuite::RSA2048 => {
                Ok((KeyType::Rsa(2048), rsa::generate_key(&mut rng, 2048usize)))
            }
            &CipherSuite::RSA3072 => {
                Ok((KeyType::Rsa(3072), rsa::generate_key(&mut rng, 3072usize)))
            }
            &CipherSuite::RSA4096 => {
                Ok((KeyType::Rsa(4096), rsa::generate_key(&mut rng, 4096usize)))
            }
            &CipherSuite::Curve25519 => {
                if for_signing {
                    Ok((KeyType::EdDSA, Ok(eddsa::generate_key(&mut rng))))
                } else {
                    Ok((KeyType::ECDH, Ok(ecdh::generate_key(&mut rng))))
                }
            }
            _ => Err(PGPError::AlgorithmNotSupportedByTheCurrentBackend(
                "NIST ECC curves are not supported".to_string(),
            )),
        }
    } {
        Ok((key_type, Ok((public_params, plain_secret_params)))) => Ok((
            key_type,
            public_params,
            SecretParams::Plain(plain_secret_params),
        )),
        Ok((_key_type, Err(_))) => Err(PGPError::KeyGenerationFailed),
        Err(e) => Err(e),
    }
}

impl Into<PublicKeyPacket> for PublicKeyPacketConverter {
    /// Transmuting to `PublicKeyPacket`
    fn into(self) -> PublicKeyPacket {
        unsafe { std::mem::transmute::<PublicKeyPacketConverter, PublicKeyPacket>(self) }
    }
}

impl Into<PublicSubkeyPacket> for PublicKeyPacketConverter {
    /// Transmuting to `PublicSubkeyPacket`
    fn into(self) -> PublicSubkeyPacket {
        unsafe { std::mem::transmute::<PublicKeyPacketConverter, PublicSubkeyPacket>(self) }
    }
}

impl PublicKeyPacketConverter {
    /// Create new instance
    fn new(algorithm: PublicKeyAlgorithm, public_params: PublicParams, created_at: u32) -> Self {
        Self {
            packet_version: Version::New,
            version: KeyVersion::V4,
            algorithm,
            created_at: Utc.timestamp(created_at as i64, 0),
            expiration: None,
            public_params,
        }
    }
}

impl Into<SecretKeyPacket> for SecretKeyPacketConverter {
    /// Transmuting to `SecretKeyPacket`
    fn into(self) -> SecretKeyPacket {
        unsafe { std::mem::transmute::<SecretKeyPacketConverter, SecretKeyPacket>(self) }
    }
}

impl SecretKeyPacketConverter {
    /// Create new instance
    fn new(details: PublicKeyPacket, secret_params: SecretParams) -> Self {
        Self {
            details,
            secret_params,
        }
    }
}

impl Into<SecretSubkeyPacket> for SecretSubkeyPacketConverter {
    /// Transmuting to `SecretSubkeyPacket`
    fn into(self) -> SecretSubkeyPacket {
        unsafe { std::mem::transmute::<SecretSubkeyPacketConverter, SecretSubkeyPacket>(self) }
    }
}

impl SecretSubkeyPacketConverter {
    /// Create new instance
    fn new(details: PublicSubkeyPacket, secret_params: SecretParams) -> Self {
        Self {
            details,
            secret_params,
        }
    }
}

impl Backend for RPGPBackend {
    fn fingerprint(&self) -> String {
        let mut hasher = Sha1::new();
        hasher.update(&self.packet_cache);
        encode_upper(hasher.finalize().to_vec())
    }

    fn shuffle(&mut self) -> Result<(), PGPError> {
        self.timestamp -= 1;
        BigEndian::write_u32(&mut self.packet_cache[4..8], self.timestamp);
        Ok(())
    }

    fn get_armored_results(self, uid: &UserID) -> Result<ArmoredKey, UniversalError> {
        // Generate Subkey
        let mut subkey_flags = KeyFlags::default();
        subkey_flags.set_encrypt_storage(true);
        subkey_flags.set_encrypt_comms(true);
        let (subkey_type, subkey_public_params, subkey_secret_params) =
            generate_key(&self.cipher_suite, false)?;
        let public_subkey_packet: PublicSubkeyPacket = PublicKeyPacketConverter::new(
            subkey_type.to_alg(),
            subkey_public_params,
            self.timestamp,
        )
        .into();
        let secret_subkey_packet: SecretSubkeyPacket =
            SecretSubkeyPacketConverter::new(public_subkey_packet, subkey_secret_params).into();
        let secret_subkey = SecretSubkey::new(secret_subkey_packet, subkey_flags);

        let uid_packet =
            UserIDPacket::from_str(Default::default(), &uid.get_id().unwrap_or("".to_string()));
        let mut key_flags = KeyFlags::default();
        key_flags.set_certify(true);
        key_flags.set_sign(true);
        let key_details = KeyDetails::new(
            uid_packet,
            Vec::new(),
            Vec::new(),
            key_flags,
            smallvec![SymmetricKeyAlgorithm::AES256, SymmetricKeyAlgorithm::AES128,],
            smallvec![HashAlgorithm::SHA2_512, HashAlgorithm::SHA2_256],
            smallvec![CompressionAlgorithm::ZLIB],
            None,
        );
        let primary_public_key_packet: PublicKeyPacket = PublicKeyPacketConverter::new(
            self.key_type.to_alg(),
            self.public_params,
            self.timestamp,
        )
        .into();
        let primary_secret_key_packet: SecretKeyPacket =
            SecretKeyPacketConverter::new(primary_public_key_packet, self.secret_params).into();

        let signed_secret_key = SecretKey::new(
            primary_secret_key_packet,
            key_details,
            Default::default(),
            vec![secret_subkey],
        )
        .sign(|| "".to_string())?;

        let signed_public_key = signed_secret_key
            .public_key()
            .sign(&signed_secret_key, || "".to_string())?;

        Ok(ArmoredKey::new(
            signed_public_key.to_armored_string(None)?,
            signed_secret_key.to_armored_string(None)?,
        ))
    }
}

impl RPGPBackend {
    /// Create new instance
    pub fn new<C: Into<CipherSuite>>(cipher_suite: C) -> Result<Self, PGPError> {
        let valid_cipher_suite = cipher_suite.into();
        if let Ok((key_type, public_params, secret_params)) =
            generate_key(&valid_cipher_suite, true)
        {
            let timestamp = Utc::now().timestamp() as u32;
            let mut packet_cache: Vec<u8> = vec![0x99, 0, 0, 4, 0, 0, 0, 0]; // Version 4
            BigEndian::write_u32(&mut packet_cache[4..8], timestamp); // Timestamp
            packet_cache.push(key_type.to_alg() as u8); // Algorithm identifier
            public_params
                .to_writer(&mut packet_cache)
                .expect("Failed to write public_params to packet cache");
            let packet_length = (packet_cache.len() as u16) - 3;
            BigEndian::write_u16(&mut packet_cache[1..3], packet_length);
            Ok(Self {
                public_params,
                secret_params,
                key_type,
                cipher_suite: valid_cipher_suite,
                timestamp,
                packet_cache,
            })
        } else {
            Err(PGPError::KeyGenerationFailed)
        }
    }

    #[allow(dead_code)]
    /// Get public params
    pub(crate) fn get_public_params(self) -> PublicParams {
        self.public_params
    }

    #[allow(dead_code)]
    /// Get `u32` timestamp
    // Boo! You've just found something that will go wrong after the year 2038
    pub(crate) fn get_timestamp(&self) -> u32 {
        self.timestamp
    }
}

#[cfg(test)]
mod rpgp_backend_test {
    use super::{
        Backend, CipherSuite, PublicKeyAlgorithm, PublicKeyPacket, PublicKeyPacketConverter,
        RPGPBackend, UserID,
    };
    use hex::encode_upper;
    use pgp::composed::{Deserializable, SignedSecretKey};
    use pgp::types::KeyTrait;
    use std::io::Cursor;

    #[test]
    fn ed25519_key_generation() {
        let backend = RPGPBackend::new(CipherSuite::Curve25519).unwrap();
        let timestamp = backend.get_timestamp();
        let public_params = backend.get_public_params();
        let _public_key_packet: PublicKeyPacket =
            PublicKeyPacketConverter::new(PublicKeyAlgorithm::EdDSA, public_params, timestamp)
                .into();
    }

    #[test]
    fn ed25519_fingerprint_calculation() {
        let backend = RPGPBackend::new(CipherSuite::Curve25519).unwrap();
        let fingerprint_custom = backend.fingerprint();
        let timestamp = backend.get_timestamp();
        let public_params = backend.get_public_params();
        let public_key_packet: PublicKeyPacket =
            PublicKeyPacketConverter::new(PublicKeyAlgorithm::EdDSA, public_params, timestamp)
                .into();
        let fingerprint_rpgp = encode_upper(public_key_packet.fingerprint());

        assert_eq!(fingerprint_custom, fingerprint_rpgp);
    }

    #[test]
    fn ed25519_shuffle() {
        let mut backend = RPGPBackend::new(CipherSuite::Curve25519).unwrap();
        let fingerprint_custom_before = backend.fingerprint();
        let timestamp_before = backend.get_timestamp();
        backend.shuffle().unwrap();
        let fingerprint_custom_after = backend.fingerprint();
        let timestamp_after = backend.get_timestamp();
        assert_ne!(timestamp_before, timestamp_after);

        let public_params = backend.get_public_params();
        let public_key_packet_before: PublicKeyPacket = PublicKeyPacketConverter::new(
            PublicKeyAlgorithm::EdDSA,
            public_params.clone(),
            timestamp_before,
        )
        .into();
        let fingerprint_rpgp_before = encode_upper(public_key_packet_before.fingerprint());
        let public_key_packet_after: PublicKeyPacket = PublicKeyPacketConverter::new(
            PublicKeyAlgorithm::EdDSA,
            public_params,
            timestamp_after,
        )
        .into();
        let fingerprint_rpgp_after = encode_upper(public_key_packet_after.fingerprint());

        assert_eq!(fingerprint_custom_before, fingerprint_rpgp_before);
        assert_eq!(fingerprint_custom_after, fingerprint_rpgp_after);
    }

    #[test]
    fn ed25519_export() {
        let mut backend = RPGPBackend::new(CipherSuite::Curve25519).unwrap();
        backend.shuffle().unwrap();
        let fingerprint_before = backend.fingerprint();
        let uid = UserID::from("Tiansuo Li <114514@example.com>".to_string());
        let results = backend.get_armored_results(&uid).unwrap();
        assert!(!results.get_private_key().is_empty());
        assert!(!results.get_public_key().is_empty());

        let cursor = Cursor::new(results.get_private_key());

        let key = SignedSecretKey::from_armor_single(cursor).unwrap().0;
        let fingerprint_after = encode_upper(key.fingerprint());
        assert_eq!(fingerprint_before, fingerprint_after);
        assert_eq!(key.algorithm(), PublicKeyAlgorithm::EdDSA);
        assert_eq!(
            &key.details.users[0].id.id(),
            &"Tiansuo Li <114514@example.com>"
        );
        key.verify().unwrap();
    }

    #[test]
    fn rsa2048_key_generation() {
        let backend = RPGPBackend::new(CipherSuite::RSA2048).unwrap();
        let timestamp = backend.get_timestamp();
        let public_params = backend.get_public_params();
        let _public_key_packet: PublicKeyPacket =
            PublicKeyPacketConverter::new(PublicKeyAlgorithm::RSA, public_params, timestamp).into();
    }

    #[test]
    fn rsa2048_fingerprint_calculation() {
        let backend = RPGPBackend::new(CipherSuite::RSA2048).unwrap();
        let fingerprint_custom = backend.fingerprint();
        let timestamp = backend.get_timestamp();
        let public_params = backend.get_public_params();
        let public_key_packet: PublicKeyPacket =
            PublicKeyPacketConverter::new(PublicKeyAlgorithm::RSA, public_params, timestamp).into();
        let fingerprint_rpgp = encode_upper(public_key_packet.fingerprint());

        assert_eq!(fingerprint_custom, fingerprint_rpgp);
    }

    #[test]
    fn rsa2048_shuffle() {
        let mut backend = RPGPBackend::new(CipherSuite::RSA2048).unwrap();
        let fingerprint_custom_before = backend.fingerprint();
        let timestamp_before = backend.get_timestamp();
        backend.shuffle().unwrap();
        let fingerprint_custom_after = backend.fingerprint();
        let timestamp_after = backend.get_timestamp();
        assert_ne!(timestamp_before, timestamp_after);

        let public_params = backend.get_public_params();
        let public_key_packet_before: PublicKeyPacket = PublicKeyPacketConverter::new(
            PublicKeyAlgorithm::RSA,
            public_params.clone(),
            timestamp_before,
        )
        .into();
        let fingerprint_rpgp_before = encode_upper(public_key_packet_before.fingerprint());
        let public_key_packet_after: PublicKeyPacket =
            PublicKeyPacketConverter::new(PublicKeyAlgorithm::RSA, public_params, timestamp_after)
                .into();
        let fingerprint_rpgp_after = encode_upper(public_key_packet_after.fingerprint());

        assert_eq!(fingerprint_custom_before, fingerprint_rpgp_before);
        assert_eq!(fingerprint_custom_after, fingerprint_rpgp_after);
    }

    #[test]
    fn rsa2048_export() {
        let mut backend = RPGPBackend::new(CipherSuite::RSA2048).unwrap();
        backend.shuffle().unwrap();
        let fingerprint_before = backend.fingerprint();
        let uid = UserID::from("Tiansuo Li <114514@example.com>".to_string());
        let results = backend.get_armored_results(&uid).unwrap();
        assert!(!results.get_private_key().is_empty());
        assert!(!results.get_public_key().is_empty());

        let cursor = Cursor::new(results.get_private_key());

        let key = SignedSecretKey::from_armor_single(cursor).unwrap().0;
        let fingerprint_after = encode_upper(key.fingerprint());
        assert_eq!(fingerprint_before, fingerprint_after);
        assert_eq!(key.algorithm(), PublicKeyAlgorithm::RSA);
        assert_eq!(
            &key.details.users[0].id.id(),
            &"Tiansuo Li <114514@example.com>"
        );
        key.verify().unwrap();
    }
}
