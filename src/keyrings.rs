//! Signing and encryption keyrings

use placer_pack::crypto::{Encryptor, PublicKey};
use placer_pack::Fingerprints;
use std::path::Path;
use uuid::Uuid;

mod config;
mod encryption;
mod signing;

use self::config::KeyringConfig;
use self::encryption::EncryptionKeyring;
use self::signing::SigningKeyring;
use crate::error::Error;

/// Cryptographic keyrings
pub struct Keyrings {
    /// Encryption keys
    pub encryption: EncryptionKeyring,

    /// Signing keys
    pub signing: SigningKeyring,
}

impl Keyrings {
    /// Load the keyring configuration from a file
    pub fn load(path: &Path) -> Result<Self, Error> {
        let config = KeyringConfig::load(path)?;

        Ok(Self {
            encryption: EncryptionKeyring::new(&config.encryption)?,
            signing: SigningKeyring::new(&config.signing)?,
        })
    }

    /// Get the keys for a set of fingerprints
    pub fn get_for_fingerprints(
        &self,
        fingerprints: &Fingerprints,
        uuid: &Uuid,
    ) -> Result<(PublicKey, Encryptor), Error> {
        let verify_key = self
            .signing
            .get(&fingerprints.signing_key)
            .map_err(|e| err!(InvalidKey, "{}", e))?;

        let encryption_key = self
            .encryption
            .get(&fingerprints.encryption_key, uuid.as_bytes())
            .map_err(|e| err!(InvalidKey, "{}", e))?;

        Ok((*verify_key, encryption_key))
    }
}
