//! Encryption keyring

use std::collections::BTreeMap;

use crate::error::Error;
use placer_pack::crypto::Encryptor;
use placer_pack::keyuri::{self, ENCRYPTION_KEY_PREFIX};

/// Keyring of `Encryptor` values
pub struct EncryptionKeyring {
    /// Encryption keys
    pub keys: BTreeMap<String, String>,
}

impl EncryptionKeyring {
    /// Create a new encryption keyring
    pub fn new(keys: &BTreeMap<String, String>) -> Result<Self, Error> {
        let mut k = BTreeMap::new();

        for (label, encoded_key) in keys {
            if !encoded_key.starts_with(ENCRYPTION_KEY_PREFIX) {
                fail!(InvalidKey, "invalid encryption KeyURI: {}", encoded_key,)
            }

            if k.insert(keyuri::fingerprint(encoded_key), encoded_key.clone())
                .is_some()
            {
                fail!(InvalidKey, "duplicate encryption key: \"{}\"", label);
            }
        }

        Ok(EncryptionKeyring { keys: k })
    }

    /// Get an `Encryptor` from the keyring
    #[inline]
    pub fn get(&self, key: &str, salt: &[u8]) -> Result<Encryptor, Error> {
        match self.keys.get(key) {
            Some(k) => Ok(Encryptor::from_keyuri(k, salt)
                .map_err(|e| err!(InvalidKey, "invalid encryption KeyURI: \"{}\" ({})", k, e))?),
            None => fail!(InvalidKey, "unknown encryption key: \"{}\"", key),
        }
    }
}
