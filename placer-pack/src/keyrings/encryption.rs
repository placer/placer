//! Encryption keyring

use std::collections::BTreeMap;

use crate::crypto::Encryptor;
use crate::error::Error;

/// Keyring of `Encryptor` values
pub struct EncryptionKeyring {
    /// Encryption keys
    pub keys: BTreeMap<String, String>,
}

impl EncryptionKeyring {
    /// Create a new encryption keyring
    pub fn new(keys: &BTreeMap<String, String>) -> Result<Self, Error> {
        Ok(EncryptionKeyring { keys: keys.clone() })
    }

    /// Get an `Encryptor` from the keyring
    #[inline]
    pub fn get(&self, key: &str, salt: &[u8]) -> Result<Encryptor, Error> {
        match self.keys.get(key) {
            Some(k) => Ok(Encryptor::from_keyuri(k, salt)?),
            None => fail!(InvalidKey, "unknown encryption key: \"{}\"", key),
        }
    }
}
