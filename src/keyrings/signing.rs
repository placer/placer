//! Signing keyring

use std::collections::BTreeMap;

use crate::error::Error;
use placer_pack::crypto::PublicKey;

/// Keyring of `PublicKey` (Ed25519 verifier key) values
pub struct SigningKeyring {
    /// Signing public keys
    keys: BTreeMap<String, PublicKey>,
}

impl SigningKeyring {
    pub fn new(keys: &BTreeMap<String, String>) -> Result<Self, Error> {
        let mut k = BTreeMap::new();

        for (label, encoded_key) in keys {
            let public_key = PublicKey::from_keyuri(encoded_key).map_err(|e| {
                err!(
                    InvalidKey,
                    "invalid Ed25519 KeyURI: {} ({})",
                    encoded_key,
                    e
                )
            })?;

            if k.insert(public_key.to_fingerprint(), public_key).is_some() {
                fail!(InvalidKey, "duplicate signing key: \"{}\"", label);
            }
        }

        Ok(SigningKeyring { keys: k })
    }

    /// Get an Ed25519 `PublicKey` from the keyring
    #[inline]
    pub fn get(&self, key: &str) -> Result<&PublicKey, Error> {
        self.keys
            .get(key)
            .ok_or_else(|| err!(InvalidKey, "unknown signing key: \"{}\"", key))
    }
}
