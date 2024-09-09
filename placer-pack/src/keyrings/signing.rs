//! Signing keyring

use std::collections::BTreeMap;

use crate::crypto::{Signer, SIGNING_KEY_SIZE};
use crate::error::Error;
use crate::keyuri::{bech32k, SIGNING_KEY_PREFIX};

/// Keyring of `Signer` values
pub struct SigningKeyring {
    /// Signing keys
    pub(crate) keys: BTreeMap<String, Signer>,
}

impl SigningKeyring {
    pub fn new(keys: &BTreeMap<String, String>) -> Result<Self, Error> {
        let mut signers = BTreeMap::new();

        for (label, encoded_key) in keys {
            let (prefix, mut decoded_key) = bech32k::decode(encoded_key)?;

            if prefix != SIGNING_KEY_PREFIX {
                fail!(InvalidKey, "invalid signing key type: \"{}\"", prefix);
            }

            if decoded_key.len() != SIGNING_KEY_SIZE {
                fail!(
                    InvalidKey,
                    "bad length for {}: {} (expected {})",
                    label,
                    decoded_key.len(),
                    SIGNING_KEY_SIZE
                );
            }

            // TODO: support signers other than dalek
            let signer = Signer::from_bytes(&decoded_key).unwrap();
            decoded_key.clear();

            if signers.insert(label.to_owned(), signer).is_some() {
                fail!(InvalidKey, "duplicate signing key: \"{}\"", label);
            }
        }

        Ok(SigningKeyring { keys: signers })
    }

    /// Get an `Signer` from the keyring
    #[inline]
    pub fn get(&self, key: &str) -> Result<&Signer, Error> {
        self.keys
            .get(key)
            .ok_or_else(|| err!(InvalidKey, "unknown signing key: \"{}\"", key))
    }
}
