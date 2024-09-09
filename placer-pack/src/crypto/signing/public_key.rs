//! Ed25519 public keys

use crate::error::Error;
use crate::keyuri::{bech32k, fingerprint, VERIFY_KEY_PREFIX};
use signatory::{ed25519, signature::Verifier};
use std::convert::TryFrom;

/// Size of an Ed25519 public key
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of an Ed25519 signature
pub const SIGNATURE_SIZE: usize = 64;

/// Ed25519 public key
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);

impl PublicKey {
    /// Create a public key from a KeyURI
    pub fn from_keyuri(keyuri: &str) -> Result<Self, Error> {
        let (prefix, bytes) = bech32k::decode(keyuri)?;

        if prefix != VERIFY_KEY_PREFIX {
            fail!(InvalidKey, "invalid encryption key prefix: {}", prefix);
        }

        if bytes.len() != PUBLIC_KEY_SIZE {
            fail!(
                InvalidKey,
                "invalid key length: {}-bytes (expected {})",
                bytes.len(),
                PUBLIC_KEY_SIZE
            );
        }

        let mut key = [0u8; PUBLIC_KEY_SIZE];
        key.copy_from_slice(&bytes);

        Ok(PublicKey(key))
    }

    /// Borrow the bytes of the public key as a slice
    #[inline]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Serialize this public key as a KeyURI
    pub fn to_keyuri(&self) -> String {
        bech32k::encode(VERIFY_KEY_PREFIX, self.as_bytes())
    }

    /// Create a public key fingerprint for this public key as a KeyURI
    pub fn to_fingerprint(&self) -> String {
        fingerprint(&self.to_keyuri())
    }

    /// Verify a message with this key
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let sig = ed25519::Signature::try_from(signature).map_err(|_| {
            err!(
                Crypto,
                "invalid signature size: {} (expected {})",
                signature.len(),
                SIGNATURE_SIZE
            )
        })?;

        ed25519::VerifyingKey::from_bytes(&self.0)
            .unwrap()
            .verify(message, &sig)
            .map_err(|_| err!(Crypto, "signature verification failed!"))
    }
}

#[cfg(feature = "signer")]
impl From<ed25519::VerifyingKey> for PublicKey {
    fn from(key: ed25519::VerifyingKey) -> PublicKey {
        let mut result = [0u8; PUBLIC_KEY_SIZE];
        result.copy_from_slice(key.as_ref());
        PublicKey(result)
    }
}
