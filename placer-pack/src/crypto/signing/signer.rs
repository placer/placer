use crate::error::Error;
use signatory::{
    ed25519::{Signature, SigningKey},
    signature::Signer as _,
};

use super::PublicKey;

/// Pack signer (using Ed25519 digital signature algorithm)
pub struct Signer(SigningKey);

impl Signer {
    /// Software-backed signer based on ed25519-dalek
    pub fn from_bytes(seed: &[u8]) -> Result<Self, Error> {
        Ok(Signer(SigningKey::from_bytes(seed).unwrap()))
    }

    /// Obtain public key for this signer
    pub fn public_key(&self) -> Result<PublicKey, Error> {
        Ok(self.0.verifying_key().into())
    }

    /// Sign a message
    pub fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        Ok(self.0.sign(msg))
    }
}
