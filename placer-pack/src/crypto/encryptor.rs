//! Symmetric encryption functionality

use aes_siv::{aead::generic_array::GenericArray, siv::Aes256Siv};
use clear_on_drop::clear::Clear;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::Error;
use crate::keyuri::{self, bech32k, ENCRYPTION_KEY_PREFIX};

/// Size of an AES-256 key in bytes (which we expand to 2 * AES-256 keys with HKDF-SHA-256)
pub const ENCRYPTION_KEY_SIZE: usize = 32;

/// A symmetric encryptor (providing AES-256-SIV)
pub struct Encryptor {
    algorithm: Aes256Siv,
    fingerprint: String,
}

impl Encryptor {
    /// Create an encryptor from a secret key encoded as a KeyURI
    pub fn from_keyuri(secret_keyuri: &str, salt: &[u8]) -> Result<Self, Error> {
        let fingerprint = keyuri::fingerprint(secret_keyuri);
        let (prefix, mut decoded_key) = bech32k::decode(secret_keyuri)?;

        if prefix != ENCRYPTION_KEY_PREFIX {
            fail!(InvalidKey, "invalid encryption key prefix: {}", prefix);
        }

        if decoded_key.len() != ENCRYPTION_KEY_SIZE {
            fail!(
                InvalidKey,
                "bad length for {}: {} (expected {})",
                prefix,
                decoded_key.len(),
                ENCRYPTION_KEY_SIZE
            );
        }

        // TODO: support salts?
        let hkdf = Hkdf::<Sha256>::extract(salt, &decoded_key);
        decoded_key.as_mut_slice().clear();

        // We need 2 * AES keys for AES-SIV
        let mut expanded_key =
            hkdf.expand(ENCRYPTION_KEY_PREFIX.as_bytes(), ENCRYPTION_KEY_SIZE * 2);

        let algorithm = Aes256Siv::new(GenericArray::clone_from_slice(&expanded_key));
        expanded_key.as_mut_slice().clear();

        Ok(Self {
            algorithm,
            fingerprint,
        })
    }

    /// Obtain SHA-256 KeyURI fingerprint
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Encrypt the message using the underlying encryption algorithm (AES-256-SIV)
    pub fn seal<I, T>(&mut self, associated_data: I, plaintext: &[u8]) -> Vec<u8>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        self.algorithm
            .encrypt(associated_data, plaintext)
            .expect("SIV error")
    }

    /// Decrypt the message using the underling encryption algorithm (AES-256-SIV)
    pub fn open<I, T>(&mut self, associated_data: I, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        self.algorithm
            .decrypt(associated_data, ciphertext)
            .map_err(|e| err!(Crypto, "{}", e))
    }
}
