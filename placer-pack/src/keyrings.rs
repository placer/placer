//! Cryptographic keyrings

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

mod config;
mod encryption;
mod signing;

pub use self::config::DEFAULT_KEY_LABEL;
use self::config::{Config, REQUIRED_FILE_PERMISSIONS};
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
    /// Generate a random set of keyrings
    pub fn generate_random(path: &Path) -> Result<(), Error> {
        Config::generate_random()?.save(path)
    }

    /// Load the keyring configuration from a file
    pub fn load(path: &Path) -> Result<Self, Error> {
        let config = Config::load(path)?;

        Ok(Self {
            encryption: EncryptionKeyring::new(&config.encryption)?,
            signing: SigningKeyring::new(&config.signing)?,
        })
    }

    /// Export verifier keys to the given file
    pub fn export_verify_keys(&self, output: &Path) -> Result<(), Error> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(REQUIRED_FILE_PERMISSIONS)
            .open(output)
            .map_err(|e| {
                err!(
                    Io,
                    "couldn't open {} for writing: {}",
                    output.to_string_lossy(),
                    e
                )
            })?;

        writeln!(
            &mut file,
            "# placer client keyring: contains pack signature verification keys"
        )?;
        writeln!(
            &mut file,
            "# Protect this file! It also contains pack decryption keys!\n"
        )?;

        // TODO: serde-powered serializer?
        writeln!(&mut file, "[signing]")?;

        for (label, signer) in &self.signing.keys {
            let public_key = signer.public_key()?;
            writeln!(&mut file, "{} = \"{}\"", label, public_key.to_keyuri())?;
        }

        writeln!(&mut file, "\n[encryption]")?;

        for (label, key) in &self.encryption.keys {
            writeln!(&mut file, "{} = \"{}\"", label, key)?;
        }

        Ok(())
    }
}
