//! Keyring configuration file

use crate::error::Error;
use crate::keyuri::{bech32k, ENCRYPTION_KEY_PREFIX, SIGNING_KEY_PREFIX};
use clear_on_drop::clear::Clear;
use rand::{OsRng, Rng};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::crypto::{ENCRYPTION_KEY_SIZE, SIGNING_KEY_SIZE};

/// Mandatory file permissions for config file.
/// Restricted since they (may) contain encryption keys
pub const REQUIRED_FILE_PERMISSIONS: u32 = 0o600;

/// Name of the default key in a keyring
pub const DEFAULT_KEY_LABEL: &str = "default";

/// Keyring configuration
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Digital signature keyring
    pub signing: BTreeMap<String, String>,

    /// Encryption keyring
    pub encryption: BTreeMap<String, String>,
}

impl Config {
    /// Create a new random set of keys
    pub fn generate_random() -> Result<Self, Error> {
        let mut rng = OsRng::new().unwrap_or_else(|e| {
            panic!("OS random number generator failure! {}", e);
        });

        let mut signing_key_bytes = [0u8; SIGNING_KEY_SIZE];
        rng.fill_bytes(&mut signing_key_bytes[..]);

        let mut signing_keys = BTreeMap::new();
        signing_keys.insert(
            DEFAULT_KEY_LABEL.to_owned(),
            bech32k::encode(SIGNING_KEY_PREFIX, &signing_key_bytes),
        );
        signing_key_bytes.clear();

        let mut encryption_key_bytes = [0u8; ENCRYPTION_KEY_SIZE];
        rng.fill_bytes(&mut encryption_key_bytes[..]);

        let mut encryption_keys = BTreeMap::new();
        encryption_keys.insert(
            DEFAULT_KEY_LABEL.to_owned(),
            bech32k::encode(ENCRYPTION_KEY_PREFIX, &encryption_key_bytes),
        );
        encryption_key_bytes.clear();

        Ok(Self {
            signing: signing_keys,
            encryption: encryption_keys,
        })
    }

    /// Load the keyring configuration from a file
    pub fn load(filename: &Path) -> Result<Self, Error> {
        let mut file = File::open(filename)
            .map_err(|e| err!(Io, "couldn't open {}: {}", filename.to_string_lossy(), e))?;

        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();

        toml::from_str(&data).map_err(|e| {
            err!(
                Config,
                "couldn't parse {}: {}",
                filename.to_string_lossy(),
                e
            )
        })
    }

    /// Save the keyring configuration to a file
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        let filename = path.to_string_lossy();
        let mut toml = toml::to_string(self).unwrap();

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(REQUIRED_FILE_PERMISSIONS)
            .open(path)
            .map_err(|e| err!(Io, "couldn't open {} for writing: {}", filename, e))?;

        writeln!(&mut file, "# placer signing key configuration")?;
        writeln!(
            &mut file,
            "# PROTECT THIS FILE!!! It contains all of your secret keys!\n"
        )?;

        file.write_all(toml.as_bytes())
            .map_err(|e| err!(Io, "couldn't write to {}: {}", filename, e))?;

        toml.clear();
        Ok(())
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        for v in self.signing.values_mut() {
            v.as_bytes().clear();
        }

        for v in self.encryption.values_mut() {
            v.as_bytes().clear();
        }
    }
}
