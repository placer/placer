//! Keyring configuration file

use crate::error::Error;
use clear_on_drop::clear::Clear;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Mandatory file permissions for config file.
/// Restricted since they (may) contain encryption keys
pub const REQUIRED_FILE_PERMISSIONS: u32 = 0o600;

/// Keyring configuration
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyringConfig {
    /// Digital signature keyring
    pub signing: BTreeMap<String, String>,

    /// Encryption keyring
    pub encryption: BTreeMap<String, String>,
}

impl KeyringConfig {
    /// Load the keyring configuration from a file
    pub fn load(filename: &Path) -> Result<Self, Error> {
        let mut file = File::open(filename)
            .map_err(|e| err!(Io, "couldn't open {}: {}", filename.to_string_lossy(), e))?;

        let permissions = file.metadata()?.permissions();

        if permissions.mode() != (0o100_000 | REQUIRED_FILE_PERMISSIONS) {
            fail!(
                Config,
                "bad file permissions for {:?} (must be chmod 0600)",
                filename.to_string_lossy()
            );
        }

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
}

impl Drop for KeyringConfig {
    fn drop(&mut self) {
        for v in self.encryption.values_mut() {
            v.as_bytes().clear();
        }
    }
}
