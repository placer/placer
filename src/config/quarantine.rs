//! Quarantine configuration: where bad files go when they die

use std::path::PathBuf;

/// File quarantine config
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct QuarantineConfig {
    /// Path to the cache directory
    pub path: PathBuf,

    /// User which files in the cache directory will be owned by
    pub user: String,

    /// Group which files in the cache directory will be owned by
    pub group: String,

    /// File permissions of files in the cache directory (in octal)
    pub mode: String,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            path: "/var/preserve/placer".into(),
            user: "nobody".to_owned(),
            group: "nobody".to_owned(),
            mode: "0000".to_owned(),
        }
    }
}
