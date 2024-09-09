//! Placer configuration file

mod cache;
mod file_config;
mod log;
mod quarantine;
mod source;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::Error;

pub use self::cache::CacheConfig;
pub use self::file_config::{FileConfig, HookConfig};
pub use self::log::LogConfig;
pub use self::quarantine::QuarantineConfig;
pub use self::source::SourceConfig;

/// Toplevel attributes of a placer configuration file
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Path to a TOML file containing keyring configuration
    pub keyrings: PathBuf,

    /// Sources where new/updated packs are fetched from
    pub sources: BTreeMap<String, SourceConfig>,

    /// Logging configuration
    pub log: LogConfig,

    /// Pack caching configuration
    pub cache: CacheConfig,

    /// File quarantine config
    pub quarantine: QuarantineConfig,

    /// File to be placed
    pub files: BTreeMap<PathBuf, FileConfig>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let filename = path.to_string_lossy().to_string();

        let mut file =
            File::open(path).map_err(|e| err!(Config, "couldn't open {}: {}", filename, e))?;

        let mut data = String::new();
        file.read_to_string(&mut data)?;

        toml::from_str(&data).map_err(|e| err!(Config, "couldn't parse {}: {}", filename, e))
    }
}
