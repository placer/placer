//! Pack caching configuration

/// Pack caching configuration
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    /// Path to the cache directory
    pub path: String,

    /// User which files in the cache directory will be owned by
    #[serde(default)]
    pub user: String,

    /// Group which files in the cache directory will be owned by
    #[serde(default)]
    pub group: String,

    /// File permissions of files in the cache directory (in octal)
    #[serde(default)]
    pub mode: String,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            path: "/var/cache/placer".to_owned(),
            user: "root".to_owned(),
            group: "root".to_owned(),
            mode: "0600".to_owned(),
        }
    }
}
