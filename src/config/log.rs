//! Logging configuration

/// Logging configuration
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// Path to logfile
    pub path: String,

    /// User which owns logfile
    pub user: String,

    /// Group which owns logfile
    pub group: String,

    /// File permissions of logfile (in octal)
    pub mode: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            path: "/var/log/placer.log".to_owned(),
            user: "root".to_owned(),
            group: "root".to_owned(),
            mode: "0600".to_owned(),
        }
    }
}
