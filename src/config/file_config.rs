//! Configuration for files to be placed by placer

use std::collections::BTreeMap;
use std::path::PathBuf;

/// File config
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Pack that this file belongs to
    pub pack: String,

    /// User which owns this file
    pub user: String,

    /// Group which owns this file
    pub group: String,

    /// Permissions of logfile (in octal)
    pub mode: String,

    /// Hooks to run before a file is placed
    #[serde(rename = "before-hook")]
    pub before_hooks: Option<BTreeMap<PathBuf, HookConfig>>,

    /// Hooks to run after a file is placed
    #[serde(rename = "after-hook")]
    pub after_hooks: Option<BTreeMap<PathBuf, HookConfig>>,
}

/// Configuration for an individual hook
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct HookConfig {
    /// User the hook should be run as
    pub user: String,

    /// Group the hook should be run as
    pub group: String,

    /// Arguments to pass to the program
    pub args: Option<Vec<String>>,
}
