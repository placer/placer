//! Commands which are run either before or after placing a file

use std::ffi::OsString;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use users::{gid_t, uid_t, Groups, Users, UsersCache};

use crate::config::HookConfig;
use crate::error::Error;

/// Magic argument which is replaced with a path to the file
pub const FILENAME_PLACEHOLDER: &str = "%f";

/// Command to run before/after placing a file
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hook {
    /// Path to the command to be run
    pub path: PathBuf,

    /// POSIX user ID to run the hook as
    pub uid: uid_t,

    /// POSIX group ID to run the hook as
    pub gid: gid_t,

    /// Arguments to pass to the hook
    pub args: Vec<OsString>,
}

impl Hook {
    /// Validate HookConfig and create a hook to be run
    pub fn new(
        non_canonical_path: &Path,
        config: &HookConfig,
        users_cache: &mut UsersCache,
    ) -> Result<Self, Error> {
        let non_canonical_parent = non_canonical_path
            .parent()
            .ok_or_else(|| err!(Config, "bad path: {}", non_canonical_path.to_string_lossy()))?;

        let canonical_parent = non_canonical_parent.canonicalize().map_err(|e| {
            err!(
                Config,
                "error canonicalizing path: {} ({})",
                non_canonical_parent.to_string_lossy(),
                e
            )
        })?;

        let canonical_path = canonical_parent.join(non_canonical_path.file_name().unwrap());

        // Disallow non-canonical paths in configuration
        ensure!(
            non_canonical_path == canonical_path,
            Config,
            "non-canonical path: {} (expected {})",
            non_canonical_path.to_string_lossy(),
            canonical_path.to_string_lossy()
        );

        let user = users_cache
            .get_user_by_name(&config.user)
            .ok_or_else(|| err!(Config, "invalid user: {}", &config.user))?;

        let group = users_cache
            .get_group_by_name(&config.group)
            .ok_or_else(|| err!(Config, "invalid group: {}", &config.group))?;

        let mut args = vec![];

        if config.args.is_some() {
            for arg in config.args.as_ref().unwrap() {
                args.push(OsString::from(arg));
            }
        }

        Ok(Self {
            path: canonical_path,
            uid: user.uid(),
            gid: group.gid(),
            args,
        })
    }

    /// Run the hook, returning an error if the subcommand returns an error
    pub fn run(&self, file_path: &Path) -> Result<(), Error> {
        let mut subprocess = Command::new(&self.path)
            .uid(self.uid)
            .gid(self.gid)
            .args(self.args.iter().map(|a| {
                if a == FILENAME_PLACEHOLDER {
                    file_path.as_os_str()
                } else {
                    a.as_os_str()
                }
            }))
            .spawn()
            .map_err(|e| err!(Hook, "[hook:{}] {}", &self.path.to_string_lossy(), e))?;

        let exit_status = subprocess
            .wait()
            .map_err(|e| err!(Hook, "[hook:{}] {}", &self.path.to_string_lossy(), e))?;

        match exit_status.code() {
            Some(0) => Ok(()),
            Some(code) => fail!(
                Hook,
                "[hook:{}] exited with non-zero error code: {}",
                &self.path.to_string_lossy(),
                code
            ),
            None => fail!(
                Hook,
                "[hook:{}] killed by signal {}",
                &self.path.to_string_lossy(),
                exit_status.signal().unwrap()
            ),
        }
    }
}
