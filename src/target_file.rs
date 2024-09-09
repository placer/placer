//! Attributes of files-to-be-placed, derived from a validated configuration

use slog::Logger;
use std::collections::BTreeMap;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::u32;
use users::{gid_t, uid_t, Groups, Users, UsersCache};

use crate::config::{FileConfig, HookConfig};
use crate::error::Error;
use crate::hook::Hook;

/// Prefix prepended to temporary files placer is placing
pub const PLACER_TEMPFILE_PREFIX: &str = ".placer-tmp-";

/// Target file to-be-placed
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetFile {
    /// Canonicalized path to file
    pub path: PathBuf,

    /// Name of the pack this file belongs to
    // TODO: find some better way to model this
    pub pack: String,

    /// POSIX user ID
    pub uid: uid_t,

    /// POSIX group ID
    pub gid: gid_t,

    /// POSIX file permissions
    pub permissions: Permissions,

    /// Before hooks
    pub before_hooks: Vec<Hook>,

    /// After hooks
    pub after_hooks: Vec<Hook>,
}

impl TargetFile {
    /// Create file properties, parsing mode and resolving uid/gid from user/group names
    pub fn new(
        non_canonical_path: &Path,
        config: &FileConfig,
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

        let permissions = Permissions::from_mode(
            u32::from_str_radix(&config.mode, 8)
                .map_err(|e| err!(Config, "bad mode: {} ({:?})", &config.mode, e))?,
        );

        Ok(Self {
            path: canonical_path,
            pack: config.pack.clone(),
            uid: user.uid(),
            gid: group.gid(),
            permissions,
            before_hooks: process_hook_configs(&config.before_hooks, users_cache)?,
            after_hooks: process_hook_configs(&config.after_hooks, users_cache)?,
        })
    }

    /// Create a tempfile containing data to-be-placed, run all before hooks
    /// against it, and if they all succeed overwrite the target file, then
    /// run any after hooks
    pub fn place(&self, body: &[u8], log: &Logger) -> Result<(), Error> {
        let mut temp_filename = OsString::from(PLACER_TEMPFILE_PREFIX);
        temp_filename.push(self.path.file_name().unwrap());

        // Write the data to a temp file first so we can swap it out
        // semi-atomically
        let temp_path = self.path.with_file_name(&temp_filename);

        // Blow the temp file away to ensure it's recreated with the right perms
        // TODO: maybe warn if this errors on something other than ENOENT
        let _ = fs::remove_file(&temp_path);

        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(self.permissions.mode())
                .open(&temp_path)?;

            file.write_all(body)?;
        }

        // Set ownership on the path
        chown(&temp_path, self.uid, self.gid)?;

        // Run before hooks
        for hook in &self.before_hooks {
            debug!(
                log,
                "[file:{}] Running before hook: {}",
                self.path.to_string_lossy(),
                hook.path.to_string_lossy(),
            );

            if let Err(e) = hook.run(&temp_path) {
                // TODO: maybe warn if this errors on something other than ENOENT
                let _ = fs::remove_file(&temp_path);
                return Err(e);
            }
        }

        // TODO: make a hard link to the original file so we can do
        // post-placement processing/quarantine on it
        // fs::hard_link(self.path, quarantine_filename)?;

        // Replace the current file with the new version
        // TODO: use renameat2() on Linux when available?
        fs::rename(&temp_path, &self.path)?;

        // Run after hooks
        for hook in &self.after_hooks {
            debug!(
                log,
                "[file:{}] Running after hook: {}",
                self.path.to_string_lossy(),
                hook.path.to_string_lossy(),
            );

            hook.run(&temp_path)?;
        }

        Ok(())
    }
}

// Process hook configurations and convert them into `Hook` structs
fn process_hook_configs(
    hooks: &Option<BTreeMap<PathBuf, HookConfig>>,
    cache: &mut UsersCache,
) -> Result<Vec<Hook>, Error> {
    let mut result = vec![];

    if let Some(ref hooks) = *hooks {
        for (path, hook_config) in hooks {
            result.push(Hook::new(path, hook_config, cache)?);
        }
    }

    Ok(result)
}

/// "Safe" wrapper for chown
// TODO: find (or create) a crate to supply this, or get stable Rust to
#[allow(unsafe_code)]
fn chown(path: &Path, uid: uid_t, gid: gid_t) -> Result<(), Error> {
    let path_osstr: &OsStr = path.as_ref();
    let path_cstring = CString::new(path_osstr.as_bytes()).unwrap();
    let ret = unsafe { libc::chown(path_cstring.as_ptr(), uid, gid) };

    if ret == 0 {
        Ok(())
    } else {
        Err(err!(Io, "chown failed: {}", errno::errno()))
    }
}
