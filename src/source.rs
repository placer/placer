//! placer sources are untrusted, low-privileged subcommands that interact
//! with the network to obtain updated file packs, which they deliver to
//! the placer process over pipes (i.e. stdout). All packs are encrypted
//! and digitally signed to ensure authenticity.

use placer_pack::MAX_PACK_SIZE;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use users::{Groups, Users, UsersCache};

use super::PLACER_PATH;
use crate::config::SourceConfig;
use crate::error::Error;

/// All placer source executable names start with this prefix
pub const PLACER_SOURCE_PREFIX: &str = "placer-source-";

/// Greetings from sources start with this string
pub const GREETING_PREFIX: &str = "OK ";

/// Source wraps an untrusted, low-privilege subprocess which fetches data
/// from the network.
pub struct Source {
    /// Name of this source (with "placer-source-" prefix)
    pub name: String,

    /// Greeting returned on initial handshake
    pub greeting: String,

    /// PID of the source command's child subprocess
    pub pid: u32,

    /// Unbuffered writer to child's STDIN
    stdin: ChildStdin,

    /// A buffered reader for consuming STDOUT
    stdout: BufReader<ChildStdout>,

    /// Mapping of resource URIs to their pack names
    resources: BTreeMap<String, String>,
}

impl Source {
    /// Spawn the source subcommand and request the packs from the source config
    pub fn new(
        source_name: &str,
        config: &SourceConfig,
        users_cache: &mut UsersCache,
    ) -> Result<Self, Error> {
        let user = users_cache
            .get_user_by_name(&config.user)
            .ok_or_else(|| err!(Config, "invalid user: {}", &config.user))?;

        let group = users_cache
            .get_group_by_name(&config.group)
            .ok_or_else(|| err!(Config, "invalid group: {}", &config.group))?;

        // Create a reverse mapping of URLs back to their pack names
        let mut resources = BTreeMap::new();

        for (label, resource) in &config.packs {
            if let Some(other) = resources.insert(resource.clone(), label.clone()) {
                fail!(
                    Config,
                    "packs \"{}\" and \"{}\" have duplicate URL: {}",
                    label,
                    other,
                    resource
                );
            }
        }

        // Source command MUST be in the same directory as the placer executable
        let source_cmd_path = PLACER_PATH
            .parent()
            .unwrap()
            .join(&format!("{}{}", PLACER_SOURCE_PREFIX, source_name));

        if !source_cmd_path.exists() {
            fail!(
                Config,
                "[{}] can't find source executable: {}",
                source_name,
                source_cmd_path.to_string_lossy()
            );
        }

        // TODO: drop privileges, support for arguments
        let source_child = Command::new(source_cmd_path.clone())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .uid(user.uid())
            .gid(group.gid())
            .spawn()
            .map_err(|e| {
                err!(
                    Source,
                    "[{}] couldn't start {} ({})",
                    source_name,
                    source_cmd_path.to_string_lossy(),
                    e
                )
            })?;

        let pid = source_child.id();

        let Child { stdin, stdout, .. } = source_child;
        let (stdin, mut stdout) = (stdin.unwrap(), BufReader::new(stdout.unwrap()));

        let greeting = read_greeting(&mut stdout)?;

        let mut result = Self {
            name: source_name.to_owned(),
            greeting,
            pid,
            stdin,
            stdout,
            resources,
        };

        // Issue the request to fetch the configured pack resources
        result.request_resources(config.packs.values())?;

        Ok(result)
    }

    /// Read the next file the source has fetched, blocking until it's available
    pub fn next_file(&mut self) -> Result<(String, Vec<u8>), Error> {
        let mut line = String::new();
        self.stdout.read_line(&mut line)?;

        let line_parts: Vec<&str> = line.split_whitespace().collect();

        if line_parts.len() != 2 {
            fail!(Source, "[{}] bad pack header: {:?}", self.name, line);
        }

        let length: u32 = line_parts[0]
            .parse()
            .map_err(|e| err!(Source, "[{}] bad length in pack header: {}", &self.name, e))?;

        let resource = line_parts[1];

        if length > MAX_PACK_SIZE as u32 {
            fail!(
                Source,
                "[{}] Resource too large ({} bytes): {}",
                self.name,
                length,
                resource
            );
        }

        let mut pack_data = vec![0u8; length as usize];
        self.stdout.read_exact(&mut pack_data)?;

        let mut blank = String::new();
        self.stdout.read_line(&mut blank)?;

        if &blank != "\n" {
            fail!(Source, "[{}] bad EOF marker: {:?}", self.name, blank);
        }

        let pack_label = self.resources.get(resource).ok_or_else(|| {
            err!(
                Source,
                "[{}] I never asked for this: {}",
                self.name,
                resource
            )
        })?;

        Ok((pack_label.clone(), pack_data))
    }

    /// Send the source command (via STDIN) the list of resource URLs to fetch
    fn request_resources<'a, I>(&'a mut self, resources: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = &'a String>,
    {
        // Write the resource URLs/URIs to fetch out to the subprocess
        for resource in resources {
            writeln!(&mut self.stdin, "{}", resource)?;
        }

        // Write a single newline as an indicator we're done writing resources
        // TODO: should we close pipe or leave it "open" to send additional commands?
        writeln!(&mut self.stdin)?;
        self.stdin.flush()?;

        Ok(())
    }
}

/// Read the greeting from the source
fn read_greeting(stdout: &mut BufReader<ChildStdout>) -> Result<String, Error> {
    let mut greeting = String::new();
    stdout.read_line(&mut greeting)?;

    // All greetings need to start with OK
    if !greeting.starts_with(GREETING_PREFIX) {
        fail!(Source, "bad greeting: {:?}", greeting)
    }

    // Remove leading prefix and trailing newline
    greeting = greeting.split_off(GREETING_PREFIX.len());
    let greeting_len = greeting.trim_end().len();
    greeting.truncate(greeting_len);

    Ok(greeting)
}
