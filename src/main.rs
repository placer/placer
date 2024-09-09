//! placer: a security-oriented event-driven file placement system

#![crate_name = "placer"]
#![deny(missing_docs, unsafe_code, unused_import_braces, unused_qualifications)]

#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate slog;

#[macro_use]
mod macros;

mod config;
mod digest;
mod error;
mod hook;
mod keyrings;
mod pack;
mod source;
mod target_file;

use slog::{Drain, Logger};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process;
use structopt::StructOpt;
use users::UsersCache;

use crate::config::{Config, FileConfig};
use crate::digest::Digest;
use crate::keyrings::Keyrings;
use crate::pack::Pack;
use crate::source::Source;
use crate::target_file::TargetFile;

lazy_static! {
    /// Path to the placer executable
    static ref PLACER_PATH: PathBuf = {
        // See below for how we mitigate the security warning in the `current_exe()` docs
        let non_canonical_path = std::env::current_exe().unwrap_or_else(|e| {
            panic!("couldn't determine path of placer executable! ({})", e);
        });

        // Canonicalize the path we get from `current_exe()` to mitigate potential security problems
        non_canonical_path.canonicalize().unwrap_or_else(|e| {
            panic!("couldn't canonicalize path of placer executable! ({})", e)
        })
    };
}

/// Command line arguments (using structopt as the parser)
#[derive(StructOpt, Debug)]
#[structopt(name = "placer", about = "Secure file placement service")]
struct Opts {
    /// Path to configuration file
    #[structopt(
        short = "c",
        long = "config",
        default_value = "/etc/placer/placer.toml",
        parse(from_os_str)
    )]
    config: PathBuf,

    /// Print debugging information
    #[structopt(short = "v", long = "verbose")]
    verbose: bool,
}

fn main() {
    let log = init_logger();

    // parse args with structopt
    let opts = Opts::from_args();

    let config = Config::load(&opts.config).unwrap_or_else(|e| {
        crit!(&log, "error loading config: {}", e);
        process::exit(1);
    });

    let keyrings = Keyrings::load(&config.keyrings).unwrap_or_else(|e| {
        crit!(&log, "error loading keyrings: {}", e);
        process::exit(1);
    });

    let mut users_cache = UsersCache::new();
    let file_properties = process_file_config(&config.files, &mut users_cache, &log);

    // TODO: support for multiple sources running in their own threads
    //let mut _sources: Vec<Source> = config
    //    .sources
    //    .iter()
    //    .map(|(name, config)| {
    //        info!(
    //            log,
    //            "[{}] Running {}",
    //            &source_name,
    //            &source_cmd_path.to_string_lossy()
    //        );
    //
    //        Source::spawn_thread(name, config, &log).unwrap_or_else(|e| {
    //            crit!(&log, "error configuring \"{}\" source: {}", name, e);
    //            process::exit(1);
    //        })
    //    })
    //    .collect();

    // TODO: hax since we only have one source for now
    let source_name = "http".to_owned();
    let source_config = &config.sources[&source_name];

    let mut source =
        Source::new(&source_name, source_config, &mut users_cache).unwrap_or_else(|e| {
            crit!(&log, "error configuring \"{}\" source: {}", source_name, e);
            process::exit(1);
        });

    info!(log, "[source:{}] {}", source_name, source.greeting);

    for (pack_name, pack_resource) in &source_config.packs {
        info!(
            &log,
            "[source:{}] Requested \"{}\" pack: {}", source_name, pack_name, pack_resource
        );
    }

    loop {
        if let Some(pack) = get_next_pack(&source_name, &mut source, &keyrings, &log) {
            process_pack(&pack, &file_properties, &log);
        }
    }
}

/// Initialize the logging subsystem
fn init_logger() -> Logger {
    // slog configuration
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build();
    let drain = std::sync::Mutex::new(drain).fuse();

    Logger::root(drain, o!())
}

/// Process file configuration into file properties
fn process_file_config(
    files: &BTreeMap<PathBuf, FileConfig>,
    users_cache: &mut UsersCache,
    log: &Logger,
) -> BTreeMap<PathBuf, TargetFile> {
    let mut result = BTreeMap::new();

    for (path, file_config) in files {
        let file = TargetFile::new(path, file_config, users_cache).unwrap_or_else(|e| {
            crit!(log, "bad config for {:?} file: {}", path, e);
            process::exit(1);
        });

        if result.insert(path.clone(), file).is_some() {
            crit!(log, "duplicate config for file {:?}", path);
            process::exit(1);
        }
    }

    result
}

/// Get the next pack to process
fn get_next_pack(
    source_name: &str,
    source: &mut Source,
    keyrings: &Keyrings,
    log: &Logger,
) -> Option<Pack> {
    let (pack_name, pack_data) = source.next_file().unwrap_or_else(|e| {
        crit!(log, "[source:{}] read error: {}", source_name, e);
        process::exit(1);
    });

    info!(
        log,
        "[source:{}] Fetched \"{}\" pack ({} bytes)",
        source_name,
        pack_name,
        pack_data.len()
    );

    Pack::verify_and_decrypt(&pack_name, &pack_data, keyrings, log)
}

/// Process pack
fn process_pack(pack: &Pack, targets: &BTreeMap<PathBuf, TargetFile>, log: &Logger) {
    for file in pack.files() {
        match targets.get(&PathBuf::from(&file.filename)) {
            Some(target) => {
                if target.pack == pack.name {
                    place_file_if_updated(target, pack, &file.body, log);
                } else {
                    debug!(
                        log,
                        "Ignoring {} from \"{}\" pack (configured pack is \"{}\")",
                        target.path.to_string_lossy(),
                        pack.name,
                        target.pack
                    );
                }
            }
            None => {
                warn!(
                    log,
                    "no config for file \"{}\" (from {}:{})",
                    file.filename,
                    pack.name,
                    pack.uuid()
                );
            }
        }
    }
}

/// Place the file on disk, but only if it's changed
fn place_file_if_updated(target: &TargetFile, pack: &Pack, body: &[u8], log: &Logger) {
    // Compare SHA-256 of current file versus the updated version
    // TODO: active file integrity monitoring
    if let Ok(mut file) = File::open(&target.path) {
        let mut data = vec![];

        match file.read_to_end(&mut data) {
            Ok(_) => {
                let current_file_digest = Digest::for_bytes(&data);
                let updated_file_digest = Digest::for_bytes(body);

                // Do nothing if the file is already up-to-date
                if current_file_digest == updated_file_digest {
                    debug!(
                        log,
                        "Not updating {}: already identical to {}:{}",
                        target.path.to_string_lossy(),
                        pack.name,
                        pack.uuid()
                    );
                    return;
                }
            }
            Err(e) => error!(
                log,
                "error reading {}: {}",
                target.path.to_string_lossy(),
                e
            ),
        }
    }

    if let Err(e) = target.place(body, log) {
        error!(
            log,
            "couldn't place {}: {}",
            target.path.to_string_lossy(),
            e
        );
        return;
    }

    info!(
        log,
        "placed {} (from {}:{})",
        target.path.to_string_lossy(),
        pack.name,
        pack.uuid()
    );
}
