//! placer-pack: read/write placer's encrypted/signed pack format
//! (also: a CLI to create packs using placer's encrypted/signed pack format!)

#![deny(missing_docs, unsafe_code, unused_import_braces, unused_qualifications)]

#[macro_use]
extern crate slog;

use slog::{Drain, Logger};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use structopt::StructOpt;
use uuid::Uuid;

use placer_pack::keyrings::DEFAULT_KEY_LABEL;
use placer_pack::{Keyrings, Pack};

/// Command line arguments (using structopt as the parser)
#[derive(StructOpt, Debug)]
#[structopt(name = "placer-pack", about = "builder for placer packs")]
enum Opts {
    #[structopt(name = "create", about = "create a placer pack (pretend it's tar!)")]
    Create {
        /// Base directory for all files
        #[structopt(short = "C", default_value = ".", parse(from_os_str))]
        base: PathBuf,

        /// Path to configuration file
        #[structopt(
            short = "c",
            long = "config",
            default_value = "placer-signing-keyring.toml",
            parse(from_os_str)
        )]
        config: PathBuf,

        /// Path to output file
        #[structopt(short = "f", long = "file", parse(from_os_str))]
        output: PathBuf,

        /// Files to include in pack
        #[structopt(name = "FILE", parse(from_os_str))]
        input: Vec<PathBuf>,
    },

    #[structopt(
        name = "export",
        about = "export a keyring suitable for a placer verifier"
    )]
    Export {
        /// Path to configuration file
        #[structopt(
            short = "c",
            long = "config",
            default_value = "placer-signing-keyring.toml",
            parse(from_os_str)
        )]
        config: PathBuf,

        /// Force overwrite the keyring if it exists
        #[structopt(short = "f", long = "force")]
        force: bool,

        /// Output file to generate
        #[structopt(
            name = "OUTPUT",
            default_value = "placer-verify-keyring.toml",
            parse(from_os_str)
        )]
        output: PathBuf,
    },

    #[structopt(name = "keygen", about = "generate random keyring for producing packs")]
    Keygen {
        /// Force overwrite the keyring if it exists
        #[structopt(short = "f", long = "force")]
        force: bool,

        /// Output file to generate
        #[structopt(
            name = "OUTPUT",
            default_value = "placer-signing-keyring.toml",
            parse(from_os_str)
        )]
        output: PathBuf,
    },
}

fn main() {
    let log = init_logger();

    match Opts::from_args() {
        Opts::Create {
            base,
            config,
            input,
            output,
        } => create(&log, &base, &config, &input, &output),
        Opts::Export {
            config,
            force,
            output,
        } => export(&log, &config, force, &output),
        Opts::Keygen { force, output } => keygen(&log, force, &output),
    }
}

/// Initialize the logger
fn init_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build();
    let drain = std::sync::Mutex::new(drain).fuse();

    Logger::root(drain, o!())
}

/// Create a new pack
fn create(log: &Logger, base_dir: &Path, config: &Path, input: &[PathBuf], output: &Path) {
    let keyrings = Keyrings::load(config).unwrap_or_else(|e| {
        crit!(log, "error parsing {}: {}", config.to_string_lossy(), e);
        process::exit(1);
    });

    let uuid = Uuid::new_v4();
    let mut encryptor = keyrings
        .encryption
        .get(DEFAULT_KEY_LABEL, uuid.as_bytes())
        .unwrap_or_else(|e| {
            crit!(log, "error initializing encryptor: {}", e);
            process::exit(1);
        });

    // TODO: support for using a non-default signing key
    let signer = keyrings.signing.get(DEFAULT_KEY_LABEL).unwrap_or_else(|e| {
        crit!(log, "error initializing signer: {}", e);
        process::exit(1);
    });

    let pack = Pack::create(uuid, base_dir, input).unwrap_or_else(|e| {
        crit!(log, "error creating pack: {}", e);
        process::exit(1);
    });

    let output_filename = output.to_string_lossy().to_string();
    let mut output_file = File::create(output).unwrap_or_else(|e| {
        crit!(log, "couldn't open {} for writing: {}", output_filename, e);
        process::exit(1);
    });

    let serialized_pack = pack
        .encrypt_and_sign(&mut encryptor, signer)
        .unwrap_or_else(|e| {
            crit!(log, "error encrypting/signing pack: {}", e);
            process::exit(1);
        });

    output_file.write_all(&serialized_pack).unwrap_or_else(|e| {
        crit!(log, "error writing pack: {}", e);
        process::exit(1);
    });

    info!(log, "created pack: {}", &output_filename);
}

/// Export secret keyring to a verifier keyring
fn export(log: &Logger, config: &Path, force: bool, output: &Path) {
    if output.exists() && !force {
        crit!(
            log,
            "{}: already exists (use -f to overwrite)",
            output.to_string_lossy()
        );
        process::exit(1);
    }

    let keyrings = Keyrings::load(config).unwrap_or_else(|e| {
        crit!(log, "error parsing {}: {}", config.to_string_lossy(), e);
        process::exit(1);
    });

    keyrings.export_verify_keys(output).unwrap_or_else(|e| {
        crit!(log, "error exporting verify keyring: {}", e);
        process::exit(1);
    });

    info!(log, "saved verify keyring to: {}", output.to_string_lossy())
}

/// Generate a new random keyring
fn keygen(log: &Logger, force: bool, output: &Path) {
    if output.exists() && !force {
        crit!(
            log,
            "{}: already exists (use -f to overwrite)",
            output.to_string_lossy()
        );
        process::exit(1);
    }

    Keyrings::generate_random(output).unwrap_or_else(|e| {
        crit!(log, "error generating keys: {}", e);
        process::exit(1);
    });

    info!(
        log,
        "new secret keys saved to: {}",
        output.to_string_lossy()
    );
}
