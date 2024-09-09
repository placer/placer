//! Error types

use crate::keyuri::bech32k;
use std::io;

/// placer-pack's error type
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum Error {
    /// Error in configuration file
    #[fail(display = "invalid config file: {}", description)]
    #[allow(clippy::enum_variant_names)]
    Config {
        /// Description of the error
        description: String,
    },

    /// Error in a cryptographic algorithm or provider
    #[fail(display = "{}", description)]
    Crypto {
        /// Description of the error
        description: String,
    },

    /// Malformatted or otherwise invalid cryptographic key
    #[fail(display = "{}", description)]
    InvalidKey {
        /// Description of the error
        description: String,
    },

    /// Input/output error
    #[fail(display = "{}", description)]
    Io {
        /// Description of the error
        description: String,
    },

    /// Error parsing data
    #[fail(display = "{}", description)]
    Parse {
        /// Description of the error
        description: String,
    },

    /// Error serializing a value
    #[fail(display = "{}", description)]
    Serialization {
        /// Description of the error
        description: String,
    },
}

impl From<io::Error> for Error {
    fn from(other: io::Error) -> Self {
        err!(Io, "{}", other)
    }
}

impl From<bech32k::Error> for Error {
    fn from(other: bech32k::Error) -> Self {
        err!(InvalidKey, "{}", other)
    }
}
