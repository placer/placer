//! Error types

use std::io;

/// placer's error type
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum Error {
    /// Error in configuration file
    #[fail(display = "{}", description)]
    Config {
        /// Description of the error
        description: String,
    },

    /// Error executing a before/after hook
    #[fail(display = "{}", description)]
    Hook {
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

    /// Error with a source subprocess
    #[fail(display = "{}", description)]
    Source {
        /// Description of the error
        description: String,
    },
}

impl From<io::Error> for Error {
    fn from(other: io::Error) -> Self {
        err!(Io, "{}", other)
    }
}
