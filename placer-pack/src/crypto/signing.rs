//! Pack signing
//!
//! Presently supports Ed25519 as a digital signature algorithm

mod public_key;
#[cfg(feature = "signer")]
mod signer;

pub use self::public_key::{PublicKey, PUBLIC_KEY_SIZE};
#[cfg(feature = "signer")]
pub use self::signer::Signer;

/// Size of an Ed25519 signing key in bytes
pub const SIGNING_KEY_SIZE: usize = 32;
