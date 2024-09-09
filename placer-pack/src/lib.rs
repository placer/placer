//! placer-pack: read/write placer's encrypted/signed pack format

#![crate_name = "placer_pack"]
#![deny(missing_docs, unsafe_code, unused_import_braces, unused_qualifications)]

#[macro_use]
extern crate failure;

#[macro_use]
extern crate prost_derive;

#[cfg(feature = "keyrings")]
#[macro_use]
extern crate serde_derive;

#[cfg(feature = "keyrings")]
extern crate toml;

#[macro_use]
mod macros;

pub mod crypto;
pub mod error;
#[cfg(feature = "keyrings")]
pub mod keyrings;
pub mod pack;
// TODO: use upstream <https://github.com/miscreant/keyuri>
pub mod keyuri;
mod protos;

#[cfg(feature = "keyrings")]
pub use crate::keyrings::Keyrings;
pub use crate::pack::{Fingerprints, Pack, PackFile, MAX_PACK_SIZE};
