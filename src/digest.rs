//! Support for computing SHA-256 digests of files

use sha2::Digest as Sha2Digest;
use sha2::Sha256;

/// SHA-256 digests
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digest([u8; 32]);

impl Digest {
    /// Create a SHA-256 digest of the given data
    pub fn for_bytes(input: &[u8]) -> Digest {
        let mut result = [0u8; 32];
        result.copy_from_slice(Sha256::digest(input).as_slice());
        Digest(result)
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
