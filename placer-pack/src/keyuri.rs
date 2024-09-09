//! Keys-as-URIs (with Bech32 binary data/checksums)
//!
//! TODO: use upstream <https://github.com/miscreant/keyuri>

use sha2::{Digest, Sha256};

pub mod bech32k;

/// Encryption `KeyURI` prefix (AES-256-SIV secret key)
pub const ENCRYPTION_KEY_PREFIX: &str = "secret.key:aes256siv+hks256";

/// Signing `KeyURI` prefix (secret key)
pub const SIGNING_KEY_PREFIX: &str = "secret.key:ed25519";

/// Verify `KeyURI` prefix (public key)
pub const VERIFY_KEY_PREFIX: &str = "public.key:ed25519";

/// Key fingerprint `KeyURI` prefix (SHA-256)
pub const FINGERPRINT_PREFIX: &str = "public.fingerprint:sha-256";

/// Encode a `KeyURI` fingerprint of the given string (which should be a `KeyURI`)
pub fn fingerprint(keyuri: &str) -> String {
    let digest = Sha256::digest(keyuri.as_bytes());
    bech32k::encode(FINGERPRINT_PREFIX, digest.as_slice())
}
