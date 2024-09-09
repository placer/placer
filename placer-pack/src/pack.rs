//! Create a placer pack from a set of input files

use chrono::{DateTime, Utc};
use prost::Message;
#[cfg(feature = "signer")]
use std::fs;
use std::fs::File as StdFile;
use std::io::Read;
use std::path::Path;
#[cfg(feature = "signer")]
use std::path::PathBuf;
use std::slice::Iter;
pub use uuid::Uuid;

#[cfg(feature = "signer")]
use crate::crypto::Signer;
use crate::crypto::{Encryptor, PublicKey};
use crate::error::Error;
pub use crate::protos::pack::File as PackFile;
use crate::protos::pack::Pack as PackProto;
use crate::protos::pack::Payload;
#[cfg(feature = "signer")]
use crate::protos::timestamp::Tai64n;

/// Maximum length of a pack in bytes
///
/// placer is presently optimized for small files. If we can nail the small
/// file use case, perhaps in the future we can consider how to deploy larger
/// files, but that's a "nice to have".
pub const MAX_PACK_SIZE: usize = 1_048_576;

/// Magic string which identifies a placer pack (v0)
pub const PACK_V0_MAGIC_STRING: &[u8] = b"placer-pack:v0.1";

/// Default Content-Type for all files in the pack
pub const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";

/// Maximum amount of clock skew (into the future) we allow on pack file timestamps (in seconds)
pub const MAX_PACK_TIMESTAMP_SKEW: i64 = 86_400; // 24h

/// Packs of files
pub struct Pack {
    /// UUID that uniquely identifies this pack (we hope!)
    pub uuid: Uuid,

    /// Date when this pack was produced
    pub date: DateTime<Utc>,

    /// Fingerprints of the keys used to sign the pack
    pub fingerprints: Option<Fingerprints>,

    /// Files in the pack
    pub files: Vec<PackFile>,
}

/// Fingerprints for the keys used to sign a pack
#[derive(Debug)]
pub struct Fingerprints {
    /// Signing public key fingerprint (in KeyURI format)
    pub signing_key: String,

    /// Encryption key fingerprint (in KeyURI format)
    pub encryption_key: String,
}

impl Pack {
    /// Create a new pack from the given files
    #[cfg(feature = "signer")]
    pub fn create(uuid: Uuid, base: &Path, input: &[PathBuf]) -> Result<Self, Error> {
        let mut files = vec![];
        let canonical_base = base.canonicalize()?;

        for filename in input {
            let path = canonical_base.join(&filename).canonicalize()?;
            let modified_at = fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .map_err(|e| err!(Io, "couldn't stat {}: {}", path.to_string_lossy(), e))?;

            let mut file = StdFile::open(&path)
                .map_err(|e| err!(Io, "couldn't open {}: {}", path.to_string_lossy(), e))?;

            let mut body = vec![];
            file.read_to_end(&mut body)?;

            // All paths for files in the pack are absolute
            let absolute_path =
                PathBuf::from("/").join(&path.strip_prefix(&canonical_base).unwrap());

            files.push(PackFile {
                filename: absolute_path.to_string_lossy().to_string(),
                content_type: DEFAULT_CONTENT_TYPE.to_owned(),
                modified_at: Some(modified_at.into()),
                body,
            });
        }

        Ok(Self {
            uuid,
            date: Utc::now(),
            fingerprints: None,
            files,
        })
    }

    /// Load an encrypted pack from a file
    pub fn load<F>(path: &Path, key_lookup: F) -> Result<Self, Error>
    where
        F: Fn(&Fingerprints, &Uuid) -> Option<(PublicKey, Encryptor)>,
    {
        let mut file = StdFile::open(path)
            .map_err(|e| err!(Io, "couldn't open {}: {}", path.to_string_lossy(), e))?;

        let mut data = vec![];
        file.read_to_end(&mut data)?;

        if data.len() > MAX_PACK_SIZE {
            fail!(
                Serialization,
                "pack too large: {}-bytes (max {})",
                data.len(),
                MAX_PACK_SIZE
            )
        }

        Self::verify_and_decrypt(&data, key_lookup)
    }

    /// Parse an encrypted pack, first verifying its signature and then decrypting it
    pub fn verify_and_decrypt<F>(bytes: &[u8], key_lookup: F) -> Result<Self, Error>
    where
        F: Fn(&Fingerprints, &Uuid) -> Option<(PublicKey, Encryptor)>,
    {
        if bytes.len() < PACK_V0_MAGIC_STRING.len() {
            fail!(
                Parse,
                "pack too short: expected at least {} bytes, got {}",
                PACK_V0_MAGIC_STRING.len(),
                bytes.len()
            );
        }

        if &bytes[..PACK_V0_MAGIC_STRING.len()] != PACK_V0_MAGIC_STRING {
            fail!(
                Parse,
                "pack does not start with magic string (\"{}\")",
                String::from_utf8(PACK_V0_MAGIC_STRING.to_vec()).unwrap()
            );
        }

        let proto = PackProto::decode(&bytes[PACK_V0_MAGIC_STRING.len()..])
            .map_err(|e| err!(Parse, "pack parsing error: {}", e))?;

        let uuid = Uuid::parse_str(&proto.uuid)
            .map_err(|e| err!(Parse, "invalid UUID: \"{}\" ({})", proto.uuid, e))?;

        let fingerprints = Fingerprints {
            signing_key: proto.signing_key_fingerprint.clone(),
            encryption_key: proto.encryption_key_fingerprint.clone(),
        };

        let (public_key, mut encryptor) = key_lookup(&fingerprints, &uuid)
            .ok_or_else(|| err!(InvalidKey, "key lookup failed"))?;

        let date_proto = proto
            .date
            .ok_or_else(|| err!(Parse, "date missing from pack file"))?;

        let date = date_proto
            .to_datetime_utc()
            .ok_or_else(|| err!(Parse, "couldn't parse date from pack file"))?;

        public_key.verify(&proto.ciphertext, &proto.signature)?;
        let plaintext = encryptor
            .open(
                &[
                    &date_proto.value,
                    proto.encryption_key_fingerprint.as_bytes(),
                    proto.signing_key_fingerprint.as_bytes(),
                ],
                &proto.ciphertext,
            )
            .map_err(|_| err!(Crypto, "decryption failed"))?;

        // Ensure pack has a timestamp in the past
        // If it does have a future timestamp, ensure it's within an acceptable skew threshold
        if date.signed_duration_since(Utc::now()).num_seconds() > MAX_PACK_TIMESTAMP_SKEW {
            fail!(
                Parse,
                "bogus future timestamp on pack: {}",
                date.format("%a %b %e %T %Y")
            );
        }

        let payload =
            Payload::decode(&plaintext).map_err(|e| err!(Parse, "payload parsing error: {}", e))?;

        Ok(Self {
            uuid,
            date,
            fingerprints: Some(fingerprints),
            files: payload.files,
        })
    }

    /// Encrypt and sign a pack with the given encryptor/signer keys
    #[cfg(feature = "signer")]
    pub fn encrypt_and_sign(
        self,
        encryptor: &mut Encryptor,
        signer: &Signer,
    ) -> Result<Vec<u8>, Error> {
        let date = Tai64n::from(self.date);
        let uuid = self.uuid.to_string();
        let encryption_key_fingerprint = encryptor.fingerprint().to_owned();
        let signing_public_key = signer.public_key()?;
        let signing_key_fingerprint = signing_public_key.to_fingerprint();

        let mut plaintext = self.serialize()?;
        let ciphertext = encryptor.seal(
            &[
                &date.value,
                encryption_key_fingerprint.as_bytes(),
                signing_key_fingerprint.as_bytes(),
            ],
            &plaintext,
        );
        plaintext.clear();

        let signature = signer.sign(&ciphertext)?.as_ref().into();
        let mut output = Vec::from(PACK_V0_MAGIC_STRING);

        let proto = PackProto {
            uuid,
            date: Some(date),
            signing_key_fingerprint,
            encryption_key_fingerprint,
            signature,
            ciphertext,
        };

        proto
            .encode(&mut output)
            .map_err(|e| err!(Serialization, "couldn't encode pack: {}", e.to_string()))?;

        Ok(output)
    }

    /// Iterate over the files in this pack
    pub fn files(&self) -> Iter<'_, PackFile> {
        self.files.iter()
    }

    /// Serialize the payload of a pack
    #[cfg(feature = "signer")]
    fn serialize(self) -> Result<Vec<u8>, Error> {
        let mut output = vec![];
        Payload { files: self.files }.encode(&mut output).unwrap();

        if output.len() > MAX_PACK_SIZE {
            fail!(
                Serialization,
                "pack too large: {}-bytes (max {})",
                output.len(),
                MAX_PACK_SIZE
            )
        }

        Ok(output)
    }
}
