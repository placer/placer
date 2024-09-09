//! Encrypted/signed packs of files

use chrono::{DateTime, Utc};
use std::slice::Iter;

use crate::keyrings::Keyrings;
use placer_pack::Pack as PackContents;
use placer_pack::PackFile;
use slog::Logger;
use uuid::Uuid;

/// Decrypted/verified pack including metadata about it
pub struct Pack {
    /// Name of this pack
    pub name: String,

    /// Contents of this pack
    pub contents: PackContents,
}

impl Pack {
    /// Parse a pack from raw data, verifying it with the given keyrings
    pub fn verify_and_decrypt(
        name: &str,
        data: &[u8],
        keyrings: &Keyrings,
        log: &Logger,
    ) -> Option<Self> {
        let contents_result = PackContents::verify_and_decrypt(data, |fingerprints, uuid| {
            match keyrings.get_for_fingerprints(fingerprints, uuid) {
                Ok(result) => Some(result),
                Err(e) => {
                    warn!(log, "missing keys for \"{}\" pack: {}", name, e);
                    None
                }
            }
        });

        match contents_result {
            Ok(contents) => {
                let pack = Self {
                    name: name.to_owned(),
                    contents,
                };

                info!(
                    log,
                    "Verified pack {}:{} ({})",
                    pack.name,
                    pack.uuid(),
                    pack.date().format("%a %b %e %T %Y")
                );

                Some(pack)
            }
            Err(e) => {
                error!(log, "bad \"{}\" pack: {}", name, e);
                None
            }
        }
    }

    /// Get the date when this crate was published
    #[inline]
    pub fn date(&self) -> &DateTime<Utc> {
        &self.contents.date
    }

    /// Get the UUID for this pack
    #[inline]
    pub fn uuid(&self) -> &Uuid {
        &self.contents.uuid
    }

    /// Iterate over the files in this pack
    #[inline]
    pub fn files(&self) -> Iter<'_, PackFile> {
        self.contents.files()
    }
}
