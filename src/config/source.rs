//! Configuration for a pack source

use std::collections::BTreeMap;

/// Pack source configuration
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    /// User that the source should be run as (and socket owned by)
    pub user: String,

    /// Group that the source should be run as (and socket owned by)
    pub group: String,

    /// Names of packs to fetch and a location identifier to pass to the source (e.g. a URI)
    pub packs: BTreeMap<String, String>,
}
