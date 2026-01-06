//! Configuration options for an ostree repository

use serde::{Deserialize, Serialize};

/// Configuration options for an ostree repository.
///
/// This struct represents configurable options for an ostree repository
/// that can be set via the `ostree config set` command.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct RepoOptions {
    /// Boot Loader Spec entries that should append arguments only for non-default entries.
    ///
    /// Corresponds to the `sysroot.bls-append-except-default` ostree config key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bls_append_except_default: Option<String>,
}

impl RepoOptions {
    /// Returns an iterator of (key, value) tuples for ostree repo configuration.
    ///
    /// Each tuple represents an ostree config key and its value, suitable for
    /// passing to `ostree config set`.
    pub fn to_config_tuples(&self) -> impl Iterator<Item = (&'static str, &str)> {
        self.bls_append_except_default
            .as_ref()
            .map(|v| ("sysroot.bls-append-except-default", v.as_str()))
            .into_iter()
    }
}
