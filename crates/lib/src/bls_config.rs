use serde::{Deserialize, Deserializer};
use serde::de::Error;
use std::collections::HashMap;
use anyhow::Result;

#[derive(Debug, Deserialize, Eq)]
pub(crate) struct BLSConfig {
    pub(crate) title: Option<String>,
    #[serde(deserialize_with = "deserialize_version")]
    pub(crate) version: u32,
    pub(crate) linux: String,
    pub(crate) initrd: String,
    pub(crate) options: String,

    #[serde(flatten)]
    pub(crate) extra: HashMap<String, String>,
}

impl PartialEq for BLSConfig {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
    }
}

impl PartialOrd for BLSConfig {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.version.partial_cmp(&other.version)
    }
}

impl Ord for BLSConfig {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.version.cmp(&other.version)
    }
}

impl BLSConfig {
    pub(crate) fn to_string(&self) -> String {
        let mut out = String::new();

        if let Some(title) = &self.title {
            out += &format!("title {}\n", title);
        }

        out += &format!("version {}\n", self.version);
        out += &format!("linux {}\n", self.linux);
        out += &format!("initrd {}\n", self.initrd);
        out += &format!("options {}\n", self.options);

        for (key, value) in &self.extra {
            out += &format!("{} {}\n", key, value);
        }

        out
    }
}

fn deserialize_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;

    match s {
        Some(s) => Ok(s.parse::<u32>().map_err(D::Error::custom)?),
        None => Err(D::Error::custom("Version not found")),
    }
}

pub(crate) fn parse_bls_config(input: &str) -> Result<BLSConfig> {
    let mut map = HashMap::new();

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once(' ') {
            map.insert(key.to_string(), value.trim().to_string());
        }
    }

    let value = serde_json::to_value(map)?;
    let parsed: BLSConfig = serde_json::from_value(value)?;

    Ok(parsed)
}
