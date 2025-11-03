use std::{fs::File, io::BufReader};

use anyhow::{Context, Result};
use bootc_utils::PathQuotedDisplay;
use fn_error_context::context;
use serde::{Deserialize, Serialize};

mod cli;

/// The environment variable that can be used to specify an image.
const CONFIG_VAR: &str = "BOOTC_REINSTALL_CONFIG";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReinstallConfig {
    /// The bootc image to install on the system.
    pub(crate) bootc_image: String,
    pub(crate) composefs_backend: bool,
}

impl ReinstallConfig {
    #[context("load")]
    pub fn load() -> Result<Option<Self>> {
        let Some(config) = std::env::var_os(CONFIG_VAR) else {
            return Ok(None);
        };
        let f = File::open(&config)
            .with_context(|| format!("Opening {}", PathQuotedDisplay::new(&config)))
            .map(BufReader::new)?;
        let r = serde_yaml::from_reader(f)
            .with_context(|| format!("Parsing config from {}", PathQuotedDisplay::new(&config)))?;
        Ok(Some(r))
    }
}
