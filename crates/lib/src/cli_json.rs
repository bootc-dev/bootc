//! Export CLI structure as JSON for documentation generation

use clap::Command;
use serde::{Deserialize, Serialize};

/// Representation of a CLI option for JSON export
#[derive(Debug, Serialize, Deserialize)]
pub struct CliOption {
    pub long: String,
    pub short: Option<String>,
    pub value_name: Option<String>,
    pub default: Option<String>,
    pub help: String,
    pub possible_values: Vec<String>,
    pub required: bool,
}

/// Representation of a CLI command for JSON export
#[derive(Debug, Serialize, Deserialize)]
pub struct CliCommand {
    pub name: String,
    pub about: Option<String>,
    pub options: Vec<CliOption>,
    pub positionals: Vec<CliPositional>,
    pub subcommands: Vec<CliCommand>,
}

/// Representation of a positional argument
#[derive(Debug, Serialize, Deserialize)]
pub struct CliPositional {
    pub name: String,
    pub help: Option<String>,
    pub required: bool,
    pub multiple: bool,
}

/// Convert a clap Command to our JSON representation
pub fn command_to_json(cmd: &Command) -> CliCommand {
    let mut options = Vec::new();
    let mut positionals = Vec::new();

    // Extract arguments
    for arg in cmd.get_arguments() {
        let id = arg.get_id().as_str();

        // Skip built-in help and version
        if id == "help" || id == "version" {
            continue;
        }

        // Skip hidden arguments
        if arg.is_hide_set() {
            continue;
        }

        if arg.is_positional() {
            // Handle positional arguments
            positionals.push(CliPositional {
                name: id.to_string(),
                help: arg.get_help().map(|h| h.to_string()),
                required: arg.is_required_set(),
                multiple: false, // For now, simplify this
            });
        } else {
            // Handle options/flags
            let mut possible_values = Vec::new();
            let pvs = arg.get_possible_values();
            if !pvs.is_empty() {
                for pv in pvs {
                    possible_values.push(pv.get_name().to_string());
                }
            }

            let help = arg.get_help().map(|h| h.to_string()).unwrap_or_default();

            options.push(CliOption {
                long: arg
                    .get_long()
                    .map(String::from)
                    .unwrap_or_else(|| id.to_string()),
                short: arg.get_short().map(|c| c.to_string()),
                value_name: arg
                    .get_value_names()
                    .and_then(|names| names.first())
                    .map(|s| s.to_string()),
                default: arg
                    .get_default_values()
                    .first()
                    .and_then(|v| v.to_str())
                    .map(String::from),
                help,
                possible_values,
                required: arg.is_required_set(),
            });
        }
    }

    // Extract subcommands
    let mut subcommands = Vec::new();
    for subcmd in cmd.get_subcommands() {
        // Skip help subcommand
        if subcmd.get_name() == "help" {
            continue;
        }

        // Skip hidden subcommands
        if subcmd.is_hide_set() {
            continue;
        }

        subcommands.push(command_to_json(subcmd));
    }

    CliCommand {
        name: cmd.get_name().to_string(),
        about: cmd.get_about().map(|s| s.to_string()),
        options,
        positionals,
        subcommands,
    }
}

/// Dump the entire CLI structure as JSON
pub fn dump_cli_json(cmd: &Command) -> Result<String, serde_json::Error> {
    let cli_structure = command_to_json(cmd);
    serde_json::to_string_pretty(&cli_structure)
}
