//! Man page generation and synchronization
//!
//! This module handles both the generation of man pages from markdown sources
//! and the synchronization of CLI options from Rust code to those markdown templates.

use anyhow::{Context, Result};
use camino::Utf8Path;
use serde::{Deserialize, Serialize};
use std::fs;
use xshell::{cmd, Shell};

/// Represents a CLI option extracted from the JSON dump
#[derive(Debug, Serialize, Deserialize)]
pub struct CliOption {
    /// The long flag (e.g., "wipe", "block-setup")
    pub long: String,
    /// The short flag if any (e.g., "h")
    pub short: Option<String>,
    /// The value name if the option takes an argument
    pub value_name: Option<String>,
    /// The default value if any
    pub default: Option<String>,
    /// The help text (doc comment from Rust)
    pub help: String,
    /// Possible values for enums
    pub possible_values: Vec<String>,
    /// Whether the option is required
    pub required: bool,
}

/// Represents a CLI command from the JSON dump
#[derive(Debug, Serialize, Deserialize)]
pub struct CliCommand {
    pub name: String,
    pub about: Option<String>,
    pub options: Vec<CliOption>,
    pub positionals: Vec<CliPositional>,
    pub subcommands: Vec<CliCommand>,
}

/// Represents a positional argument
#[derive(Debug, Serialize, Deserialize)]
pub struct CliPositional {
    pub name: String,
    pub help: Option<String>,
    pub required: bool,
    pub multiple: bool,
}

/// Extract CLI structure by running the JSON dump command
pub fn extract_cli_json(sh: &Shell) -> Result<CliCommand> {
    let json_output = cmd!(sh, "cargo run --features=docgen -- internals dump-cli-json")
        .read()
        .context("Running CLI JSON dump command")?;

    let cli_structure: CliCommand =
        serde_json::from_str(&json_output).context("Parsing CLI JSON output")?;

    Ok(cli_structure)
}

/// Find a subcommand by path
pub fn find_subcommand<'a>(cli: &'a CliCommand, path: &[&str]) -> Option<&'a CliCommand> {
    if path.is_empty() {
        return Some(cli);
    }

    let first = path[0];
    let rest = &path[1..];

    cli.subcommands
        .iter()
        .find(|cmd| cmd.name == first)
        .and_then(|cmd| find_subcommand(cmd, rest))
}

/// Convert CLI options to markdown format
fn format_options_as_markdown(options: &[CliOption], positionals: &[CliPositional]) -> String {
    let mut result = String::new();

    // Format positional arguments first
    for pos in positionals {
        let name = pos.name.to_uppercase();
        result.push_str(&format!("**{}**\n\n", name));

        if let Some(help) = &pos.help {
            result.push_str(&format!("    {}\n\n", help));
        }

        if pos.required {
            result.push_str("    This argument is required.\n\n");
        }
    }

    // Format options
    for opt in options {
        let mut flag_line = String::new();

        // Add short flag if available
        if let Some(short) = &opt.short {
            flag_line.push_str(&format!("**-{}**", short));
            flag_line.push_str(", ");
        }

        // Add long flag
        flag_line.push_str(&format!("**--{}**", opt.long));

        // Add value name if option takes argument
        if let Some(value_name) = &opt.value_name {
            flag_line.push_str(&format!("=*{}*", value_name));
        }

        result.push_str(&format!("{}\n\n", flag_line));
        result.push_str(&format!("    {}\n\n", opt.help));

        // Add possible values for enums
        if !opt.possible_values.is_empty() {
            result.push_str("    Possible values:\n");
            for value in &opt.possible_values {
                result.push_str(&format!("    - {}\n", value));
            }
            result.push('\n');
        }

        // Add default value if present
        if let Some(default) = &opt.default {
            result.push_str(&format!("    Default: {}\n\n", default));
        }
    }

    result
}

/// Update markdown file with generated options
pub fn update_markdown_with_options(
    markdown_path: &Utf8Path,
    options: &[CliOption],
    positionals: &[CliPositional],
) -> Result<()> {
    let content =
        fs::read_to_string(markdown_path).with_context(|| format!("Reading {}", markdown_path))?;

    let begin_marker = "<!-- BEGIN GENERATED OPTIONS -->";
    let end_marker = "<!-- END GENERATED OPTIONS -->";

    let Some((before, rest)) = content.split_once(begin_marker) else {
        return Ok(()); // Skip files without markers
    };

    let Some((_, after)) = rest.split_once(end_marker) else {
        anyhow::bail!("Found BEGIN marker but not END marker in {}", markdown_path);
    };

    let generated_options = format_options_as_markdown(options, positionals);

    // Trim trailing whitespace from before section and ensure exactly one blank line
    let before = before.trim_end();

    let new_content = format!(
        "{}\n\n{}\n{}{}{}",
        before, begin_marker, generated_options, end_marker, after
    );

    fs::write(markdown_path, new_content)
        .with_context(|| format!("Writing to {}", markdown_path))?;

    println!("Updated {}", markdown_path);
    Ok(())
}

/// Discover man page files and infer their command paths from filenames
fn discover_man_page_mappings(
    cli_structure: &CliCommand,
) -> Result<Vec<(String, Option<Vec<String>>)>> {
    let man_dir = Utf8Path::new("docs/src/man");
    let mut mappings = Vec::new();

    // Read all .md files in the man directory
    for entry in fs::read_dir(man_dir)? {
        let entry = entry?;
        let path = entry.path();

        if let Some(extension) = path.extension() {
            if extension != "md" {
                continue;
            }
        } else {
            continue;
        }

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid filename"))?;

        // Check if the file contains generation markers
        let content = fs::read_to_string(&path)?;
        if !content.contains("<!-- BEGIN GENERATED OPTIONS -->") {
            continue;
        }

        // Infer command path from filename by matching against CLI structure
        let command_path = if let Some(cmd_part) = filename
            .strip_prefix("bootc-")
            .and_then(|s| s.strip_suffix(".md"))
        {
            find_command_path_for_filename(cli_structure, cmd_part)
        } else {
            None
        };

        mappings.push((filename.to_string(), command_path));
    }

    Ok(mappings)
}

/// Find the command path for a filename by searching the CLI structure
fn find_command_path_for_filename(
    cli_structure: &CliCommand,
    filename_part: &str,
) -> Option<Vec<String>> {
    // First, try to match top-level commands
    if let Some(subcommand) = cli_structure
        .subcommands
        .iter()
        .find(|cmd| cmd.name == filename_part)
    {
        return Some(vec![subcommand.name.clone()]);
    }

    // Then, try to match subcommands with pattern COMMAND-SUBCOMMAND
    for subcommand in &cli_structure.subcommands {
        for sub_subcommand in &subcommand.subcommands {
            let expected_pattern = format!("{}-{}", subcommand.name, sub_subcommand.name);
            if expected_pattern == filename_part {
                return Some(vec![subcommand.name.clone(), sub_subcommand.name.clone()]);
            }
        }
    }

    None
}

/// Sync all man pages with their corresponding CLI commands
pub fn sync_all_man_pages(sh: &Shell) -> Result<()> {
    let cli_structure = extract_cli_json(sh)?;

    // Discover man page files automatically
    let mappings = discover_man_page_mappings(&cli_structure)?;

    for (filename, subcommand_path) in mappings {
        let markdown_path = Utf8Path::new("docs/src/man").join(filename);

        if !markdown_path.exists() {
            continue;
        }

        // Navigate to the right subcommand
        let target_cmd = if let Some(path) = subcommand_path {
            let path_refs: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
            find_subcommand(&cli_structure, &path_refs)
                .ok_or_else(|| anyhow::anyhow!("Subcommand {:?} not found", path))?
        } else {
            &cli_structure
        };

        update_markdown_with_options(&markdown_path, &target_cmd.options, &target_cmd.positionals)?;
    }

    Ok(())
}

/// Test the sync workflow
pub fn test_sync_workflow(sh: &Shell) -> Result<()> {
    println!("🧪 Testing man page sync workflow...");

    // Create a backup of current files
    let test_dir = "target/test-sync";
    sh.create_dir(test_dir)?;

    // Run sync
    sync_all_man_pages(sh)?;

    println!("✅ Sync workflow test completed successfully");
    Ok(())
}

/// Generate man pages from hand-written markdown sources
pub fn generate_man_pages(sh: &Shell) -> Result<()> {
    let man_src_dir = Utf8Path::new("docs/src/man");
    let man_output_dir = Utf8Path::new("target/man");

    // Ensure output directory exists
    sh.create_dir(man_output_dir)?;

    // First, sync the markdown files with current CLI options
    sync_all_man_pages(sh)?;

    // Get version for replacement during generation
    let version = get_package_version()?;

    // Convert each markdown file to man page format
    for entry in fs::read_dir(man_src_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) != Some("md") {
            continue;
        }

        let filename = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid filename"))?;

        // Parse section from filename (e.g., bootc.8, bootc-config.5)
        // All man page files must have a section number
        let (base_name, section) = filename
            .rsplit_once('.')
            .and_then(|(name, section_str)| {
                section_str.parse::<u8>().ok().map(|section| (name, section))
            })
            .ok_or_else(|| anyhow::anyhow!("Man page filename must include section number (e.g., bootc.8.md, bootc-config.5.md): {}.md", filename))?;

        let output_file = man_output_dir.join(format!("{}.{}", base_name, section));

        // Read markdown content and replace version placeholders
        let content = fs::read_to_string(&path)?;
        let content_with_version = content.replace("<!-- VERSION PLACEHOLDER -->", &version);

        // Create temporary file with version-replaced content
        let temp_path = format!("{}.tmp", path.display());
        fs::write(&temp_path, content_with_version)?;

        cmd!(sh, "go-md2man -in {temp_path} -out {output_file}")
            .run()
            .with_context(|| format!("Converting {} to man page", path.display()))?;

        // Clean up temporary file
        fs::remove_file(&temp_path)?;

        println!("Generated {}", output_file);
    }

    // Apply post-processing fixes for apostrophe handling
    apply_man_page_fixes(sh, man_output_dir)?;

    Ok(())
}

/// Get version from Cargo.toml
fn get_package_version() -> Result<String> {
    let cargo_toml =
        fs::read_to_string("crates/lib/Cargo.toml").context("Reading crates/lib/Cargo.toml")?;

    let parsed: toml::Table = cargo_toml.parse().context("Parsing Cargo.toml")?;

    let version = parsed
        .get("package")
        .and_then(|p| p.as_table())
        .and_then(|p| p.get("version"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Could not find package.version in Cargo.toml"))?;

    Ok(format!("v{}", version))
}

/// Single command to update all man pages - auto-discover new commands and sync existing ones
pub fn update_manpages(sh: &Shell) -> Result<()> {
    println!("Discovering CLI structure...");
    let cli_structure = extract_cli_json(sh)?;

    println!("Checking for missing man pages...");
    let mut created_count = 0;

    // Auto-discover commands that need man pages
    let mut commands_to_check = Vec::new();

    // Add top-level commands
    for cmd in &cli_structure.subcommands {
        commands_to_check.push(vec![cmd.name.clone()]);
    }

    // Add subcommands
    for cmd in &cli_structure.subcommands {
        for subcmd in &cmd.subcommands {
            commands_to_check.push(vec![cmd.name.clone(), subcmd.name.clone()]);
        }
    }

    // Check each command and create man page if missing
    for command_parts in commands_to_check {
        let filename = if command_parts.len() == 1 {
            format!("bootc-{}.md", command_parts[0])
        } else {
            format!("bootc-{}.md", command_parts.join("-"))
        };

        let filepath = format!("docs/src/man/{}", filename);

        if !std::path::Path::new(&filepath).exists() {
            // Find the command in CLI structure
            let command_parts_refs: Vec<&str> = command_parts.iter().map(|s| s.as_str()).collect();
            let target_cmd = find_subcommand(&cli_structure, &command_parts_refs);

            if let Some(cmd) = target_cmd {
                let command_name_full = format!("bootc {}", command_parts.join(" "));
                let command_description = cmd.about.as_deref().unwrap_or("TODO: Add description");

                let template = format!(
                    r#"# NAME

{} - {}

# SYNOPSIS

**{}** [*OPTIONS*]

# DESCRIPTION

{}

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->

<!-- END GENERATED OPTIONS -->

# EXAMPLES

TODO: Add practical examples showing how to use this command.

# SEE ALSO

**bootc**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
"#,
                    command_name_full.replace(" ", "-"),
                    command_description,
                    command_name_full,
                    command_description
                );

                std::fs::write(&filepath, template)
                    .with_context(|| format!("Writing template to {}", filepath))?;

                println!("✓ Created man page template: {}", filepath);
                created_count += 1;
            }
        }
    }

    if created_count > 0 {
        println!("✓ Created {} new man page templates", created_count);
    } else {
        println!("✓ All commands already have man pages");
    }

    println!("🔄 Syncing OPTIONS sections...");
    sync_all_man_pages(sh)?;

    println!("Man pages updated.");
    println!("");
    println!("Next steps for new templates:");
    println!("   - Edit the templates to add detailed descriptions and examples");
    println!("   - Run 'cargo xtask manpages' to generate final man pages");

    Ok(())
}

/// Apply post-processing fixes to generated man pages
fn apply_man_page_fixes(sh: &Shell, dir: &Utf8Path) -> Result<()> {
    // Fix apostrophe rendering issue
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path
            .extension()
            .and_then(|s| s.to_str())
            .map_or(false, |e| e.chars().all(|c| c.is_numeric()))
        {
            // Apply the same sed fixes as before
            let groffsub = r"1i .ds Aq \\(aq";
            let dropif = r"/\.g \.ds Aq/d";
            let dropelse = r"/.el .ds Aq '/d";
            cmd!(sh, "sed -i -e {groffsub} -e {dropif} -e {dropelse} {path}").run()?;
        }
    }

    Ok(())
}
