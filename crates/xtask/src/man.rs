//! Man page generation and synchronization
//!
//! This module handles both the generation of man pages from markdown sources
//! and the synchronization of CLI options from Rust code to those markdown templates.
//! Canonical chapters use `<manual-name>.<section>.md`; SUMMARY.md owns their
//! navigation order. Guides and references share preparation and conversion.

use anyhow::{Context, Result, ensure};
use camino::{Utf8Path, Utf8PathBuf};
use fn_error_context::context;
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    ops::Range,
};
use xshell::{Shell, cmd};

use crate::out_of_sync_error;

mod guides;

const DOCS_SRC: &str = "docs/src";
const BOOK_URL: &str = "https://bootc.dev/bootc/";

struct Page {
    source: String,
    name: String,
    section: u8,
    group: String,
    content: String,
}

impl Page {
    fn filename(&self) -> String {
        format!("{}.{}", self.name, self.section)
    }

    fn reference(&self) -> String {
        format!("**{}**({})", self.name, self.section)
    }
}

struct Inventory {
    pages: Vec<Page>,
    names: BTreeMap<String, String>,
}

fn sources_in(
    root: &Utf8Path,
    dir: &Utf8Path,
    sources: &mut BTreeMap<String, String>,
) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("Reading {dir}"))? {
        let path = Utf8PathBuf::from_path_buf(entry?.path())
            .map_err(|_| anyhow::anyhow!("Non-UTF-8 documentation path"))?;
        if path.is_dir() {
            sources_in(root, &path, sources)?;
        } else if path.extension() == Some("md") {
            let source = path.strip_prefix(root)?.to_string();
            let content = fs::read_to_string(&path).with_context(|| format!("Reading {path}"))?;
            sources.insert(source, content);
        }
    }
    Ok(())
}

/// Navigation is shared by the website and the offline index, including order.
fn chapters(summary: &str) -> Vec<(String, String)> {
    let mut group = String::new();
    let mut in_heading = false;
    let mut result = Vec::new();
    for event in Parser::new(summary) {
        match event {
            Event::Start(Tag::Heading { .. }) => {
                group.clear();
                in_heading = true;
            }
            Event::End(TagEnd::Heading(_)) => in_heading = false,
            Event::Text(text) | Event::Code(text) if in_heading => group.push_str(&text),
            Event::Start(Tag::Link { dest_url, .. }) => {
                result.push((group.clone(), dest_url.into_string()));
            }
            _ => (),
        }
    }
    result
}

fn title_and_body(content: &str) -> Result<(&str, &str)> {
    let (heading, body) = content
        .trim_start()
        .split_once('\n')
        .context("Page has no body")?;
    let title = heading
        .strip_prefix("# ")
        .context("Page must start with an H1 heading")?
        .trim();
    ensure!(
        !title.is_empty() && !body.trim().is_empty(),
        "Empty documentation page"
    );
    Ok((title, body.trim_start_matches('\n')))
}

impl Inventory {
    fn load() -> Result<Self> {
        let root = Utf8Path::new(DOCS_SRC);
        let mut sources = BTreeMap::new();
        sources_in(root, root, &mut sources)?;
        Self::from_sources(sources)
    }

    fn from_sources(mut sources: BTreeMap<String, String>) -> Result<Self> {
        let summary = sources.remove("SUMMARY.md").context("Missing SUMMARY.md")?;
        // This historical, unlinked placeholder is not documentation. If it acquires
        // content, require it to participate in coverage like every other chapter.
        if sources
            .get("related.md")
            .is_some_and(|s| s.trim() == "# Related projects")
        {
            sources.remove("related.md");
        }
        let mut seen = BTreeSet::new();
        let mut outputs = BTreeSet::from(["bootc-docs.7".to_string()]);
        let mut pages = Vec::new();
        for (group, source) in chapters(&summary) {
            ensure!(
                seen.insert(source.clone()),
                "Duplicate navigation entry: {source}"
            );
            let content = sources
                .remove(&source)
                .with_context(|| format!("Missing chapter: {source}"))?;
            title_and_body(&content).with_context(|| format!("Invalid chapter: {source}"))?;
            // Use the same filename convention for guides and native manuals,
            // regardless of their source directory. Keep service-name dots.
            let (name, section) = Utf8Path::new(&source)
                .file_name()
                .and_then(|s| s.strip_suffix(".md"))
                .and_then(|s| s.rsplit_once('.'))
                .with_context(|| format!("Expected <manual-name>.<section>.md: {source}"))?;
            ensure!(
                matches!(section, "5" | "7" | "8"),
                "Manuals must use section 5, 7 or 8: {source}"
            );
            let section: u8 = section.parse()?;
            ensure!(
                name.contains("bootc")
                    && name.chars().all(|c| c.is_ascii_lowercase()
                        || c.is_ascii_digit()
                        || matches!(c, '-' | '.')),
                "Manual name must be safe and match the RPM bootc file pattern: {source}"
            );
            ensure!(
                section != 7 || name.starts_with("bootc-"),
                "Guide manual names must start with bootc-: {source}"
            );
            let name = name.to_string();
            let page = Page {
                source,
                name,
                section,
                group,
                content,
            };
            ensure!(
                outputs.insert(page.filename()),
                "Duplicate manual output: {}",
                page.filename()
            );
            pages.push(page);
        }
        let missing: Vec<_> = sources.keys().collect();
        ensure!(
            missing.is_empty(),
            "Chapters missing from SUMMARY.md: {missing:?}"
        );
        let names = pages
            .iter()
            .map(|p| (p.source.clone(), p.reference()))
            .collect();
        Ok(Self { pages, names })
    }

    /// Change only link spans, not the surrounding Markdown. A Markdown parser
    /// handles multiline/reference links and avoids links in inline/fenced code.
    fn rewrite_links(&self, body: &str, source: &str) -> Result<(String, BTreeSet<String>)> {
        let mut replacements = Vec::new();
        let mut references = BTreeSet::new();
        let mut link: Option<(String, Range<usize>, Option<Range<usize>>)> = None;
        for (event, span) in Parser::new_ext(body, Options::ENABLE_TABLES).into_offset_iter() {
            match event {
                Event::Start(Tag::Link { dest_url, .. }) => {
                    link = Some((dest_url.into_string(), span, None));
                }
                Event::End(TagEnd::Link) => {
                    let (destination, whole, label) =
                        link.take().context("Unmatched Markdown link")?;
                    let label = label.map(|r| &body[r]).unwrap_or("");
                    let replacement = if destination.starts_with('#') {
                        Some(label.to_string())
                    } else if destination.contains(':') || destination.starts_with('/') {
                        None
                    } else {
                        let split = destination.find(['#', '?']).unwrap_or(destination.len());
                        let (path, suffix) = destination.split_at(split);
                        let path = normalize_link_path(source, path)?;
                        if let Some(reference) = self.names.get(&path) {
                            references.insert(reference.clone());
                            Some(format!("{label} (see {reference})"))
                        } else if path.ends_with(".md") {
                            anyhow::bail!("Unmapped local link in {source}: {destination}");
                        } else {
                            // Generated rustdoc and schemas are online artifacts,
                            // not narrative Markdown chapters or offline manuals.
                            Some(format!("[{label}]({BOOK_URL}{path}{suffix})"))
                        }
                    };
                    if let Some(replacement) = replacement {
                        replacements.push((whole, replacement));
                    }
                }
                _ => {
                    if let Some((_, _, label)) = &mut link {
                        if let Some(label) = label {
                            label.start = label.start.min(span.start);
                            label.end = label.end.max(span.end);
                        } else {
                            *label = Some(span);
                        }
                    }
                }
            }
        }
        let mut output = body.to_string();
        for (span, replacement) in replacements.into_iter().rev() {
            output.replace_range(span, &replacement);
        }
        Ok((output, references))
    }

    /// Prepare every manual from one source snapshot, without running a converter.
    fn prepare(&self, version: &str) -> Result<Vec<(String, String)>> {
        let mut manuals = Vec::new();
        let mut index = String::from(
            "# BOOTC-DOCS 7\n\n## NAME\n\nbootc-docs - Guide to bootc documentation\n\n## DESCRIPTION\n\nThe documentation shipped with bootc: guides in section 7, commands in section 8, and configuration and services in section 5. The groups below follow the website navigation.\n",
        );
        let mut group = "";
        for page in &self.pages {
            let (title, body) = title_and_body(&page.content)
                .with_context(|| format!("Invalid chapter: {}", page.source))?;
            if page.group != group {
                group = &page.group;
                index.push_str(&format!("\n## {group}\n\n"));
            }
            let description = if page.section == 7 {
                title.to_string()
            } else {
                reference_description(body)
            };
            index.push_str(&format!("- {} - {description}\n", page.reference()));
            let content = if page.section == 7 {
                // Validate source links before terminal-only adaptations.
                self.rewrite_links(&page.content, &page.source)?;
                guides::adapt_markdown(body)
                    .with_context(|| format!("Preparing manual for {}", page.source))?
            } else {
                page.content.clone()
            };
            let (content, references) = self.rewrite_links(&content, &page.source)?;
            let markdown = if page.section == 7 {
                guides::markdown(&page.name, title, &content, references, version)
            } else {
                reference_markdown(&content, &page.name, page.section, version)
            };
            manuals.push((page.filename(), markdown));
        }
        index.push_str(&format!("\n## VERSION\n\n{version}\n"));
        manuals.push(("bootc-docs.7".to_string(), index));
        Ok(manuals)
    }
}

fn normalize_link_path(source: &str, destination: &str) -> Result<String> {
    let mut parts: Vec<&str> = source.split('/').collect();
    parts.pop();
    for part in destination.split('/') {
        match part {
            "" | "." => (),
            ".." => {
                ensure!(!parts.is_empty(), "Link escapes docs/src: {destination}");
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    Ok(parts.join("/"))
}

fn reference_description(body: &str) -> String {
    let paragraph = body
        .trim_start()
        .lines()
        .take_while(|line| !line.trim().is_empty())
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(" ");
    paragraph
        .split_once(" - ")
        .map(|(_, description)| description.to_string())
        .unwrap_or(paragraph)
}

// target/man is build output, and bootc-*.7 is owned by this generator.
// Remove obsolete guide artifacts so the Makefile's wildcard cannot install them.
fn prune_stale_guides(output: &Utf8Path, expected: &BTreeSet<String>) -> Result<()> {
    for entry in fs::read_dir(output)? {
        let path = Utf8PathBuf::from_path_buf(entry?.path())
            .map_err(|_| anyhow::anyhow!("Non-UTF-8 output path"))?;
        let filename = path.file_name().context("Invalid output filename")?;
        if filename.starts_with("bootc-")
            && path.extension() == Some("7")
            && !expected.contains(filename)
        {
            fs::remove_file(&path).with_context(|| format!("Removing stale guide {path}"))?;
        }
    }
    Ok(())
}

/// Validate one-to-one website and installed manual coverage.
pub fn check_docs() -> Result<()> {
    let inventory = Inventory::load()?;
    inventory.prepare(&get_package_version()?)?;
    println!(
        "Validated {} canonical pages for website and manuals",
        inventory.pages.len()
    );
    Ok(())
}

/// Render narrative guides without rebuilding the bootc CLI.
pub fn generate_guide_man_pages(sh: &Shell) -> Result<()> {
    generate_pages(sh, true)
}

/// Guides and references use the same preparation and conversion path.
fn generate_pages(sh: &Shell, guides_only: bool) -> Result<()> {
    let inventory = Inventory::load()?;
    let manuals = inventory.prepare(&get_package_version()?)?;
    let output = Utf8Path::new("target/man");
    sh.create_dir(output)?;
    let expected = manuals
        .iter()
        .map(|(filename, _)| filename.clone())
        .collect();
    prune_stale_guides(output, &expected)?;
    for (filename, markdown) in &manuals {
        if !guides_only || filename.ends_with(".7") {
            convert_markdown(sh, markdown, &output.join(filename))?;
        }
    }
    apply_man_page_fixes(sh, output)
}

fn convert_markdown(sh: &Shell, markdown: &str, output: &Utf8Path) -> Result<()> {
    // Temporary and generated files never belong in docs/src.
    let mut input = tempfile::NamedTempFile::new_in(output.parent().unwrap())?;
    input.write_all(markdown.as_bytes())?;
    let input = input.path();
    cmd!(sh, "go-md2man -in {input} -out {output}")
        .run()
        .with_context(|| format!("Generating {output}"))?;
    // A source newline inside inline code can leave a leading apostrophe
    // unescaped by go-md2man. Roff treats it as a request and drops the line.
    let rendered = fs::read_to_string(output)?;
    let escaped = escape_roff_apostrophes(&rendered);
    if escaped != rendered {
        fs::write(output, escaped)?;
    }
    Ok(())
}

fn escape_roff_apostrophes(content: &str) -> String {
    let mut result = String::new();
    for line in content.split_inclusive('\n') {
        if line.starts_with('\'') {
            result.push_str("\\&");
        }
        result.push_str(line);
    }
    result
}

fn reference_markdown(content: &str, name: &str, section: u8, version: &str) -> String {
    // go-md2man consumes the first H1 as its title, not a body heading.
    // Supply it from the filename so NAME remains visible and the header
    // identifies the actual manual instead of displaying NAME().
    format!(
        "# {} {section}\n\n{}",
        name.to_ascii_uppercase(),
        content.replace("<!-- VERSION PLACEHOLDER -->", version)
    )
}

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
    /// Whether this is a boolean flag
    pub is_boolean: bool,
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
#[context("Extracting CLI")]
pub fn extract_cli_json(sh: &Shell) -> Result<CliCommand> {
    // If we have a release binary, assume that we should compile
    // in release mode as hopefully we'll have incremental compilation
    // enabled.
    let releasebin = Utf8Path::new("target/release/bootc");
    let release = releasebin
        .try_exists()
        .context("Querying release bin")?
        .then_some("--release");
    let json_output = cmd!(
        sh,
        "cargo run {release...} --features=docgen -- internals dump-cli-json"
    )
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

/// Convert CLI subcommands to markdown table format (like podman)
fn format_subcommands_as_table(subcommands: &[CliCommand], parent_path: &[&str]) -> String {
    if subcommands.is_empty() {
        return String::new();
    }

    let mut result = String::new();

    // Table header
    result.push_str("| Command | Description |\n");
    result.push_str("|---------|-------------|\n");

    // Table rows
    for subcmd in subcommands {
        let mut full_path = vec!["bootc"];
        full_path.extend_from_slice(parent_path);
        full_path.push(&subcmd.name);

        let cmd_name = format!("**{}**", full_path.join(" "));
        let description = subcmd.about.as_deref().unwrap_or("").trim_end_matches('.');
        result.push_str(&format!("| {} | {} |\n", cmd_name, description));
    }

    result.push('\n');
    result
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

        // Add value name if option takes argument (but not for boolean flags)
        // Boolean flags are detected by having no value_name (set to None in cli_json.rs)
        if let Some(value_name) = &opt.value_name {
            flag_line.push_str(&format!("=*{}*", value_name));
        }

        result.push_str(&format!("{}\n\n", flag_line));
        result.push_str(&format!("    {}\n\n", opt.help));

        // Add possible values for enums (but not for boolean flags)
        if !opt.possible_values.is_empty() && !opt.is_boolean {
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

/// Compute what `docs/src/man/<file>` should look like after regenerating its subcommands section.
/// Returns `None` if the file has no subcommands marker (nothing to do).
fn compute_markdown_with_subcommands(
    markdown_path: &Utf8Path,
    content: &str,
    subcommands: &[CliCommand],
    parent_path: &[&str],
) -> Result<Option<String>> {
    let begin_marker = "<!-- BEGIN GENERATED SUBCOMMANDS -->";
    let end_marker = "<!-- END GENERATED SUBCOMMANDS -->";

    let Some((before, rest)) = content.split_once(begin_marker) else {
        return Ok(None); // Skip files without markers
    };

    let Some((_, after)) = rest.split_once(end_marker) else {
        anyhow::bail!(
            "Found BEGIN SUBCOMMANDS marker but not END marker in {}",
            markdown_path
        );
    };

    let generated_subcommands = format_subcommands_as_table(subcommands, parent_path);

    // Trim trailing whitespace from before section and ensure exactly one blank line
    let before = before.trim_end();

    Ok(Some(format!(
        "{}\n\n{}\n{}{}{}",
        before, begin_marker, generated_subcommands, end_marker, after
    )))
}

/// Compute what `docs/src/man/<file>` should look like after regenerating its options section.
/// Returns `None` if the file has no options marker (nothing to do).
fn compute_markdown_with_options(
    markdown_path: &Utf8Path,
    content: &str,
    options: &[CliOption],
    positionals: &[CliPositional],
) -> Result<Option<String>> {
    let begin_marker = "<!-- BEGIN GENERATED OPTIONS -->";
    let end_marker = "<!-- END GENERATED OPTIONS -->";

    let Some((before, rest)) = content.split_once(begin_marker) else {
        return Ok(None); // Skip files without markers
    };

    let Some((_, after)) = rest.split_once(end_marker) else {
        anyhow::bail!("Found BEGIN marker but not END marker in {}", markdown_path);
    };

    let generated_options = format_options_as_markdown(options, positionals);

    // Trim trailing whitespace from before section
    let mut before = before.trim_end();

    // Remove # OPTIONS header if it's right before the marker
    if before.ends_with("# OPTIONS") {
        before = before.strip_suffix("# OPTIONS").unwrap().trim_end();
    }

    // Only add OPTIONS header if there are options or positionals
    let new_content = if !options.is_empty() || !positionals.is_empty() {
        format!(
            "{}\n\n# OPTIONS\n\n{}\n{}{}{}",
            before, begin_marker, generated_options, end_marker, after
        )
    } else {
        format!("{}\n\n{}\n{}{}", before, begin_marker, end_marker, after)
    };

    Ok(Some(new_content))
}

/// Update markdown file with generated subcommands
pub fn update_markdown_with_subcommands(
    markdown_path: &Utf8Path,
    subcommands: &[CliCommand],
    parent_path: &[&str],
) -> Result<()> {
    let content =
        fs::read_to_string(markdown_path).with_context(|| format!("Reading {}", markdown_path))?;

    let Some(new_content) =
        compute_markdown_with_subcommands(markdown_path, &content, subcommands, parent_path)?
    else {
        return Ok(());
    };

    // Only write if content has changed to avoid updating mtime unnecessarily
    if new_content != content {
        fs::write(markdown_path, new_content)
            .with_context(|| format!("Writing to {}", markdown_path))?;
        println!("Updated subcommands in {}", markdown_path);
    }
    Ok(())
}

/// Update markdown file with generated options
pub fn update_markdown_with_options(
    markdown_path: &Utf8Path,
    options: &[CliOption],
    positionals: &[CliPositional],
) -> Result<()> {
    let content =
        fs::read_to_string(markdown_path).with_context(|| format!("Reading {}", markdown_path))?;

    let Some(new_content) =
        compute_markdown_with_options(markdown_path, &content, options, positionals)?
    else {
        return Ok(());
    };

    // Only write if content has changed to avoid updating mtime unnecessarily
    if new_content != content {
        fs::write(markdown_path, new_content)
            .with_context(|| format!("Writing to {}", markdown_path))?;
        println!("Updated {}", markdown_path);
    }
    Ok(())
}

/// Discover man page files and infer their command paths from filenames
#[context("Querying man page mappings")]
fn discover_man_page_mappings(
    cli_structure: &CliCommand,
) -> Result<Vec<(String, Option<Vec<String>>)>> {
    let man_dir = Utf8Path::new("docs/src/man");
    let mut mappings = Vec::new();

    // Read all .md files in the man directory
    for entry in fs::read_dir(man_dir).context("Reading docs/src/man")? {
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
        let content = fs::read_to_string(&path).with_context(|| format!("Reading {path:?}"))?;
        if !content.contains("<!-- BEGIN GENERATED OPTIONS -->")
            && !content.contains("<!-- BEGIN GENERATED SUBCOMMANDS -->")
        {
            continue;
        }

        // Infer command path from filename by matching against CLI structure
        let command_path = if let Some(cmd_part) = filename
            .strip_prefix("bootc-")
            .and_then(|s| s.strip_suffix(".md"))
            .and_then(|s| s.rsplit_once('.').map(|(name, _section)| name))
        {
            let path = find_command_path_for_filename(cli_structure, cmd_part);
            path
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
#[context("Syncing man pages")]
pub fn sync_all_man_pages(sh: &Shell) -> Result<()> {
    let cli_structure = extract_cli_json(sh)?;

    // Discover man page files automatically
    let mappings = discover_man_page_mappings(&cli_structure)?;

    for (filename, subcommand_path) in mappings {
        let markdown_path = Utf8Path::new("docs/src/man").join(&filename);

        if !markdown_path.exists() {
            continue;
        }

        // Navigate to the right subcommand
        let target_cmd = if let Some(ref path) = subcommand_path {
            let path_refs: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
            find_subcommand(&cli_structure, &path_refs)
                .ok_or_else(|| anyhow::anyhow!("Subcommand {:?} not found", path))?
        } else {
            &cli_structure
        };

        // Update options if the file has options markers
        let content = fs::read_to_string(&markdown_path)?;
        if content.contains("<!-- BEGIN GENERATED OPTIONS -->") {
            update_markdown_with_options(
                &markdown_path,
                &target_cmd.options,
                &target_cmd.positionals,
            )?;
        }

        // Update subcommands if the file has subcommands markers
        if content.contains("<!-- BEGIN GENERATED SUBCOMMANDS -->") {
            let parent_path: Vec<&str> = if let Some(path) = &subcommand_path {
                path.iter().map(|s| s.as_str()).collect()
            } else {
                vec![]
            };
            update_markdown_with_subcommands(
                &markdown_path,
                &target_cmd.subcommands,
                &parent_path,
            )?;
        }
    }

    Ok(())
}

/// Generate manuals from the same canonical Markdown used by the website.
#[context("Generating manpages")]
pub fn generate_man_pages(sh: &Shell) -> Result<()> {
    // Load the source snapshot after CLI options have been synchronized.
    sync_all_man_pages(sh)?;
    generate_pages(sh, false)
}

/// Get version from Cargo.toml
#[context("Querying package version")]
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
            format!("bootc-{}.8.md", command_parts[0])
        } else {
            format!("bootc-{}.8.md", command_parts.join("-"))
        };

        let filepath = format!("docs/src/man/{}", filename);

        if !std::path::Path::new(&filepath).exists() {
            // Find the command in CLI structure
            let command_parts_refs: Vec<&str> = command_parts.iter().map(|s| s.as_str()).collect();
            let target_cmd = find_subcommand(&cli_structure, &command_parts_refs);

            if let Some(cmd) = target_cmd {
                let command_name_full = format!("bootc {}", command_parts.join(" "));
                let command_description = cmd.about.as_deref().unwrap_or("TODO: Add description");

                // Generate SYNOPSIS line with proper arguments
                let mut synopsis = format!("**{}** \\[*OPTIONS...*\\]", command_name_full);

                // Add positional arguments
                for positional in &cmd.positionals {
                    if positional.required {
                        synopsis.push_str(&format!(" <*{}*>", positional.name.to_uppercase()));
                    } else {
                        synopsis.push_str(&format!(" \\[*{}*\\]", positional.name.to_uppercase()));
                    }
                }

                // Add subcommand if this command has subcommands
                if !cmd.subcommands.is_empty() {
                    synopsis.push_str(" <*SUBCOMMAND*>");
                }

                let template = format!(
                    r#"# NAME

{} - {}

# SYNOPSIS

{}

# DESCRIPTION

{}

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

                println!("Created man page template: {}", filepath);
                created_count += 1;
            }
        }
    }

    if created_count > 0 {
        println!("Created {} new man page templates", created_count);
    } else {
        println!("All commands already have man pages");
    }

    println!("Syncing OPTIONS sections...");
    sync_all_man_pages(sh)?;

    println!("Man pages updated.");
    println!("");
    println!("Next steps for new templates:");
    println!("   - Edit the templates to add detailed descriptions and examples");
    println!("   - Run 'cargo xtask manpages' to generate final man pages");

    Ok(())
}

/// Check that all man page markdown files are up to date.
/// Fails with an error if any file would change, similar to `cargo fmt --check`.
#[context("Checking man pages")]
pub fn check_manpages(sh: &Shell) -> Result<()> {
    check_docs()?;
    let cli_structure = extract_cli_json(sh)?;

    // First: check no man pages are missing
    fn collect_commands(cmd: &CliCommand, path: Vec<String>, acc: &mut Vec<Vec<String>>) {
        for sub in &cmd.subcommands {
            let mut sub_path = path.clone();
            sub_path.push(sub.name.clone());
            acc.push(sub_path.clone());
            collect_commands(sub, sub_path, acc);
        }
    }
    let mut commands_to_check = Vec::new();
    collect_commands(&cli_structure, Vec::new(), &mut commands_to_check);
    for command_parts in &commands_to_check {
        let filename = format!("bootc-{}.8.md", command_parts.join("-"));
        let filepath = Utf8Path::new("docs/src/man").join(&filename);
        if !filepath.exists() {
            return out_of_sync_error(&format!("{filepath} is missing"));
        }
    }

    let mappings = discover_man_page_mappings(&cli_structure)?;

    for (filename, subcommand_path) in mappings {
        let markdown_path = Utf8Path::new("docs/src/man").join(&filename);
        if !markdown_path.exists() {
            continue;
        }

        let target_cmd = if let Some(ref path) = subcommand_path {
            let path_refs: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
            find_subcommand(&cli_structure, &path_refs)
                .ok_or_else(|| anyhow::anyhow!("Subcommand {:?} not found", path))?
        } else {
            &cli_structure
        };

        let content = fs::read_to_string(&markdown_path)
            .with_context(|| format!("Reading {}", markdown_path))?;

        if content.contains("<!-- BEGIN GENERATED OPTIONS -->") {
            check_markdown_options(
                &markdown_path,
                &content,
                &target_cmd.options,
                &target_cmd.positionals,
            )?;
        }
        if content.contains("<!-- BEGIN GENERATED SUBCOMMANDS -->") {
            let parent_path: Vec<&str> = if let Some(path) = &subcommand_path {
                path.iter().map(|s| s.as_str()).collect()
            } else {
                vec![]
            };
            check_markdown_subcommands(
                &markdown_path,
                &content,
                &target_cmd.subcommands,
                &parent_path,
            )?;
        }
    }

    Ok(())
}

/// Compare-only variant of `update_markdown_with_options`.
fn check_markdown_options(
    markdown_path: &Utf8Path,
    content: &str,
    options: &[CliOption],
    positionals: &[CliPositional],
) -> Result<()> {
    let Some(new_content) =
        compute_markdown_with_options(markdown_path, content, options, positionals)?
    else {
        return Ok(());
    };
    if new_content != content {
        return out_of_sync_error(&format!("{markdown_path} is out of date"));
    }
    Ok(())
}

/// Compare-only variant of `update_markdown_with_subcommands`.
fn check_markdown_subcommands(
    markdown_path: &Utf8Path,
    content: &str,
    subcommands: &[CliCommand],
    parent_path: &[&str],
) -> Result<()> {
    let Some(new_content) =
        compute_markdown_with_subcommands(markdown_path, content, subcommands, parent_path)?
    else {
        return Ok(());
    };
    if new_content != content {
        return out_of_sync_error(&format!("{markdown_path} is out of date"));
    }
    Ok(())
}

/// Apply post-processing fixes to generated man pages
#[context("Fixing man pages")]
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
            // Check if the file already has the fix applied
            let content = fs::read_to_string(&path).with_context(|| format!("Reading {path:?}"))?;
            if content.starts_with(".ds Aq \\(aq\n") {
                // Already fixed, skip
                continue;
            }

            // Apply the same sed fixes as before
            let groffsub = r"1i .ds Aq \\(aq";
            let dropif = r"/\.g \.ds Aq/d";
            let dropelse = r"/.el .ds Aq '/d";
            cmd!(sh, "sed -i -e {groffsub} -e {dropif} -e {dropelse} {path}").run()?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod rendering_tests {
    use super::*;

    #[test]
    fn leading_apostrophe_is_text_not_a_roff_request() {
        let input = ".TH BOOTC 8\nDon't change normal prose.\n'wheel' in /etc/group\\fR).\n";
        let expected = ".TH BOOTC 8\nDon't change normal prose.\n\\&'wheel' in /etc/group\\fR).\n";
        assert_eq!(escape_roff_apostrophes(input), expected);
        assert_eq!(escape_roff_apostrophes(expected), expected);
    }

    #[test]
    fn reference_title_and_version_do_not_change_prose() {
        let input = "# NAME\n\nbootc - Don't lose apostrophes or `code`\n\n# VERSION\n\n<!-- VERSION PLACEHOLDER -->\n";
        for (name, section) in [("bootc", 8), ("bootc-config", 5)] {
            let rendered = reference_markdown(input, name, section, "v-test");
            assert_eq!(
                rendered,
                format!(
                    "# {} {section}\n\n{}",
                    name.to_ascii_uppercase(),
                    input.replace("<!-- VERSION PLACEHOLDER -->", "v-test")
                )
            );
            assert!(reference_markdown(input, name, section, "v-next").contains("v-next"));
        }
    }

    #[test]
    fn boolean_options_do_not_gain_values() {
        let options = [CliOption {
            long: "apply".into(),
            short: None,
            value_name: None,
            default: None,
            help: "Don't delay".into(),
            possible_values: vec!["true".into(), "false".into()],
            required: false,
            is_boolean: true,
        }];
        assert_eq!(
            format_options_as_markdown(&options, &[]),
            "**--apply**\n\n    Don't delay\n\n"
        );
    }
}

#[cfg(test)]
mod documentation_tests {
    use super::*;

    fn sources() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("SUMMARY.md".into(), "# Guides\n\n- [Introduction](bootc-overview.7.md)\n\n# Commands\n\n- [bootc](man/bootc.8.md)\n".into()),
            ("bootc-overview.7.md".into(), "# Introduction\n\nA guide with **formatting**.\n".into()),
            ("man/bootc.8.md".into(), "# NAME\n\nbootc - Bootable containers\n".into()),
        ])
    }

    #[test]
    fn coverage_and_order() {
        let inventory = Inventory::from_sources(sources()).unwrap();
        assert_eq!(
            inventory
                .pages
                .iter()
                .map(Page::filename)
                .collect::<Vec<_>>(),
            ["bootc-overview.7", "bootc.8"]
        );
        assert_eq!(inventory.pages[0].group, "Guides");
        assert_eq!(inventory.pages[1].group, "Commands");
    }

    #[test]
    fn coverage_rejects_omissions_duplicates_and_empty_pages() {
        for (path, content, error) in [
            (
                "unlisted.md",
                "# Missing\n\nContent\n",
                "missing from SUMMARY",
            ),
            ("bootc-overview.7.md", "# Empty\n", "Invalid chapter"),
            ("SUMMARY.md", "- [Missing](missing.md)\n", "Missing chapter"),
            (
                "SUMMARY.md",
                "- [Intro](bootc-overview.7.md)\n- [Again](bootc-overview.7.md)\n",
                "Duplicate navigation",
            ),
            (
                "SUMMARY.md",
                "- [Intro](bootc-overview.7.md)\n",
                "missing from SUMMARY",
            ),
        ] {
            let mut sources = sources();
            sources.insert(path.into(), content.into());
            let result = Inventory::from_sources(sources);
            let message = result.err().unwrap().to_string();
            assert!(message.contains(error), "{path}: {message}");
        }
    }

    #[test]
    fn filenames_identify_manuals_in_any_directory() {
        for (source, expected) in [
            ("building/bootc-images.7.md", "bootc-images.7"),
            ("man/bootc-guide.7.md", "bootc-guide.7"),
            ("configuration/bootc-config.5.md", "bootc-config.5"),
            ("man/bootc-example.service.5.md", "bootc-example.service.5"),
            (
                "man/system-reinstall-bootc.8.md",
                "system-reinstall-bootc.8",
            ),
            ("commands/bootc-example.8.md", "bootc-example.8"),
        ] {
            let mut sources = sources();
            sources.remove("bootc-overview.7.md");
            sources.insert(source.into(), "# Example\n\nContent\n".into());
            let summary = sources.get_mut("SUMMARY.md").unwrap();
            *summary = summary.replace("bootc-overview.7.md", source);
            let inventory = Inventory::from_sources(sources).unwrap();
            assert_eq!(inventory.pages[0].filename(), expected, "{source}");
        }
    }

    #[test]
    fn filenames_reject_invalid_and_colliding_manuals() {
        for (source, error) in [
            ("intro.md", "Expected <manual-name>.<section>.md"),
            ("bootc-intro.1.md", "Manuals must use section 5, 7 or 8"),
            ("bootc-intro.07.md", "Manuals must use section 5, 7 or 8"),
            ("bootc-intro.x.md", "Manuals must use section 5, 7 or 8"),
            ("other.7.md", "Manual name must be safe"),
            ("bootc-Bad.7.md", "Manual name must be safe"),
            ("bootc-bad name.7.md", "Manual name must be safe"),
            (
                "system-bootc.7.md",
                "Guide manual names must start with bootc-",
            ),
            ("bootc-docs.7.md", "Duplicate manual output"),
            ("nested/bootc-overview.7.md", "Duplicate manual output"),
        ] {
            let mut sources = sources();
            sources.insert(source.into(), "# Additional\n\nContent\n".into());
            sources
                .get_mut("SUMMARY.md")
                .unwrap()
                .push_str(&format!("- [Additional](<{source}>)\n"));
            let message = Inventory::from_sources(sources).err().unwrap().to_string();
            assert!(message.contains(error), "{source}: {message}");
        }
    }

    #[test]
    fn placeholder_is_exempt_only_while_empty() {
        let mut sources = sources();
        sources.insert("related.md".into(), "# Related projects\n".into());
        assert!(Inventory::from_sources(sources.clone()).is_ok());
        sources
            .get_mut("related.md")
            .unwrap()
            .push_str("\nNow it has content.\n");
        assert!(Inventory::from_sources(sources).is_err());
    }

    #[test]
    fn parsed_links_preserve_formatting_and_code() {
        let inventory = Inventory::from_sources(sources()).unwrap();
        for (input, expected) in [
            (
                "[guide](../bootc-overview.7.md#details)",
                "guide (see **bootc-overview**(7))",
            ),
            (
                "[**guide**\nlabel](../bootc-overview.7.md)",
                "**guide**\nlabel (see **bootc-overview**(7))",
            ),
            (
                "[guide][g]\n\n[g]: ../bootc-overview.7.md\n",
                "guide (see **bootc-overview**(7))\n\n[g]: ../bootc-overview.7.md\n",
            ),
            ("[`bootc`](bootc.8.md)", "`bootc` (see **bootc**(8))"),
            ("[local](#details)", "local"),
            (
                "[web](https://example.com/a(b))",
                "[web](https://example.com/a(b))",
            ),
            (
                "[email](mailto:bootc@example.com)",
                "[email](mailto:bootc@example.com)",
            ),
            (
                "[api](../internals/api.html#section)",
                "[api](https://bootc.dev/bootc/internals/api.html#section)",
            ),
            ("`[code](../missing.md)`", "`[code](../missing.md)`"),
            (
                "~~~~md\n[code](../missing.md)\n~~~~\n",
                "~~~~md\n[code](../missing.md)\n~~~~\n",
            ),
        ] {
            let (actual, _) = inventory.rewrite_links(input, "man/bootc.8.md").unwrap();
            assert_eq!(actual, expected, "{input}");
        }
        let (_, refs) = inventory
            .rewrite_links("[guide](../bootc-overview.7.md)", "man/bootc.8.md")
            .unwrap();
        assert_eq!(refs, BTreeSet::from(["**bootc-overview**(7)".into()]));
    }

    #[test]
    fn missing_or_escaping_doc_links_fail() {
        let inventory = Inventory::from_sources(sources()).unwrap();
        for link in ["[bad](missing.md)", "[bad](../../bootc-overview.7.md)"] {
            assert!(
                inventory
                    .rewrite_links(link, "bootc-overview.7.md")
                    .is_err()
            );
        }
    }

    #[test]
    fn title_keeps_body_and_subheadings() {
        let (title, body) = title_and_body("# A guide\n\nContent.\n\n## Subtopic\n").unwrap();
        assert_eq!(title, "A guide");
        assert_eq!(body, "Content.\n\n## Subtopic\n");
    }

    #[test]
    fn reference_index_keeps_wrapped_name_paragraphs() {
        assert_eq!(
            reference_description(
                "\nbootc-install - Install to an externally\ncreated filesystem\n\n# OPTIONS\n"
            ),
            "Install to an externally created filesystem"
        );
        assert_eq!(
            reference_description("bootc-config.toml\n\n# DESCRIPTION\n"),
            "bootc-config.toml"
        );
    }

    #[test]
    fn stale_guides_removed_without_touching_references() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        for name in ["bootc-current.7", "bootc-stale.7", "bootc.8", "other.7"] {
            fs::write(dir.join(name), "test").unwrap();
        }
        prune_stale_guides(dir, &BTreeSet::from(["bootc-current.7".into()])).unwrap();
        assert!(dir.join("bootc-current.7").exists());
        assert!(!dir.join("bootc-stale.7").exists());
        assert!(dir.join("bootc.8").exists());
        assert!(dir.join("other.7").exists());
    }
}
