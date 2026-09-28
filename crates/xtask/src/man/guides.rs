//! Publish canonical mdBook chapters as manuals, without generating website copies.

use anyhow::{Context, Result, ensure};
use camino::{Utf8Path, Utf8PathBuf};
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    ops::Range,
};
use xshell::Shell;

const DOCS_SRC: &str = "docs/src";
const BOOK_URL: &str = "https://bootc.dev/bootc/";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    guides: BTreeMap<String, String>,
}

pub(super) struct Page {
    pub source: String,
    pub name: String,
    pub section: u8,
    group: String,
}

impl Page {
    pub fn filename(&self) -> String {
        format!("{}.{}", self.name, self.section)
    }

    fn reference(&self) -> String {
        format!("**{}**({})", self.name, self.section)
    }
}

pub(super) struct Inventory {
    pub pages: Vec<Page>,
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
    pub fn load() -> Result<Self> {
        let manifest = fs::read_to_string("docs/manpages.toml")?;
        let root = Utf8Path::new(DOCS_SRC);
        let mut sources = BTreeMap::new();
        sources_in(root, root, &mut sources)?;
        Self::from_sources(&manifest, sources)
    }

    fn from_sources(manifest: &str, mut sources: BTreeMap<String, String>) -> Result<Self> {
        let manifest: Manifest = toml::from_str(manifest).context("Parsing docs/manpages.toml")?;
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
        let mut mapped = BTreeSet::new();
        for (group, source) in chapters(&summary) {
            ensure!(
                seen.insert(source.clone()),
                "Duplicate navigation entry: {source}"
            );
            let content = sources
                .get(&source)
                .with_context(|| format!("Missing chapter: {source}"))?;
            title_and_body(content).with_context(|| format!("Invalid chapter: {source}"))?;
            let (name, section) = if let Some(native) = source.strip_prefix("man/") {
                let (name, section) = native
                    .strip_suffix(".md")
                    .and_then(|s| s.rsplit_once('.'))
                    .context("Invalid native manual filename")?;
                let section: u8 = section.parse()?;
                ensure!(
                    name.contains("bootc")
                        && name.chars().all(|c| c.is_ascii_lowercase()
                            || c.is_ascii_digit()
                            || matches!(c, '-' | '.')),
                    "Manual name must be safe and match the RPM bootc file pattern: {source}"
                );
                ensure!(
                    matches!(section, 5 | 8),
                    "Native manuals must use section 5 or 8: {source}"
                );
                (name.to_string(), section)
            } else {
                let name = manifest
                    .guides
                    .get(&source)
                    .with_context(|| format!("Missing man page mapping: {source}"))?;
                ensure!(
                    name.starts_with("bootc-")
                        && name
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                    "Invalid guide manual name: {name}"
                );
                mapped.insert(source.clone());
                (name.clone(), 7)
            };
            let page = Page {
                source,
                name,
                section,
                group,
            };
            ensure!(
                outputs.insert(page.filename()),
                "Duplicate manual output: {}",
                page.filename()
            );
            pages.push(page);
        }
        let missing: Vec<_> = sources.keys().filter(|p| !seen.contains(*p)).collect();
        ensure!(
            missing.is_empty(),
            "Chapters missing from SUMMARY.md: {missing:?}"
        );
        let extra: Vec<_> = manifest
            .guides
            .keys()
            .filter(|p| !mapped.contains(*p))
            .collect();
        ensure!(extra.is_empty(), "Unused guide mappings: {extra:?}");
        let names = pages
            .iter()
            .map(|p| (p.source.clone(), p.reference()))
            .collect();
        let result = Self { pages, names };
        // Validate all internal Markdown links and terminal-only transformations
        // even in website-only builds; mdBook otherwise tolerates missing pages.
        for page in &result.pages {
            let content = &sources[&page.source];
            result.rewrite_links(content, &page.source)?;
            if page.section == 7 {
                adapt_guide_markdown_for_man(content)?;
            }
        }
        Ok(result)
    }

    /// Change only link spans, not the surrounding Markdown. A Markdown parser
    /// handles multiline/reference links and avoids links in inline/fenced code.
    pub fn rewrite_links(&self, body: &str, source: &str) -> Result<(String, BTreeSet<String>)> {
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

    pub fn generate_guides(&self, sh: &Shell, output: &Utf8Path, version: &str) -> Result<()> {
        let expected = self
            .pages
            .iter()
            .filter(|p| p.section == 7)
            .map(Page::filename)
            .chain(["bootc-docs.7".to_string()])
            .collect();
        prune_stale_guides(output, &expected)?;
        let mut index = String::from(
            "# BOOTC-DOCS 7\n\n## NAME\n\nbootc-docs - Guide to bootc documentation\n\n## DESCRIPTION\n\nThe documentation shipped with bootc: guides in section 7, commands in section 8, and configuration and services in section 5. The groups below follow the website navigation.\n",
        );
        let mut group = "";
        for page in &self.pages {
            let content = fs::read_to_string(Utf8Path::new(DOCS_SRC).join(&page.source))?;
            let (title, body) = title_and_body(&content)?;
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
            if page.section != 7 {
                continue;
            }
            let adapted = adapt_guide_markdown_for_man(body)?;
            let (body, mut references) = self.rewrite_links(&adapted, &page.source)?;
            references.extend(["**bootc**(8)".to_string(), "**bootc-docs**(7)".to_string()]);
            let markdown = format!(
                "# {} 7\n\n## NAME\n\n{} - {title}\n\n## DESCRIPTION\n\n{body}\n\n## SEE ALSO\n\n{}\n\n## VERSION\n\n{version}\n",
                page.name.to_ascii_uppercase(),
                page.name,
                references.into_iter().collect::<Vec<_>>().join(", ")
            );
            super::convert_markdown(sh, &markdown, &output.join(page.filename()))?;
        }
        index.push_str(&format!("\n## VERSION\n\n{version}\n"));
        super::convert_markdown(sh, &index, &output.join("bootc-docs.7"))
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

// Use parsed spans so fences inside examples remain examples, and equivalent
// Markdown spellings (tilde fences, aligned tables) receive the same treatment.
fn adapt_guide_markdown_for_man(body: &str) -> Result<String> {
    let mut events = Parser::new_ext(body, Options::ENABLE_TABLES).into_offset_iter();
    let mut replacements = Vec::new();
    while let Some((event, span)) = events.next() {
        match event {
            Event::Start(Tag::CodeBlock(pulldown_cmark::CodeBlockKind::Fenced(info)))
                if info.split_whitespace().next() == Some("mermaid") =>
            {
                let raw = &body[span.clone()];
                let opening = raw.lines().next().context("Missing Mermaid fence")?.trim();
                let marker = opening.chars().next().context("Empty Mermaid fence")?;
                let width = opening.chars().take_while(|c| *c == marker).count();
                let closing = raw.lines().last().unwrap_or("").trim();
                ensure!(
                    closing.chars().count() >= width && closing.chars().all(|c| c == marker),
                    "Unclosed Mermaid code fence"
                );
                let mut diagram = String::new();
                for (event, _) in events.by_ref() {
                    match event {
                        Event::Text(text) => diagram.push_str(&text),
                        Event::End(TagEnd::CodeBlock) => break,
                        _ => (),
                    }
                }
                replacements.push((span, flowchart_as_text(&diagram)?));
            }
            Event::Start(Tag::Table(columns)) => {
                ensure!(
                    columns.len() == 2,
                    "Only two-column guide tables have a terminal representation"
                );
                let mut rows = Vec::new();
                let mut row = Vec::new();
                for (event, cell) in events.by_ref() {
                    match event {
                        Event::Start(Tag::TableCell) => row.push(body[cell].trim().to_string()),
                        Event::End(TagEnd::TableHead | TagEnd::TableRow) => {
                            ensure!(row.len() == 2, "Malformed guide table row");
                            rows.push(std::mem::take(&mut row));
                        }
                        Event::End(TagEnd::Table) => break,
                        _ => (),
                    }
                }
                let headers = rows.first().context("Missing table header")?;
                let mut text = String::new();
                for row in rows.iter().skip(1) {
                    text.push_str(&format!(
                        "- {}: {}; {}: {}\n",
                        headers[0], row[0], headers[1], row[1]
                    ));
                }
                text.push('\n');
                replacements.push((span, text));
            }
            _ => (),
        }
    }
    let mut result = body.to_string();
    for (span, replacement) in replacements.into_iter().rev() {
        result.replace_range(span, &replacement);
    }
    Ok(result)
}

fn flowchart_as_text(diagram: &str) -> Result<String> {
    let mut lines = diagram
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    ensure!(
        lines
            .next()
            .is_some_and(|line| line.starts_with("flowchart ")),
        "Only Mermaid flowcharts have a terminal representation"
    );
    let mut text = String::from("Connected components:\n\n");
    for edge in lines {
        let nodes: Vec<_> = edge
            .split("---")
            .map(|node| {
                let node = node.trim();
                if let Some((_, label)) = node.split_once("[\"") {
                    label.strip_suffix("\"]").map(str::to_string)
                } else if !node.is_empty()
                    && node
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/'))
                {
                    Some(node.to_string())
                } else {
                    None
                }
            })
            .collect::<Option<_>>()
            .context("Unsupported Mermaid node syntax")?;
        ensure!(nodes.len() >= 2, "Unsupported Mermaid edge: {edge}");
        text.push_str(&format!("- {}\n", nodes.join(" — ")));
    }
    text.push('\n');
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = "[guides]\n\"intro.md\" = \"bootc-overview\"\n";

    fn sources() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("SUMMARY.md".into(), "# Guides\n\n- [Introduction](intro.md)\n\n# Commands\n\n- [bootc](man/bootc.8.md)\n".into()),
            ("intro.md".into(), "# Introduction\n\nA guide with **formatting**.\n".into()),
            ("man/bootc.8.md".into(), "# NAME\n\nbootc - Bootable containers\n".into()),
        ])
    }

    #[test]
    fn coverage_and_order() {
        let inventory = Inventory::from_sources(MANIFEST, sources()).unwrap();
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
            ("intro.md", "# Empty\n", "Invalid chapter"),
            ("SUMMARY.md", "- [Missing](missing.md)\n", "Missing chapter"),
            (
                "SUMMARY.md",
                "- [Intro](intro.md)\n- [Again](intro.md)\n",
                "Duplicate navigation",
            ),
            (
                "SUMMARY.md",
                "- [Intro](intro.md)\n",
                "missing from SUMMARY",
            ),
        ] {
            let mut sources = sources();
            sources.insert(path.into(), content.into());
            let result = Inventory::from_sources(MANIFEST, sources);
            let message = result.err().unwrap().to_string();
            assert!(message.contains(error), "{path}: {message}");
        }
    }

    #[test]
    fn manifest_rejects_missing_extra_unsafe_and_reserved_names() {
        for manifest in [
            "[guides]\n",
            "[guides]\n\"intro.md\"=\"bootc-overview\"\n\"missing.md\"=\"bootc-missing\"\n",
            "[guides]\n\"intro.md\"=\"../bad\"\n",
            "[guides]\n\"intro.md\"=\"bootc-docs\"\n",
        ] {
            assert!(
                Inventory::from_sources(manifest, sources()).is_err(),
                "{manifest}"
            );
        }
        let mut sources = sources();
        sources.insert("second.md".into(), "# Second\n\nContent\n".into());
        sources
            .get_mut("SUMMARY.md")
            .unwrap()
            .push_str("- [Second](second.md)\n");
        assert!(
            Inventory::from_sources(
                &format!("{MANIFEST}\"second.md\"=\"bootc-overview\"\n"),
                sources
            )
            .is_err()
        );
    }

    #[test]
    fn placeholder_is_exempt_only_while_empty() {
        let mut sources = sources();
        sources.insert("related.md".into(), "# Related projects\n".into());
        assert!(Inventory::from_sources(MANIFEST, sources.clone()).is_ok());
        sources
            .get_mut("related.md")
            .unwrap()
            .push_str("\nNow it has content.\n");
        assert!(Inventory::from_sources(MANIFEST, sources).is_err());
    }

    #[test]
    fn parsed_links_preserve_formatting_and_code() {
        let inventory = Inventory::from_sources(MANIFEST, sources()).unwrap();
        for (input, expected) in [
            (
                "[guide](../intro.md#details)",
                "guide (see **bootc-overview**(7))",
            ),
            (
                "[**guide**\nlabel](../intro.md)",
                "**guide**\nlabel (see **bootc-overview**(7))",
            ),
            (
                "[guide][g]\n\n[g]: ../intro.md\n",
                "guide (see **bootc-overview**(7))\n\n[g]: ../intro.md\n",
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
            .rewrite_links("[guide](../intro.md)", "man/bootc.8.md")
            .unwrap();
        assert_eq!(refs, BTreeSet::from(["**bootc-overview**(7)".into()]));
    }

    #[test]
    fn missing_or_escaping_doc_links_fail() {
        let inventory = Inventory::from_sources(MANIFEST, sources()).unwrap();
        for link in ["[bad](missing.md)", "[bad](../../intro.md)"] {
            assert!(inventory.rewrite_links(link, "intro.md").is_err());
        }
    }

    #[test]
    fn title_keeps_body_and_subheadings() {
        let (title, body) = title_and_body("# A guide\n\nContent.\n\n## Subtopic\n").unwrap();
        assert_eq!(title, "A guide");
        assert_eq!(body, "Content.\n\n## Subtopic\n");
    }

    #[test]
    fn diagrams_and_tables_have_terminal_text() {
        let input = "```mermaid\nflowchart TD\nbootc --- image[\"containers/storage\"]\n```\n\n| Mode | Method |\n|---|---|\n| `to-disk` | UUID |\n";
        let output = adapt_guide_markdown_for_man(input).unwrap();
        assert!(output.contains("bootc — containers/storage"));
        assert!(output.contains("Mode: `to-disk`; Method: UUID"));
        assert!(!output.contains("```mermaid"));
        assert_eq!(
            adapt_guide_markdown_for_man(&input.replace("```", "~~~~")).unwrap(),
            output
        );
        assert_eq!(
            adapt_guide_markdown_for_man(&input.replace("|---|---|", "| :--- | ---: |")).unwrap(),
            output
        );
        let example = "````markdown\n```mermaid\nnot a real diagram\n```\n````\n";
        assert_eq!(adapt_guide_markdown_for_man(example).unwrap(), example);
        for bad in [
            "```mermaid\nsequenceDiagram\nA->>B: hello\n```\n",
            "```mermaid\nflowchart TD\nA --> B\n```\n",
            "```mermaid\nflowchart TD\nA --- B\n",
        ] {
            assert!(adapt_guide_markdown_for_man(bad).is_err(), "{bad}");
        }
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
