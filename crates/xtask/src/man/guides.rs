//! Publish canonical mdBook chapters as manuals, without generating website copies.

use anyhow::{Context, Result, ensure};
use camino::{Utf8Path, Utf8PathBuf};
use pulldown_cmark::{Event, Parser, Tag, TagEnd};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

const DOCS_SRC: &str = "docs/src";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    guides: BTreeMap<String, String>,
}

pub(super) struct Page {
    pub name: String,
    pub section: u8,
}

impl Page {
    pub fn filename(&self) -> String {
        format!("{}.{}", self.name, self.section)
    }
}

pub(super) struct Inventory {
    pub pages: Vec<Page>,
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
        for (_group, source) in chapters(&summary) {
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
            let page = Page { name, section };
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
        Ok(Self { pages })
    }
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
    fn title_keeps_body_and_subheadings() {
        let (title, body) = title_and_body("# A guide\n\nContent.\n\n## Subtopic\n").unwrap();
        assert_eq!(title, "A guide");
        assert_eq!(body, "Content.\n\n## Subtopic\n");
    }
}
