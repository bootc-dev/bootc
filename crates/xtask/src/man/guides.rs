//! Pure adaptations needed only by narrative section-7 manuals.
//! Discovery, validation, indexing and conversion are shared in man.rs.

use anyhow::{Context, Result, ensure};
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
use std::collections::BTreeSet;

/// Wrap narrative text in manual sections without changing the website source.
pub(super) fn markdown(
    name: &str,
    title: &str,
    body: &str,
    mut references: BTreeSet<String>,
    version: &str,
) -> String {
    references.extend(["**bootc**(8)".to_string(), "**bootc-docs**(7)".to_string()]);
    format!(
        "# {} 7\n\n## NAME\n\n{name} - {title}\n\n## DESCRIPTION\n\n{body}\n\n## SEE ALSO\n\n{}\n\n## VERSION\n\n{version}\n",
        name.to_ascii_uppercase(),
        references.into_iter().collect::<Vec<_>>().join(", ")
    )
}

// Use parsed spans so fences inside examples remain examples, and equivalent
// Markdown spellings (tilde fences, aligned tables) receive the same treatment.
pub(super) fn adapt_markdown(body: &str) -> Result<String> {
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

    #[test]
    fn diagrams_and_tables_have_terminal_text() {
        let input = "```mermaid\nflowchart TD\nbootc --- image[\"containers/storage\"]\n```\n\n| Mode | Method |\n|---|---|\n| `to-disk` | UUID |\n";
        let output = adapt_markdown(input).unwrap();
        assert!(output.contains("bootc — containers/storage"));
        assert!(output.contains("Mode: `to-disk`; Method: UUID"));
        assert!(!output.contains("```mermaid"));
        assert_eq!(
            adapt_markdown(&input.replace("```", "~~~~")).unwrap(),
            output
        );
        assert_eq!(
            adapt_markdown(&input.replace("|---|---|", "| :--- | ---: |")).unwrap(),
            output
        );
        let example = "````markdown\n```mermaid\nnot a real diagram\n```\n````\n";
        assert_eq!(adapt_markdown(example).unwrap(), example);
        for bad in [
            "```mermaid\nsequenceDiagram\nA->>B: hello\n```\n",
            "```mermaid\nflowchart TD\nA --> B\n```\n",
            "```mermaid\nflowchart TD\nA --- B\n",
        ] {
            assert!(adapt_markdown(bad).is_err(), "{bad}");
        }
    }
}
