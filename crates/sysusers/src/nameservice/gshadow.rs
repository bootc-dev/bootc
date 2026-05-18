//! Helpers for [GShadow file](https://man7.org/linux/man-pages/man5/gshadow.5.html).
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{Context, Result, anyhow};
use std::io::{BufRead, Write};

/// Entry from gshadow file.
/// Format: name:password:admins:members
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GshadowEntry {
    /// group name
    pub name: String,
    /// encrypted password (or ! or empty)
    pub password: String,
    /// comma-separated list of group administrators
    pub admins: String,
    /// comma-separated list of group members
    pub members: String,
}

impl GshadowEntry {
    /// Parse a single gshadow entry.
    pub fn parse_line(s: impl AsRef<str>) -> Option<Self> {
        let mut parts = s.as_ref().splitn(4, ':');
        let entry = Self {
            name: parts.next()?.to_string(),
            password: parts.next()?.to_string(),
            admins: parts.next()?.to_string(),
            members: parts.next()?.to_string(),
        };
        Some(entry)
    }

    /// Serialize entry to writer, as a gshadow line.
    pub fn to_writer(&self, writer: &mut impl Write) -> Result<()> {
        std::writeln!(
            writer,
            "{}:{}:{}:{}",
            self.name,
            self.password,
            self.admins,
            self.members,
        )
        .with_context(|| "failed to write gshadow entry")
    }
}

pub fn parse_gshadow_content(content: impl BufRead) -> Result<Vec<GshadowEntry>> {
    let mut entries = vec![];
    for (line_num, line) in content.lines().enumerate() {
        let input =
            line.with_context(|| format!("failed to read gshadow entry at line {line_num}"))?;

        // Skip empty and comment lines
        if input.is_empty() || input.starts_with('#') {
            continue;
        }

        let entry = GshadowEntry::parse_line(&input).ok_or_else(|| {
            anyhow!(
                "failed to parse gshadow entry at line {}, content: {}",
                line_num,
                &input
            )
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn mock_gshadow_entry() -> GshadowEntry {
        GshadowEntry {
            name: "wheel".to_string(),
            password: "!".to_string(),
            admins: "admin1".to_string(),
            members: "user1,user2".to_string(),
        }
    }

    #[test]
    fn test_parse_lines() {
        let content = r#"
root:*::
daemon:*::

# Dummy comment
wheel:!:admin1:user1,user2
plocate:!::
"#;
        let input = Cursor::new(content);
        let entries = parse_gshadow_content(input).unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[2], mock_gshadow_entry());
    }

    #[test]
    fn test_write_entry() {
        let entry = mock_gshadow_entry();
        let expected = b"wheel:!:admin1:user1,user2\n";
        let mut buf = Vec::new();
        entry.to_writer(&mut buf).unwrap();
        assert_eq!(&buf, expected);
    }

    #[test]
    fn test_duplicate_detection() {
        let content = "plocate:!::\nplocate:!::\nwheel:!::\n";
        let input = Cursor::new(content);
        let entries = parse_gshadow_content(input).unwrap();
        assert_eq!(entries.len(), 3);
        // Verify we can detect duplicates
        let mut seen = std::collections::HashSet::new();
        let has_dups = entries.iter().any(|e| !seen.insert(&e.name));
        assert!(has_dups);
    }
}
