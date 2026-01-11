//! Helpers for [user passwd file](https://man7.org/linux/man-pages/man5/passwd.5.html).
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{Context, Result, anyhow};
use cap_std_ext::cap_std::fs::Dir;
use std::io::{BufRead, BufReader, Write};

// Entry from group file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupEntry {
    pub(crate) name: String,
    pub(crate) passwd: String,
    pub(crate) gid: u32,
    pub(crate) users: Vec<String>,
}

impl GroupEntry {
    /// Parse a single group entry.
    pub fn parse_line(s: impl AsRef<str>) -> Option<Self> {
        let mut parts = s.as_ref().splitn(4, ':');
        let entry = Self {
            name: parts.next()?.to_string(),
            passwd: parts.next()?.to_string(),
            gid: parts.next().and_then(|s| s.parse().ok())?,
            users: {
                let users = parts.next()?;
                users.split(',').map(String::from).collect()
            },
        };
        Some(entry)
    }

    /// Serialize entry to writer, as a group line.
    pub fn to_writer(&self, writer: &mut impl Write) -> Result<()> {
        let users: String = self.users.join(",");
        std::writeln!(
            writer,
            "{}:{}:{}:{}",
            self.name,
            self.passwd,
            self.gid,
            users,
        )
        .with_context(|| "failed to write passwd entry")
    }
}

pub(crate) fn parse_group_content(content: impl BufRead) -> Result<Vec<GroupEntry>> {
    let mut groups = vec![];
    for (line_num, line) in content.lines().enumerate() {
        let input =
            line.with_context(|| format!("failed to read group entry at line {line_num}"))?;

        // Skip empty and comment lines
        if input.is_empty() || input.starts_with('#') {
            continue;
        }
        // Skip NSS compat lines, see "Compatibility mode" in
        // https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html
        if input.starts_with('+') || input.starts_with('-') {
            continue;
        }

        let entry = GroupEntry::parse_line(&input).ok_or_else(|| {
            anyhow!(
                "failed to parse group entry at line {}, content: {}",
                line_num,
                &input
            )
        })?;
        groups.push(entry);
    }
    Ok(groups)
}

pub(crate) fn load_etc_group(rootfs: &Dir) -> Result<Vec<GroupEntry>> {
    let r = rootfs.open("etc/group").map(BufReader::new)?;
    parse_group_content(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn mock_group_entry() -> GroupEntry {
        GroupEntry {
            name: "staff".to_string(),
            passwd: "x".to_string(),
            gid: 50,
            users: vec!["operator".to_string()],
        }
    }

    #[test]
    fn test_parse_lines() {
        let content = r#"
+groupA
-groupB

root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:
www-data:x:33:
backup:x:34:
operator:x:37:

# Dummy comment
staff:x:50:operator

+
"#;

        let input = Cursor::new(content);
        let groups = parse_group_content(input).unwrap();
        assert_eq!(groups.len(), 9);
        assert_eq!(groups[8], mock_group_entry());
    }

    #[test]
    fn test_write_entry() {
        let entry = mock_group_entry();
        let expected = b"staff:x:50:operator\n";
        let mut buf = Vec::new();
        entry.to_writer(&mut buf).unwrap();
        assert_eq!(&buf, expected);
    }
}
