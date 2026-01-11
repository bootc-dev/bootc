//! Helpers for [password file](https://man7.org/linux/man-pages/man5/passwd.5.html).
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{Context, Result, anyhow};
use cap_std_ext::{cap_std::fs::Dir, dirext::CapStdExtDirExt};
use std::io::{BufRead, BufReader, Write};

// Entry from passwd file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PasswdEntry {
    pub(crate) name: String,
    pub(crate) passwd: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) gecos: String,
    pub(crate) home_dir: String,
    pub(crate) shell: String,
}

impl PasswdEntry {
    /// Parse a single passwd entry.
    pub fn parse_line(s: impl AsRef<str>) -> Option<Self> {
        let mut parts = s.as_ref().splitn(7, ':');
        let entry = Self {
            name: parts.next()?.to_string(),
            passwd: parts.next()?.to_string(),
            uid: parts.next().and_then(|s| s.parse().ok())?,
            gid: parts.next().and_then(|s| s.parse().ok())?,
            gecos: parts.next()?.to_string(),
            home_dir: parts.next()?.to_string(),
            shell: parts.next()?.to_string(),
        };
        Some(entry)
    }

    /// Serialize entry to writer, as a passwd line.
    pub fn to_writer(&self, writer: &mut impl Write) -> Result<()> {
        std::writeln!(
            writer,
            "{}:{}:{}:{}:{}:{}:{}",
            self.name,
            self.passwd,
            self.uid,
            self.gid,
            self.gecos,
            self.home_dir,
            self.shell
        )
        .with_context(|| "failed to write passwd entry")
    }
}

pub(crate) fn parse_passwd_content(content: impl BufRead) -> Result<Vec<PasswdEntry>> {
    let mut passwds = vec![];
    for (line_num, line) in content.lines().enumerate() {
        let input =
            line.with_context(|| format!("failed to read passwd entry at line {line_num}"))?;

        // Skip empty and comment lines
        if input.is_empty() || input.starts_with('#') {
            continue;
        }
        // Skip NSS compat lines, see "Compatibility mode" in
        // https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html
        if input.starts_with('+') || input.starts_with('-') {
            continue;
        }

        let entry = PasswdEntry::parse_line(&input).ok_or_else(|| {
            anyhow!(
                "failed to parse passwd entry at line {}, content: {}",
                line_num,
                &input
            )
        })?;
        passwds.push(entry);
    }
    Ok(passwds)
}

pub(crate) fn load_etc_passwd(rootfs: &Dir) -> Result<Option<Vec<PasswdEntry>>> {
    if let Some(r) = rootfs.open_optional("etc/passwd")? {
        parse_passwd_content(BufReader::new(r)).map(Some)
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn mock_passwd_entry() -> PasswdEntry {
        PasswdEntry {
            name: "someuser".to_string(),
            passwd: "x".to_string(),
            uid: 1000,
            gid: 1000,
            gecos: "Foo BAR,,,".to_string(),
            home_dir: "/home/foobar".to_string(),
            shell: "/bin/bash".to_string(),
        }
    }

    #[test]
    fn test_parse_lines() {
        let content = r#"
root:x:0:0:root:/root:/bin/bash

+userA
-userB

daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
systemd-coredump:x:1:1:systemd Core Dumper:/:/usr/sbin/nologin

+@groupA
-@groupB

# Dummy comment
someuser:x:1000:1000:Foo BAR,,,:/home/foobar:/bin/bash

+
"#;

        let input = Cursor::new(content);
        let groups = parse_passwd_content(input).unwrap();
        assert_eq!(groups.len(), 4);
        assert_eq!(groups[3], mock_passwd_entry());
    }

    #[test]
    fn test_write_entry() {
        let entry = mock_passwd_entry();
        let expected = b"someuser:x:1000:1000:Foo BAR,,,:/home/foobar:/bin/bash\n";
        let mut buf = Vec::new();
        entry.to_writer(&mut buf).unwrap();
        assert_eq!(&buf, expected);
    }
}
