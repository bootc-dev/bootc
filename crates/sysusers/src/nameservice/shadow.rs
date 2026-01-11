//! Helpers for [shadowed password file](https://man7.org/linux/man-pages/man5/shadow.5.html).
// Copyright (C) 2021 Oracle and/or its affiliates.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{Context, Result, anyhow};
use std::io::{BufRead, Write};

/// Entry from shadow file.
// Field names taken from (presumably glibc's) /usr/include/shadow.h, descriptions adapted
// from the [shadow(3) manual page](https://man7.org/linux/man-pages/man3/shadow.3.html).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShadowEntry {
    /// user login name
    pub(crate) namp: String,
    /// encrypted password
    pub(crate) pwdp: String,
    /// days (from Jan 1, 1970) since password was last changed
    pub(crate) lstchg: Option<u32>,
    /// days before which password may not be changed
    pub(crate) min: Option<u32>,
    /// days after which password must be changed
    pub(crate) max: Option<u32>,
    /// days before password is to expire that user is warned of pending password expiration
    pub(crate) warn: Option<u32>,
    /// days after password expires that account is considered inactive and disabled
    pub(crate) inact: Option<u32>,
    /// date (in days since Jan 1, 1970) when account will be disabled
    pub(crate) expire: Option<u32>,
    /// reserved for future use
    pub(crate) flag: String,
}

fn u32_or_none(value: &str) -> Result<Option<u32>, std::num::ParseIntError> {
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.parse()?))
    }
}

fn number_or_empty(value: Option<u32>) -> String {
    if let Some(number) = value {
        format!("{number}")
    } else {
        "".to_string()
    }
}

impl ShadowEntry {
    /// Parse a single shadow entry.
    pub fn parse_line(s: impl AsRef<str>) -> Option<Self> {
        let mut parts = s.as_ref().splitn(9, ':');

        let entry = Self {
            namp: parts.next()?.to_string(),
            pwdp: parts.next()?.to_string(),
            lstchg: u32_or_none(parts.next()?).ok()?,
            min: u32_or_none(parts.next()?).ok()?,
            max: u32_or_none(parts.next()?).ok()?,
            warn: u32_or_none(parts.next()?).ok()?,
            inact: u32_or_none(parts.next()?).ok()?,
            expire: u32_or_none(parts.next()?).ok()?,
            flag: parts.next()?.to_string(),
        };
        Some(entry)
    }

    /// Serialize entry to writer, as a shadow line.
    pub fn to_writer(&self, writer: &mut impl Write) -> Result<()> {
        std::writeln!(
            writer,
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.namp,
            self.pwdp,
            number_or_empty(self.lstchg),
            number_or_empty(self.min),
            number_or_empty(self.max),
            number_or_empty(self.warn),
            number_or_empty(self.inact),
            number_or_empty(self.expire),
            self.flag
        )
        .with_context(|| "failed to write shadow entry")
    }
}

pub(crate) fn parse_shadow_content(content: impl BufRead) -> Result<Vec<ShadowEntry>> {
    let mut entries = vec![];
    for (line_num, line) in content.lines().enumerate() {
        let input =
            line.with_context(|| format!("failed to read shadow entry at line {line_num}"))?;

        // Skip empty and comment lines
        if input.is_empty() || input.starts_with('#') {
            continue;
        }

        let entry = ShadowEntry::parse_line(&input).ok_or_else(|| {
            anyhow!(
                "failed to parse shadow entry at line {}, content: {}",
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

    fn salted() -> String {
        // Hex encoded hashed password to avoid tripping leak detectors
        let obfuscated = "24362473616c7453616c7453414c544e61436c247865354c5a47466c656b35334350467765327069495065536947414e6f596f696e5544755157307179645879766f594b566d4c3257524c71445a48586b626e706f4148714c3079616c6939344e526355527445616f51";
        String::from_utf8(hex::decode(obfuscated).unwrap()).unwrap()
    }

    fn mock_shadow_entry() -> ShadowEntry {
        ShadowEntry {
            namp: "salty".to_string(),
            pwdp: salted(),
            lstchg: Some(18912),
            min: Some(0),
            max: Some(99999),
            warn: Some(7),
            inact: None,
            expire: None,
            flag: "".to_string(),
        }
    }

    #[test]
    fn test_parse_lines() {
        let salted = salted();
        let content = format!(
            r#"
root:*:18912:0:99999:7:::
daemon:*:18474:0:99999:7:::

salty:{salted}:18912:0:99999:7:::

# Dummy comment
systemd-coredump:!!:::::::
systemd-resolve:!!:::::::
rngd:!!:::::::
"#
        );

        let input = Cursor::new(content);
        let entries = parse_shadow_content(input).unwrap();
        assert_eq!(entries.len(), 6);
        assert_eq!(entries[2], mock_shadow_entry());
    }

    #[test]
    fn test_write_entry() {
        let entry = mock_shadow_entry();
        let expected = format!("salty:{}:18912:0:99999:7:::\n", salted());
        let mut buf = Vec::new();
        entry.to_writer(&mut buf).unwrap();
        assert_eq!(&buf, expected.as_bytes());
    }
}
