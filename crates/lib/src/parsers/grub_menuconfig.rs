//! Parser for GRUB menuentry configuration files using nom combinators.

#![allow(dead_code)]

use std::fmt::Display;

use anyhow::Result;
use camino::Utf8PathBuf;
use composefs_boot::bootloader::EFI_EXT;
use nom::{
    bytes::complete::{escaped, tag, take_until},
    character::complete::{multispace0, multispace1, none_of},
    error::{Error, ErrorKind, ParseError},
    sequence::delimited,
    Err, IResult, Parser,
};

use crate::bootc_composefs::boot::BOOTC_UKI_DIR;

/// Body content of a GRUB menuentry containing parsed commands.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MenuentryBody<'a> {
    /// Kernel modules to load
    pub(crate) insmod: Vec<&'a str>,
    /// Chainloader path (optional)
    pub(crate) chainloader: String,
    /// Search command (optional)
    pub(crate) search: &'a str,
    /// The version
    pub(crate) version: u8,
    /// Additional commands
    pub(crate) extra: Vec<(&'a str, &'a str)>,
}

impl<'a> Display for MenuentryBody<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for insmod in &self.insmod {
            writeln!(f, "insmod {}", insmod)?;
        }

        writeln!(f, "search {}", self.search)?;
        writeln!(f, "chainloader {}", self.chainloader)?;

        for (k, v) in &self.extra {
            writeln!(f, "{k} {v}")?;
        }

        Ok(())
    }
}

impl<'a> From<Vec<(&'a str, &'a str)>> for MenuentryBody<'a> {
    fn from(vec: Vec<(&'a str, &'a str)>) -> Self {
        let mut entry = Self {
            insmod: vec![],
            chainloader: "".into(),
            search: "",
            version: 0,
            extra: vec![],
        };

        for (key, value) in vec {
            match key {
                "insmod" => entry.insmod.push(value),
                "chainloader" => entry.chainloader = value.into(),
                "search" => entry.search = value,
                "set" => {}
                _ => entry.extra.push((key, value)),
            }
        }

        entry
    }
}

/// A complete GRUB menuentry with title and body commands.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MenuEntry<'a> {
    /// Display title (supports escaped quotes)
    pub(crate) title: String,
    /// Commands within the menuentry block
    pub(crate) body: MenuentryBody<'a>,
}

impl<'a> Display for MenuEntry<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "menuentry \"{}\" {{", self.title)?;
        write!(f, "{}", self.body)?;
        writeln!(f, "}}")
    }
}

impl<'a> MenuEntry<'a> {
    #[allow(dead_code)]
    pub(crate) fn new(boot_label: &str, uki_id: &str) -> Self {
        Self {
            title: format!("{boot_label}: ({uki_id})"),
            body: MenuentryBody {
                insmod: vec!["fat", "chain"],
                chainloader: format!("/{BOOTC_UKI_DIR}/{uki_id}.efi"),
                search: "--no-floppy --set=root --fs-uuid \"${EFI_PART_UUID}\"",
                version: 0,
                extra: vec![],
            },
        }
    }

    pub(crate) fn get_verity(&self) -> Result<String> {
        let to_path = Utf8PathBuf::from(self.body.chainloader.clone());

        Ok(to_path
            .components()
            .last()
            .ok_or(anyhow::anyhow!("Empty efi field"))?
            .to_string()
            .strip_suffix(EFI_EXT)
            .ok_or(anyhow::anyhow!("efi doesn't end with .efi"))?
            .to_string())
    }
}

/// Parser that takes content until balanced brackets, handling nested brackets and escapes.
fn take_until_balanced_allow_nested(
    opening_bracket: char,
    closing_bracket: char,
) -> impl Fn(&str) -> IResult<&str, &str> {
    move |i: &str| {
        let mut index = 0;
        let mut bracket_counter = 0;

        while let Some(n) = &i[index..].find(&[opening_bracket, closing_bracket, '\\'][..]) {
            index += n;
            let mut characters = i[index..].chars();

            match characters.next().unwrap_or_default() {
                c if c == '\\' => {
                    // Skip '\'
                    index += '\\'.len_utf8();
                    // Skip char following '\'
                    let c = characters.next().unwrap_or_default();
                    index += c.len_utf8();
                }

                c if c == opening_bracket => {
                    bracket_counter += 1;
                    index += opening_bracket.len_utf8();
                }

                c if c == closing_bracket => {
                    bracket_counter -= 1;
                    index += closing_bracket.len_utf8();
                }

                // Should not happen
                _ => unreachable!(),
            };

            // We found the unmatched closing bracket.
            if bracket_counter == -1 {
                // Don't consume it as we'll "tag" it afterwards
                index -= closing_bracket.len_utf8();
                return Ok((&i[index..], &i[0..index]));
            };
        }

        if bracket_counter == 0 {
            Ok(("", i))
        } else {
            Err(Err::Error(Error::from_error_kind(i, ErrorKind::TakeUntil)))
        }
    }
}

/// Parses a single menuentry with title and body commands.
fn parse_menuentry(input: &str) -> IResult<&str, MenuEntry<'_>> {
    let (input, _) = tag("menuentry").parse(input)?;

    // Require at least one space after "menuentry"
    let (input, _) = multispace1.parse(input)?;
    // Eat up the title, handling escaped quotes
    let (input, title) = delimited(
        tag("\""),
        escaped(none_of("\\\""), '\\', none_of("")),
        tag("\""),
    )
    .parse(input)?;

    // Skip any whitespace after title
    let (input, _) = multispace0.parse(input)?;

    // Eat up everything insde { .. }
    let (input, body) = delimited(
        tag("{"),
        take_until_balanced_allow_nested('{', '}'),
        tag("}"),
    )
    .parse(input)?;

    let mut map = vec![];

    for line in body.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once(' ') {
            map.push((key, value.trim()));
        }
    }

    Ok((
        input,
        MenuEntry {
            title: title.to_string(),
            body: MenuentryBody::from(map),
        },
    ))
}

/// Skips content until finding "menuentry" keyword or end of input.
fn skip_to_menuentry(input: &str) -> IResult<&str, ()> {
    let (input, _) = take_until("menuentry")(input)?;
    Ok((input, ()))
}

/// Parses all menuentries from a GRUB configuration file.
fn parse_all(input: &str) -> IResult<&str, Vec<MenuEntry<'_>>> {
    let mut remaining = input;
    let mut entries = Vec::new();

    // Skip any content before the first menuentry
    let Ok((new_input, _)) = skip_to_menuentry(remaining) else {
        return Ok(("", Default::default()));
    };
    remaining = new_input;

    while !remaining.trim().is_empty() {
        let (new_input, entry) = parse_menuentry(remaining)?;
        entries.push(entry);
        remaining = new_input;

        // Skip whitespace and try to find next menuentry
        let (ws_input, _) = multispace0(remaining)?;
        remaining = ws_input;

        if let Ok((next_input, _)) = skip_to_menuentry(remaining) {
            remaining = next_input;
        } else if !remaining.trim().is_empty() {
            // No more menuentries found, but content remains
            break;
        }
    }

    Ok((remaining, entries))
}

/// Main entry point for parsing GRUB menuentry files.
pub(crate) fn parse_grub_menuentry_file(contents: &str) -> anyhow::Result<Vec<MenuEntry<'_>>> {
    let (_, entries) = parse_all(&contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse GRUB menuentries: {e}"))?;
    // Validate that entries have reasonable structure
    for entry in &entries {
        if entry.title.is_empty() {
            anyhow::bail!("Found menuentry with empty title");
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_menuconfig_parser() {
        let menuentry = r#"
            if [ -f ${config_directory}/efiuuid.cfg ]; then
                    source ${config_directory}/efiuuid.cfg
            fi

            # Skip this comment

            menuentry "Fedora 42: (Verity-42)" {
                insmod fat
                insmod chain
                # This should also be skipped
                search --no-floppy --set=root --fs-uuid "${EFI_PART_UUID}"
                chainloader /EFI/Linux/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6.efi
            }

            menuentry "Fedora 43: (Verity-43)" {
                insmod fat
                insmod chain
                search --no-floppy --set=root --fs-uuid "${EFI_PART_UUID}"
                chainloader /EFI/Linux/uki.efi
                extra_field1 this is extra
                extra_field2 this is also extra
            }
        "#;

        let result = parse_grub_menuentry_file(menuentry).expect("Expected parsed entries");

        let expected = vec![
            MenuEntry {
                title: "Fedora 42: (Verity-42)".into(),
                body: MenuentryBody {
                    insmod: vec!["fat", "chain"],
                    search: "--no-floppy --set=root --fs-uuid \"${EFI_PART_UUID}\"",
                    chainloader: "/EFI/Linux/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6.efi".into(),
                    version: 0,
                    extra: vec![],
                },
            },
            MenuEntry {
                title: "Fedora 43: (Verity-43)".into(),
                body: MenuentryBody {
                    insmod: vec!["fat", "chain"],
                    search: "--no-floppy --set=root --fs-uuid \"${EFI_PART_UUID}\"",
                    chainloader: "/EFI/Linux/uki.efi".into(),
                    version: 0,
                    extra: vec![
                        ("extra_field1", "this is extra"), 
                        ("extra_field2", "this is also extra")
                    ]
                },
            },
        ];

        println!("{}", expected[0]);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_escaped_quotes_in_title() {
        let menuentry = r#"
            menuentry "Title with \"escaped quotes\" inside" {
                insmod fat
                chainloader /EFI/Linux/test.efi
            }
        "#;

        let result = parse_grub_menuentry_file(menuentry).expect("Expected parsed entries");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].title, "Title with \\\"escaped quotes\\\" inside");
        assert_eq!(result[0].body.chainloader, "/EFI/Linux/test.efi");
    }

    #[test]
    fn test_multiple_escaped_quotes() {
        let menuentry = r#"
            menuentry "Test \"first\" and \"second\" quotes" {
                insmod fat
                chainloader /EFI/Linux/test.efi
            }
        "#;

        let result = parse_grub_menuentry_file(menuentry).expect("Expected parsed entries");

        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].title,
            "Test \\\"first\\\" and \\\"second\\\" quotes"
        );
    }

    #[test]
    fn test_escaped_backslash_in_title() {
        let menuentry = r#"
            menuentry "Path with \\ backslash" {
                insmod fat
                chainloader /EFI/Linux/test.efi
            }
        "#;

        let result = parse_grub_menuentry_file(menuentry).expect("Expected parsed entries");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].title, "Path with \\\\ backslash");
    }

    #[test]
    fn test_minimal_menuentry() {
        let menuentry = r#"
            menuentry "Minimal Entry" {
                # Just a comment
            }
        "#;

        let result = parse_grub_menuentry_file(menuentry).expect("Expected parsed entries");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].title, "Minimal Entry");
        assert_eq!(result[0].body.insmod.len(), 0);
        assert_eq!(result[0].body.chainloader, "");
        assert_eq!(result[0].body.search, "");
        assert_eq!(result[0].body.extra.len(), 0);
    }

    #[test]
    fn test_menuentry_with_only_insmod() {
        let menuentry = r#"
            menuentry "Insmod Only" {
                insmod fat
                insmod chain
                insmod ext2
            }
        "#;

        let result = parse_grub_menuentry_file(menuentry).expect("Expected parsed entries");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].body.insmod, vec!["fat", "chain", "ext2"]);
        assert_eq!(result[0].body.chainloader, "");
        assert_eq!(result[0].body.search, "");
    }

    #[test]
    fn test_menuentry_with_set_commands_ignored() {
        let menuentry = r#"
            menuentry "With Set Commands" {
                set timeout=5
                set root=(hd0,1)
                insmod fat
                chainloader /EFI/Linux/test.efi
            }
        "#;

        let result = parse_grub_menuentry_file(menuentry).expect("Expected parsed entries");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].body.insmod, vec!["fat"]);
        assert_eq!(result[0].body.chainloader, "/EFI/Linux/test.efi");
        // set commands should be ignored
        assert!(!result[0].body.extra.iter().any(|(k, _)| k == &"set"));
    }

    #[test]
    fn test_nested_braces_in_body() {
        let menuentry = r#"
            menuentry "Nested Braces" {
                if [ -f ${config_directory}/test.cfg ]; then
                    source ${config_directory}/test.cfg
                fi
                insmod fat
                chainloader /EFI/Linux/test.efi
            }
        "#;

        let result = parse_grub_menuentry_file(menuentry).expect("Expected parsed entries");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].title, "Nested Braces");
        assert_eq!(result[0].body.insmod, vec!["fat"]);
        assert_eq!(result[0].body.chainloader, "/EFI/Linux/test.efi");
        // The if/fi block should be captured as extra commands
        assert!(result[0].body.extra.iter().any(|(k, _)| k == &"if"));
    }

    #[test]
    fn test_empty_file() {
        let result = parse_grub_menuentry_file("").expect("Should handle empty file");
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_file_with_no_menuentries() {
        let content = r#"
            # Just comments and other stuff
            set timeout=10
            if [ -f /boot/grub/custom.cfg ]; then
                source /boot/grub/custom.cfg
            fi
        "#;

        let result =
            parse_grub_menuentry_file(content).expect("Should handle file with no menuentries");
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_malformed_menuentry_missing_quote() {
        let menuentry = r#"
            menuentry "Missing closing quote {
                insmod fat
            }
        "#;

        let result = parse_grub_menuentry_file(menuentry);
        assert!(result.is_err(), "Should fail on malformed menuentry");
    }

    #[test]
    fn test_malformed_menuentry_missing_brace() {
        let menuentry = r#"
            menuentry "Missing Brace" {
                insmod fat
                chainloader /EFI/Linux/test.efi
            // Missing closing brace
        "#;

        let result = parse_grub_menuentry_file(menuentry);
        assert!(result.is_err(), "Should fail on unbalanced braces");
    }

    #[test]
    fn test_multiple_menuentries_with_content_between() {
        let content = r#"
            # Some initial config
            set timeout=10
            
            menuentry "First Entry" {
                insmod fat
                chainloader /EFI/Linux/first.efi
            }
            
            # Some comments between entries
            set default=0
            
            menuentry "Second Entry" {
                insmod ext2
                search --set=root --fs-uuid "some-uuid"
                chainloader /EFI/Linux/second.efi
            }
            
            # Trailing content
        "#;

        let result = parse_grub_menuentry_file(content)
            .expect("Should parse multiple entries with content between");

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].title, "First Entry");
        assert_eq!(result[0].body.chainloader, "/EFI/Linux/first.efi");
        assert_eq!(result[1].title, "Second Entry");
        assert_eq!(result[1].body.chainloader, "/EFI/Linux/second.efi");
        assert_eq!(result[1].body.search, "--set=root --fs-uuid \"some-uuid\"");
    }
}
