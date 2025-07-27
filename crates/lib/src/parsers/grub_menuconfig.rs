use std::fmt::Display;

use nom::{
    bytes::complete::{tag, take_until},
    character::complete::multispace0,
    error::{Error, ErrorKind, ParseError},
    multi::many0,
    sequence::{delimited, preceded},
    Err, IResult, Parser,
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MenuentryBody<'a> {
    insmod: Vec<&'a str>,
    pub(crate) chainloader: String,
    search: &'a str,
    version: u8,
    extra: Vec<(&'a str, &'a str)>,
}

impl<'a> Display for MenuentryBody<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for insmod in &self.insmod {
            writeln!(f, "insmod {}", insmod)?;
        }

        writeln!(f, "search {}", self.search)?;
        // writeln!(f, "version {}", self.version)?;
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

        return entry;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MenuEntry<'a> {
    pub(crate) title: String,
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
    pub(crate) fn new(boot_label: &str, uki_id: &str) -> Self {
        Self {
            title: format!("{boot_label}: ({uki_id})"),
            body: MenuentryBody {
                insmod: vec!["fat", "chain"],
                chainloader: format!("/EFI/Linux/{uki_id}.efi"),
                search: "--no-floppy --set=root --fs-uuid \"${EFI_PART_UUID}\"",
                version: 0,
                extra: vec![],
            },
        }
    }
}

pub fn take_until_balanced_allow_nested(
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

fn parse_menuentry(input: &str) -> IResult<&str, MenuEntry> {
    let (input, _) = take_until("menuentry")(input)?; // skip irrelevant prefix
    let (input, _) = tag("menuentry").parse(input)?;

    // Skip the whitespace after "menuentry"
    let (input, _) = multispace0.parse(input)?;
    // Eat up the title
    let (input, title) = delimited(tag("\""), take_until("\""), tag("\"")).parse(input)?;

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

#[rustfmt::skip]
fn parse_all(input: &str) -> IResult<&str, Vec<MenuEntry>> {
    many0(
        preceded(
            multispace0,
            parse_menuentry,
        )
    )
    .parse(input)
}

pub(crate) fn parse_grub_menuentry_file(contents: &str) -> anyhow::Result<Vec<MenuEntry>> {
    let result = parse_all(&contents);

    return match result {
        Ok((_, entries)) => Ok(entries),
        Result::Err(_) => anyhow::bail!("Failed to parse grub menuentry"),
    };
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
}
