use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};

/// Searches for the BOOTC_IMAGE key in a given os-release file.
/// Follows standard os-release(5) quoting rules.
fn parse_bootc_image_from_reader<R: BufRead>(reader: R) -> Result<Option<String>> {
    let mut last_found = None;

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == "BOOTC_IMAGE" {
                let value = value.trim();

                if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
                    let unquoted = &value[1..value.len() - 1];
                    let processed = unquoted
                        .replace(r#"\""#, "\"")
                        .replace(r#"\\"#, "\\")
                        .replace(r#"\$"#, "$")
                        .replace(r#"\`"#, "`");
                    last_found = Some(processed);
                } else if value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2 {
                    last_found = Some(value[1..value.len() - 1].to_string());
                } else {
                    last_found = Some(value.to_string());
                }
            }
        }
    }

    Ok(last_found)
}

/// Reads the provided os-release file and returns the BOOTC_IMAGE value if found.
pub(crate) fn get_bootc_image_from_file<P: AsRef<Path>>(path: P) -> Result<Option<String>> {
    let file = File::open(path.as_ref()).with_context(|| format!("Opening {:?}", path.as_ref()))?;
    let reader = BufReader::new(file);
    parse_bootc_image_from_reader(reader)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use std::io::Cursor;

    fn parse_str(content: &str) -> Option<String> {
        let reader = Cursor::new(content);
        parse_bootc_image_from_reader(reader).unwrap()
    }

    #[test]
    fn test_parse_os_release_standard() {
        let content = indoc! { "
            NAME=Fedora
            BOOTC_IMAGE=quay.io/example/image:latest
            VERSION=39
        " };
        assert_eq!(parse_str(content).unwrap(), "quay.io/example/image:latest");
    }

    #[test]
    fn test_parse_os_release_double_quotes() {
        let content = "BOOTC_IMAGE=\"quay.io/example/image:latest\"";
        assert_eq!(parse_str(content).unwrap(), "quay.io/example/image:latest");
    }

    #[test]
    fn test_parse_os_release_single_quotes() {
        let content = "BOOTC_IMAGE='quay.io/example/image:latest'";
        assert_eq!(parse_str(content).unwrap(), "quay.io/example/image:latest");
    }

    #[test]
    fn test_parse_os_release_escaped() {
        let content = indoc! { r#"
            BOOTC_IMAGE="quay.io/img/with\"quote"
        "# };
        assert_eq!(parse_str(content).unwrap(), "quay.io/img/with\"quote");
    }

    #[test]
    fn test_parse_os_release_missing() {
        let content = indoc! { "
            NAME=Fedora
            VERSION=39
        " };
        assert!(parse_str(content).is_none());
    }

    #[test]
    fn test_parse_os_release_comments_and_spaces() {
        let content = indoc! { "
              # comment
              BOOTC_IMAGE=  \"quay.io/img\"  
        " };
        assert_eq!(parse_str(content).unwrap(), "quay.io/img");
    }

    #[test]
    fn test_parse_os_release_last_wins() {
        let content = indoc! { "
            BOOTC_IMAGE=quay.io/old/image
            BOOTC_IMAGE=quay.io/new/image
        " };
        assert_eq!(parse_str(content).unwrap(), "quay.io/new/image");
    }
}
