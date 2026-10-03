//! Output as shell-quoted `KEY="value"` lines, in the style of util-linux's
//! `lsblk --pairs --shell`, for scripts to `eval` without needing `jq`.
//!
//! This doesn't use [`shlex`]: its quoting is for command arguments, and it
//! leaves plain words unquoted and a newline as is inside single quotes.
//! Here every value is double-quoted like `lsblk` and os-release(5) do, and
//! stays on one line, so the output is also easy to parse without a shell.

use std::io::Write;

use anyhow::{Context, Result};
use serde::Serialize;

/// Write the fields of `v`, a struct of scalars, as `KEY="value"` lines,
/// sorted by key.  Keys are converted from camelCase to shell variable
/// names, e.g. `etcPath` to `ETC_PATH`, and a `null` is an empty string.
pub fn write_shell_pairs<T: Serialize>(mut w: impl Write, v: &T) -> Result<()> {
    let serde_json::Value::Object(map) = serde_json::to_value(v)? else {
        anyhow::bail!("Expected an object");
    };
    let mut pairs = map
        .into_iter()
        .map(|(k, v)| {
            let v = match v {
                serde_json::Value::String(s) => s,
                serde_json::Value::Null => String::new(),
                serde_json::Value::Bool(_) | serde_json::Value::Number(_) => v.to_string(),
                _ => anyhow::bail!("Unsupported nested value for {k}"),
            };
            Ok((shell_key(&k), v))
        })
        .collect::<Result<Vec<_>>>()?;
    pairs.sort();
    for (k, v) in pairs {
        writeln!(w, "{k}={}", shell_quote(&v)).context("Writing pairs")?;
    }
    Ok(())
}

/// Convert a camelCase key to a shell variable name, e.g. `etcPath` to
/// `ETC_PATH`.  Like `lsblk --shell`, any other character that isn't valid in
/// a variable name becomes `_`.
fn shell_key(key: &str) -> String {
    let mut r = String::with_capacity(key.as_bytes().len() + 4);
    let mut prev_lower = false;
    for c in key.chars() {
        if c.is_ascii_uppercase() && prev_lower {
            r.push('_');
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        r.push(if c.is_ascii_alphanumeric() {
            c.to_ascii_uppercase()
        } else {
            '_'
        });
    }
    r
}

/// Double-quote a value for a POSIX shell, keeping it on one line.
///
/// `"`, `\`, `$` and `` ` `` are escaped with a backslash, as in os-release(5),
/// so that `eval` yields the original value.  Control characters such as a
/// newline are written as `\xNN` like `lsblk` does: that can't run anything
/// and keeps one line per key, but doesn't round-trip.  Everything else,
/// including non-ASCII, is kept as is.
fn shell_quote(value: &str) -> String {
    let mut r = String::with_capacity(value.as_bytes().len() + 2);
    r.push('"');
    for c in value.chars() {
        match c {
            '"' | '\\' | '$' | '`' => {
                r.push('\\');
                r.push(c);
            }
            c if c.is_control() => r.push_str(&format!("\\x{:02x}", u32::from(c))),
            c => r.push(c),
        }
    }
    r.push('"');
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_key() {
        for (input, expected) in [
            ("backend", "BACKEND"),
            ("etcPath", "ETC_PATH"),
            ("imageDigest", "IMAGE_DIGEST"),
            ("v2Thing", "V2_THING"),
            ("MAJ:MIN", "MAJ_MIN"),
            ("kebab-case", "KEBAB_CASE"),
        ] {
            assert_eq!(shell_key(input), expected, "{input}");
        }
    }

    // (input, quoted, whether `eval` yields the input again)
    const QUOTE_CASES: &[(&str, &str, bool)] = &[
        ("", r#""""#, true),
        ("plain", r#""plain""#, true),
        ("with spaces", r#""with spaces""#, true),
        (r#"a"quote"#, r#""a\"quote""#, true),
        ("single'quote", r#""single'quote""#, true),
        ("$HOME ${x}", r#""\$HOME \${x}""#, true),
        ("`id`", r#""\`id\`""#, true),
        ("$(id)", r#""\$(id)""#, true),
        (r"back\slash", r#""back\\slash""#, true),
        ("semi;colon & | < >", r#""semi;colon & | < >""#, true),
        ("ünïcødé ☃", r#""ünïcødé ☃""#, true),
        ("new\nline", r#""new\x0aline""#, false),
        ("tab\tdel\x7f", r#""tab\x09del\x7f""#, false),
    ];

    #[test]
    fn test_shell_quote() {
        for &(input, expected, _) in QUOTE_CASES {
            assert_eq!(shell_quote(input), expected, "{input:?}");
        }
    }

    /// Check what a real shell makes of the quoted values.
    #[test]
    fn test_shell_quote_eval() {
        for &(input, quoted, roundtrips) in QUOTE_CASES {
            let out = std::process::Command::new("sh")
                .args(["-c", r#"eval "V=$1"; printf %s "$V""#, "sh", quoted])
                .output()
                .unwrap();
            assert!(out.status.success(), "{input:?}: {out:?}");
            let out = String::from_utf8(out.stdout).unwrap();
            if roundtrips {
                assert_eq!(out, input, "{input:?}");
            } else {
                // Escaped control characters stay literal, and run nothing.
                let unquoted = quoted.strip_prefix('"').and_then(|q| q.strip_suffix('"'));
                assert_eq!(Some(out.as_str()), unquoted, "{input:?}");
            }
        }
    }

    #[test]
    fn test_write_shell_pairs() -> Result<()> {
        let v = serde_json::json!({
            "zeta": "last",
            "someValue": "a \"b\"",
            "count": 3,
            "flag": true,
            "missing": null,
        });
        let mut buf = Vec::new();
        write_shell_pairs(&mut buf, &v)?;
        assert_eq!(
            String::from_utf8(buf)?,
            "COUNT=\"3\"\nFLAG=\"true\"\nMISSING=\"\"\nSOME_VALUE=\"a \\\"b\\\"\"\nZETA=\"last\"\n"
        );

        for v in [serde_json::json!("scalar"), serde_json::json!({"a": [1]})] {
            assert!(write_shell_pairs(std::io::sink(), &v).is_err(), "{v}");
        }
        Ok(())
    }
}
