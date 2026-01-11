//! Escape strings for use in ostree refs.
//!
//! It can be desirable to map arbitrary identifiers, such as RPM/dpkg
//! package names or container image references (e.g. `docker://quay.io/examplecorp/os:latest`)
//! into ostree refs (branch names) which have a quite restricted set
//! of valid characters; basically alphanumeric, plus `/`, `-`, `_`.
//!
//! This escaping scheme uses `_` in a similar way as a `\` character is
//! used in Rust unicode escaped values.  For example, `:` is `_3A_` (hexadecimal).
//! Because the empty path is not valid, `//` is escaped as `/_2F_` (i.e. the second `/` is escaped).

use anyhow::Result;
use std::fmt::Write;

/// Escape a single string; this is a backend of [`prefix_escape_for_ref`].
fn escape_for_ref(s: &str) -> Result<String> {
    if s.is_empty() {
        return Err(anyhow::anyhow!("Invalid empty string for ref"));
    }
    fn escape_c(r: &mut String, c: char) {
        write!(r, "_{:02X}_", c as u32).unwrap()
    }
    let mut r = String::new();
    let mut it = s
        .chars()
        .map(|c| {
            if c == '\0' {
                Err(anyhow::anyhow!(
                    "Invalid embedded NUL in string for ostree ref"
                ))
            } else {
                Ok(c)
            }
        })
        .peekable();

    let mut previous_alphanumeric = false;
    while let Some(c) = it.next() {
        let has_next = it.peek().is_some();
        let c = c?;
        let current_alphanumeric = c.is_ascii_alphanumeric();
        match c {
            c if current_alphanumeric => r.push(c),
            '/' if previous_alphanumeric && has_next => r.push(c),
            // Pass through `-` unconditionally
            '-' => r.push(c),
            // The underscore `_` quotes itself `__`.
            '_' => r.push_str("__"),
            o => escape_c(&mut r, o),
        }
        previous_alphanumeric = current_alphanumeric;
    }
    Ok(r)
}

/// Compute a string suitable for use as an OSTree ref, where `s` can be a (nearly)
/// arbitrary UTF-8 string.  This requires a non-empty prefix.
///
/// The restrictions on `s` are:
/// - The empty string is not supported
/// - There may not be embedded `NUL` (`\0`) characters.
///
/// The intention behind requiring a prefix is that a common need is to use e.g.
/// [`ostree::Repo::list_refs`] to find refs of a certain "type".
///
/// # Examples:
///
/// ```rust
/// # fn test() -> anyhow::Result<()> {
/// use ostree_ext::refescape;
/// let s = "registry:quay.io/coreos/fedora:latest";
/// assert_eq!(refescape::prefix_escape_for_ref("container", s)?,
///            "container/registry_3A_quay_2E_io/coreos/fedora_3A_latest");
/// # Ok(())
/// # }
/// ```
pub fn prefix_escape_for_ref(prefix: &str, s: &str) -> Result<String> {
    Ok(format!("{}/{}", prefix, escape_for_ref(s)?))
}

/// Reverse the effect of [`escape_for_ref()`].
fn unescape_for_ref(s: &str) -> Result<String> {
    let mut r = String::new();
    let mut it = s.chars();
    let mut buf = String::new();
    while let Some(c) = it.next() {
        match c {
            c if c.is_ascii_alphanumeric() => {
                r.push(c);
            }
            '-' | '/' => r.push(c),
            '_' => {
                let next = it.next();
                if let Some('_') = next {
                    r.push('_')
                } else if let Some(c) = next {
                    buf.clear();
                    buf.push(c);
                    for c in &mut it {
                        if c == '_' {
                            break;
                        }
                        buf.push(c);
                    }
                    let v = u32::from_str_radix(&buf, 16)?;
                    let c: char = v.try_into()?;
                    r.push(c);
                }
            }
            o => anyhow::bail!("Invalid character {}", o),
        }
    }
    Ok(r)
}

/// Remove a prefix from an ostree ref, and return the unescaped remainder.
///
/// # Examples:
///
/// ```rust
/// # fn test() -> anyhow::Result<()> {
/// use ostree_ext::refescape;
/// let s = "registry:quay.io/coreos/fedora:latest";
/// assert_eq!(refescape::unprefix_unescape_ref("container", "container/registry_3A_quay_2E_io/coreos/fedora_3A_latest")?, s);
/// # Ok(())
/// # }
/// ```
pub fn unprefix_unescape_ref(prefix: &str, ostree_ref: &str) -> Result<String> {
    let rest = ostree_ref
        .strip_prefix(prefix)
        .and_then(|s| s.strip_prefix('/'))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "ref does not match expected prefix {}/: {}",
                ostree_ref,
                prefix
            )
        })?;
    unescape_for_ref(rest)
}

#[cfg(test)]
mod test {
    use super::*;
    use quickcheck::{TestResult, quickcheck};

    const TESTPREFIX: &str = "testprefix/blah";

    const UNCHANGED: &[&str] = &["foo", "foo/bar/baz-blah/foo"];
    const ROUNDTRIP: &[&str] = &[
        "localhost:5000/foo:latest",
        "fedora/x86_64/coreos",
        "/foo/bar/foo.oci-archive",
        "/foo/bar/foo.docker-archive",
        "docker://quay.io/exampleos/blah:latest",
        "oci-archive:/path/to/foo.ociarchive",
        "docker-archive:/path/to/foo.dockerarchive",
    ];
    const CORNERCASES: &[&str] = &["/", "blah/", "/foo/"];

    #[test]
    fn escape() {
        // These strings shouldn't change
        for &v in UNCHANGED {
            let escaped = &escape_for_ref(v).unwrap();
            ostree::validate_rev(escaped).unwrap();
            assert_eq!(escaped.as_str(), v);
        }
        // Roundtrip cases, plus unchanged cases
        for &v in UNCHANGED.iter().chain(ROUNDTRIP).chain(CORNERCASES) {
            let escaped = &prefix_escape_for_ref(TESTPREFIX, v).unwrap();
            ostree::validate_rev(escaped).unwrap();
            let unescaped = unprefix_unescape_ref(TESTPREFIX, escaped).unwrap();
            assert_eq!(v, unescaped);
        }
        // Explicit test
        assert_eq!(
            escape_for_ref(ROUNDTRIP[0]).unwrap(),
            "localhost_3A_5000/foo_3A_latest"
        );
    }

    fn roundtrip(s: String) -> TestResult {
        // Ensure we only try strings which match the predicates.
        let r = prefix_escape_for_ref(TESTPREFIX, &s);
        let escaped = match r {
            Ok(v) => v,
            Err(_) => return TestResult::discard(),
        };
        let unescaped = unprefix_unescape_ref(TESTPREFIX, &escaped).unwrap();
        TestResult::from_bool(unescaped == s)
    }

    #[test]
    fn qcheck() {
        quickcheck(roundtrip as fn(String) -> TestResult);
    }
}
