//! Read `/proc/self/mountinfo` and select mounts nested beneath the source `/var`.
//!
//! The byte-oriented parser preserves non-UTF-8 Unix paths and decodes kernel
//! escapes. The `procfs` crate requires UTF-8 and leaves escaped mountpoint
//! paths undecoded; bootc-mount/findmnt exposes `String` targets and invokes
//! external `findmnt`, so neither preserves arbitrary path bytes. There is no
//! standard-library mountinfo API.

use std::{
    collections::BTreeSet,
    os::unix::ffi::OsStringExt,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};

/// The mountpoint is the fifth space-separated mountinfo field.
const MOUNTINFO_MOUNTPOINT_FIELD: usize = 4;

/// Read one snapshot and return the paths of mounts nested beneath `src_var`.
///
/// `src_var` is the canonical path used to open the source directory;
/// mountinfo paths are already kernel-canonical.
pub(super) fn nested_mountpoints_for(src_var: &Path) -> Result<BTreeSet<PathBuf>> {
    let snapshot = read_mountinfo_snapshot()?;
    nested_mountpoints(src_var, parse_mountinfo(&snapshot)?)
}

/// Read one complete installer mount namespace snapshot.
fn read_mountinfo_snapshot() -> Result<Vec<u8>> {
    std::fs::read("/proc/self/mountinfo")
        .context("Reading installer /proc/self/mountinfo for /var migration")
}

fn nested_mountpoints(
    src_var: &Path,
    mountpoints: impl IntoIterator<Item = PathBuf>,
) -> Result<BTreeSet<PathBuf>> {
    anyhow::ensure!(src_var.is_absolute(), "Source /var path must be absolute");
    let mut nested = BTreeSet::new();
    for mountpoint in mountpoints {
        let Ok(relative) = mountpoint.strip_prefix(src_var) else {
            continue;
        };
        // The mount on /var itself is not a nested mount. Only child paths are
        // filtered; Path::strip_prefix provides component-safe containment.
        if relative.as_os_str().is_empty() {
            continue;
        }
        anyhow::ensure!(
            relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
            "Invalid nested mountpoint below {}: {}",
            src_var.display(),
            mountpoint.display()
        );
        nested.insert(relative.to_path_buf());
    }
    Ok(nested)
}

/// Extract mountpoints from the byte-oriented Linux mountinfo format without
/// requiring UTF-8. Only field 5 is relevant; in particular, empty fields and
/// malformed trailing fields in records for unrelated mounts are ignored.
/// Literal spaces are the field delimiter, so CR, form-feed, and other path
/// bytes remain intact. Kernel pathname escapes are decoded before paths are
/// constructed.
fn parse_mountinfo(data: &[u8]) -> Result<Vec<PathBuf>> {
    let mountpoints = data
        .split(|byte| *byte == b'\n')
        .enumerate()
        .filter(|(_, line)| !line.is_empty())
        .map(|(index, line)| {
            let field = line
                .split(|byte| *byte == b' ')
                .nth(MOUNTINFO_MOUNTPOINT_FIELD)
                .with_context(|| {
                    format!("Malformed mountinfo line {}: no mountpoint", index + 1)
                })?;
            Ok(PathBuf::from(std::ffi::OsString::from_vec(
                decode_mountinfo_escapes(field),
            )))
        })
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(!mountpoints.is_empty(), "Mountinfo contained no records");
    Ok(mountpoints)
}

/// Decode the kernel's `\ooo` escapes for space, tab, newline, and backslash.
/// Unknown or malformed escape sequences are retained as literal bytes.
fn decode_mountinfo_escapes(value: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut rest = value;
    while let Some((&byte, tail)) = rest.split_first() {
        let escaped = (byte == b'\\')
            .then(|| tail.get(..3))
            .flatten()
            .filter(|digits| digits.iter().all(|digit| (b'0'..=b'7').contains(digit)))
            .and_then(|digits| {
                let value = digits
                    .iter()
                    .fold(0u16, |acc, digit| acc * 8 + u16::from(digit - b'0'));
                u8::try_from(value).ok()
            })
            .filter(|value| matches!(value, b'\t' | b'\n' | b' ' | b'\\'));
        if let Some(escaped) = escaped {
            decoded.push(escaped);
            rest = &tail[3..];
        } else {
            decoded.push(byte);
            rest = tail;
        }
    }
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::ffi::OsStrExt};

    #[test]
    fn mountinfo_decodes_escaped_and_non_utf8_paths() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_var = temp.path().join("var");
        fs::create_dir(&src_var)?;
        let source = src_var.as_os_str().as_bytes();
        let mut mountinfo = format!(
            "36 0 0:32 / {0} rw,relatime - tmpfs tmpfs rw\n37 25 0:33 / {0}/rpc\\040pipefs rw - nfs nfs rw\n",
            src_var.display()
        )
        .into_bytes();
        mountinfo.extend_from_slice(b"38 25 0:34 / ");
        mountinfo.extend_from_slice(source);
        mountinfo.extend_from_slice(b"/\xffstate rw - tmpfs tmpfs rw\n");
        let parsed = parse_mountinfo(&mountinfo)?;
        let escaped_name = src_var.join("rpc pipefs");
        assert_eq!(parsed[1], escaped_name);
        let mut non_utf8 = source.to_vec();
        non_utf8.extend_from_slice(b"/\xffstate");
        assert_eq!(parsed[2].as_os_str().as_bytes(), non_utf8);

        let nested = nested_mountpoints(&src_var, parsed)?;
        assert_eq!(
            nested,
            BTreeSet::from([
                PathBuf::from("rpc pipefs"),
                PathBuf::from(std::ffi::OsStr::from_bytes(b"\xffstate"))
            ])
        );
        Ok(())
    }

    #[test]
    fn mountinfo_preserves_cr_form_feed_and_decodes_kernel_escapes() -> Result<()> {
        use std::os::unix::ffi::OsStrExt;

        let parsed = parse_mountinfo(
            b"1 0 0:1 / /target/var rw - tmpfs tmpfs rw\n\
              2 1 0:2 / /target/var/a\\040b\\011c\\012d\\134e\r\x0cf rw - x x rw\n",
        )?;
        let mountpoint = parsed[1].as_os_str().as_bytes();
        assert_eq!(mountpoint, b"/target/var/a b\tc\nd\\e\r\x0cf");
        Ok(())
    }

    #[test]
    fn unrelated_mount_records_do_not_change_nested_mount_selection() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_var = temp.path().join("target/var");
        fs::create_dir_all(&src_var)?;
        let base = format!(
            "36 0 0:32 / {0} rw - tmpfs tmpfs rw\n37 25 0:33 / {0}/lib/data rw - nfs nfs rw\n",
            src_var.display()
        );
        let with_unrelated = format!(
            "21 0 0:21 / / rw - overlay overlay rw\n{base}38 25 0:34 / /unrelated rw - tmpfs tmpfs rw\n"
        );

        let selected = |mountinfo: &str| -> Result<BTreeSet<PathBuf>> {
            nested_mountpoints(&src_var, parse_mountinfo(mountinfo.as_bytes())?)
        };
        assert_eq!(
            selected(&base)?,
            BTreeSet::from([PathBuf::from("lib/data")])
        );
        assert_eq!(selected(&with_unrelated)?, selected(&base)?);
        Ok(())
    }

    #[test]
    fn mountinfo_allows_relative_and_noncanonical_roots_with_valid_nested_mountpoints() -> Result<()>
    {
        let temp = tempfile::tempdir()?;
        let src_var = temp.path().join("target/var");
        fs::create_dir_all(&src_var)?;

        for root in ["/some/../root", "relative/root"] {
            let mountinfo = format!(
                "36 0 0:32 / {0} rw - tmpfs tmpfs rw\n37 25 0:33 {1} {0}/lib/data rw - nfs nfs rw\n",
                src_var.display(),
                root
            );

            assert_eq!(
                nested_mountpoints(&src_var, parse_mountinfo(mountinfo.as_bytes())?)?,
                BTreeSet::from([PathBuf::from("lib/data")]),
                "root field {root:?} should not affect mountpoint selection"
            );
        }
        Ok(())
    }

    #[test]
    fn mountinfo_ignores_empty_source_and_unrelated_malformed_trailing_fields() -> Result<()> {
        let parsed = parse_mountinfo(
            b"36 25 0:32 / /target/var rw - tmpfs tmpfs rw\n\
              37 36 0:33 / /target/var/lib/mounted rw,relatime shared:1 - tmpfs  rw\n\
              38 36 0:34 / /unrelated rw - missing-fields\n",
        )?;
        assert_eq!(
            parsed,
            [
                PathBuf::from("/target/var"),
                PathBuf::from("/target/var/lib/mounted"),
                PathBuf::from("/unrelated")
            ]
        );
        let nested = nested_mountpoints(Path::new("/target/var"), parsed)?;
        assert_eq!(nested, BTreeSet::from([PathBuf::from("lib/mounted")]));

        for mountinfo in [b"".as_slice(), b"\n", b"36 25 0:32 /\n"] {
            assert!(
                parse_mountinfo(mountinfo).is_err(),
                "accepted {mountinfo:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn nested_mountpoint_detection_is_component_safe() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir()?;
        let src_var = temp.path().join("target/var");
        fs::create_dir_all(&src_var)?;
        let alias = temp.path().join("var-alias");
        symlink(&src_var, &alias)?;
        let paths = [
            src_var.clone(),
            src_var.join("lib/data"),
            temp.path().join("target/var-old/other"),
            PathBuf::from("/elsewhere/var/mount"),
        ];
        let canonical_src_var = fs::canonicalize(&alias)?;
        assert_eq!(
            nested_mountpoints(&canonical_src_var, paths)?,
            BTreeSet::from([PathBuf::from("lib/data")])
        );
        Ok(())
    }
}
