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

/// Parse the byte-oriented Linux mountinfo format without requiring UTF-8.
/// Kernel pathname escapes are decoded before paths are constructed.
fn parse_mountinfo(data: &[u8]) -> Result<Vec<PathBuf>> {
    let mut mountpoints = Vec::new();
    let lines = data.split(|byte| *byte == b'\n');
    let line_count = lines.clone().count();
    for (index, line) in lines.enumerate() {
        if line.is_empty() && index + 1 == line_count {
            continue; // A final newline is conventional.
        }
        anyhow::ensure!(!line.is_empty(), "Empty mountinfo line {}", index + 1);
        anyhow::ensure!(
            !line.contains(&0),
            "NUL byte in mountinfo line {}",
            index + 1
        );
        let fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        let separator = fields
            .iter()
            .enumerate()
            .skip(6)
            .find_map(|(index, field)| (*field == b"-").then_some(index))
            .with_context(|| {
                format!("Malformed mountinfo line {}: missing separator", index + 1)
            })?;
        anyhow::ensure!(
            separator >= 6 && fields.len() == separator + 4,
            "Malformed mountinfo line {}: invalid field count",
            index + 1
        );
        anyhow::ensure!(
            is_positive_decimal(fields[0])
                && is_decimal(fields[1])
                && is_device_number(fields[2])
                && !fields[5].is_empty()
                && !fields[separator + 1].is_empty()
                && !fields[separator + 2].is_empty()
                && !fields[separator + 3].is_empty(),
            "Malformed mountinfo line {}: invalid required field",
            index + 1
        );
        // The root field is not used for mount selection. Decode it to ensure
        // its escape syntax is valid, but don't impose pathname constraints:
        // unlike the mountpoint, it may be relative or noncanonical.
        decode_mountinfo_escapes(fields[3])
            .with_context(|| format!("Malformed root path on mountinfo line {}", index + 1))?;
        let mountpoint = decode_mountinfo_path(fields[4])
            .with_context(|| format!("Malformed mountpoint on mountinfo line {}", index + 1))?;
        decode_mountinfo_escapes(fields[separator + 2])
            .with_context(|| format!("Malformed source path on mountinfo line {}", index + 1))?;
        mountpoints.push(mountpoint);
    }
    anyhow::ensure!(!mountpoints.is_empty(), "Mountinfo contained no records");
    Ok(mountpoints)
}

fn is_decimal(value: &[u8]) -> bool {
    !value.is_empty()
        && value.iter().all(u8::is_ascii_digit)
        && std::str::from_utf8(value)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some()
}

fn is_positive_decimal(value: &[u8]) -> bool {
    is_decimal(value)
        && std::str::from_utf8(value)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|value| value > 0)
}

fn is_device_number(value: &[u8]) -> bool {
    let Some(separator) = value.iter().position(|byte| *byte == b':') else {
        return false;
    };
    is_decimal(&value[..separator]) && is_decimal(&value[separator + 1..])
}

fn decode_mountinfo_path(value: &[u8]) -> Result<PathBuf> {
    let decoded = decode_mountinfo_escapes(value)?;
    anyhow::ensure!(
        decoded.first() == Some(&b'/'),
        "Mountinfo path is not absolute"
    );
    let mut components = decoded[1..].split(|byte| *byte == b'/');
    anyhow::ensure!(
        decoded.len() == 1
            || components.all(|component| {
                !component.is_empty() && component != b"." && component != b".."
            }),
        "Mountinfo path is not canonical"
    );
    Ok(PathBuf::from(std::ffi::OsString::from_vec(decoded)))
}

fn decode_mountinfo_escapes(value: &[u8]) -> Result<Vec<u8>> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] != b'\\' {
            decoded.push(value[index]);
            index += 1;
            continue;
        }
        anyhow::ensure!(
            index + 3 < value.len()
                && value[index + 1..index + 4]
                    .iter()
                    .all(|byte| (b'0'..=b'7').contains(byte)),
            "Invalid octal escape in mountinfo path"
        );
        // Mountinfo escapes are three octal digits. Decode wider than a byte
        // so malformed values such as `\777` cannot overflow or wrap.
        let escaped = u16::from(value[index + 1] - b'0') * 64
            + u16::from(value[index + 2] - b'0') * 8
            + u16::from(value[index + 3] - b'0');
        anyhow::ensure!(
            escaped <= u16::from(u8::MAX),
            "Octal escape exceeds one byte"
        );
        anyhow::ensure!(
            matches!(escaped, 0o11 | 0o12 | 0o40 | 0o134),
            "Unsupported octal escape in mountinfo path"
        );
        decoded.push(escaped as u8);
        index += 4;
    }
    Ok(decoded)
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
    fn mountinfo_rejects_malformed_records_and_escapes() {
        for mountinfo in [
            b"".as_slice(),
            b"not a mountinfo record\n",
            b"36 25 0:32 /bad\\04x /target/var rw - tmpfs tmpfs rw\n",
            b"36 25 0:32 / /target/var\\04x rw - tmpfs tmpfs rw\n",
            b"36 25 0:32 / /target/var\\400 rw - tmpfs tmpfs rw\n",
            b"36 25 0:32 / /target/var\\777 rw - tmpfs tmpfs rw\n",
            b"36 25 0:32 / /target/var\\041 rw - tmpfs tmpfs rw\n",
            b"36 25 0:32 / relative rw - tmpfs tmpfs rw\n",
            b"36 25 0:32 / /target/var/../outside rw - tmpfs tmpfs rw\n",
            b"36 25 0:32 / /target/var rw - tmpfs tmpfs rw extra\n",
        ] {
            assert!(
                parse_mountinfo(mountinfo).is_err(),
                "accepted {mountinfo:?}"
            );
        }
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
