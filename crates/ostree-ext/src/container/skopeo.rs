//! Fork skopeo as a subprocess

use super::ImageReference;
use anyhow::{Context, Result};
use cap_std_ext::cap_std;
use cap_std_ext::cmdext::{CapStdExtCommandExt, CmdFds};
use containers_image_proxy::oci_spec::image as oci_image;
use fn_error_context::context;
use io_lifetimes::OwnedFd;
use serde::Deserialize;
use std::io::Read;
use std::path::Path;
use std::process::Stdio;
use std::str::FromStr;
use tokio::process::Command;

// See `man containers-policy.json` and
// https://github.com/containers/image/blob/main/signature/policy_types.go
// Ideally we add something like `skopeo pull --disallow-insecure-accept-anything`
// but for now we parse the policy.
const INSECURE_ACCEPT_ANYTHING: &str = "insecureAcceptAnything";

/// The env var that overrides the policy path, matching the upstream Go
/// containers/image library behavior.
const POLICY_ENV_VAR: &str = "CONTAINERS_POLICY_JSON";

/// Well-known system paths for `containers-policy.json`, checked in order.
const SYSTEM_POLICY_PATHS: &[&str] = &[
    "etc/containers/policy.json",
    "usr/share/containers/policy.json",
];

/// Suffix appended under `$XDG_CONFIG_HOME` (or `$HOME/.config`).
const USER_POLICY_SUFFIX: &str = "containers/policy.json";

/// Resolve the containers policy path using the same load order as the
/// upstream Go containers/image library, with all lookups relative to `root`:
///
/// 1. `CONTAINERS_POLICY_JSON` env var (trusted, no existence check)
/// 2. `$XDG_CONFIG_HOME/containers/policy.json` (or `$HOME/.config/…`)
/// 3. `/etc/containers/policy.json`
/// 4. `/usr/share/containers/policy.json`
///
/// For candidates 2–4 we only return a path when the file exists on disk.
///
/// Absolute paths (from env vars) have their leading `/` stripped so they
/// resolve under `root`. Passing `root` opened on `/` gives normal behaviour;
/// tests can pass a cap-std `Dir` backed by a temporary directory.
fn resolve_policy_path(
    root: &cap_std::fs::Dir,
    env_override: Option<&Path>,
    xdg_config_home: Option<&Path>,
    home: Option<&Path>,
) -> Result<cap_std::fs::File> {
    // Helper: strip a leading `/` so the path is relative to root.
    fn strip_abs(p: &Path) -> &Path {
        p.strip_prefix("/").unwrap_or(p)
    }

    // 1. Env var override – trust unconditionally (no existence check).
    if let Some(raw) = env_override.filter(|v| !v.as_os_str().is_empty()) {
        let relative = strip_abs(raw);
        tracing::debug!("Using policy path from {POLICY_ENV_VAR}: {}", raw.display());
        return root.open(relative).with_context(|| {
            format!(
                "Opening policy file from {POLICY_ENV_VAR}={}",
                raw.display()
            )
        });
    }

    // 2. Per-user config dir.
    let user_candidate = if let Some(xdg) = xdg_config_home {
        Some(strip_abs(xdg).join(USER_POLICY_SUFFIX))
    } else {
        home.map(|h| strip_abs(h).join(".config").join(USER_POLICY_SUFFIX))
    };
    if let Some(p) = &user_candidate {
        if let Ok(f) = root.open(p) {
            tracing::debug!("Using user policy path: {}", p.display());
            return Ok(f);
        }
    }

    // 3–4. System paths.
    for candidate in SYSTEM_POLICY_PATHS {
        if let Ok(f) = root.open(candidate) {
            tracing::debug!("Using system policy path: {candidate}");
            return Ok(f);
        }
    }

    anyhow::bail!(
        "No containers policy.json found; \
         checked ${POLICY_ENV_VAR}, user config dir, and system paths"
    )
}

#[derive(Deserialize)]
struct PolicyEntry {
    #[serde(rename = "type")]
    ty: String,
}
#[derive(Deserialize)]
struct ContainerPolicy {
    default: Option<Vec<PolicyEntry>>,
}

impl ContainerPolicy {
    fn is_default_insecure(&self) -> bool {
        if let Some(default) = self.default.as_deref() {
            match default.split_first() {
                Some((v, &[])) => v.ty == INSECURE_ACCEPT_ANYTHING,
                _ => false,
            }
        } else {
            false
        }
    }
}

pub(crate) fn container_policy_is_default_insecure(root: &cap_std::fs::Dir) -> Result<bool> {
    let f = resolve_policy_path(
        root,
        std::env::var_os(POLICY_ENV_VAR).as_deref().map(Path::new),
        std::env::var_os("XDG_CONFIG_HOME")
            .as_deref()
            .map(Path::new),
        std::env::var_os("HOME").as_deref().map(Path::new),
    )
    .context("Resolving containers policy path")?;
    let r = std::io::BufReader::new(f);
    let policy: ContainerPolicy = serde_json::from_reader(r)?;
    Ok(policy.is_default_insecure())
}

/// Create a Command builder for skopeo.
pub(crate) fn new_cmd() -> std::process::Command {
    let mut cmd = std::process::Command::new(bootc_utils::skopeo_bin());
    cmd.stdin(Stdio::null());
    cmd
}

/// Spawn the child process
pub(crate) fn spawn(mut cmd: Command) -> Result<tokio::process::Child> {
    let cmd = cmd.stdin(Stdio::null()).stderr(Stdio::piped());
    cmd.spawn().context("Failed to exec skopeo")
}

/// Use skopeo to copy a container image.
#[context("Skopeo copy")]
pub async fn copy(
    src: &ImageReference,
    dest: &ImageReference,
    authfile: Option<&Path>,
    add_fd: Option<(std::sync::Arc<OwnedFd>, i32)>,
    progress: bool,
) -> Result<oci_image::Digest> {
    let digestfile = tempfile::NamedTempFile::new()?;
    let mut cmd = new_cmd();
    cmd.arg("copy");
    if !progress {
        cmd.stdout(std::process::Stdio::null());
    }
    cmd.arg("--digestfile");
    cmd.arg(digestfile.path());
    if let Some((add_fd, n)) = add_fd {
        let mut fds = CmdFds::new();
        fds.take_fd_n(add_fd, n);
        cmd.take_fds(fds);
    }
    if let Some(authfile) = authfile {
        cmd.arg("--authfile");
        cmd.arg(authfile);
    }
    cmd.args(&[src.to_string(), dest.to_string()]);
    let mut cmd = tokio::process::Command::from(cmd);
    cmd.kill_on_drop(true);
    let proc = super::skopeo::spawn(cmd)?;
    let output = proc.wait_with_output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("skopeo failed: {}\n", stderr));
    }
    let mut digestfile = digestfile.into_file();
    let mut r = String::new();
    digestfile.read_to_string(&mut r)?;
    Ok(oci_image::Digest::from_str(r.trim())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::cap_tempfile;

    // Default value as of the Fedora 34 containers-common-1-21.fc34.noarch package.
    const DEFAULT_POLICY: &str = indoc::indoc! {r#"
    {
        "default": [
            {
                "type": "insecureAcceptAnything"
            }
        ],
        "transports":
            {
                "docker-daemon":
                    {
                        "": [{"type":"insecureAcceptAnything"}]
                    }
            }
    }
    "#};

    // Stripped down copy from the manual.
    const REASONABLY_LOCKED_DOWN: &str = indoc::indoc! { r#"
    {
        "default": [{"type": "reject"}],
        "transports": {
            "dir": {
                "": [{"type": "insecureAcceptAnything"}]
            },
            "atomic": {
                "hostname:5000/myns/official": [
                    {
                        "type": "signedBy",
                        "keyType": "GPGKeys",
                        "keyPath": "/path/to/official-pubkey.gpg"
                    }
                ]
            }
        }
    }
    "#};

    #[test]
    fn policy_is_insecure() {
        let p: ContainerPolicy = serde_json::from_str(DEFAULT_POLICY).unwrap();
        assert!(p.is_default_insecure());
        for &v in &["{}", REASONABLY_LOCKED_DOWN] {
            let p: ContainerPolicy = serde_json::from_str(v).unwrap();
            assert!(!p.is_default_insecure());
        }
    }

    /// Create `<dir>/<path>` with empty JSON content, creating parent dirs.
    /// Returns the (dev, ino) of the created file for identity checks.
    fn touch(dir: &cap_std::fs::Dir, path: &str) -> (u64, u64) {
        use cap_std::fs::MetadataExt;
        if let Some(parent) = Path::new(path).parent() {
            dir.create_dir_all(parent).unwrap();
        }
        dir.write(path, b"{}").unwrap();
        let m = dir.metadata(path).unwrap();
        (m.dev(), m.ino())
    }

    /// Return (dev, ino) for an open cap-std file.
    fn file_id(f: &cap_std::fs::File) -> (u64, u64) {
        use cap_std::fs::MetadataExt;
        let m = f.metadata().unwrap();
        (m.dev(), m.ino())
    }

    #[test]
    fn resolve_policy_path_cases() -> Result<()> {
        let td = cap_tempfile::TempDir::new(cap_std::ambient_authority())?;

        let etc_id = touch(&td, "etc/containers/policy.json");
        let _usr_id = touch(&td, "usr/share/containers/policy.json");

        // Env var override wins (trusted — errors if file missing)
        let custom = Path::new("/custom/policy.json");
        assert!(resolve_policy_path(&td, Some(custom), None, None).is_err());
        let custom_id = touch(&td, "custom/policy.json");
        let f = resolve_policy_path(&td, Some(custom), None, None)?;
        assert_eq!(
            file_id(&f),
            custom_id,
            "env var should open the custom file"
        );

        // Empty env var is ignored, falls through to /etc
        let f = resolve_policy_path(&td, Some(Path::new("")), None, None)?;
        assert_eq!(
            file_id(&f),
            etc_id,
            "empty env var should fall through to /etc"
        );

        // XDG_CONFIG_HOME wins when file exists
        let xdg_id = touch(&td, "xdg/containers/policy.json");
        let f = resolve_policy_path(&td, None, Some(Path::new("/xdg")), None)?;
        assert_eq!(file_id(&f), xdg_id, "XDG_CONFIG_HOME should win");

        // XDG_CONFIG_HOME skipped when file missing, falls through to /etc
        let f = resolve_policy_path(&td, None, Some(Path::new("/xdg-empty")), None)?;
        assert_eq!(file_id(&f), etc_id, "missing XDG dir should fall through");

        // HOME/.config fallback when XDG unset
        let home_id = touch(&td, "home/.config/containers/policy.json");
        let f = resolve_policy_path(&td, None, None, Some(Path::new("/home")))?;
        assert_eq!(file_id(&f), home_id, "HOME fallback should work");

        // /etc preferred over /usr/share
        let f = resolve_policy_path(&td, None, None, None)?;
        assert_eq!(
            file_id(&f),
            etc_id,
            "/etc should be preferred over /usr/share"
        );

        // Falls through to /usr/share when /etc missing
        let td2 = cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
        let usr2_id = touch(&td2, "usr/share/containers/policy.json");
        let f = resolve_policy_path(&td2, None, None, None)?;
        assert_eq!(file_id(&f), usr2_id, "should fall through to /usr/share");

        // Nothing found returns error
        let td3 = cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
        assert!(resolve_policy_path(&td3, None, None, None).is_err());

        Ok(())
    }
}
