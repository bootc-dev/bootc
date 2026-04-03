//! Integration tests for the bootc varlink IPC interface.
//!
//! Tests spawn bootc as a child process with a connected socketpair,
//! simulating socket activation, then use zlink proxy traits to make
//! typed varlink calls.

use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::Arc;

use anyhow::Result;
use cap_std_ext::cmdext::CapStdExtCommandExt;
use libtest_mimic::Trial;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Client-side response types (redefined to keep integration tests
// independent of the bootc library)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GetStatusReply {
    status: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct UpdateReply {
    progress: Option<serde_json::Value>,
    result: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GetConfigurationReply {
    config: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct InstallReply {
    progress: Option<serde_json::Value>,
    result: Option<serde_json::Value>,
}

/// Options for `ToDisk` (client-side, kept in sync with server).
#[derive(Debug, Clone, serde::Serialize, Deserialize, Default, zlink::introspect::Type)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct ToDiskOpts {
    device: String,
    source_imgref: Option<String>,
    target_imgref: Option<String>,
    #[serde(default)]
    via_loopback: bool,
    #[serde(default)]
    kargs: Vec<String>,
    root_fs_type: Option<String>,
    #[serde(default)]
    disable_selinux: bool,
    #[serde(default)]
    generic_image: bool,
    #[serde(default)]
    composefs_backend: bool,
}

// ---------------------------------------------------------------------------
// Error types (needed by proxy return types)
// ---------------------------------------------------------------------------

#[derive(Debug, zlink::ReplyError, zlink::introspect::ReplyError)]
#[zlink(interface = "containers.bootc")]
enum BootcError {
    Failed {
        #[allow(dead_code)]
        message: String,
    },
}

impl std::fmt::Display for BootcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed { message } => write!(f, "bootc error: {message}"),
        }
    }
}

impl std::error::Error for BootcError {}

#[derive(Debug, zlink::ReplyError, zlink::introspect::ReplyError)]
#[zlink(interface = "containers.bootc.update")]
enum UpdateError {
    Failed {
        #[allow(dead_code)]
        message: String,
    },
    NotBooted {
        #[allow(dead_code)]
        message: String,
    },
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed { message } => write!(f, "update failed: {message}"),
            Self::NotBooted { message } => write!(f, "not booted: {message}"),
        }
    }
}

impl std::error::Error for UpdateError {}

#[derive(Debug, zlink::ReplyError, zlink::introspect::ReplyError)]
#[zlink(interface = "containers.bootc.install")]
enum InstallError {
    Failed {
        #[allow(dead_code)]
        message: String,
    },
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed { message } => write!(f, "install failed: {message}"),
        }
    }
}

impl std::error::Error for InstallError {}

// ---------------------------------------------------------------------------
// Proxy traits
// ---------------------------------------------------------------------------

#[zlink::proxy("containers.bootc")]
trait BootcProxy {
    async fn get_status(&mut self) -> zlink::Result<Result<GetStatusReply, BootcError>>;
    async fn get_status_for_sysroot(
        &mut self,
        sysroot_path: String,
    ) -> zlink::Result<Result<GetStatusReply, BootcError>>;
}

#[zlink::proxy("containers.bootc.update")]
trait UpdateProxy {
    async fn upgrade(&mut self) -> zlink::Result<Result<UpdateReply, UpdateError>>;
    async fn switch(
        &mut self,
        target: String,
    ) -> zlink::Result<Result<UpdateReply, UpdateError>>;
}

#[zlink::proxy("containers.bootc.install")]
trait InstallProxy {
    async fn get_configuration(
        &mut self,
    ) -> zlink::Result<Result<GetConfigurationReply, InstallError>>;

    async fn to_disk(
        &mut self,
        opts: ToDiskOpts,
    ) -> zlink::Result<Result<InstallReply, InstallError>>;
}

// ---------------------------------------------------------------------------
// Helper: spawn bootc with socket activation
// ---------------------------------------------------------------------------

/// Wraps a zlink connection to a socket-activated bootc process.
struct ActivatedBootc {
    conn: zlink::Connection<zlink::unix::Stream>,
    rt: tokio::runtime::Runtime,
    /// Held to keep the child process alive; dropped when the test completes.
    _child: std::process::Child,
}

/// Spawn bootc with socket activation and return a zlink connection.
///
/// Creates a Unix socketpair and spawns bootc with socket-activation
/// env vars. `LISTEN_PID` must equal the child's actual PID (which is
/// only known after `fork()`), so it is set in a `pre_exec` hook where
/// `std::process::id()` returns the child PID. The other env vars are
/// static and set via `Command::env()`.
fn activated_connection() -> Result<ActivatedBootc> {
    let bootc_path = which_bootc()?;
    let (ours, theirs) = UnixStream::pair()?;
    let theirs_fd: Arc<std::os::fd::OwnedFd> = Arc::new(theirs.into());

    let mut cmd = Command::new(&bootc_path);
    cmd.take_fd_n(theirs_fd, 3)
        .lifecycle_bind_to_parent_thread();
    // All socket activation env vars must be set via libc::setenv in the
    // pre_exec hook, NOT via Command::env(). When Command::env() is used,
    // Rust builds a custom envp array *before* fork that is passed to exec,
    // which does not include anything set by pre_exec. Using libc::setenv
    // modifies the actual process environ which *is* inherited by exec when
    // no custom envp is provided.
    //
    // LISTEN_PID must equal the child's PID, which is only known post-fork.
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(|| {
            let pid = std::process::id();
            let pid_str = std::ffi::CString::new(pid.to_string()).unwrap();
            libc::setenv(c"LISTEN_PID".as_ptr(), pid_str.as_ptr(), 1);
            libc::setenv(c"LISTEN_FDS".as_ptr(), c"1".as_ptr(), 1);
            libc::setenv(c"LISTEN_FDNAMES".as_ptr(), c"varlink".as_ptr(), 1);
            Ok(())
        });
    }
    let child = cmd.spawn()?;

    ours.set_nonblocking(true)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let tokio_stream = rt.block_on(async { tokio::net::UnixStream::from_std(ours) })?;
    let zlink_stream = zlink::unix::Stream::from(tokio_stream);
    let conn = zlink::Connection::from(zlink_stream);

    Ok(ActivatedBootc {
        conn,
        rt,
        _child: child,
    })
}

/// Find the bootc binary.
fn which_bootc() -> Result<String> {
    // Prefer BOOTC_TEST_BINARY env var, fall back to resolving via PATH.
    // We always return an absolute path because `varlinkctl exec:` requires one.
    if let Ok(p) = std::env::var("BOOTC_TEST_BINARY") {
        return Ok(p);
    }
    let p = which::which("bootc")
        .map_err(|e| anyhow::anyhow!("bootc not found in PATH: {e}"))?;
    Ok(p.to_string_lossy().into_owned())
}

// ===========================================================================
// Tests: containers.bootc (status)
// ===========================================================================

/// Verify that `GetStatus` returns a JSON object with expected top-level keys.
fn test_varlink_get_status() -> Result<()> {
    let mut bootc = activated_connection()?;
    let reply = bootc
        .rt
        .block_on(async { bootc.conn.get_status().await })??;

    let status = &reply.status;
    assert!(status.is_object(), "status should be a JSON object");
    // The Host type always has apiVersion and kind
    assert!(
        status.get("apiVersion").is_some(),
        "status should have apiVersion"
    );
    assert!(status.get("kind").is_some(), "status should have kind");
    assert!(status.get("status").is_some(), "status should have status");
    Ok(())
}

/// Verify that the status `kind` is `BootcHost`.
fn test_varlink_status_kind() -> Result<()> {
    let mut bootc = activated_connection()?;
    let reply = bootc
        .rt
        .block_on(async { bootc.conn.get_status().await })??;

    let kind = reply.status.get("kind").and_then(|v| v.as_str());
    assert_eq!(kind, Some("BootcHost"), "kind should be BootcHost");
    Ok(())
}

/// Verify that calling GetStatus twice returns consistent results.
fn test_varlink_status_consistent() -> Result<()> {
    let mut bootc = activated_connection()?;
    let reply1 = bootc
        .rt
        .block_on(async { bootc.conn.get_status().await })??;
    let reply2 = bootc
        .rt
        .block_on(async { bootc.conn.get_status().await })??;

    assert_eq!(
        reply1.status, reply2.status,
        "two consecutive GetStatus calls should return identical results"
    );
    Ok(())
}

// ===========================================================================
// Tests: containers.bootc (GetStatusForSysroot)
// ===========================================================================

/// Verify that `GetStatusForSysroot` with a bad path returns an error.
fn test_varlink_status_for_sysroot_bad_path() -> Result<()> {
    let mut bootc = activated_connection()?;
    let result = bootc.rt.block_on(async {
        bootc
            .conn
            .get_status_for_sysroot("/nonexistent-path-for-varlink-test".into())
            .await
    })?;
    match result {
        Err(BootcError::Failed { .. }) => Ok(()),
        Ok(_) => Err(anyhow::anyhow!(
            "expected Failed error for nonexistent sysroot, got success"
        )),
    }
}

// ===========================================================================
// Tests: containers.bootc.update (upgrade/switch)
// ===========================================================================

/// Verify that `Upgrade` in a non-booted container returns `NotBooted`.
fn test_varlink_upgrade_not_booted() -> Result<()> {
    let mut bootc = activated_connection()?;
    let result = bootc
        .rt
        .block_on(async { bootc.conn.upgrade().await })?;
    match result {
        Err(UpdateError::NotBooted { .. }) => Ok(()),
        Err(other) => Err(anyhow::anyhow!("expected NotBooted, got: {other}")),
        Ok(_) => Err(anyhow::anyhow!(
            "expected NotBooted error, got success"
        )),
    }
}

/// Verify that `Switch` in a non-booted container returns `NotBooted`.
fn test_varlink_switch_not_booted() -> Result<()> {
    let mut bootc = activated_connection()?;
    let result = bootc.rt.block_on(async {
        bootc
            .conn
            .switch("quay.io/example/test:latest".to_string())
            .await
    })?;
    match result {
        Err(UpdateError::NotBooted { .. }) => Ok(()),
        Err(other) => Err(anyhow::anyhow!("expected NotBooted, got: {other}")),
        Ok(_) => Err(anyhow::anyhow!(
            "expected NotBooted error, got success"
        )),
    }
}

// ===========================================================================
// Tests: containers.bootc.install
// ===========================================================================

/// Verify that `GetConfiguration` returns a JSON object.
fn test_varlink_get_configuration() -> Result<()> {
    let mut bootc = activated_connection()?;
    let reply = bootc
        .rt
        .block_on(async { bootc.conn.get_configuration().await })??;

    let config = &reply.config;
    assert!(
        config.is_object(),
        "config should be a JSON object, got: {config}"
    );
    Ok(())
}

/// Verify that `ToDisk` with a nonexistent device returns `Failed`.
fn test_varlink_to_disk_bad_device() -> Result<()> {
    let mut bootc = activated_connection()?;
    let result = bootc.rt.block_on(async {
        bootc
            .conn
            .to_disk(ToDiskOpts {
                device: "/dev/nonexistent-device-for-varlink-test".into(),
                ..Default::default()
            })
            .await
    })?;
    match result {
        Err(InstallError::Failed { .. }) => Ok(()),
        Ok(_) => Err(anyhow::anyhow!(
            "expected Failed error for nonexistent device, got success"
        )),
    }
}

// ===========================================================================
// Tests: varlinkctl exec: (if available)
// ===========================================================================

/// Verify that `varlinkctl introspect exec:bootc` works for all interfaces.
///
/// This validates that socket activation works end-to-end with varlinkctl.
/// We use `introspect` rather than `call` because systemd's varlinkctl
/// sends method calls with an empty `parameters: {}` key even for
/// zero-argument methods, which zlink's deserializer rejects. This is
/// a varlinkctl/zlink interop issue tracked upstream. The socketpair-based
/// tests above cover actual method calls comprehensively.
fn test_varlink_introspect_varlinkctl() -> Result<()> {
    if which::which("varlinkctl").is_err() {
        eprintln!("skipping varlinkctl introspect test: varlinkctl not found in PATH");
        return Ok(());
    }

    let bootc_path = which_bootc()?;
    let sh = xshell::Shell::new()?;

    for iface in [
        "containers.bootc",
        "containers.bootc.update",
        "containers.bootc.install",
    ] {
        let output = xshell::cmd!(
            sh,
            "varlinkctl introspect exec:{bootc_path} {iface}"
        )
        .read()?;
        assert!(
            output.contains(iface),
            "introspect output missing '{iface}'"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Test registration
// ---------------------------------------------------------------------------

fn new_test(description: &'static str, f: fn() -> Result<()>) -> Trial {
    Trial::test(description, move || f().map_err(Into::into))
}

/// All varlink integration tests, suitable for running in a container
/// environment (non-destructive).
pub(crate) fn tests() -> Vec<Trial> {
    vec![
        new_test("varlink get-status", test_varlink_get_status),
        new_test("varlink status-kind", test_varlink_status_kind),
        new_test("varlink status-consistent", test_varlink_status_consistent),
        new_test(
            "varlink status-for-sysroot-bad-path",
            test_varlink_status_for_sysroot_bad_path,
        ),
        new_test(
            "varlink upgrade-not-booted",
            test_varlink_upgrade_not_booted,
        ),
        new_test(
            "varlink switch-not-booted",
            test_varlink_switch_not_booted,
        ),
        new_test(
            "varlink get-configuration",
            test_varlink_get_configuration,
        ),
        new_test(
            "varlink to-disk-bad-device",
            test_varlink_to_disk_bad_device,
        ),
        new_test(
            "varlink introspect-varlinkctl",
            test_varlink_introspect_varlinkctl,
        ),
    ]
}
