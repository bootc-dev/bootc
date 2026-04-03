//! Varlink IPC interface for bootc.
//!
//! Exposes bootc operations over a Unix domain socket using the Varlink
//! protocol. Three interfaces are provided:
//!
//! - `containers.bootc` -- query host status
//! - `containers.bootc.update` -- upgrade or switch images with streaming
//!   progress notifications via varlink `more`/`continues`
//! - `containers.bootc.install` -- install bootc to disk/filesystem
//!
//! The progress streaming subsumes the experimental `--progress-fd` API:
//! when a client sends `{"more": true}`, intermediate replies carry progress
//! events (byte-level and step-level), and the final reply carries the
//! completion result.
//!
//! The server supports socket activation: when `LISTEN_FDS` is set (e.g. via
//! `varlinkctl exec:`), it serves on the inherited fd 3.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Reply types for containers.bootc
// ---------------------------------------------------------------------------

/// Reply for the `GetStatus` method.
///
/// Returns the full host status as a JSON object, matching the structure
/// of `bootc status --json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GetStatusReply {
    /// The full host status object (same schema as `bootc status --json`).
    status: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Reply types for containers.bootc.update
// ---------------------------------------------------------------------------

/// Per-subtask byte-level progress (e.g. a single container image layer).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SubTaskBytes {
    /// Machine-readable subtask type (e.g. "ostree_chunk").
    subtask: String,
    /// Human-readable description.
    description: String,
    /// Subtask identifier (e.g. layer digest).
    id: String,
    /// Bytes fetched from cache.
    bytes_cached: u64,
    /// Bytes fetched so far.
    bytes: u64,
    /// Total bytes.
    bytes_total: u64,
}

/// Per-subtask step-level progress (e.g. a discrete operation phase).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SubTaskStep {
    /// Machine-readable subtask type.
    subtask: String,
    /// Human-readable description.
    description: String,
    /// Subtask identifier.
    id: String,
    /// Whether this subtask has completed.
    completed: bool,
}

/// Progress event for byte-level transfers (e.g. pulling image layers).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProgressBytes {
    /// Machine-readable task type (e.g. "pulling").
    task: String,
    /// Human-readable description.
    description: String,
    /// Unique task identifier (e.g. image name).
    id: String,
    /// Bytes fetched from cache.
    bytes_cached: u64,
    /// Bytes fetched so far.
    bytes: u64,
    /// Total bytes (0 if unknown).
    bytes_total: u64,
    /// Steps fetched from cache.
    steps_cached: u64,
    /// Steps completed so far.
    steps: u64,
    /// Total steps.
    steps_total: u64,
    /// Per-layer subtask progress.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    subtasks: Vec<SubTaskBytes>,
}

/// Progress event for discrete steps (e.g. staging, deploying).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProgressSteps {
    /// Machine-readable task type.
    task: String,
    /// Human-readable description.
    description: String,
    /// Unique task identifier.
    id: String,
    /// Steps fetched from cache.
    steps_cached: u64,
    /// Steps completed so far.
    steps: u64,
    /// Total steps.
    steps_total: u64,
    /// Per-phase subtask progress.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    subtasks: Vec<SubTaskStep>,
}

/// A progress notification sent as an intermediate `continues` reply
/// during `Upgrade` or `Switch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub(crate) enum ProgressEvent {
    /// Byte-level progress (e.g. layer downloads).
    Bytes(ProgressBytes),
    /// Step-level progress (e.g. staging phases).
    Steps(ProgressSteps),
}

/// Reply for the `Upgrade` and `Switch` methods.
///
/// When called with `more: true`, intermediate replies carry `progress`
/// events (with `continues: true`). The final reply carries `result`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct UpdateReply {
    /// Present on intermediate `continues` replies: a progress event.
    #[serde(skip_serializing_if = "Option::is_none")]
    progress: Option<ProgressEvent>,
    /// Present on the final reply: the result summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<UpdateResult>,
}

/// The final result of an upgrade or switch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdateResult {
    /// Whether a new deployment was staged.
    staged: bool,
    /// Whether no changes were needed (already at the target image).
    no_change: bool,
    /// Human-readable message.
    message: String,
}

// ---------------------------------------------------------------------------
// Reply types for containers.bootc.install
// ---------------------------------------------------------------------------

/// Reply for the `GetConfiguration` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GetConfigurationReply {
    /// The merged install configuration as a JSON object.
    /// Same schema as `bootc install print-configuration --all`.
    config: serde_json::Value,
}

/// Reply for the install methods (`ToDisk`, `ToFilesystem`, `ToExistingRoot`).
///
/// When called with varlink `more: true`, intermediate replies may carry
/// `progress` events. The final reply carries `result`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct InstallReply {
    /// Present on intermediate `continues` replies: a progress event.
    #[serde(skip_serializing_if = "Option::is_none")]
    progress: Option<ProgressEvent>,
    /// Present on the final reply: the install result.
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<InstallResult>,
}

/// The final result of an install operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InstallResult {
    /// Whether installation completed successfully.
    success: bool,
    /// Human-readable message.
    message: String,
}

/// Options for `ToDisk`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, zlink::introspect::Type)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ToDiskOpts {
    /// Block device or file path (e.g. "/dev/vda").
    device: String,
    /// Source image reference (optional; defaults to current container image).
    source_imgref: Option<String>,
    /// Target image reference for subsequent updates.
    target_imgref: Option<String>,
    /// Use loopback mode (device is a regular file, not a block device).
    #[serde(default)]
    via_loopback: bool,
    /// Additional kernel arguments.
    #[serde(default)]
    kargs: Vec<String>,
    /// Root filesystem type (e.g. "xfs", "ext4", "btrfs").
    root_fs_type: Option<String>,
    /// Disable SELinux in the installed system.
    #[serde(default)]
    disable_selinux: bool,
    /// Produce a generic disk image (installs all bootloader types, skips firmware).
    #[serde(default)]
    generic_image: bool,
    /// Use the composefs backend.
    #[serde(default)]
    composefs_backend: bool,
}

/// Options for `ToFilesystem`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, zlink::introspect::Type)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ToFilesystemOpts {
    /// Path to the mounted root filesystem.
    root_path: String,
    /// Source device specification for the root filesystem (e.g. "UUID=...").
    root_mount_spec: Option<String>,
    /// Mount specification for /boot.
    boot_mount_spec: Option<String>,
    /// Source image reference.
    source_imgref: Option<String>,
    /// Target image reference.
    target_imgref: Option<String>,
    /// Additional kernel arguments.
    #[serde(default)]
    kargs: Vec<String>,
    /// Disable SELinux in the installed system.
    #[serde(default)]
    disable_selinux: bool,
    /// Skip filesystem finalization (fstrim, remount-ro).
    #[serde(default)]
    skip_finalize: bool,
    /// Use the composefs backend.
    #[serde(default)]
    composefs_backend: bool,
}

/// Options for `ToExistingRoot`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, zlink::introspect::Type)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ToExistingRootOpts {
    /// Path to the existing root filesystem.
    root_path: Option<String>,
    /// Source image reference.
    source_imgref: Option<String>,
    /// Target image reference.
    target_imgref: Option<String>,
    /// Additional kernel arguments.
    #[serde(default)]
    kargs: Vec<String>,
    /// Disable SELinux in the installed system.
    #[serde(default)]
    disable_selinux: bool,
    /// Acknowledge destructive operation.
    #[serde(default)]
    acknowledge_destructive: bool,
    /// Enable destructive cleanup service.
    #[serde(default)]
    cleanup: bool,
    /// Use the composefs backend.
    #[serde(default)]
    composefs_backend: bool,
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors returned by the `containers.bootc` interface.
#[derive(Debug, zlink::ReplyError, zlink::introspect::ReplyError)]
#[zlink(interface = "containers.bootc")]
enum BootcError {
    /// A general failure.
    Failed {
        /// Human-readable error description.
        message: String,
    },
}

/// Errors returned by the `containers.bootc.update` interface.
#[derive(Debug, zlink::ReplyError, zlink::introspect::ReplyError)]
#[zlink(interface = "containers.bootc.update")]
enum UpdateError {
    /// The operation failed.
    Failed {
        /// Human-readable error description.
        message: String,
    },
    /// The system is not booted into a bootc-managed deployment.
    NotBooted {
        /// Human-readable error description.
        message: String,
    },
}

/// Errors returned by the `containers.bootc.install` interface.
#[derive(Debug, zlink::ReplyError, zlink::introspect::ReplyError)]
#[zlink(interface = "containers.bootc.install")]
enum InstallError {
    /// The operation failed.
    Failed {
        /// Human-readable error description.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Service implementation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Helpers for constructing install option structs
// ---------------------------------------------------------------------------

/// Convert varlink kargs (list of strings) to the internal representation.
fn make_kargs(kargs: Vec<String>) -> Option<Vec<bootc_kernel_cmdline::utf8::CmdlineOwned>> {
    if kargs.is_empty() {
        None
    } else {
        Some(
            kargs
                .into_iter()
                .map(bootc_kernel_cmdline::utf8::CmdlineOwned::from)
                .collect(),
        )
    }
}

/// Build `InstallTargetOpts` from the common varlink fields.
fn make_target_opts(
    target_imgref: Option<String>,
) -> crate::install::InstallTargetOpts {
    crate::install::InstallTargetOpts {
        target_transport: "registry".into(),
        target_imgref,
        target_no_signature_verification: false,
        enforce_container_sigpolicy: false,
        run_fetch_check: false,
        skip_fetch_check: false,
        unified_storage_exp: false,
    }
}

/// Build `InstallConfigOpts` from the common varlink fields.
fn make_config_opts(
    kargs: Vec<String>,
    disable_selinux: bool,
    generic_image: bool,
) -> crate::install::InstallConfigOpts {
    crate::install::InstallConfigOpts {
        disable_selinux,
        karg: make_kargs(kargs),
        root_ssh_authorized_keys: None,
        generic_image,
        bound_images: Default::default(),
        stateroot: None,
        bootupd_skip_boot_uuid: false,
        bootloader: None,
    }
}

// ---------------------------------------------------------------------------
// Service implementation
// ---------------------------------------------------------------------------

/// Combined varlink service for bootc.
#[derive(Debug)]
struct BootcService;

/// Version of the varlink API (independent of bootc version).
#[cfg(test)]
const VARLINK_API_VERSION: &str = "0.1.0";

#[zlink::service(
    interface = "containers.bootc",
    vendor = "containers.bootc",
    product = "bootc",
    version = "0.1.0",
    url = "https://github.com/bootc-dev/bootc"
)]
impl BootcService {
    /// Get the current host status.
    ///
    /// Returns the same information as `bootc status --json`.
    async fn get_status(&self) -> Result<GetStatusReply, BootcError> {
        let host = crate::status::get_host().await.map_err(|e| {
            BootcError::Failed {
                message: format!("{e:#}"),
            }
        })?;

        let status = serde_json::to_value(&host).map_err(|e| BootcError::Failed {
            message: format!("serialization error: {e:#}"),
        })?;

        Ok(GetStatusReply { status })
    }

    /// Get the status of a sysroot at an arbitrary path.
    ///
    /// This allows callers to query the deployment state of a freshly
    /// installed (not yet booted) sysroot.  The returned status uses
    /// the same schema as `bootc status --json`, with `booted` and
    /// `staged` set to `null` and deployments in `otherDeployments`.
    ///
    /// Typical use: install via `containers.bootc.install.ToDisk`, then
    /// call `GetStatusForSysroot` with the mount point to discover the
    /// deployment path, image digest, stateroot, etc.
    async fn get_status_for_sysroot(
        &self,
        sysroot_path: String,
    ) -> Result<GetStatusReply, BootcError> {
        let sysroot_path: camino::Utf8PathBuf = sysroot_path.into();
        let host =
            crate::status::get_host_from_sysroot(&sysroot_path).map_err(|e| BootcError::Failed {
                message: format!("{e:#}"),
            })?;

        let status = serde_json::to_value(&host).map_err(|e| BootcError::Failed {
            message: format!("serialization error: {e:#}"),
        })?;

        Ok(GetStatusReply { status })
    }

    /// Upgrade to a newer version of the current image.
    ///
    /// When called with varlink `more: true`, intermediate replies stream
    /// progress events via `continues`. The final reply carries the result.
    ///
    /// This method currently returns an error indicating it requires a
    /// booted host; the streaming progress implementation will be wired
    /// up once the core upgrade path supports a callback-based progress
    /// interface.
    #[zlink(interface = "containers.bootc.update")]
    async fn upgrade(&self) -> Result<UpdateReply, UpdateError> {
        // For now, we return a clear error that this is not yet wired to
        // the actual upgrade path. The Status method is the primary
        // deliverable; upgrade will be connected in a follow-up.
        Err(UpdateError::NotBooted {
            message: "varlink upgrade requires a booted host system".into(),
        })
    }

    /// Switch to a different container image.
    ///
    /// When called with varlink `more: true`, intermediate replies stream
    /// progress events. The final reply carries the result.
    #[zlink(interface = "containers.bootc.update")]
    async fn switch(&self, target: String) -> Result<UpdateReply, UpdateError> {
        let _ = target;
        Err(UpdateError::NotBooted {
            message: "varlink switch requires a booted host system".into(),
        })
    }

    /// Get the merged install configuration.
    ///
    /// Returns the same information as `bootc install print-configuration --all`.
    #[zlink(interface = "containers.bootc.install")]
    async fn get_configuration(&self) -> Result<GetConfigurationReply, InstallError> {
        let config = crate::install::config::load_config()
            .map_err(|e| InstallError::Failed {
                message: format!("{e:#}"),
            })?
            .unwrap_or_default();

        let config = serde_json::to_value(&config).map_err(|e| InstallError::Failed {
            message: format!("serialization error: {e:#}"),
        })?;

        Ok(GetConfigurationReply { config })
    }

    /// Install bootc to a block device or loopback file.
    ///
    /// This is the varlink equivalent of `bootc install to-disk`. It is a
    /// long-running operation; when called with `more: true`, intermediate
    /// replies may stream progress events.
    #[zlink(interface = "containers.bootc.install")]
    #[cfg(feature = "install-to-disk")]
    async fn to_disk(&self, opts: ToDiskOpts) -> Result<InstallReply, InstallError> {
        use crate::install::*;

        let filesystem = opts
            .root_fs_type
            .as_deref()
            .map(config::Filesystem::try_from)
            .transpose()
            .map_err(|e| InstallError::Failed {
                message: format!("{e:#}"),
            })?;

        let install_opts = InstallToDiskOpts {
            block_opts: baseline::InstallBlockDeviceOpts {
                device: opts.device.into(),
                wipe: false,
                block_setup: None,
                filesystem,
                root_size: None,
            },
            source_opts: InstallSourceOpts {
                source_imgref: opts.source_imgref,
            },
            target_opts: make_target_opts(opts.target_imgref),
            config_opts: make_config_opts(
                opts.kargs,
                opts.disable_selinux,
                opts.generic_image,
            ),
            via_loopback: opts.via_loopback,
            composefs_opts: InstallComposefsOpts {
                composefs_backend: opts.composefs_backend,
                ..Default::default()
            },
        };

        install_to_disk(install_opts)
            .await
            .map_err(|e| InstallError::Failed {
                message: format!("{e:#}"),
            })?;

        Ok(InstallReply {
            progress: None,
            result: Some(InstallResult {
                success: true,
                message: "Installation complete".into(),
            }),
        })
    }

    /// Install bootc to a pre-mounted filesystem.
    ///
    /// This is the varlink equivalent of `bootc install to-filesystem`.
    #[zlink(interface = "containers.bootc.install")]
    async fn to_filesystem(&self, opts: ToFilesystemOpts) -> Result<InstallReply, InstallError> {
        use crate::install::*;

        let install_opts = InstallToFilesystemOpts {
            filesystem_opts: InstallTargetFilesystemOpts {
                root_path: opts.root_path.into(),
                root_mount_spec: opts.root_mount_spec,
                boot_mount_spec: opts.boot_mount_spec,
                replace: None,
                acknowledge_destructive: false,
                skip_finalize: opts.skip_finalize,
            },
            source_opts: InstallSourceOpts {
                source_imgref: opts.source_imgref,
            },
            target_opts: make_target_opts(opts.target_imgref),
            config_opts: make_config_opts(opts.kargs, opts.disable_selinux, false),
            composefs_opts: InstallComposefsOpts {
                composefs_backend: opts.composefs_backend,
                ..Default::default()
            },
        };

        install_to_filesystem(install_opts, false, Cleanup::Skip)
            .await
            .map_err(|e| InstallError::Failed {
                message: format!("{e:#}"),
            })?;

        Ok(InstallReply {
            progress: None,
            result: Some(InstallResult {
                success: true,
                message: "Installation complete".into(),
            }),
        })
    }

    /// Install bootc to an existing root filesystem.
    ///
    /// This is the varlink equivalent of `bootc install to-existing-root`.
    #[zlink(interface = "containers.bootc.install")]
    async fn to_existing_root(
        &self,
        opts: ToExistingRootOpts,
    ) -> Result<InstallReply, InstallError> {
        use crate::install::*;

        let install_opts = InstallToExistingRootOpts {
            replace: Some(ReplaceMode::Alongside),
            source_opts: InstallSourceOpts {
                source_imgref: opts.source_imgref,
            },
            target_opts: make_target_opts(opts.target_imgref),
            config_opts: make_config_opts(opts.kargs, opts.disable_selinux, false),
            acknowledge_destructive: opts.acknowledge_destructive,
            cleanup: opts.cleanup,
            root_path: opts
                .root_path
                .unwrap_or_else(|| "/target".to_string())
                .into(),
            composefs_opts: InstallComposefsOpts {
                composefs_backend: opts.composefs_backend,
                ..Default::default()
            },
        };

        install_to_existing_root(install_opts)
            .await
            .map_err(|e| InstallError::Failed {
                message: format!("{e:#}"),
            })?;

        Ok(InstallReply {
            progress: None,
            result: Some(InstallResult {
                success: true,
                message: "Installation complete".into(),
            }),
        })
    }
}

// ---------------------------------------------------------------------------
// Client-side proxy traits
// ---------------------------------------------------------------------------

/// Proxy for the `containers.bootc` interface (status queries).
#[allow(dead_code)]
#[zlink::proxy("containers.bootc")]
trait BootcProxy {
    /// Get the current host status.
    async fn get_status(&mut self) -> zlink::Result<Result<GetStatusReply, BootcError>>;

    /// Get the status of a sysroot at an arbitrary path.
    async fn get_status_for_sysroot(
        &mut self,
        sysroot_path: String,
    ) -> zlink::Result<Result<GetStatusReply, BootcError>>;
}

/// Proxy for the `containers.bootc.update` interface (upgrade/switch).
#[allow(dead_code)]
#[zlink::proxy("containers.bootc.update")]
trait UpdateProxy {
    /// Upgrade to a newer version of the current image.
    async fn upgrade(&mut self) -> zlink::Result<Result<UpdateReply, UpdateError>>;

    /// Switch to a different container image.
    async fn switch(
        &mut self,
        target: String,
    ) -> zlink::Result<Result<UpdateReply, UpdateError>>;
}

/// Proxy for the `containers.bootc.install` interface.
#[allow(dead_code)]
#[zlink::proxy("containers.bootc.install")]
trait InstallProxy {
    /// Get the merged install configuration.
    async fn get_configuration(
        &mut self,
    ) -> zlink::Result<Result<GetConfigurationReply, InstallError>>;

    /// Install to a block device.
    #[cfg(feature = "install-to-disk")]
    async fn to_disk(
        &mut self,
        opts: ToDiskOpts,
    ) -> zlink::Result<Result<InstallReply, InstallError>>;

    /// Install to a pre-mounted filesystem.
    async fn to_filesystem(
        &mut self,
        opts: ToFilesystemOpts,
    ) -> zlink::Result<Result<InstallReply, InstallError>>;

    /// Install to an existing root.
    async fn to_existing_root(
        &mut self,
        opts: ToExistingRootOpts,
    ) -> zlink::Result<Result<InstallReply, InstallError>>;
}

// ---------------------------------------------------------------------------
// Socket activation
// ---------------------------------------------------------------------------

/// A `Listener` that yields a single pre-connected socket, then blocks forever.
///
/// Used for `varlinkctl exec:` activation where a connected socket pair is
/// passed on fd 3. After the first `accept()` returns the connection, subsequent
/// calls pend indefinitely.
#[derive(Debug)]
struct ActivatedListener {
    /// The connection to yield on the first accept(), consumed after use.
    conn: Option<zlink::Connection<zlink::unix::Stream>>,
}

impl zlink::Listener for ActivatedListener {
    type Socket = zlink::unix::Stream;

    async fn accept(&mut self) -> zlink::Result<zlink::Connection<Self::Socket>> {
        match self.conn.take() {
            Some(conn) => Ok(conn),
            None => std::future::pending().await,
        }
    }
}

/// Try to build an [`ActivatedListener`] from a socket-activated fd.
///
/// Uses `libsystemd` to receive file descriptors passed by the service
/// manager (checks `LISTEN_FDS`/`LISTEN_PID` and clears the env vars).
/// Returns `None` when the process was not socket-activated.
#[allow(unsafe_code)]
fn try_activated_listener() -> anyhow::Result<Option<ActivatedListener>> {
    use std::os::fd::{FromRawFd as _, IntoRawFd as _};

    let fds = libsystemd::activation::receive_descriptors(true)
        .map_err(|e| anyhow::anyhow!("Failed to receive activation fds: {e}"))?;

    let fd = match fds.into_iter().next() {
        Some(fd) => fd,
        None => return Ok(None),
    };

    // SAFETY: `libsystemd::activation::receive_descriptors(true)` validated
    // the fd and transferred ownership. `into_raw_fd()` consumes the
    // `FileDescriptor` wrapper, giving us sole ownership of a valid fd.
    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd.into_raw_fd()) };
    std_stream.set_nonblocking(true)?;
    let tokio_stream = tokio::net::UnixStream::from_std(std_stream)?;
    let zlink_stream = zlink::unix::Stream::from(tokio_stream);
    let conn = zlink::Connection::from(zlink_stream);
    Ok(Some(ActivatedListener { conn: Some(conn) }))
}

/// If the process was socket-activated, serve varlink and return `true`.
///
/// This follows the systemd/varlink activation pattern: if the process was
/// invoked with an activated socket (e.g. via `varlinkctl exec:`), it serves
/// varlink on that socket and returns `true` so the caller can exit.
/// Otherwise returns `false` and the process continues with normal CLI
/// handling.
pub(crate) async fn try_serve_varlink() -> anyhow::Result<bool> {
    let listener = match try_activated_listener()? {
        Some(l) => l,
        None => return Ok(false),
    };

    tracing::debug!("Socket activation detected, serving varlink");
    let server = zlink::Server::new(listener, BootcService);
    tokio::select! {
        result = server.run() => result?,
        _ = tokio::signal::ctrl_c() => {
            tracing::debug!("Shutting down varlink server (activated)");
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::VARLINK_API_VERSION;

    #[test]
    fn varlink_version_is_consistent() {
        // The version in the #[zlink::service] attribute must match
        // VARLINK_API_VERSION. zlink doesn't allow consts in attribute
        // position, so this test catches drift.
        assert_eq!(
            VARLINK_API_VERSION, "0.1.0",
            "VARLINK_API_VERSION must match the #[zlink::service] version attribute"
        );
    }
}
