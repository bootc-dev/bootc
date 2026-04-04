//! Async podman client using the native libpod API.
//!
//! Provides a high-level interface for pulling container images through
//! podman's native libpod HTTP API, enabling streaming per-blob byte-level
//! progress display. The transient `podman system service` is started
//! against bootc's custom storage root and automatically torn down.

use std::collections::HashMap;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use bootc_utils::AsyncCommandRunExt;
use cap_std_ext::cap_std::fs::Dir;
use fn_error_context::context;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use tokio::io::AsyncBufReadExt;

/// Podman libpod API version to use.
const LIBPOD_API_VERSION: &str = "v5.0.0";

/// A report object from podman's native image pull endpoint.
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct ImagePullReport {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    stream: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    images: Option<Vec<String>>,
    #[serde(default)]
    id: Option<String>,
    #[serde(rename = "pullProgress", default)]
    pull_progress: Option<ArtifactPullProgress>,
}

/// Per-blob download progress from podman's native pull API.
#[derive(Debug, serde::Deserialize)]
struct ArtifactPullProgress {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    current: u64,
    #[serde(default)]
    total: i64,
    #[serde(rename = "progressComponentID", default)]
    progress_component_id: String,
}

/// Manages a transient podman service, providing HTTP access to the
/// native libpod API via a Unix socket.
pub(crate) struct PodmanClient {
    service_child: tokio::process::Child,
    /// Filesystem path to the socket.
    socket_path: String,
    /// Stored for subprocess fallback when the image transport is not
    /// supported by the libpod HTTP API (which only handles `docker:`).
    sysroot: Dir,
    storage_root: Dir,
    run_root: Dir,
}

impl PodmanClient {
    /// Start a transient `podman system service` pointing at the given
    /// storage root and connect to it.
    ///
    /// Registry auth is configured via `REGISTRY_AUTH_FILE` on the
    /// podman service process, using the same bootc/ostree auth as
    /// existing podman CLI invocations.
    //
    // TODO: Eliminate the socket-path polling by passing a pre-created
    // listener via the systemd LISTEN_FDS protocol (podman supports
    // this when a URI is provided and LISTEN_FDS is set — it calls
    // `os.NewFile(3)` + `net.FileListener` instead of `net.Listen`).
    //
    // The blocker is that `bind_storage_roots()` hardcodes the runroot
    // fd at STORAGE_RUN_FD=3, which conflicts with LISTEN_FDS's
    // requirement that the listener be at fd 3.  Podman also stores
    // the runroot path (`/proc/self/fd/3`) in its on-disk database
    // (bolt_state.db), so changing the fd number for the API service
    // causes a "database configuration mismatch" error.
    //
    // Fixing this requires either:
    //   (a) Changing STORAGE_RUN_FD to a higher number globally (breaks
    //       existing installed systems whose DB has /proc/self/fd/3),
    //   (b) Using a separate runroot path for the transient API service
    //       (e.g. /run/bootc/api-run) that doesn't conflict, or
    //   (c) Upstream podman change to support LISTEN_FDS at arbitrary
    //       fd numbers (not just fd 3).
    #[context("Connecting to podman API")]
    pub(crate) async fn connect(sysroot: &Dir, storage_root: &Dir, run_root: &Dir) -> Result<Self> {
        use crate::podstorage::STORAGE_ALIAS_DIR;

        let socket_path = "/run/bootc/podman-api.sock".to_owned();
        std::fs::create_dir_all("/run/bootc/").ok();
        let _ = std::fs::remove_file(&socket_path);

        let mut cmd = std::process::Command::new("podman");
        crate::podstorage::bind_storage_roots(&mut cmd, storage_root, run_root)?;
        crate::podstorage::setup_auth(&mut cmd, sysroot)?;

        let run_root_arg = format!("/proc/self/fd/{}", crate::podstorage::STORAGE_RUN_FD);
        let socket_uri = format!("unix://{socket_path}");
        cmd.args([
            "--root",
            STORAGE_ALIAS_DIR,
            "--runroot",
            &run_root_arg,
            "system",
            "service",
            "--time=0",
            &socket_uri,
        ]);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::piped());

        tracing::debug!("Starting podman API service at {socket_path}");
        let mut child = tokio::process::Command::from(cmd)
            .spawn()
            .context("Spawning podman system service")?;

        // Poll for the socket to appear, checking for early exit.
        for _ in 0..50 {
            if let Some(status) = child.try_wait()? {
                let mut stderr_msg = String::new();
                if let Some(mut stderr) = child.stderr.take() {
                    use tokio::io::AsyncReadExt;
                    stderr.read_to_string(&mut stderr_msg).await.ok();
                }
                anyhow::bail!("Podman API service exited with {status}: {stderr_msg}");
            }
            if std::path::Path::new(&socket_path).exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if !std::path::Path::new(&socket_path).exists() {
            anyhow::bail!("Podman API socket did not appear at {socket_path}");
        }

        Ok(Self {
            service_child: child,
            socket_path,
            sysroot: sysroot.try_clone().context("Cloning sysroot")?,
            storage_root: storage_root.try_clone().context("Cloning storage root")?,
            run_root: run_root.try_clone().context("Cloning run root")?,
        })
    }

    /// Pull a container image with streaming progress display.
    ///
    /// Uses the native podman libpod API (`/libpod/images/pull`) which
    /// provides real download progress (bytes transferred) on podman
    /// 5.9+ (see containers/podman#28224). On older podman, status
    /// messages ("Copying blob ...", "Writing manifest ...") are shown
    /// as a spinner.
    ///
    /// The libpod HTTP API only supports the `docker:` transport.  When
    /// the image reference uses a different transport (`oci:`, `dir:`,
    /// `containers-storage:`, etc.) we fall back to invoking `podman pull`
    /// as a subprocess with the same storage and auth configuration.
    ///
    /// Registry authentication is handled by the podman service process
    /// via `REGISTRY_AUTH_FILE`, configured at connect() time.
    #[context("Pulling image via podman API: {image}")]
    pub(crate) async fn pull_with_progress(&self, image: &str) -> Result<()> {
        if uses_non_docker_transport(image) {
            return self.pull_via_subprocess(image).await;
        }
        self.pull_via_api(image).await
    }

    /// Pull using the libpod HTTP API (docker transport only).
    async fn pull_via_api(&self, image: &str) -> Result<()> {
        let stream = tokio::net::UnixStream::connect(&self.socket_path)
            .await
            .context("Connecting to podman API socket")?;
        let io = hyper_util::rt::TokioIo::new(stream);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("HTTP/1.1 handshake with podman")?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::warn!("Podman HTTP connection error: {e}");
            }
        });

        let encoded_ref =
            percent_encoding::utf8_percent_encode(image, percent_encoding::NON_ALPHANUMERIC);
        let uri = format!(
            "/{LIBPOD_API_VERSION}/libpod/images/pull?reference={encoded_ref}&pullProgress=true&policy=always"
        );

        tracing::debug!("POST {uri}");
        let response = sender
            .send_request(
                hyper::Request::builder()
                    .method(hyper::Method::POST)
                    .uri(&uri)
                    .header(hyper::header::HOST, "d")
                    .body(http_body_util::Empty::<hyper::body::Bytes>::new())
                    .context("Building pull request")?,
            )
            .await
            .context("Sending pull request to podman")?;

        let status = response.status();
        if !status.is_success() {
            let body = response
                .into_body()
                .collect()
                .await
                .context("Reading error response body")?
                .to_bytes();
            anyhow::bail!(
                "Podman libpod pull failed with HTTP {status}: {}",
                String::from_utf8_lossy(&body)
            );
        }

        // Turn the HTTP body into an AsyncBufRead so we can use read_line().
        let body_stream =
            http_body_util::BodyStream::new(response.into_body()).filter_map(|r| async {
                match r {
                    Ok(frame) => frame.into_data().ok().map(|b| Ok::<_, std::io::Error>(b)),
                    Err(e) => Some(Err(std::io::Error::other(e))),
                }
            });
        let reader = tokio_util::io::StreamReader::new(body_stream);
        let mut reader = Box::pin(tokio::io::BufReader::new(reader));
        display_pull_progress(&mut reader).await
    }

    /// Fallback: pull via `podman pull` subprocess for non-docker transports.
    ///
    /// The libpod HTTP API only supports `docker:` transport, so transports
    /// like `oci:`, `dir:`, `containers-storage:`, etc. are handled by
    /// shelling out to `podman pull` with the same storage and auth
    /// configuration used by the API service.
    async fn pull_via_subprocess(&self, image: &str) -> Result<()> {
        tracing::debug!(
            "Image uses non-docker transport, falling back to podman pull subprocess: {image}"
        );
        let mut cmd = Command::new("podman");
        crate::podstorage::bind_storage_roots(&mut cmd, &self.storage_root, &self.run_root)?;
        crate::podstorage::setup_auth(&mut cmd, &self.sysroot)?;

        let run_root_arg = format!("/proc/self/fd/{}", crate::podstorage::STORAGE_RUN_FD);
        cmd.args([
            "--root",
            crate::podstorage::STORAGE_ALIAS_DIR,
            "--runroot",
            &run_root_arg,
            "pull",
            image,
        ]);
        cmd.stdin(Stdio::null());

        let mut cmd = tokio::process::Command::from(cmd);
        cmd.run()
            .await
            .context("Pulling image via podman subprocess")?;
        Ok(())
    }
}

/// Non-docker container image transports known to containers/image.
///
/// The libpod HTTP API only supports `docker:` (registry) transport.
/// Any image reference starting with one of these prefixes followed by `:`
/// must be pulled via the `podman pull` CLI instead.
const NON_DOCKER_TRANSPORTS: &[&str] = &[
    "oci:",
    "oci-archive:",
    "dir:",
    "docker-archive:",
    "docker-daemon:",
    "containers-storage:",
];

/// Returns `true` if `image` uses a non-docker transport prefix.
///
/// Plain image names (e.g. `quay.io/example/foo:latest`) and explicit
/// `docker:` references are handled by the libpod HTTP API.  Everything
/// else needs the subprocess fallback.
fn uses_non_docker_transport(image: &str) -> bool {
    NON_DOCKER_TRANSPORTS
        .iter()
        .any(|prefix| image.starts_with(prefix))
}

/// Read NDJSON lines from `reader` and display pull progress.
///
/// Handles two modes:
/// - **Modern podman** (5.9+, with `pullProgress` support): per-blob
///   byte-level progress bars via indicatif
/// - **Older podman** (5.x): shows status messages from the `stream` field
///   ("Copying blob ...", "Writing manifest ...") as a live spinner
async fn display_pull_progress(reader: &mut (impl AsyncBufReadExt + Unpin)) -> Result<()> {
    let mp = MultiProgress::new();
    let mut blob_bars: HashMap<String, ProgressBar> = HashMap::new();
    let mut have_pull_progress = false;

    let download_style = ProgressStyle::default_bar()
        .template(
            "{prefix:.bold} [{bar:30}] {binary_bytes}/{binary_total_bytes} ({binary_bytes_per_sec})",
        )
        .expect("valid template")
        .progress_chars("=> ");

    let spinner_style = ProgressStyle::default_spinner()
        .template("{spinner} {msg}")
        .expect("valid template");

    // A top-level status spinner for stream messages (used on older
    // podman that doesn't emit pullProgress events).
    let status_bar = mp.add(ProgressBar::new_spinner());
    status_bar.set_style(spinner_style.clone());
    status_bar.enable_steady_tick(std::time::Duration::from_millis(100));

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .await
            .context("Reading NDJSON line")?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let report: ImagePullReport = serde_json::from_str(trimmed)
            .with_context(|| format!("Parsing pull report: {trimmed}"))?;

        if let Some(ref err) = report.error {
            status_bar.finish_and_clear();
            anyhow::bail!("Pull error from podman: {err}");
        }

        // Show stream messages ("Copying blob ...", "Writing manifest ...").
        if let Some(ref stream_msg) = report.stream {
            let msg = stream_msg.trim();
            if !msg.is_empty() {
                status_bar.set_message(msg.to_owned());
            }
        }

        // Handle per-blob progress (modern podman with pullProgress=true).
        if let Some(ref progress) = report.pull_progress {
            let blob_id = &progress.progress_component_id;
            if blob_id.is_empty() {
                continue;
            }

            // Once we see pullProgress events, hide the status spinner —
            // the per-blob bars are more informative.
            if !have_pull_progress {
                have_pull_progress = true;
                status_bar.finish_and_clear();
            }

            let short_id = ostree_ext::oci_spec::image::Digest::try_from(blob_id.as_str())
                .map(|d| d.digest().to_owned())
                .unwrap_or_else(|_| blob_id.clone());
            let display_id: String = short_id.chars().take(12).collect();

            match progress.status.as_deref().unwrap_or("") {
                "pulling" => {
                    let bar = blob_bars.entry(blob_id.to_owned()).or_insert_with(|| {
                        let total = if progress.total > 0 {
                            progress.total as u64
                        } else {
                            0
                        };
                        let pb = mp.add(ProgressBar::new(total));
                        pb.set_style(download_style.clone());
                        pb.set_prefix(display_id.clone());
                        pb
                    });
                    if progress.total > 0 {
                        let new_total = progress.total as u64;
                        if bar.length() != Some(new_total) {
                            bar.set_length(new_total);
                        }
                    }
                    bar.set_position(progress.current);
                }
                "success" => {
                    let bar = blob_bars.entry(blob_id.to_owned()).or_insert_with(|| {
                        let pb = mp.add(ProgressBar::new(0));
                        pb.set_prefix(display_id.clone());
                        pb
                    });
                    bar.set_style(spinner_style.clone());
                    bar.set_message("done");
                    bar.finish();
                }
                "skipped" => {
                    let bar = blob_bars.entry(blob_id.to_owned()).or_insert_with(|| {
                        let pb = mp.add(ProgressBar::new(0));
                        pb.set_prefix(display_id.clone());
                        pb
                    });
                    bar.set_style(spinner_style.clone());
                    bar.set_message("Already exists");
                    bar.finish();
                }
                _ => {}
            }
        }
    }

    // Clean up.
    for bar in blob_bars.values() {
        if !bar.is_finished() {
            bar.finish_and_clear();
        }
    }
    if !status_bar.is_finished() {
        status_bar.finish_and_clear();
    }

    Ok(())
}

impl Drop for PodmanClient {
    fn drop(&mut self) {
        let _ = self.service_child.start_kill();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_pull_report_progress() {
        let json = r#"{"status":"pulling","pullProgress":{"status":"pulling","current":12345,"total":98765,"progressComponentID":"sha256:abc123"}}"#;
        let report: ImagePullReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.status.as_deref(), Some("pulling"));
        let progress = report.pull_progress.unwrap();
        assert_eq!(progress.status.as_deref(), Some("pulling"));
        assert_eq!(progress.current, 12345);
        assert_eq!(progress.total, 98765);
        assert_eq!(progress.progress_component_id, "sha256:abc123");
    }

    #[test]
    fn test_deserialize_pull_report_success() {
        let json = r#"{"status":"success","images":["sha256:fullid"],"id":"sha256:fullid"}"#;
        let report: ImagePullReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.status.as_deref(), Some("success"));
        assert_eq!(report.id.as_deref(), Some("sha256:fullid"));
        assert_eq!(
            report.images.as_deref(),
            Some(&["sha256:fullid".to_owned()][..])
        );
    }

    #[test]
    fn test_deserialize_pull_report_skipped() {
        let json = r#"{"status":"pulling","pullProgress":{"status":"skipped","progressComponentID":"sha256:def456"}}"#;
        let report: ImagePullReport = serde_json::from_str(json).unwrap();
        let progress = report.pull_progress.unwrap();
        assert_eq!(progress.status.as_deref(), Some("skipped"));
        assert_eq!(progress.progress_component_id, "sha256:def456");
        assert_eq!(progress.current, 0);
        assert_eq!(progress.total, 0);
    }

    #[test]
    fn test_deserialize_pull_report_error() {
        let json = r#"{"error":"something went wrong"}"#;
        let report: ImagePullReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.error.as_deref(), Some("something went wrong"));
    }

    #[test]
    fn test_uses_non_docker_transport() {
        // Non-docker transports should be detected
        assert!(uses_non_docker_transport("oci:/var/tmp/bootc-oci"));
        assert!(uses_non_docker_transport("oci-archive:/tmp/image.tar"));
        assert!(uses_non_docker_transport("dir:/tmp/image-dir"));
        assert!(uses_non_docker_transport("docker-archive:/tmp/image.tar"));
        assert!(uses_non_docker_transport(
            "docker-daemon:localhost/img:latest"
        ));
        assert!(uses_non_docker_transport(
            "containers-storage:localhost/bootc"
        ));

        // Docker/registry references should NOT be detected
        assert!(!uses_non_docker_transport("quay.io/example/foo:latest"));
        assert!(!uses_non_docker_transport("docker.io/library/nginx:latest"));
        assert!(!uses_non_docker_transport("localhost:5000/myimage:v1"));
        assert!(!uses_non_docker_transport("registry.example.com/img"));
    }
}
