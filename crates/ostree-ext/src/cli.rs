//! # Commandline parsing
//!
//! While there is a separate `ostree-ext-cli` crate that
//! can be installed and used directly, the CLI code is
//! also exported as a library too, so that projects
//! such as `rpm-ostree` can directly reuse it.

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use canon_json::CanonJsonSerialize;
use cap_std::fs::Dir;
use cap_std_ext::cap_std;
use cap_std_ext::prelude::CapStdExtDirExt;
use clap::{Parser, Subcommand};
use fn_error_context::context;
use indexmap::IndexMap;
use io_lifetimes::AsFd;
use ostree::{gio, glib};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::process::Command;
use tokio::sync::mpsc::Receiver;

use crate::chunking::{ObjectMetaSized, ObjectSourceMetaSized};
use crate::commit::container_commit;
use crate::container::store::{ExportToOCIOpts, ImportProgress, LayerProgress, PreparedImport};
use crate::container::{self as ostree_container, ManifestDiff};
use crate::container::{Config, ImageReference, OstreeImageReference};
use crate::objectsource::ObjectSourceMeta;
use crate::sysroot::SysrootLock;
use ostree_container::store::{ImageImporter, PrepareResult};
use serde::{Deserialize, Serialize};

/// Parse an [`OstreeImageReference`] from a CLI argument.
pub fn parse_imgref(s: &str) -> Result<OstreeImageReference> {
    OstreeImageReference::try_from(s)
}

/// Parse a base [`ImageReference`] from a CLI argument.
pub fn parse_base_imgref(s: &str) -> Result<ImageReference> {
    ImageReference::try_from(s)
}

/// Parse an [`ostree::Repo`] from a CLI argument.
pub fn parse_repo(s: &Utf8Path) -> Result<ostree::Repo> {
    let repofd = cap_std::fs::Dir::open_ambient_dir(s, cap_std::ambient_authority())
        .with_context(|| format!("Opening directory at '{s}'"))?;
    ostree::Repo::open_at_dir(repofd.as_fd(), ".")
        .with_context(|| format!("Opening ostree repository at '{s}'"))
}

/// Options for importing a tar archive.
#[derive(Debug, Parser)]
pub(crate) struct ImportOpts {
    /// Path to the repository
    #[clap(long, value_parser)]
    repo: Utf8PathBuf,

    /// Path to a tar archive; if unspecified, will be stdin.  Currently the tar archive must not be compressed.
    path: Option<String>,
}

/// Options for exporting a tar archive.
#[derive(Debug, Parser)]
pub(crate) struct ExportOpts {
    /// Path to the repository
    #[clap(long, value_parser)]
    repo: Utf8PathBuf,

    /// The format version.  Must be 1.
    #[clap(long, hide(true))]
    format_version: u32,

    /// The ostree ref or commit to export
    rev: String,
}

/// Options for import/export to tar archives.
#[derive(Debug, Subcommand)]
pub(crate) enum TarOpts {
    /// Import a tar archive (currently, must not be compressed)
    Import(ImportOpts),

    /// Write a tar archive to stdout
    Export(ExportOpts),
}

/// Options for container import/export.
#[derive(Debug, Subcommand)]
pub(crate) enum ContainerOpts {
    #[clap(alias = "import")]
    /// Import an ostree commit embedded in a remote container image
    Unencapsulate {
        /// Path to the repository
        #[clap(long, value_parser)]
        repo: Utf8PathBuf,

        #[clap(flatten)]
        proxyopts: ContainerProxyOpts,

        /// Image reference, e.g. registry:quay.io/exampleos/exampleos:latest
        #[clap(value_parser = parse_imgref)]
        imgref: OstreeImageReference,

        /// Create an ostree ref pointing to the imported commit
        #[clap(long)]
        write_ref: Option<String>,

        /// Don't display progress
        #[clap(long)]
        quiet: bool,
    },

    /// Print information about an exported ostree-container image.
    Info {
        /// Image reference, e.g. registry:quay.io/exampleos/exampleos:latest
        #[clap(value_parser = parse_imgref)]
        imgref: OstreeImageReference,
    },

    /// Wrap an ostree commit into a container image.
    ///
    /// The resulting container image will have a single layer, which is
    /// very often not what's desired. To handle things more intelligently,
    /// you will need to use (or create) a higher level tool that splits
    /// content into distinct "chunks"; functionality for this is
    /// exposed by the API but not CLI currently.
    #[clap(alias = "export")]
    Encapsulate {
        /// Path to the repository
        #[clap(long, value_parser)]
        repo: Utf8PathBuf,

        /// The ostree ref or commit to export
        rev: String,

        /// Image reference, e.g. registry:quay.io/exampleos/exampleos:latest
        #[clap(value_parser = parse_base_imgref)]
        imgref: ImageReference,

        /// Additional labels for the container
        #[clap(name = "label", long, short)]
        labels: Vec<String>,

        #[clap(long)]
        /// Path to Docker-formatted authentication file.
        authfile: Option<PathBuf>,

        /// Path to a JSON-formatted serialized container configuration; this is the
        /// `config` property of https://github.com/opencontainers/image-spec/blob/main/config.md
        #[clap(long)]
        config: Option<Utf8PathBuf>,

        /// Propagate an OSTree commit metadata key to container label
        #[clap(name = "copymeta", long)]
        copy_meta_keys: Vec<String>,

        /// Propagate an optionally-present OSTree commit metadata key to container label
        #[clap(name = "copymeta-opt", long)]
        copy_meta_opt_keys: Vec<String>,

        /// Corresponds to the Dockerfile `CMD` instruction.
        #[clap(long)]
        cmd: Option<Vec<String>>,

        /// Compress at the fastest level (e.g. gzip level 1)
        #[clap(long)]
        compression_fast: bool,

        /// Path to a JSON-formatted content meta object.
        #[clap(long)]
        contentmeta: Option<Utf8PathBuf>,
    },

    /// Perform build-time checking and canonicalization.
    /// This is presently an optional command, but may become required in the future.
    Commit,

    /// Commands for working with (possibly layered, non-encapsulated) container images.
    #[clap(subcommand)]
    Image(ContainerImageOpts),

    /// Compare the contents of two OCI compliant images.
    Compare {
        /// Image reference, e.g. ostree-remote-image:someremote:registry:quay.io/exampleos/exampleos:latest
        #[clap(value_parser = parse_imgref)]
        imgref_old: OstreeImageReference,

        /// Image reference, e.g. ostree-remote-image:someremote:registry:quay.io/exampleos/exampleos:latest
        #[clap(value_parser = parse_imgref)]
        imgref_new: OstreeImageReference,
    },
}

/// Options for container image fetching.
#[derive(Debug, Parser)]
pub(crate) struct ContainerProxyOpts {
    #[clap(long)]
    /// Do not use default authentication files.
    auth_anonymous: bool,

    #[clap(long)]
    /// Path to Docker-formatted authentication file.
    authfile: Option<PathBuf>,

    #[clap(long)]
    /// Directory with certificates (*.crt, *.cert, *.key) used to connect to registry
    /// Equivalent to `skopeo --cert-dir`
    cert_dir: Option<PathBuf>,

    #[clap(long)]
    /// Skip TLS verification.
    insecure_skip_tls_verification: bool,
}

/// Options for import/export to tar archives.
#[derive(Debug, Subcommand)]
pub(crate) enum ContainerImageOpts {
    /// List container images
    List {
        /// Path to the repository
        #[clap(long, value_parser)]
        repo: Utf8PathBuf,
    },

    /// Pull (or update) a container image.
    Pull {
        /// Path to the repository
        #[clap(value_parser)]
        repo: Utf8PathBuf,

        /// Image reference, e.g. ostree-remote-image:someremote:registry:quay.io/exampleos/exampleos:latest
        #[clap(value_parser = parse_imgref)]
        imgref: OstreeImageReference,

        /// File to which to write the resulting OSTree commit digest
        #[clap(long)]
        ostree_digestfile: Option<Utf8PathBuf>,

        #[clap(flatten)]
        proxyopts: ContainerProxyOpts,

        /// Don't display progress
        #[clap(long)]
        quiet: bool,

        /// Just check for an updated manifest, but do not download associated container layers.
        /// If an updated manifest is found, a file at the provided path will be created and contain
        /// the new manifest.
        #[clap(long)]
        check: Option<Utf8PathBuf>,
    },

    /// Output metadata about an already stored container image.
    History {
        /// Path to the repository
        #[clap(long, value_parser)]
        repo: Utf8PathBuf,

        /// Container image reference, e.g. registry:quay.io/exampleos/exampleos:latest
        #[clap(value_parser = parse_base_imgref)]
        imgref: ImageReference,
    },

    /// Output manifest or configuration for an already stored container image.
    Metadata {
        /// Path to the repository
        #[clap(long, value_parser)]
        repo: Utf8PathBuf,

        /// Container image reference, e.g. registry:quay.io/exampleos/exampleos:latest
        #[clap(value_parser = parse_base_imgref)]
        imgref: ImageReference,

        /// Output the config, not the manifest
        #[clap(long)]
        config: bool,
    },

    /// Remove metadata for a cached update.
    ClearCachedUpdate {
        /// Path to the repository
        #[clap(long, value_parser)]
        repo: Utf8PathBuf,

        /// Container image reference, e.g. registry:quay.io/exampleos/exampleos:latest
        #[clap(value_parser = parse_base_imgref)]
        imgref: ImageReference,
    },

    /// Copy a pulled container image from one repo to another.
    Copy {
        /// Path to the source repository
        #[clap(long, value_parser)]
        src_repo: Utf8PathBuf,

        /// Path to the destination repository
        #[clap(long, value_parser)]
        dest_repo: Utf8PathBuf,

        /// Image reference, e.g. ostree-remote-image:someremote:registry:quay.io/exampleos/exampleos:latest
        #[clap(value_parser = parse_imgref)]
        imgref: OstreeImageReference,
    },

    /// Re-export a fetched image.
    ///
    /// Unlike `encapsulate`, this verb handles layered images, and will
    /// also automatically preserve chunked structure from the fetched image.
    Reexport {
        /// Path to the repository
        #[clap(long, value_parser)]
        repo: Utf8PathBuf,

        /// Source image reference, e.g. registry:quay.io/exampleos/exampleos:latest
        #[clap(value_parser = parse_base_imgref)]
        src_imgref: ImageReference,

        /// Destination image reference, e.g. registry:quay.io/exampleos/exampleos:latest
        #[clap(value_parser = parse_base_imgref)]
        dest_imgref: ImageReference,

        #[clap(long)]
        /// Path to Docker-formatted authentication file.
        authfile: Option<PathBuf>,

        /// Compress at the fastest level (e.g. gzip level 1)
        #[clap(long)]
        compression_fast: bool,
    },

    /// Replace the detached metadata (e.g. to add a signature)
    ReplaceDetachedMetadata {
        /// Path to the source repository
        #[clap(long)]
        #[clap(value_parser = parse_base_imgref)]
        src: ImageReference,

        /// Target image
        #[clap(long)]
        #[clap(value_parser = parse_base_imgref)]
        dest: ImageReference,

        /// Path to file containing new detached metadata; if not provided,
        /// any existing detached metadata will be deleted.
        contents: Option<Utf8PathBuf>,
    },

    /// Unreference one or more pulled container images and perform a garbage collection.
    Remove {
        /// Path to the repository
        #[clap(long, value_parser)]
        repo: Utf8PathBuf,

        /// Image reference, e.g. quay.io/exampleos/exampleos:latest
        #[clap(value_parser = parse_base_imgref)]
        imgrefs: Vec<ImageReference>,

        /// Do not garbage collect unused layers
        #[clap(long)]
        skip_gc: bool,
    },

    /// Garbage collect unreferenced image layer references.
    PruneLayers {
        /// Path to the repository
        #[clap(long, value_parser)]
        repo: Utf8PathBuf,
    },

    /// Garbage collect unreferenced image layer references.
    PruneImages {
        /// Path to the system root
        #[clap(long)]
        sysroot: Utf8PathBuf,

        #[clap(long)]
        /// Also prune layers
        and_layers: bool,

        #[clap(long, conflicts_with = "and_layers")]
        /// Also prune layers and OSTree objects
        full: bool,
    },

    /// Perform initial deployment for a container image
    Deploy {
        /// Path to the system root
        #[clap(long)]
        sysroot: Option<String>,

        /// Name for the state directory, also known as "osname".
        /// If the current system is booted via ostree, then this will default to the booted stateroot.
        /// Otherwise, the default is `default`.
        #[clap(long)]
        stateroot: Option<String>,

        /// Source image reference, e.g. ostree-remote-image:someremote:registry:quay.io/exampleos/exampleos@sha256:abcd...
        /// This conflicts with `--image`.
        /// This conflicts with `--image`. Supports `registry:`, `docker://`, `oci:`, `oci-archive:`, `containers-storage:`, and `dir:`
        #[clap(long, required_unless_present = "image")]
        imgref: Option<String>,

        /// Name of the container image; for the `registry` transport this would be e.g. `quay.io/exampleos/foo:latest`.
        /// This conflicts with `--imgref`.
        #[clap(long, required_unless_present = "imgref")]
        image: Option<String>,

        /// The transport; e.g. registry, oci, oci-archive.  The default is `registry`.
        #[clap(long)]
        transport: Option<String>,

        /// This option does nothing and is now deprecated.  Signature verification enforcement
        /// proved to not be viable.
        ///
        /// If you want to still enforce it, use `--enforce-container-sigpolicy`.
        #[clap(long, conflicts_with = "enforce_container_sigpolicy")]
        no_signature_verification: bool,

        /// Require that the containers-storage stack
        #[clap(long)]
        enforce_container_sigpolicy: bool,

        /// Enable verification via an ostree remote
        #[clap(long)]
        ostree_remote: Option<String>,

        #[clap(flatten)]
        proxyopts: ContainerProxyOpts,

        /// Target image reference, e.g. ostree-remote-image:someremote:registry:quay.io/exampleos/exampleos:latest
        ///
        /// If specified, `--imgref` will be used as a source, but this reference will be emitted into the origin
        /// so that later OS updates pull from it.
        #[clap(long)]
        #[clap(value_parser = parse_imgref)]
        target_imgref: Option<OstreeImageReference>,

        /// If set, only write the layer refs, but not the final container image reference.  This
        /// allows generating a disk image that when booted uses "native ostree", but has layer
        /// references "pre-cached" such that a container image fetch will avoid redownloading
        /// everything.
        #[clap(long)]
        no_imgref: bool,

        #[clap(long)]
        /// Add a kernel argument
        karg: Option<Vec<String>>,

        /// Write the deployed checksum to this file
        #[clap(long)]
        write_commitid_to: Option<Utf8PathBuf>,
    },
}

/// Options for deployment repair.
#[derive(Debug, Parser)]
pub(crate) enum ProvisionalRepairOpts {
    AnalyzeInodes {
        /// Path to the repository
        #[clap(long, value_parser)]
        repo: Utf8PathBuf,

        /// Print additional information
        #[clap(long)]
        verbose: bool,

        /// Serialize the repair result to this file as JSON
        #[clap(long)]
        write_result_to: Option<Utf8PathBuf>,
    },

    Repair {
        /// Path to the sysroot
        #[clap(long, value_parser)]
        sysroot: Utf8PathBuf,

        /// Do not mutate any system state
        #[clap(long)]
        dry_run: bool,

        /// Serialize the repair result to this file as JSON
        #[clap(long)]
        write_result_to: Option<Utf8PathBuf>,

        /// Print additional information
        #[clap(long)]
        verbose: bool,
    },
}

/// Options for the Integrity Measurement Architecture (IMA).
#[derive(Debug, Parser)]
pub(crate) struct ImaSignOpts {
    /// Path to the repository
    #[clap(long, value_parser)]
    repo: Utf8PathBuf,

    /// The ostree ref or commit to use as a base
    src_rev: String,
    /// The ostree ref to use for writing the signed commit
    target_ref: String,

    /// Digest algorithm
    algorithm: String,
    /// Path to IMA key
    key: Utf8PathBuf,

    #[clap(long)]
    /// Overwrite any existing signatures
    overwrite: bool,
}

/// Options for internal testing
#[derive(Debug, Subcommand)]
pub(crate) enum TestingOpts {
    /// Detect the current environment
    DetectEnv,
    /// Generate a test fixture
    CreateFixture,
    /// Execute integration tests, assuming mutable environment
    Run,
    /// Execute IMA tests
    RunIMA,
    FilterTar,
}

/// Options for man page generation
#[derive(Debug, Parser)]
pub(crate) struct ManOpts {
    #[clap(long)]
    /// Output to this directory
    directory: Utf8PathBuf,
}

/// Toplevel options for extended ostree functionality.
#[derive(Debug, Parser)]
#[clap(name = "ostree-ext")]
#[clap(rename_all = "kebab-case")]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Opt {
    /// Import and export to tar
    #[clap(subcommand)]
    Tar(TarOpts),
    /// Import and export to a container image
    #[clap(subcommand)]
    Container(ContainerOpts),
    /// IMA signatures
    ImaSign(ImaSignOpts),
    /// Internal integration testing helpers.
    #[clap(hide(true), subcommand)]
    #[cfg(feature = "internal-testing-api")]
    InternalOnlyForTesting(TestingOpts),
    #[clap(hide(true))]
    #[cfg(feature = "docgen")]
    Man(ManOpts),
    #[clap(hide = true, subcommand)]
    ProvisionalRepair(ProvisionalRepairOpts),
}

#[allow(clippy::from_over_into)]
impl Into<ostree_container::store::ImageProxyConfig> for ContainerProxyOpts {
    fn into(self) -> ostree_container::store::ImageProxyConfig {
        ostree_container::store::ImageProxyConfig {
            auth_anonymous: self.auth_anonymous,
            authfile: self.authfile,
            certificate_directory: self.cert_dir,
            insecure_skip_tls_verification: Some(self.insecure_skip_tls_verification),
            ..Default::default()
        }
    }
}

/// Import a tar archive containing an ostree commit.
async fn tar_import(opts: &ImportOpts) -> Result<()> {
    let repo = parse_repo(&opts.repo)?;
    let imported = if let Some(path) = opts.path.as_ref() {
        let instream = tokio::fs::File::open(path).await?;
        crate::tar::import_tar(&repo, instream, None).await?
    } else {
        let stdin = tokio::io::stdin();
        crate::tar::import_tar(&repo, stdin, None).await?
    };
    println!("Imported: {imported}");
    Ok(())
}

/// Export a tar archive containing an ostree commit.
fn tar_export(opts: &ExportOpts) -> Result<()> {
    let repo = parse_repo(&opts.repo)?;
    #[allow(clippy::needless_update)]
    let subopts = crate::tar::ExportOptions {
        ..Default::default()
    };
    crate::tar::export_commit(&repo, opts.rev.as_str(), std::io::stdout(), Some(subopts))?;
    Ok(())
}

/// Render an import progress notification as a string.
pub fn layer_progress_format(p: &ImportProgress) -> String {
    let (starting, s, layer) = match p {
        ImportProgress::OstreeChunkStarted(v) => (true, "ostree chunk", v),
        ImportProgress::OstreeChunkCompleted(v) => (false, "ostree chunk", v),
        ImportProgress::DerivedLayerStarted(v) => (true, "layer", v),
        ImportProgress::DerivedLayerCompleted(v) => (false, "layer", v),
    };
    // podman outputs 12 characters of digest, let's add 7 for `sha256:`.
    let short_digest = layer
        .digest()
        .digest()
        .chars()
        .take(12 + 7)
        .collect::<String>();
    if starting {
        let size = glib::format_size(layer.size());
        format!("Fetching {s} {short_digest} ({size})")
    } else {
        format!("Fetched {s} {short_digest}")
    }
}

/// Write container fetch progress to standard output.
pub async fn handle_layer_progress_print(
    mut layers: Receiver<ImportProgress>,
    mut layer_bytes: tokio::sync::watch::Receiver<Option<LayerProgress>>,
) {
    let style = indicatif::ProgressStyle::default_bar();
    let pb = indicatif::ProgressBar::new(100);
    pb.set_style(
        style
            .template("{prefix} {bytes} [{bar:20}] ({eta}) {msg}")
            .unwrap(),
    );
    loop {
        tokio::select! {
            // Always handle layer changes first.
            biased;
            layer = layers.recv() => {
                if let Some(l) = layer {
                    if l.is_starting() {
                        pb.set_position(0);
                    } else {
                        pb.finish();
                    }
                    pb.set_message(layer_progress_format(&l));
                } else {
                    // If the receiver is disconnected, then we're done
                    break
                };
            },
            r = layer_bytes.changed() => {
                if r.is_err() {
                    // If the receiver is disconnected, then we're done
                    break
                }
                let bytes = layer_bytes.borrow();
                if let Some(bytes) = &*bytes {
                    pb.set_length(bytes.total);
                    pb.set_position(bytes.fetched);
                }
            }

        }
    }
}

/// Write the status of layers to download.
pub fn print_layer_status(prep: &PreparedImport) {
    if let Some(status) = prep.format_layer_status() {
        println!("{status}");
        let _ = std::io::stdout().flush();
    }
}

/// Write a deprecation notice, and sleep for 3 seconds.
pub async fn print_deprecated_warning(msg: &str) {
    eprintln!("warning: {msg}");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await
}

/// Import a container image with an encapsulated ostree commit.
async fn container_import(
    repo: &ostree::Repo,
    imgref: &OstreeImageReference,
    proxyopts: ContainerProxyOpts,
    write_ref: Option<&str>,
    quiet: bool,
) -> Result<()> {
    let target = indicatif::ProgressDrawTarget::stdout();
    let style = indicatif::ProgressStyle::default_bar();
    let pb = (!quiet).then(|| {
        let pb = indicatif::ProgressBar::new_spinner();
        pb.set_draw_target(target);
        pb.set_style(style.template("{spinner} {prefix} {msg}").unwrap());
        pb.enable_steady_tick(std::time::Duration::from_millis(200));
        pb.set_message("Downloading...");
        pb
    });
    let importer = ImageImporter::new(repo, imgref, proxyopts.into()).await?;
    let import = importer.unencapsulate().await;
    // Ensure we finish the progress bar before potentially propagating an error
    if let Some(pb) = pb.as_ref() {
        pb.finish();
    }
    let import = import?;
    if let Some(warning) = import.deprecated_warning.as_deref() {
        print_deprecated_warning(warning).await;
    }
    if let Some(write_ref) = write_ref {
        repo.set_ref_immediate(
            None,
            write_ref,
            Some(import.ostree_commit.as_str()),
            gio::Cancellable::NONE,
        )?;
        println!(
            "Imported: {} => {}",
            write_ref,
            import.ostree_commit.as_str()
        );
    } else {
        println!("Imported: {}", import.ostree_commit);
    }

    Ok(())
}

/// Grouping of metadata about an object.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RawMeta {
    /// The metadata format version. Should be set to 1.
    pub version: u32,
    /// The image creation timestamp. Format is YYYY-MM-DDTHH:MM:SSZ.
    /// Should be synced with the label io.container.image.created.
    pub created: Option<String>,
    /// Top level labels, to be prefixed to the ones with --label
    /// Applied to both the outer config annotations and the inner config labels.
    pub labels: Option<BTreeMap<String, String>>,
    /// The output layers ordered. Provided as an ordered mapping of a unique
    /// machine readable strings to a human readable name (e.g., the layer contents).
    /// The human-readable name is placed in a layer annotation.
    pub layers: IndexMap<String, String>,
    /// The layer contents. The key is an ostree hash and the value is the
    /// machine readable string of the layer the hash belongs to.
    /// WARNING: needs to contain all ostree hashes in the input commit.
    pub mapping: IndexMap<String, String>,
    /// Whether the mapping is ordered. If true, the output tar stream of the
    /// layers will reflect the order of the hashes in the mapping.
    /// Otherwise, a deterministic ordering will be used regardless of mapping
    /// order. Potentially useful for optimizing zstd:chunked compression.
    /// WARNING: not currently supported.
    pub ordered: Option<bool>,
}

/// Export a container image with an encapsulated ostree commit.
#[allow(clippy::too_many_arguments)]
async fn container_export(
    repo: &ostree::Repo,
    rev: &str,
    imgref: &ImageReference,
    labels: BTreeMap<String, String>,
    authfile: Option<PathBuf>,
    copy_meta_keys: Vec<String>,
    copy_meta_opt_keys: Vec<String>,
    container_config: Option<Utf8PathBuf>,
    cmd: Option<Vec<String>>,
    compression_fast: bool,
    package_contentmeta: Option<Utf8PathBuf>,
) -> Result<()> {
    let container_config = if let Some(container_config) = container_config {
        serde_json::from_reader(File::open(container_config).map(BufReader::new)?)?
    } else {
        None
    };

    let mut contentmeta_data = None;
    let mut created = None;
    let mut labels = labels.clone();
    if let Some(contentmeta) = package_contentmeta {
        let buf = File::open(contentmeta).map(BufReader::new);
        let raw: RawMeta = serde_json::from_reader(buf?)?;

        // Check future variables are set correctly
        let supported_version = 1;
        if raw.version != supported_version {
            return Err(anyhow::anyhow!(
                "Unsupported metadata version: {}. Currently supported: {}",
                raw.version,
                supported_version
            ));
        }
        if let Some(ordered) = raw.ordered {
            if ordered {
                return Err(anyhow::anyhow!("Ordered mapping not currently supported."));
            }
        }

        created = raw.created;
        contentmeta_data = Some(ObjectMetaSized {
            map: raw
                .mapping
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            sizes: raw
                .layers
                .into_iter()
                .map(|(k, v)| ObjectSourceMetaSized {
                    meta: ObjectSourceMeta {
                        identifier: k.clone().into(),
                        name: v.into(),
                        srcid: k.clone().into(),
                        change_frequency: if k == "unpackaged" { u32::MAX } else { 1 },
                        change_time_offset: 1,
                    },
                    size: 1,
                })
                .collect(),
        });

        // Merge --label args to the labels from the metadata
        labels.extend(raw.labels.into_iter().flatten());
    }

    // Use enough layers so that each package ends in its own layer
    // while respecting the layer ordering.
    let max_layers = if let Some(contentmeta_data) = &contentmeta_data {
        NonZeroU32::new((contentmeta_data.sizes.len() + 1).try_into().unwrap())
    } else {
        None
    };

    let config = Config {
        labels: Some(labels),
        cmd,
    };

    let opts = crate::container::ExportOpts {
        copy_meta_keys,
        copy_meta_opt_keys,
        container_config,
        authfile,
        skip_compression: compression_fast, // TODO rename this in the struct at the next semver break
        package_contentmeta: contentmeta_data.as_ref(),
        max_layers,
        created,
        ..Default::default()
    };
    let pushed = crate::container::encapsulate(repo, rev, &config, Some(opts), imgref).await?;
    println!("{pushed}");
    Ok(())
}

/// Load metadata for a container image with an encapsulated ostree commit.
async fn container_info(imgref: &OstreeImageReference) -> Result<()> {
    let (_, digest) = crate::container::fetch_manifest(imgref).await?;
    println!("{imgref} digest: {digest}");
    Ok(())
}

/// Write a layered container image into an OSTree commit.
async fn container_store(
    repo: &ostree::Repo,
    imgref: &OstreeImageReference,
    ostree_digestfile: Option<Utf8PathBuf>,
    proxyopts: ContainerProxyOpts,
    quiet: bool,
    check: Option<Utf8PathBuf>,
) -> Result<()> {
    let mut imp = ImageImporter::new(repo, imgref, proxyopts.into()).await?;
    let prep = match imp.prepare().await? {
        PrepareResult::AlreadyPresent(c) => {
            write_digest_file(ostree_digestfile, &c.merge_commit)?;
            println!("No changes in {} => {}", imgref, c.merge_commit);
            return Ok(());
        }
        PrepareResult::Ready(r) => r,
    };
    if let Some(warning) = prep.deprecated_warning() {
        print_deprecated_warning(warning).await;
    }
    if let Some(check) = check.as_deref() {
        let rootfs = Dir::open_ambient_dir("/", cap_std::ambient_authority())?;
        rootfs.atomic_replace_with(check.as_str().trim_start_matches('/'), |w| {
            prep.manifest
                .to_canon_json_writer(w)
                .context("Serializing manifest")
        })?;
        // In check mode, we're done
        return Ok(());
    }
    if let Some(previous_state) = prep.previous_state.as_ref() {
        let diff = ManifestDiff::new(&previous_state.manifest, &prep.manifest);
        diff.print();
    }
    print_layer_status(&prep);
    let printer = (!quiet).then(|| {
        let layer_progress = imp.request_progress();
        let layer_byte_progress = imp.request_layer_progress();
        tokio::task::spawn(async move {
            handle_layer_progress_print(layer_progress, layer_byte_progress).await
        })
    });
    let import = imp.import(prep).await;
    if let Some(printer) = printer {
        let _ = printer.await;
    }
    let import = import?;
    if let Some(msg) =
        ostree_container::store::image_filtered_content_warning(&import.filtered_files)?
    {
        eprintln!("{msg}")
    }
    if let Some(ref text) = import.verify_text {
        println!("{text}");
    }
    write_digest_file(ostree_digestfile, &import.merge_commit)?;
    println!("Wrote: {} => {}", imgref, import.merge_commit);
    Ok(())
}

fn write_digest_file(digestfile: Option<Utf8PathBuf>, digest: &str) -> Result<()> {
    if let Some(digestfile) = digestfile.as_deref() {
        let rootfs = Dir::open_ambient_dir("/", cap_std::ambient_authority())?;
        rootfs.write(digestfile.as_str().trim_start_matches('/'), digest)?;
    }
    Ok(())
}

/// Output the container image history
async fn container_history(repo: &ostree::Repo, imgref: &ImageReference) -> Result<()> {
    let img = crate::container::store::query_image(repo, imgref)?
        .ok_or_else(|| anyhow::anyhow!("No such image: {}", imgref))?;
    let mut table = comfy_table::Table::new();
    table
        .load_preset(comfy_table::presets::NOTHING)
        .set_content_arrangement(comfy_table::ContentArrangement::Dynamic)
        .set_header(["ID", "SIZE", "CRCEATED BY"]);

    let mut history = img.configuration.history().iter().flatten();
    let layers = img.manifest.layers().iter();
    for layer in layers {
        let histent = history.next();
        let created_by = histent
            .and_then(|s| s.created_by().as_deref())
            .unwrap_or("");

        let digest = layer.digest().digest();
        // Verify it's OK to slice, this should all be ASCII
        assert!(digest.is_ascii());
        let digest_max = 20usize;
        let digest = &digest[0..digest_max];
        let size = glib::format_size(layer.size());
        table.add_row([digest, size.as_str(), created_by]);
    }
    println!("{table}");
    Ok(())
}

/// Add IMA signatures to an ostree commit, generating a new commit.
fn ima_sign(cmdopts: &ImaSignOpts) -> Result<()> {
    let cancellable = gio::Cancellable::NONE;
    let signopts = crate::ima::ImaOpts {
        algorithm: cmdopts.algorithm.clone(),
        key: cmdopts.key.clone(),
        overwrite: cmdopts.overwrite,
    };
    let repo = parse_repo(&cmdopts.repo)?;
    let tx = repo.auto_transaction(cancellable)?;
    let signed_commit = crate::ima::ima_sign(&repo, cmdopts.src_rev.as_str(), &signopts)?;
    repo.transaction_set_ref(
        None,
        cmdopts.target_ref.as_str(),
        Some(signed_commit.as_str()),
    );
    let _stats = tx.commit(cancellable)?;
    println!("{} => {}", cmdopts.target_ref, signed_commit);
    Ok(())
}

#[cfg(feature = "internal-testing-api")]
async fn testing(opts: &TestingOpts) -> Result<()> {
    match opts {
        TestingOpts::DetectEnv => {
            println!("{}", crate::integrationtest::detectenv()?);
            Ok(())
        }
        TestingOpts::CreateFixture => crate::integrationtest::create_fixture().await,
        TestingOpts::Run => crate::integrationtest::run_tests(),
        TestingOpts::RunIMA => crate::integrationtest::test_ima(),
        TestingOpts::FilterTar => {
            let tmpdir = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
            crate::tar::filter_tar(
                std::io::stdin(),
                std::io::stdout(),
                &Default::default(),
                &tmpdir,
            )
            .map(|_| {})
        }
    }
}

// Quick hack; TODO dedup this with the code in bootc or lower here
#[context("Remounting sysroot writable")]
fn container_remount_sysroot(sysroot: &Utf8Path) -> Result<()> {
    if !Utf8Path::new("/run/.containerenv").exists() {
        return Ok(());
    }
    println!("Running in container, assuming we can remount {sysroot} writable");
    let st = Command::new("mount")
        .args(["-o", "remount,rw", sysroot.as_str()])
        .status()?;
    if !st.success() {
        anyhow::bail!("Failed to remount {sysroot}: {st:?}");
    }
    Ok(())
}

#[context("Serializing to output file")]
fn handle_serialize_to_file<T: serde::Serialize>(path: Option<&Utf8Path>, obj: T) -> Result<()> {
    if let Some(path) = path {
        let mut out = std::fs::File::create(path)
            .map(BufWriter::new)
            .with_context(|| anyhow::anyhow!("Opening {path} for writing"))?;
        obj.to_canon_json_writer(&mut out)
            .context("Serializing output")?;
    }
    Ok(())
}

/// Parse the provided arguments and execute.
/// Calls [`clap::Error::exit`] on failure, printing the error message and aborting the program.
pub async fn run_from_iter<I>(args: I) -> Result<()>
where
    I: IntoIterator,
    I::Item: Into<OsString> + Clone,
{
    run_from_opt(Opt::parse_from(args)).await
}

async fn run_from_opt(opt: Opt) -> Result<()> {
    match opt {
        Opt::Tar(TarOpts::Import(ref opt)) => tar_import(opt).await,
        Opt::Tar(TarOpts::Export(ref opt)) => tar_export(opt),
        Opt::Container(o) => match o {
            ContainerOpts::Info { imgref } => container_info(&imgref).await,
            ContainerOpts::Commit => container_commit().await,
            ContainerOpts::Unencapsulate {
                repo,
                imgref,
                proxyopts,
                write_ref,
                quiet,
            } => {
                let repo = parse_repo(&repo)?;
                container_import(&repo, &imgref, proxyopts, write_ref.as_deref(), quiet).await
            }
            ContainerOpts::Encapsulate {
                repo,
                rev,
                imgref,
                labels,
                authfile,
                copy_meta_keys,
                copy_meta_opt_keys,
                config,
                cmd,
                compression_fast,
                contentmeta,
            } => {
                let labels: Result<BTreeMap<_, _>> = labels
                    .into_iter()
                    .map(|l| {
                        let (k, v) = l
                            .split_once('=')
                            .ok_or_else(|| anyhow::anyhow!("Missing '=' in label {}", l))?;
                        Ok((k.to_string(), v.to_string()))
                    })
                    .collect();
                let repo = parse_repo(&repo)?;
                container_export(
                    &repo,
                    &rev,
                    &imgref,
                    labels?,
                    authfile,
                    copy_meta_keys,
                    copy_meta_opt_keys,
                    config,
                    cmd,
                    compression_fast,
                    contentmeta,
                )
                .await
            }
            ContainerOpts::Image(opts) => match opts {
                ContainerImageOpts::List { repo } => {
                    let repo = parse_repo(&repo)?;
                    for image in crate::container::store::list_images(&repo)? {
                        println!("{image}");
                    }
                    Ok(())
                }
                ContainerImageOpts::Pull {
                    repo,
                    imgref,
                    ostree_digestfile,
                    proxyopts,
                    quiet,
                    check,
                } => {
                    let repo = parse_repo(&repo)?;
                    container_store(&repo, &imgref, ostree_digestfile, proxyopts, quiet, check)
                        .await
                }
                ContainerImageOpts::Reexport {
                    repo,
                    src_imgref,
                    dest_imgref,
                    authfile,
                    compression_fast,
                } => {
                    let repo = &parse_repo(&repo)?;
                    let opts = ExportToOCIOpts {
                        authfile,
                        skip_compression: compression_fast,
                        ..Default::default()
                    };
                    let digest = ostree_container::store::export(
                        repo,
                        &src_imgref,
                        &dest_imgref,
                        Some(opts),
                    )
                    .await?;
                    println!("Exported: {digest}");
                    Ok(())
                }
                ContainerImageOpts::History { repo, imgref } => {
                    let repo = parse_repo(&repo)?;
                    container_history(&repo, &imgref).await
                }
                ContainerImageOpts::Metadata {
                    repo,
                    imgref,
                    config,
                } => {
                    let repo = parse_repo(&repo)?;
                    let image = crate::container::store::query_image(&repo, &imgref)?
                        .ok_or_else(|| anyhow::anyhow!("No such image"))?;
                    let stdout = std::io::stdout().lock();
                    let mut stdout = std::io::BufWriter::new(stdout);
                    if config {
                        image.configuration.to_canon_json_writer(&mut stdout)?;
                    } else {
                        image.manifest.to_canon_json_writer(&mut stdout)?;
                    }
                    stdout.flush()?;
                    Ok(())
                }
                ContainerImageOpts::ClearCachedUpdate { repo, imgref } => {
                    let repo = parse_repo(&repo)?;
                    crate::container::store::clear_cached_update(&repo, &imgref)?;
                    Ok(())
                }
                ContainerImageOpts::Remove {
                    repo,
                    imgrefs,
                    skip_gc,
                } => {
                    let nimgs = imgrefs.len();
                    let repo = parse_repo(&repo)?;
                    crate::container::store::remove_images(&repo, imgrefs.iter())?;
                    if !skip_gc {
                        let nlayers = crate::container::store::gc_image_layers(&repo)?;
                        println!("Removed images: {nimgs} layers: {nlayers}");
                    } else {
                        println!("Removed images: {nimgs}");
                    }
                    Ok(())
                }
                ContainerImageOpts::PruneLayers { repo } => {
                    let repo = parse_repo(&repo)?;
                    let nlayers = crate::container::store::gc_image_layers(&repo)?;
                    println!("Removed layers: {nlayers}");
                    Ok(())
                }
                ContainerImageOpts::PruneImages {
                    sysroot,
                    and_layers,
                    full,
                } => {
                    let sysroot = &ostree::Sysroot::new(Some(&gio::File::for_path(&sysroot)));
                    sysroot.load(gio::Cancellable::NONE)?;
                    let sysroot = &SysrootLock::new_from_sysroot(sysroot).await?;
                    if full {
                        let res = crate::container::deploy::prune(sysroot)?;
                        if res.is_empty() {
                            println!("No content was pruned.");
                        } else {
                            println!("Removed images: {}", res.n_images);
                            println!("Removed layers: {}", res.n_layers);
                            println!("Removed objects: {}", res.n_objects_pruned);
                            let objsize = glib::format_size(res.objsize);
                            println!("Freed: {objsize}");
                        }
                    } else {
                        let removed = crate::container::deploy::remove_undeployed_images(sysroot)?;
                        match removed.as_slice() {
                            [] => {
                                println!("No unreferenced images.");
                                return Ok(());
                            }
                            o => {
                                for imgref in o {
                                    println!("Removed: {imgref}");
                                }
                            }
                        }
                        if and_layers {
                            let nlayers =
                                crate::container::store::gc_image_layers(&sysroot.repo())?;
                            println!("Removed layers: {nlayers}");
                        }
                    }
                    Ok(())
                }
                ContainerImageOpts::Copy {
                    src_repo,
                    dest_repo,
                    imgref,
                } => {
                    let src_repo = parse_repo(&src_repo)?;
                    let dest_repo = parse_repo(&dest_repo)?;
                    let imgref = &imgref.imgref;
                    crate::container::store::copy(&src_repo, imgref, &dest_repo, imgref).await
                }
                ContainerImageOpts::ReplaceDetachedMetadata {
                    src,
                    dest,
                    contents,
                } => {
                    let contents = contents.map(std::fs::read).transpose()?;
                    let digest = crate::container::update_detached_metadata(
                        &src,
                        &dest,
                        contents.as_deref(),
                    )
                    .await?;
                    println!("Pushed: {digest}");
                    Ok(())
                }
                ContainerImageOpts::Deploy {
                    sysroot,
                    stateroot,
                    imgref,
                    image,
                    transport,
                    no_signature_verification: _,
                    enforce_container_sigpolicy,
                    ostree_remote,
                    target_imgref,
                    no_imgref,
                    karg,
                    proxyopts,
                    write_commitid_to,
                } => {
                    // As of recent releases, signature verification enforcement is
                    // off by default, and must be explicitly enabled.
                    let no_signature_verification = !enforce_container_sigpolicy;
                    let sysroot = &if let Some(sysroot) = sysroot {
                        ostree::Sysroot::new(Some(&gio::File::for_path(sysroot)))
                    } else {
                        ostree::Sysroot::new_default()
                    };
                    sysroot.load(gio::Cancellable::NONE)?;
                    let kargs = karg.as_deref();
                    let kargs = kargs.map(|v| {
                        let r: Vec<_> = v.iter().map(|s| s.as_str()).collect();
                        r
                    });

                    // If the user specified a stateroot, we always use that.
                    let stateroot = if let Some(stateroot) = stateroot.as_deref() {
                        Cow::Borrowed(stateroot)
                    } else {
                        // Otherwise, if we're booted via ostree, use the booted.
                        // If that doesn't hold, then use `default`.
                        let booted_stateroot = sysroot
                            .booted_deployment()
                            .map(|d| Cow::Owned(d.osname().to_string()));
                        booted_stateroot.unwrap_or({
                            Cow::Borrowed(crate::container::deploy::STATEROOT_DEFAULT)
                        })
                    };

                    let imgref = if let Some(image) = image {
                        let transport = transport.as_deref().unwrap_or("registry");
                        let transport = ostree_container::Transport::try_from(transport)?;
                        let imgref = ostree_container::ImageReference {
                            transport,
                            name: image,
                        };
                        let sigverify = if no_signature_verification {
                            ostree_container::SignatureSource::ContainerPolicyAllowInsecure
                        } else if let Some(remote) = ostree_remote.as_ref() {
                            ostree_container::SignatureSource::OstreeRemote(remote.to_string())
                        } else {
                            ostree_container::SignatureSource::ContainerPolicy
                        };
                        ostree_container::OstreeImageReference { sigverify, imgref }
                    } else {
                        // SAFETY: We use the clap required_unless_present flag, so this must be set
                        // because --image is not.
                        let imgref = imgref.expect("imgref option should be set");
                        imgref.as_str().try_into()?
                    };

                    #[allow(clippy::needless_update)]
                    let options = crate::container::deploy::DeployOpts {
                        kargs: kargs.as_deref(),
                        target_imgref: target_imgref.as_ref(),
                        proxy_cfg: Some(proxyopts.into()),
                        no_imgref,
                        ..Default::default()
                    };
                    let state = crate::container::deploy::deploy(
                        sysroot,
                        &stateroot,
                        &imgref,
                        Some(options),
                    )
                    .await?;
                    if let Some(msg) = ostree_container::store::image_filtered_content_warning(
                        &state.filtered_files,
                    )? {
                        eprintln!("{msg}")
                    }
                    if let Some(p) = write_commitid_to {
                        std::fs::write(&p, state.merge_commit.as_bytes())
                            .with_context(|| format!("Failed to write commitid to {p}"))?;
                    }
                    Ok(())
                }
            },
            ContainerOpts::Compare {
                imgref_old,
                imgref_new,
            } => {
                let (manifest_old, _) = crate::container::fetch_manifest(&imgref_old).await?;
                let (manifest_new, _) = crate::container::fetch_manifest(&imgref_new).await?;
                let manifest_diff =
                    crate::container::ManifestDiff::new(&manifest_old, &manifest_new);
                manifest_diff.print();
                Ok(())
            }
        },
        Opt::ImaSign(ref opts) => ima_sign(opts),
        #[cfg(feature = "internal-testing-api")]
        Opt::InternalOnlyForTesting(ref opts) => testing(opts).await,
        #[cfg(feature = "docgen")]
        Opt::Man(manopts) => crate::docgen::generate_manpages(&manopts.directory),
        Opt::ProvisionalRepair(opts) => match opts {
            ProvisionalRepairOpts::AnalyzeInodes {
                repo,
                verbose,
                write_result_to,
            } => {
                let repo = parse_repo(&repo)?;
                let check_res = crate::repair::check_inode_collision(&repo, verbose)?;
                handle_serialize_to_file(write_result_to.as_deref(), &check_res)?;
                if check_res.collisions.is_empty() {
                    println!("OK: No colliding objects found.");
                } else {
                    eprintln!(
                        "warning: {} potentially colliding inodes found",
                        check_res.collisions.len()
                    );
                }
                Ok(())
            }
            ProvisionalRepairOpts::Repair {
                sysroot,
                verbose,
                dry_run,
                write_result_to,
            } => {
                container_remount_sysroot(&sysroot)?;
                let sysroot = &ostree::Sysroot::new(Some(&gio::File::for_path(&sysroot)));
                sysroot.load(gio::Cancellable::NONE)?;
                let sysroot = &SysrootLock::new_from_sysroot(sysroot).await?;
                let result = crate::repair::analyze_for_repair(sysroot, verbose)?;
                handle_serialize_to_file(write_result_to.as_deref(), &result)?;
                if dry_run {
                    result.check()
                } else {
                    result.repair(sysroot)
                }
            }
        },
    }
}
