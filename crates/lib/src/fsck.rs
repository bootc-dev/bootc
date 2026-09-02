//! # Perform consistency checking.
//!
//! This is an internal module, backing the experimental `bootc internals fsck`
//! command.

// Unfortunately needed here to work with linkme
#![allow(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::future::Future;
use std::io::Write as IoWrite;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::num::NonZeroUsize;
use std::path::{Component, Path};
use std::pin::Pin;

use bootc_utils::collect_until;
use camino::Utf8PathBuf;
use cap_std_ext::cap_std::fs::{Dir, File, MetadataExt as _};
use cap_std_ext::dirext::CapStdExtDirExt;
use composefs::fsverity::{FsVerityHashValue as _, Sha512HashValue};
use composefs::splitstream::SplitStreamReader;
use composefs_ctl::composefs;
use composefs_ctl::composefs_oci;
use fn_error_context::context;
use linkme::distributed_slice;
use linux_kernel_cmdline::utf8::Cmdline;
use ostree_ext::oci_spec::image::{ImageConfiguration, ImageManifest, MediaType};
use ostree_ext::ostree;
use ostree_ext::ostree_prepareroot::Tristate;
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use serde::Serialize;

use crate::bootc_composefs::status::ComposefsCmdline;
use crate::composefs_consts::{
    BOOTC_TAG_PREFIX, COMPOSEFS_STAGED_DEPLOYMENT_FNAME, USER_CFG, USER_CFG_STAGED,
};
use crate::parsers::bls_config::{BLSConfigType, EFIKey, parse_bls_config};
use crate::parsers::grub_menuconfig::parse_grub_menuentry_file;
use crate::store::Storage;

use std::os::fd::AsFd;
use std::os::unix::ffi::OsStringExt as _;

const MAX_DEPLOYMENTS: usize = 256;
const MAX_BOOT_ENTRIES: usize = 256;
const MAX_READ_BYTES: u64 = 1024 * 1024;
const MAX_FILE_BYTES: u64 = 64 * 1024;
const MAX_FINDINGS: usize = 512;
const MAX_REPOSITORY_ENTRIES: usize = 256;
const MAX_IMAGES: usize = 256;
const MAX_ARTIFACTS: usize = 256;
const MAX_LAYERS: usize = 256;
const MAX_REPORT_STRING: usize = 256;
const EFI_LOADER_INFO: &str = "LoaderInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";
const PE_DOS_STUB_SIZE: usize = 64;
const PE_HEADER_SIZE: usize = 24;
const PE_SECTION_HEADER_SIZE: usize = 40;

#[derive(Debug, Serialize)]
struct ReadonlyReport {
    report_version: u8,
    collection: Collection,
    host: Host,
    composefs: ComposefsReport,
    repository: RepositoryReport,
    images: Vec<ImageReport>,
    deployments: Vec<DeploymentReport>,
    bootloader: BootloaderReport,
    edges: Vec<GraphEdge>,
    boot_entries: Vec<BootEntryReport>,
    artifacts: Vec<ArtifactReport>,
    findings: Vec<Finding>,
    summary: Summary,
}

#[derive(Debug, Serialize)]
struct Collection {
    mode: &'static str,
    sysroot: &'static str,
    limits: Limits,
    truncated: bool,
    raced: bool,
    collection_errors: usize,
}

#[derive(Debug, Serialize)]
struct Limits {
    deployments: usize,
    boot_entries: usize,
    read_bytes: u64,
    repository_entries: usize,
    images: usize,
}

#[derive(Debug, Serialize)]
struct Host {
    kernel_release: Option<String>,
    architecture: Option<String>,
    os_release_id: Option<String>,
    backend_evidence: String,
    cmdline_composefs: Option<String>,
    root_mount: &'static str,
    staged: RuntimeStaged,
}

#[derive(Debug, Serialize)]
struct RuntimeStaged {
    present: bool,
    deployment: Option<String>,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct ComposefsReport {
    path_present: bool,
    metadata_present: bool,
    open: Option<bool>,
    open_error: Option<String>,
    refs: Vec<String>,
    refs_status: &'static str,
}

#[derive(Debug, Serialize)]
struct RepositoryReport {
    meta: MetaReport,
    typed_open: &'static str,
    erofs_default: Option<String>,
    erofs_extra: Vec<String>,
    inventory: BTreeMap<&'static str, DirectoryInventory>,
    tags: Vec<TagReport>,
}
#[derive(Debug, Serialize)]
struct MetaReport {
    present: bool,
    file_type: &'static str,
    size: Option<u64>,
    parse: &'static str,
}
#[derive(Debug, Serialize)]
struct DirectoryInventory {
    entries: Vec<String>,
    count: usize,
    truncated: bool,
    status: &'static str,
}
#[derive(Debug, Serialize)]
struct TagReport {
    name: String,
    bootc_root: bool,
    manifest: Option<String>,
    manifest_state: &'static str,
    resolution: &'static str,
}
#[derive(Debug, Serialize)]
struct ImageReport {
    manifest: String,
    sources: Vec<String>,
    tags: Vec<String>,
    availability: &'static str,
    error: Option<String>,
    config: Option<String>,
    manifest_media_type: Option<String>,
    schema_version: Option<u32>,
    layers: Vec<LayerReport>,
    os: Option<String>,
    architecture: Option<String>,
    created: Option<String>,
    image_v1: Option<String>,
    image_v2: Option<String>,
    boot_image_v1: Option<String>,
    boot_image_v2: Option<String>,
}
#[derive(Debug, Serialize)]
struct LayerReport {
    digest: String,
    media_type: String,
    size: u64,
}
#[derive(Debug, Serialize)]
struct GraphEdge {
    from: String,
    to: String,
    kind: &'static str,
    resolution: Resolution,
}
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Resolution {
    Present,
    Missing,
    Unknown,
}

#[derive(Debug, Serialize)]
struct DeploymentReport {
    id: String,
    origin_present: bool,
    image: Option<String>,
    manifest_digest: Option<String>,
    manifest_digest_state: &'static str,
    manifest_stream_present: Option<bool>,
    manifest_stream_resolution: &'static str,
    state_present: bool,
    role: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct BootEntryReport {
    filename: String,
    source: &'static str,
    kind: &'static str,
    order: usize,
    title: Option<String>,
    version: Option<String>,
    sort_key: Option<String>,
    linux: Option<String>,
    initrd: Vec<String>,
    efi: Option<String>,
    menu_index: Option<usize>,
    chainloader: Option<String>,
    search: Option<String>,
    composefs: ComposefsIdentity,
    parse: &'static str,
}

#[derive(Debug, Serialize)]
struct ComposefsIdentity {
    value: Option<String>,
    allow_missing: Option<bool>,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct BootloaderReport {
    classification: &'static str,
    grub_directories: Vec<String>,
    bls_directories: Vec<String>,
    loader_info: Option<String>,
    efi: &'static str,
    esp: EspReport,
}

#[derive(Debug, Serialize)]
struct EspReport {
    status: &'static str,
    mountpoint: Option<String>,
    entries: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ArtifactReport {
    path: String,
    kind: &'static str,
    present: bool,
    size: Option<u64>,
    file_type: &'static str,
    uki: Option<UkiReport>,
}

#[derive(Debug, Serialize)]
struct UkiReport {
    parse: &'static str,
    uname: Option<String>,
    os_release: Option<String>,
    composefs: ComposefsIdentity,
    sections: &'static str,
}

#[derive(Debug, Serialize)]
struct Finding {
    code: &'static str,
    subject: String,
    detail: String,
}

#[derive(Debug, Serialize)]
struct Summary {
    findings: usize,
    deployments: usize,
    incomplete: bool,
    collection_errors: usize,
}

/// Collect a non-mutating diagnostic report.  This intentionally does not use
/// `BootedStorage`: that constructor can remount sysroot, mount an ESP, and
/// upgrade composefs repositories.
pub(crate) async fn fsck_readonly(
    host: &Dir,
    report: bool,
    mut output: impl IoWrite,
) -> anyhow::Result<()> {
    let result = collect_readonly_host(host)?;
    if report {
        serde_json::to_writer_pretty(&mut output, &result)?;
        writeln!(output)?;
    } else {
        writeln!(
            output,
            "readonly fsck: {} deployment(s), {} finding(s)",
            result.summary.deployments, result.summary.findings
        )?;
        for finding in &result.findings {
            writeln!(output, "{}: {}", finding.code, finding.subject)?;
        }
    };
    if result.summary.incomplete {
        anyhow::bail!("Readonly fsck found findings or incomplete data")
    }
    Ok(())
}

/// Capability roots held for the entire report collection.  Every filesystem
/// operation starts from one of these descriptors, never from an ambient path.
struct ReadonlyRoots<'a> {
    host: &'a Dir,
    sysroot: Dir,
    repo: Option<Dir>,
    deploy: Option<Dir>,
    run: Option<Dir>,
    boot: Option<Dir>,
    esp: Option<Dir>,
}

impl<'a> ReadonlyRoots<'a> {
    fn new(host: &'a Dir) -> std::io::Result<Self> {
        let sysroot = open_dir_from(host, Path::new("sysroot"));
        match sysroot {
            Ok(sysroot) => Ok(Self {
                repo: open_dir_from(&sysroot, Path::new("composefs")).ok(),
                deploy: open_dir_from(&sysroot, Path::new("state/deploy")).ok(),
                run: open_dir_from(&sysroot, Path::new("run")).ok(),
                boot: open_dir_from(&sysroot, Path::new("boot")).ok(),
                esp: open_dir_from(&sysroot, Path::new("boot/efi")).ok(),
                host,
                sysroot,
            }),
            Err(error) => Err(error),
        }
    }
}

fn collect_readonly_host(host: &Dir) -> anyhow::Result<ReadonlyReport> {
    let roots = ReadonlyRoots::new(host)?;
    Ok(collect_readonly_with_roots(&roots))
}

#[cfg(test)]
fn collect_readonly(sysroot: &Dir) -> ReadonlyReport {
    let roots = ReadonlyRoots {
        repo: open_dir_from(&sysroot, Path::new("composefs")).ok(),
        deploy: open_dir_from(&sysroot, Path::new("state/deploy")).ok(),
        run: open_dir_from(&sysroot, Path::new("run")).ok(),
        boot: open_dir_from(&sysroot, Path::new("boot")).ok(),
        esp: open_dir_from(&sysroot, Path::new("boot/efi")).ok(),
        host: sysroot,
        sysroot: sysroot.try_clone().unwrap(),
    };
    collect_readonly_with_roots(&roots)
}

fn collect_readonly_with_roots(roots: &ReadonlyRoots<'_>) -> ReadonlyReport {
    let sysroot = &roots.sysroot;
    let host_root = roots.host;
    // Keep all pre-opened capability roots alive for the whole collection.
    let _held_roots = (&roots.repo, &roots.run, &roots.boot, &roots.esp);
    let mut findings = Vec::new();
    let mut truncated = false;
    let mut read_bytes = 0;
    let composefs_dir = open_dir_beneath(sysroot, Path::new("composefs"));
    let metadata_present = composefs_dir
        .as_ref()
        .ok()
        .and_then(|dir| metadata_at(dir, "meta.json".as_ref()).ok())
        .is_some_and(|metadata| metadata.file_type == EntryType::File);
    // Repository::open parses metadata through an unbounded dependency API.
    // The readonly report only uses descriptor-relative, explicitly bounded reads.
    let (open, open_error, refs, refs_status) = if composefs_dir.is_ok() {
        (Some(true), None, Vec::new(), "unchecked-bounded-api")
    } else {
        (None, None, Vec::new(), "not-present")
    };
    let repository = collect_repository(sysroot, &mut findings, &mut truncated, &mut read_bytes);
    if matches!(open, Some(false)) {
        findings.push(finding(
            "COMPOSEFS_REPOSITORY_OPEN_FAILED",
            "composefs",
            open_error.as_deref().unwrap_or("unknown error"),
        ));
    }

    let deploy_token_before = roots.deploy.as_ref().and_then(metadata_token);
    let deploy_root_fd = match roots.deploy.as_ref() {
        Some(dir) => match dir.try_clone() {
            Ok(dir) => Some(dir),
            Err(e) => {
                findings.push(finding(
                    "DEPLOYMENT_DIRECTORY_UNREADABLE",
                    "state/deploy",
                    &e.to_string(),
                ));
                None
            }
        },
        None => None,
    };
    let ids = deploy_root_fd
        .as_ref()
        .map(|dir| {
            read_dir_dirs_fd(
                dir,
                &mut findings,
                Path::new("state/deploy"),
                MAX_DEPLOYMENTS,
            )
        })
        .unwrap_or_default();
    truncated |= ids.truncated;
    let mut deployments = Vec::with_capacity(ids.values.len());
    for id in ids.values {
        let deployment_dir = match deploy_root_fd.as_ref() {
            Some(dir) => match open_dir_from(dir, Path::new(&id)) {
                Ok(dir) => Some(dir),
                Err(e) => {
                    findings.push(finding(
                        "DEPLOYMENT_DIRECTORY_UNREADABLE",
                        &id,
                        &e.to_string(),
                    ));
                    None
                }
            },
            None => None,
        };
        let origin_name = format!("{id}.origin");
        let origin_meta = deployment_dir
            .as_ref()
            .map(|dir| metadata_at(dir, origin_name.as_ref()));
        let mut deployment = DeploymentReport {
            id: id.clone(),
            origin_present: origin_meta.as_ref().is_some_and(Result::is_ok),
            image: None,
            manifest_digest: None,
            manifest_digest_state: "absent",
            manifest_stream_present: None,
            manifest_stream_resolution: "unchecked",
            state_present: deployment_dir.is_some(),
            role: None,
        };
        if let Some(Err(e)) = origin_meta.as_ref()
            && e.kind() != std::io::ErrorKind::NotFound
        {
            findings.push(finding("DEPLOYMENT_ORIGIN_UNREADABLE", &id, &e.to_string()));
        } else if !deployment.origin_present {
            findings.push(finding(
                "DEPLOYMENT_ORIGIN_MISSING",
                &id,
                "origin file is absent",
            ));
        } else if origin_meta
            .as_ref()
            .is_some_and(|m| m.as_ref().is_ok_and(|m| m.file_type == EntryType::Symlink))
        {
            findings.push(finding(
                "DEPLOYMENT_ORIGIN_SYMLINK",
                &id,
                "refusing symlink",
            ));
        } else if let Some(contents) = deployment_dir.as_ref().and_then(|dir| {
            read_limited_at(
                dir,
                origin_name.as_ref(),
                &mut read_bytes,
                &mut findings,
                &mut truncated,
                &id,
            )
        }) {
            match tini::Ini::from_string(&contents) {
                Ok(ini) => {
                    deployment.image = ini
                        .get::<String>("origin", "container")
                        .map(|v| redact_ref(&v));
                    let state = checked_manifest(
                        ini.get::<String>("image", "manifest_digest").as_deref(),
                        &mut findings,
                        &id,
                    );
                    deployment.manifest_digest_state = state.name();
                    deployment.manifest_digest = state.digest().map(str::to_owned);
                    match state {
                        ManifestState::Absent => findings.push(finding(
                            "DEPLOYMENT_MANIFEST_DIGEST_MISSING",
                            &id,
                            "origin has no image.manifest_digest",
                        )),
                        ManifestState::Valid(ref digest) if open == Some(true) => {
                            match manifest_stream_resolution(sysroot, digest) {
                                ManifestStreamResolution::Present => {
                                    deployment.manifest_stream_present = Some(true);
                                    deployment.manifest_stream_resolution = "present";
                                }
                                ManifestStreamResolution::Missing => {
                                    deployment.manifest_stream_present = Some(false);
                                    deployment.manifest_stream_resolution = "missing";
                                    findings.push(finding(
                                        "DEPLOYMENT_MANIFEST_STREAM_MISSING",
                                        &id,
                                        digest,
                                    ));
                                }
                                ManifestStreamResolution::RepositoryUnavailable(error) => {
                                    deployment.manifest_stream_resolution =
                                        "repository-unavailable";
                                    findings.push(finding(
                                        "DEPLOYMENT_MANIFEST_STREAM_UNCHECKED",
                                        &id,
                                        &error,
                                    ));
                                }
                                ManifestStreamResolution::Unchecked(error) => {
                                    findings.push(finding(
                                        "DEPLOYMENT_MANIFEST_STREAM_UNCHECKED",
                                        &id,
                                        &error,
                                    ));
                                }
                            }
                        }
                        ManifestState::Valid(_) => {
                            deployment.manifest_stream_resolution = "repository-unavailable"
                        }
                        ManifestState::Invalid | ManifestState::OversizedOrRedacted => {
                            deployment.manifest_stream_resolution = "unchecked"
                        }
                    }
                }
                Err(e) => findings.push(finding("DEPLOYMENT_ORIGIN_INVALID", &id, &e.to_string())),
            }
        }
        deployments.push(deployment);
    }
    let staged = collect_staged(sysroot, &mut findings, &mut truncated, &mut read_bytes);
    for deployment in &mut deployments {
        if staged.deployment.as_deref() == Some(&deployment.id) {
            deployment.role = Some("staged");
        }
    }
    let kernel_release = host_read_string(
        host_root,
        "proc/sys/kernel/osrelease",
        "kernel release",
        &mut read_bytes,
        &mut findings,
        &mut truncated,
    )
    .map(|v| sanitize(v.trim()));
    let os_release_id = os_release_id(host_root, &mut read_bytes, &mut findings, &mut truncated);
    let cmdline_composefs =
        read_composefs_cmdline(host_root, &mut read_bytes, &mut findings, &mut truncated);
    let stream_names = repository
        .inventory
        .get("streams")
        .map(|inventory| inventory.entries.clone())
        .unwrap_or_default();
    let mut images = collect_images(
        sysroot,
        &deployments,
        &repository.tags,
        &stream_names,
        &mut findings,
        &mut truncated,
        &mut read_bytes,
    );
    let (bootloader, boot_entries, artifacts) = collect_boot_data(
        sysroot,
        host_root,
        &deployments,
        &mut findings,
        &mut read_bytes,
        &mut truncated,
    );
    let mut edges = collect_edges(&deployments, &repository.tags, &images, &staged);
    collect_boot_edges(&mut edges, &boot_entries, &artifacts, &deployments);
    images.sort_by(|a, b| a.manifest.cmp(&b.manifest));
    edges.sort_by(|a, b| (&a.from, a.kind, &a.to).cmp(&(&b.from, b.kind, &b.to)));
    let raced = deploy_token_before != deploy_root_fd.as_ref().and_then(|dir| metadata_token(dir));
    if raced {
        findings.push(finding(
            "COLLECTION_RACE_DETECTED",
            "state/deploy",
            "metadata changed during collection",
        ));
    }
    if findings.len() > MAX_FINDINGS {
        findings.truncate(MAX_FINDINGS);
        truncated = true;
    }
    findings
        .sort_by(|a, b| (&a.code, &a.subject, &a.detail).cmp(&(&b.code, &b.subject, &b.detail)));
    let incomplete = !findings.is_empty() || truncated || raced;
    let deployment_count = deployments.len();
    ReadonlyReport {
        report_version: 1,
        collection: Collection {
            mode: "readonly",
            sysroot: "/sysroot",
            limits: Limits {
                deployments: MAX_DEPLOYMENTS,
                boot_entries: MAX_BOOT_ENTRIES,
                read_bytes: MAX_READ_BYTES,
                repository_entries: MAX_REPOSITORY_ENTRIES,
                images: MAX_IMAGES,
            },
            truncated,
            raced,
            collection_errors: findings
                .iter()
                .filter(|f| f.code.ends_with("UNREADABLE") || f.code.ends_with("FAILED"))
                .count(),
        },
        host: Host {
            kernel_release,
            os_release_id,
            architecture: Some(std::env::consts::ARCH.into()),
            backend_evidence: if composefs_dir.is_ok() {
                "composefs-directory".into()
            } else {
                "no-composefs-directory".into()
            },
            cmdline_composefs,
            root_mount: "unsupported-without-mount-api",
            staged,
        },
        composefs: ComposefsReport {
            path_present: composefs_dir.is_ok(),
            metadata_present,
            open,
            open_error,
            refs,
            refs_status,
        },
        repository,
        images,
        deployments,
        bootloader,
        edges,
        boot_entries,
        artifacts,
        summary: Summary {
            findings: findings.len(),
            deployments: deployment_count,
            incomplete,
            collection_errors: findings
                .iter()
                .filter(|f| f.code.ends_with("UNREADABLE") || f.code.ends_with("FAILED"))
                .count(),
        },
        findings,
    }
}

fn finding(code: &'static str, subject: &str, detail: &str) -> Finding {
    Finding {
        code,
        subject: sanitize(subject),
        detail: sanitize(detail),
    }
}
fn read_composefs_cmdline(
    host_root: &Dir,
    total: &mut u64,
    findings: &mut Vec<Finding>,
    truncated: &mut bool,
) -> Option<String> {
    let cmdline = host_read_string(
        host_root,
        "proc/cmdline",
        "host cmdline",
        total,
        findings,
        truncated,
    )?;
    cmdline.split_whitespace().find_map(|part| {
        part.strip_prefix("composefs=").map(|value| {
            let value = value.strip_prefix('?').unwrap_or(value);
            if value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit()) {
                format!("composefs={value}")
            } else {
                "composefs=<redacted-invalid>".into()
            }
        })
    })
}
fn collect_staged(
    sysroot: &Dir,
    findings: &mut Vec<Finding>,
    truncated: &mut bool,
    total: &mut u64,
) -> RuntimeStaged {
    let Ok(dir) = open_dir_beneath(sysroot, Path::new("run/composefs")) else {
        return RuntimeStaged {
            present: false,
            deployment: None,
            status: "absent",
        };
    };
    let name = std::ffi::OsStr::new(COMPOSEFS_STAGED_DEPLOYMENT_FNAME);
    let metadata = match metadata_at(&dir, name) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return RuntimeStaged {
                present: false,
                deployment: None,
                status: "absent",
            };
        }
        Err(e) => {
            findings.push(finding(
                "STAGED_MARKER_UNREADABLE",
                "run/composefs/staged-deployment",
                &e.to_string(),
            ));
            return RuntimeStaged {
                present: true,
                deployment: None,
                status: "unreadable",
            };
        }
    };
    if metadata.file_type == EntryType::Symlink {
        findings.push(finding(
            "STAGED_MARKER_SYMLINK",
            "run/composefs/staged-deployment",
            "refusing symlink",
        ));
        return RuntimeStaged {
            present: true,
            deployment: None,
            status: "unreadable",
        };
    }
    let Some(data) = read_limited_at(
        &dir,
        name,
        total,
        findings,
        truncated,
        "run/composefs/staged-deployment",
    ) else {
        return RuntimeStaged {
            present: true,
            deployment: None,
            status: "unreadable",
        };
    };
    match serde_json::from_str::<serde_json::Value>(&data) {
        Ok(value) => RuntimeStaged {
            present: true,
            deployment: value.get("depl_id").and_then(|v| v.as_str()).map(sanitize),
            status: "parsed",
        },
        Err(e) => {
            findings.push(finding(
                "STAGED_MARKER_INVALID",
                "run/composefs/staged-deployment",
                &e.to_string(),
            ));
            RuntimeStaged {
                present: true,
                deployment: None,
                status: "invalid",
            }
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum EntryType {
    File,
    Directory,
    Symlink,
    Other,
}

struct EntryMetadata {
    file_type: EntryType,
    size: u64,
}

fn metadata_at(dir: &Dir, name: &std::ffi::OsStr) -> std::io::Result<EntryMetadata> {
    let stat =
        rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(std::io::Error::from)?;
    let file_type = match FileType::from_raw_mode(stat.st_mode) {
        FileType::RegularFile => EntryType::File,
        FileType::Directory => EntryType::Directory,
        FileType::Symlink => EntryType::Symlink,
        _ => EntryType::Other,
    };
    Ok(EntryMetadata {
        file_type,
        size: stat.st_size.try_into().unwrap_or(0),
    })
}

fn open_dir_beneath(sysroot: &Dir, relative: &Path) -> std::io::Result<Dir> {
    open_dir_from(sysroot, relative)
}

fn open_dir_from(dir: &Dir, relative: &Path) -> std::io::Result<Dir> {
    let components: Vec<_> = relative.components().collect();
    if components.is_empty()
        || components
            .iter()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "non-normal path",
        ));
    }
    let mut dir = dir.try_clone()?;
    for component in components {
        let fd = rustix::fs::openat(
            dir.as_fd(),
            component.as_os_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        dir = Dir::from(fd);
    }
    Ok(dir)
}

fn open_from(dir: &Dir, relative: &Path) -> std::io::Result<File> {
    let components: Vec<_> = relative.components().collect();
    if components.is_empty()
        || components
            .iter()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "non-normal path",
        ));
    }
    let mut parent = dir.try_clone()?;
    for component in &components[..components.len() - 1] {
        let fd = rustix::fs::openat(
            parent.as_fd(),
            component.as_os_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        parent = Dir::from(fd);
    }
    let Some(last) = components.last() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty path",
        ));
    };
    let fd = rustix::fs::openat(
        parent.as_fd(),
        last.as_os_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    Ok(File::from(fd))
}

fn inventory_fd(dir: &Dir, findings: &mut Vec<Finding>, label: &'static str) -> DirectoryInventory {
    let mut result = DirectoryInventory {
        entries: Vec::new(),
        count: 0,
        truncated: false,
        status: "ok",
    };
    let dir = match dir.try_clone() {
        Ok(dir) => dir,
        Err(e) => {
            findings.push(finding(
                "REPOSITORY_DIRECTORY_UNREADABLE",
                label,
                &e.to_string(),
            ));
            result.status = "unreadable";
            return result;
        }
    };
    match dir.entries() {
        Ok(entries) => {
            for entry in entries.take(MAX_REPOSITORY_ENTRIES + 1) {
                match entry {
                    Ok(entry) => {
                        result.count += 1;
                        if result.entries.len() < MAX_REPOSITORY_ENTRIES {
                            result
                                .entries
                                .push(sanitize(&entry.file_name().to_string_lossy()));
                        } else {
                            result.truncated = true;
                        }
                    }
                    Err(e) => findings.push(finding(
                        "REPOSITORY_DIRECTORY_UNREADABLE",
                        label,
                        &e.to_string(),
                    )),
                }
            }
        }
        Err(e) => {
            result.status = "unreadable";
            findings.push(finding(
                "REPOSITORY_DIRECTORY_UNREADABLE",
                label,
                &e.to_string(),
            ));
        }
    }
    result.entries.sort();
    result
}

fn collect_repository(
    sysroot: &Dir,
    findings: &mut Vec<Finding>,
    truncated: &mut bool,
    total: &mut u64,
) -> RepositoryReport {
    let repo_dir = open_dir_beneath(sysroot, Path::new("composefs"));
    let meta_fs = repo_dir
        .as_ref()
        .ok()
        .and_then(|dir| metadata_at(dir, "meta.json".as_ref()).ok());
    let meta_contents = meta_fs
        .as_ref()
        .is_some_and(|m| m.file_type == EntryType::File)
        .then(|| {
            read_sysroot_string(
                sysroot,
                Path::new("composefs/meta.json"),
                total,
                findings,
                truncated,
                "composefs/meta.json",
            )
        })
        .flatten();
    let meta = MetaReport {
        present: meta_fs.is_some(),
        file_type: match meta_fs.as_ref() {
            Some(m) if m.file_type == EntryType::Symlink => "symlink",
            Some(m) if m.file_type == EntryType::File => "file",
            Some(_) => "other",
            None => "absent",
        },
        size: meta_fs.as_ref().map(|m| m.size),
        parse: match meta_contents
            .as_deref()
            .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
        {
            Some(_) => "json",
            None if meta_fs.is_some() => "invalid-or-unreadable",
            None => "absent",
        },
    };
    let mut inventory_map = BTreeMap::new();
    for (name, subpath) in [
        ("streams", "streams"),
        ("images", "images"),
        ("objects", "objects"),
        ("refs", "streams/refs"),
    ] {
        let inv = match repo_dir.as_ref() {
            Err(_) => DirectoryInventory {
                entries: Vec::new(),
                count: 0,
                truncated: false,
                status: "absent",
            },
            Ok(dir) => match open_dir_from(dir, Path::new(subpath)) {
                Ok(dir) => inventory_fd(&dir, findings, subpath),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => DirectoryInventory {
                    entries: Vec::new(),
                    count: 0,
                    truncated: false,
                    status: "absent",
                },
                Err(e) => {
                    findings.push(finding(
                        "REPOSITORY_DIRECTORY_UNREADABLE",
                        subpath,
                        &e.to_string(),
                    ));
                    DirectoryInventory {
                        entries: Vec::new(),
                        count: 0,
                        truncated: false,
                        status: "unreadable",
                    }
                }
            },
        };
        *truncated |= inv.truncated;
        inventory_map.insert(name, inv);
    }
    let mut tags = Vec::new();
    let tag_dir = match repo_dir.as_ref() {
        Ok(dir) => match open_dir_from(dir, Path::new("streams/refs/oci")) {
            Ok(dir) => Some(dir),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                findings.push(finding(
                    "REPOSITORY_DIRECTORY_UNREADABLE",
                    "streams/refs/oci",
                    &e.to_string(),
                ));
                None
            }
        },
        Err(_) => None,
    };
    if let Some(tag_dir) = tag_dir {
        let dir = match tag_dir.try_clone() {
            Ok(dir) => dir,
            Err(e) => {
                findings.push(finding(
                    "REPOSITORY_DIRECTORY_UNREADABLE",
                    "streams/refs/oci",
                    &e.to_string(),
                ));
                return RepositoryReport {
                    meta,
                    typed_open: "unavailable",
                    erofs_default: None,
                    erofs_extra: Vec::new(),
                    inventory: inventory_map,
                    tags,
                };
            }
        };
        match dir.entries() {
            Ok(entries) => {
                for entry in entries.take(MAX_REPOSITORY_ENTRIES + 1) {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(e) => {
                            findings.push(finding(
                                "REPOSITORY_DIRECTORY_UNREADABLE",
                                "streams/refs/oci",
                                &e.to_string(),
                            ));
                            continue;
                        }
                    };
                    if tags.len() == MAX_REPOSITORY_ENTRIES {
                        *truncated = true;
                        break;
                    }
                    let entry_name = entry.file_name();
                    let name = redact_ref(&decode_tag(&entry_name.to_string_lossy()));
                    // Reading a link's text through its parent FD cannot resolve its target.
                    let state = match rustix::fs::readlinkat(&tag_dir, &entry_name, Vec::new()) {
                        Ok(target) => std::path::PathBuf::from(std::ffi::OsString::from_vec(
                            target.into_bytes(),
                        ))
                        .file_name()
                        .and_then(|v| v.to_str())
                        .and_then(|v| v.strip_prefix("oci-manifest-"))
                        .map_or(ManifestState::Invalid, |value| {
                            checked_manifest(Some(value), findings, "repository tag")
                        }),
                        Err(e) => {
                            findings.push(finding(
                                "REPOSITORY_TAG_UNREADABLE",
                                &name,
                                &e.to_string(),
                            ));
                            ManifestState::Invalid
                        }
                    };
                    tags.push(TagReport {
                        bootc_root: name.starts_with(BOOTC_TAG_PREFIX),
                        name,
                        resolution: if state.digest().is_some() {
                            "target-parsed"
                        } else {
                            "unresolved"
                        },
                        manifest: state.digest().map(str::to_owned),
                        manifest_state: state.name(),
                    });
                }
            }
            Err(e) => findings.push(finding(
                "REPOSITORY_DIRECTORY_UNREADABLE",
                "streams/refs/oci",
                &e.to_string(),
            )),
        }
    }
    tags.sort_by(|a, b| a.name.cmp(&b.name));
    let (typed_open, erofs_default, erofs_extra) = ("unchecked-bounded-api", None, Vec::new());
    RepositoryReport {
        meta,
        typed_open,
        erofs_default,
        erofs_extra,
        inventory: inventory_map,
        tags,
    }
}
fn decode_tag(value: &str) -> String {
    value.replace("%2F", "/").replace("%25", "%")
}
fn collect_images(
    sysroot: &Dir,
    deployments: &[DeploymentReport],
    tags: &[TagReport],
    stream_names: &[String],
    findings: &mut Vec<Finding>,
    truncated: &mut bool,
    total: &mut u64,
) -> Vec<ImageReport> {
    let mut candidates = BTreeMap::<String, Vec<String>>::new();
    for d in deployments {
        if let Some(v) = &d.manifest_digest {
            candidates
                .entry(v.clone())
                .or_default()
                .push(format!("deployment:{}", d.id));
        }
    }
    for tag in tags {
        if let Some(v) = &tag.manifest {
            candidates
                .entry(v.clone())
                .or_default()
                .push(format!("tag:{}", tag.name));
        }
    }
    for name in stream_names {
        if let Some(v) = name.strip_prefix("oci-manifest-") {
            let state = checked_manifest(Some(v), findings, "repository stream");
            if let Some(v) = state.digest() {
                candidates
                    .entry(v.to_owned())
                    .or_default()
                    .push("stream".into());
            }
        }
    }
    if candidates.len() > MAX_IMAGES {
        if let Some(cutoff) = candidates.keys().nth(MAX_IMAGES).cloned() {
            candidates.retain(|key, _| key < &cutoff);
            *truncated = true;
        }
    }
    let Ok(repo) = open_dir_beneath(sysroot, Path::new("composefs")) else {
        return candidates
            .into_iter()
            .map(|(manifest, sources)| {
                ImageReport::unavailable(manifest, sources, "repository unavailable")
            })
            .collect();
    };
    candidates
        .into_iter()
        .map(|(manifest, sources)| {
            image_report(&repo, manifest, sources, tags, findings, truncated, total)
        })
        .collect()
}
impl ImageReport {
    fn unavailable(manifest: String, sources: Vec<String>, error: &str) -> Self {
        Self {
            manifest,
            sources,
            tags: Vec::new(),
            availability: "unavailable",
            error: Some(sanitize(error)),
            config: None,
            manifest_media_type: None,
            schema_version: None,
            layers: Vec::new(),
            os: None,
            architecture: None,
            created: None,
            image_v1: None,
            image_v2: None,
            boot_image_v1: None,
            boot_image_v2: None,
        }
    }
}
fn image_report(
    repo: &Dir,
    manifest: String,
    sources: Vec<String>,
    tags: &[TagReport],
    findings: &mut Vec<Finding>,
    truncated: &mut bool,
    total: &mut u64,
) -> ImageReport {
    let image_tags = tags
        .iter()
        .filter(|t| t.manifest.as_deref() == Some(&manifest))
        .map(|t| t.name.clone())
        .collect();
    let digest = match manifest.parse::<composefs_oci::OciDigest>() {
        Ok(digest) => digest,
        Err(error) => {
            findings.push(finding(
                "OCI_MANIFEST_INVALID",
                &manifest,
                &error.to_string(),
            ));
            return ImageReport::unavailable(manifest, sources, "invalid manifest digest");
        }
    };
    let manifest_data = match read_oci_object(
        repo,
        &composefs_oci::oci_image::manifest_identifier(&digest),
        total,
    ) {
        Ok(data) => data,
        Err(error) => {
            *truncated |= error.is_limited();
            findings.push(finding(error.finding(), &manifest, error.detail()));
            return ImageReport::unavailable(manifest, sources, error.detail());
        }
    };
    if composefs_oci::sha256_content_digest(&manifest_data) != digest {
        findings.push(finding(
            "OCI_MANIFEST_DIGEST_INVALID",
            &manifest,
            "manifest does not match its digest",
        ));
        return ImageReport::unavailable(manifest, sources, "invalid manifest digest");
    }
    let image = match ImageManifest::from_reader(&manifest_data[..]) {
        Ok(image) => image,
        Err(error) => {
            findings.push(finding(
                "OCI_MANIFEST_INVALID",
                &manifest,
                &error.to_string(),
            ));
            return ImageReport::unavailable(manifest, sources, "invalid manifest");
        }
    };
    let config_digest = image.config().digest().to_string();
    let config_digest_parsed = match config_digest.parse::<composefs_oci::OciDigest>() {
        Ok(digest) => digest,
        Err(error) => {
            findings.push(finding("OCI_CONFIG_INVALID", &manifest, &error.to_string()));
            return ImageReport::unavailable(manifest, sources, "invalid config digest");
        }
    };
    let config = match read_oci_object(repo, &format!("oci-config-{config_digest}"), total) {
        Ok(data) if image.config().media_type() == &MediaType::ImageConfig => {
            if composefs_oci::sha256_content_digest(&data) != config_digest_parsed {
                findings.push(finding(
                    "OCI_CONFIG_DIGEST_INVALID",
                    &manifest,
                    "config does not match its digest",
                ));
                return ImageReport::unavailable(manifest, sources, "invalid config digest");
            }
            match ImageConfiguration::from_reader(&data[..]) {
                Ok(config) => Some(config),
                Err(error) => {
                    findings.push(finding("OCI_CONFIG_INVALID", &manifest, &error.to_string()));
                    return ImageReport::unavailable(manifest, sources, "invalid config");
                }
            }
        }
        Ok(_) => None,
        Err(error) => {
            *truncated |= error.is_limited();
            findings.push(finding(error.finding(), &manifest, error.detail()));
            return ImageReport::unavailable(manifest, sources, error.detail());
        }
    };
    let bounded_layers = bounded(image.layers().iter(), MAX_LAYERS);
    if bounded_layers.omitted > 0 {
        *truncated = true;
        findings.push(finding(
            "OCI_LAYER_LIMIT_EXCEEDED",
            &manifest,
            &format!("{} or more omitted", bounded_layers.omitted),
        ));
    }
    let layers = bounded_layers
        .values
        .into_iter()
        .map(|d| LayerReport {
            digest: sanitize(&d.digest().to_string()),
            media_type: sanitize(&d.media_type().to_string()),
            size: d.size(),
        })
        .collect();
    ImageReport {
        manifest,
        sources,
        tags: image_tags,
        availability: "available",
        error: None,
        config: Some(sanitize(&config_digest)),
        manifest_media_type: image
            .media_type()
            .as_ref()
            .map(|v| sanitize(&v.to_string())),
        schema_version: Some(image.schema_version()),
        layers,
        os: config
            .as_ref()
            .map(|v| v.os().to_string())
            .filter(|v| !v.is_empty())
            .map(|v| sanitize(&v)),
        architecture: config
            .as_ref()
            .map(|v| v.architecture().to_string())
            .filter(|v| !v.is_empty())
            .map(|v| sanitize(&v)),
        created: config
            .as_ref()
            .and_then(|v| v.created().as_deref())
            .map(sanitize),
        image_v1: None,
        image_v2: None,
        boot_image_v1: None,
        boot_image_v2: None,
    }
}
fn collect_edges(
    deployments: &[DeploymentReport],
    tags: &[TagReport],
    images: &[ImageReport],
    staged: &RuntimeStaged,
) -> Vec<GraphEdge> {
    let available: BTreeSet<_> = images
        .iter()
        .filter(|i| i.availability == "available")
        .map(|i| i.manifest.as_str())
        .collect();
    let mut edges = Vec::new();
    for d in deployments {
        if let Some(m) = &d.manifest_digest {
            edges.push(GraphEdge {
                from: format!("deployment:{}", d.id),
                to: format!("manifest:{m}"),
                kind: "deployment-manifest",
                resolution: if available.contains(m.as_str()) {
                    Resolution::Present
                } else if d.manifest_stream_present == Some(false) {
                    Resolution::Missing
                } else {
                    Resolution::Unknown
                },
            });
        }
    }
    for tag in tags {
        if let Some(m) = &tag.manifest {
            edges.push(GraphEdge {
                from: format!("tag:{}", tag.name),
                to: format!("manifest:{m}"),
                kind: "tag-manifest",
                resolution: if available.contains(m.as_str()) {
                    Resolution::Present
                } else {
                    Resolution::Unknown
                },
            });
        }
    }
    for image in images {
        if let Some(config) = &image.config {
            edges.push(GraphEdge {
                from: format!("manifest:{}", image.manifest),
                to: format!("config:{config}"),
                kind: "manifest-config",
                // OciImage validates the manifest, not independent config object presence.
                resolution: Resolution::Unknown,
            });
        }
        for layer in &image.layers {
            edges.push(GraphEdge {
                from: format!("manifest:{}", image.manifest),
                to: format!("layer:{}", layer.digest),
                kind: "manifest-layer",
                // Descriptor enumeration does not resolve the layer object.
                resolution: Resolution::Unknown,
            });
        }
        for (kind, value) in [
            ("config-v1-image", &image.image_v1),
            ("config-v2-image", &image.image_v2),
        ] {
            if let Some(value) = value {
                edges.push(GraphEdge {
                    from: format!("config:{}", image.config.as_deref().unwrap_or("unknown")),
                    to: format!("image:{value}"),
                    kind,
                    resolution: Resolution::Unknown,
                });
            }
        }
    }
    if let Some(deployment) = &staged.deployment {
        edges.push(GraphEdge {
            from: "runtime:staged".into(),
            to: format!("deployment:{deployment}"),
            kind: "runtime-deployment",
            resolution: if deployments.iter().any(|d| d.id == *deployment) {
                Resolution::Present
            } else {
                Resolution::Missing
            },
        });
    }
    edges
}
fn valid_sha256(v: &str) -> bool {
    v.strip_prefix("sha256:")
        .is_some_and(|value| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
}
enum ManifestState {
    Absent,
    Valid(String),
    Invalid,
    OversizedOrRedacted,
}
impl ManifestState {
    fn digest(&self) -> Option<&str> {
        match self {
            Self::Valid(value) => Some(value),
            _ => None,
        }
    }
    fn name(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Valid(_) => "valid",
            Self::Invalid => "invalid",
            Self::OversizedOrRedacted => "oversized-or-redacted",
        }
    }
}
fn checked_manifest(
    value: Option<&str>,
    findings: &mut Vec<Finding>,
    subject: &str,
) -> ManifestState {
    let Some(value) = value else {
        return ManifestState::Absent;
    };
    if value.len() > MAX_REPORT_STRING || value.contains('@') || value.contains("://") {
        findings.push(finding(
            "MANIFEST_DIGEST_OVERSIZED_OR_REDACTED",
            subject,
            "manifest digest was not retained",
        ));
        ManifestState::OversizedOrRedacted
    } else if valid_sha256(value) {
        ManifestState::Valid(value.to_ascii_lowercase())
    } else {
        findings.push(finding(
            "MANIFEST_DIGEST_INVALID",
            subject,
            "invalid or unsafe manifest digest",
        ));
        ManifestState::Invalid
    }
}
fn redact_ref(v: &str) -> String {
    let value = sanitize(v);
    if value.contains("@") || value.contains("://") || value.contains('%') {
        return "<redacted-reference>".into();
    }
    if value.len() > 255
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"./:_-+".contains(&c))
    {
        return "<redacted-reference>".into();
    }
    value
}
fn sanitize(value: &str) -> String {
    let value = value
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_REPORT_STRING)
        .collect::<String>();
    if value.contains("@") || value.contains("://") {
        "<redacted>".into()
    } else {
        value
    }
}

#[derive(Default)]
struct BoundedNames {
    values: Vec<String>,
    truncated: bool,
}

struct Bounded<T> {
    values: Vec<T>,
    omitted: usize,
}

// Consume one item past the limit to distinguish an exact limit from overflow.
fn bounded<T>(values: impl IntoIterator<Item = T>, limit: usize) -> Bounded<T> {
    let mut iter = values.into_iter();
    let values = iter.by_ref().take(limit).collect();
    Bounded {
        values,
        omitted: usize::from(iter.next().is_some()),
    }
}

#[derive(Default)]
struct BoundedArtifacts {
    values: BTreeSet<String>,
    truncated: bool,
}

impl BoundedArtifacts {
    fn insert(&mut self, value: String) {
        if self.values.contains(&value) {
            return;
        }
        if self.values.len() == MAX_ARTIFACTS {
            self.truncated = true;
        } else {
            self.values.insert(value);
        }
    }
}

fn read_dir_dirs_fd(
    dir: &Dir,
    findings: &mut Vec<Finding>,
    path: &Path,
    limit: usize,
) -> BoundedNames {
    let mut result = BoundedNames {
        values: Vec::with_capacity(limit),
        truncated: false,
    };
    let dir = match dir.try_clone() {
        Ok(dir) => dir,
        Err(e) => {
            findings.push(finding(
                "DEPLOYMENT_DIRECTORY_UNREADABLE",
                &path.display().to_string(),
                &e.to_string(),
            ));
            return result;
        }
    };
    match dir.entries() {
        Ok(entries) => {
            for entry in entries.take(limit + 1) {
                match entry {
                    Ok(_) if result.values.len() >= limit => result.truncated = true,
                    Ok(entry) => match entry.file_type() {
                        Ok(t) if t.is_dir() => match entry.file_name().into_string() {
                            Ok(name) if result.values.len() < limit => result.values.push(name),
                            Ok(_) => result.truncated = true,
                            Err(_) => findings.push(finding(
                                "DEPLOYMENT_NAME_INVALID",
                                &path.display().to_string(),
                                "non-UTF-8 entry",
                            )),
                        },
                        Ok(t) if t.is_symlink() => findings.push(finding(
                            "DEPLOYMENT_DIRECTORY_SYMLINK",
                            &path.join(entry.file_name()).display().to_string(),
                            "refusing symlink",
                        )),
                        Ok(_) => {}
                        Err(e) => findings.push(finding(
                            "DEPLOYMENT_DIRECTORY_UNREADABLE",
                            &path.display().to_string(),
                            &e.to_string(),
                        )),
                    },
                    Err(e) => findings.push(finding(
                        "DEPLOYMENT_DIRECTORY_UNREADABLE",
                        &path.display().to_string(),
                        &e.to_string(),
                    )),
                }
            }
        }
        Err(e) => findings.push(finding(
            "DEPLOYMENT_DIRECTORY_UNREADABLE",
            &path.display().to_string(),
            &e.to_string(),
        )),
    }
    result.values.sort();
    result
}

/// Read a UTF-8 file below the diagnostic sysroot.
fn read_sysroot_string(
    sysroot: &Dir,
    path: &Path,
    total: &mut u64,
    findings: &mut Vec<Finding>,
    truncated: &mut bool,
    subject: &str,
) -> Option<String> {
    read_string_beneath(sysroot, path, total, findings, truncated, subject, false)
}

fn read_limited_at(
    dir: &Dir,
    name: &std::ffi::OsStr,
    total: &mut u64,
    findings: &mut Vec<Finding>,
    truncated: &mut bool,
    subject: &str,
) -> Option<String> {
    let root = match dir.try_clone() {
        Ok(root) => root,
        Err(e) => {
            findings.push(finding("READ_UNREADABLE", subject, &e.to_string()));
            return None;
        }
    };
    read_string_from_dir(&root, name, total, findings, truncated, subject, false)
}

#[derive(Debug, PartialEq, Eq)]
enum BoundedRead {
    Present(Vec<u8>),
    Absent,
    NonRegular,
    Oversized,
    BudgetExhausted,
    BudgetInsufficient,
    Truncated,
    Io(String),
}

/// Read bounded bytes below `root` without following any path component.
///
/// `root` is either the host root or the diagnostic sysroot; callers name this
/// distinction explicitly instead of relying on absolute paths.
fn read_bytes_beneath(root: &Dir, relative: &Path, total: &mut u64) -> BoundedRead {
    let file = match open_beneath(root, relative) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return BoundedRead::Absent,
        Err(e) => return BoundedRead::Io(e.to_string()),
    };
    read_bounded_file(file, total)
}

fn read_bounded_file(file: File, total: &mut u64) -> BoundedRead {
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(e) => return BoundedRead::Io(e.to_string()),
    };
    if !metadata.is_file() {
        return BoundedRead::NonRegular;
    }
    if metadata.len() > MAX_FILE_BYTES {
        return BoundedRead::Oversized;
    }
    if *total >= MAX_READ_BYTES {
        return BoundedRead::BudgetExhausted;
    }
    let available = (MAX_READ_BYTES - *total).min(MAX_FILE_BYTES);
    if metadata.len() > available {
        return BoundedRead::BudgetInsufficient;
    }
    let mut bytes = Vec::with_capacity(usize::try_from(available).unwrap_or(0));
    if let Err(e) = (&file).take(available).read_to_end(&mut bytes) {
        return BoundedRead::Io(e.to_string());
    }
    // Count bytes before decoding so malformed host data consumes the budget.
    *total += bytes.len() as u64;
    if bytes.len() as u64 == available
        && (metadata.len() < available || file.metadata().map_or(true, |m| m.len() > available))
    {
        return BoundedRead::Truncated;
    }
    BoundedRead::Present(bytes)
}

fn host_read_string(
    host_root: &Dir,
    relative: &str,
    subject: &str,
    total: &mut u64,
    findings: &mut Vec<Finding>,
    truncated: &mut bool,
) -> Option<String> {
    read_string_beneath(
        host_root,
        Path::new(relative),
        total,
        findings,
        truncated,
        subject,
        true,
    )
}

fn read_string_beneath(
    root: &Dir,
    relative: &Path,
    total: &mut u64,
    findings: &mut Vec<Finding>,
    truncated: &mut bool,
    subject: &str,
    host: bool,
) -> Option<String> {
    record_string_read(
        read_bytes_beneath(root, relative, total),
        findings,
        truncated,
        subject,
        host,
    )
}

fn record_string_read(
    read: BoundedRead,
    findings: &mut Vec<Finding>,
    truncated: &mut bool,
    subject: &str,
    host: bool,
) -> Option<String> {
    match read {
        BoundedRead::Present(bytes) => String::from_utf8(bytes).map_or_else(
            |_| {
                findings.push(finding(
                    if host {
                        "HOST_READ_INVALID_UTF8"
                    } else {
                        "READ_INVALID_UTF8"
                    },
                    subject,
                    "file is not UTF-8",
                ));
                None
            },
            Some,
        ),
        BoundedRead::Absent => None,
        BoundedRead::NonRegular => {
            findings.push(finding(
                if host {
                    "HOST_READ_LIMIT_EXCEEDED"
                } else {
                    "READ_NONREGULAR_REFUSED"
                },
                subject,
                "refusing non-regular file",
            ));
            None
        }
        BoundedRead::Oversized => {
            *truncated = true;
            findings.push(finding(
                if host {
                    "HOST_READ_LIMIT_EXCEEDED"
                } else {
                    "READ_LIMIT_EXCEEDED"
                },
                subject,
                "file is oversized",
            ));
            None
        }
        BoundedRead::BudgetExhausted => {
            *truncated = true;
            findings.push(finding(
                if host {
                    "HOST_READ_LIMIT_EXCEEDED"
                } else {
                    "READ_LIMIT_EXCEEDED"
                },
                subject,
                "global read budget exhausted",
            ));
            None
        }
        BoundedRead::BudgetInsufficient => {
            *truncated = true;
            findings.push(finding(
                if host {
                    "HOST_READ_LIMIT_EXCEEDED"
                } else {
                    "READ_LIMIT_EXCEEDED"
                },
                subject,
                "file exceeds remaining global read budget",
            ));
            None
        }
        BoundedRead::Truncated => {
            *truncated = true;
            findings.push(finding(
                if host {
                    "HOST_READ_LIMIT_EXCEEDED"
                } else {
                    "READ_LIMIT_EXCEEDED"
                },
                subject,
                "file grew while being read",
            ));
            None
        }
        BoundedRead::Io(error) => {
            findings.push(finding(
                if host {
                    "HOST_READ_UNREADABLE"
                } else {
                    "READ_UNREADABLE"
                },
                subject,
                &error,
            ));
            None
        }
    }
}

fn read_string_from_dir(
    dir: &Dir,
    name: &std::ffi::OsStr,
    total: &mut u64,
    findings: &mut Vec<Finding>,
    truncated: &mut bool,
    subject: &str,
    host: bool,
) -> Option<String> {
    let file = match rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(e) if std::io::Error::from(e).kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            findings.push(finding(
                if host {
                    "HOST_READ_UNREADABLE"
                } else {
                    "READ_UNREADABLE"
                },
                subject,
                &e.to_string(),
            ));
            return None;
        }
    };
    record_string_read(
        read_bounded_file(file, total),
        findings,
        truncated,
        subject,
        host,
    )
}
fn open_beneath(sysroot: &Dir, relative: &Path) -> std::io::Result<File> {
    let components: Vec<_> = relative.components().collect();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "non-normal path",
        ));
    }
    let mut dir = sysroot.try_clone()?;
    for component in &components[..components.len() - 1] {
        let fd = rustix::fs::openat(
            dir.as_fd(),
            component.as_os_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        dir = Dir::from(fd);
    }
    let Some(last) = components.last() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty path",
        ));
    };
    let fd = rustix::fs::openat(
        dir.as_fd(),
        last.as_os_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    Ok(File::from(fd))
}

fn metadata_beneath(sysroot: &Dir, relative: &Path) -> std::io::Result<EntryMetadata> {
    let components: Vec<_> = relative.components().collect();
    if components.is_empty()
        || components
            .iter()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "non-normal path",
        ));
    }
    let parent = if components.len() == 1 {
        sysroot.try_clone()?
    } else {
        let path = components[..components.len() - 1]
            .iter()
            .collect::<std::path::PathBuf>();
        open_dir_beneath(sysroot, &path)?
    };
    let Some(last) = components.last() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty path",
        ));
    };
    metadata_at(&parent, last.as_os_str())
}
fn metadata_token(dir: &Dir) -> Option<(u64, u64, u64)> {
    let metadata = dir.metadata(".").ok()?;
    Some((
        metadata.ino(),
        metadata.size(),
        metadata.mtime_nsec() as u64,
    ))
}
fn collect_boot_data(
    sysroot: &Dir,
    host_root: &Dir,
    deployments: &[DeploymentReport],
    findings: &mut Vec<Finding>,
    total: &mut u64,
    truncated: &mut bool,
) -> (BootloaderReport, Vec<BootEntryReport>, Vec<ArtifactReport>) {
    let bls_roots = [
        ("active", "boot/loader/entries"),
        ("staged", "boot/loader/entries.staged"),
        ("active", "boot/efi/loader/entries"),
        ("staged", "boot/efi/loader/entries.staged"),
    ];
    let mut entries = Vec::new();
    let mut artifacts = BoundedArtifacts::default();
    let mut bls_directories = Vec::new();
    for (source, root) in bls_roots {
        let root = Path::new(root);
        if metadata_beneath(sysroot, root)
            .ok()
            .is_some_and(|metadata| metadata.file_type == EntryType::Symlink)
        {
            findings.push(finding(
                "BLS_DIRECTORY_SYMLINK",
                &root.display().to_string(),
                "refusing symlink",
            ));
            continue;
        }
        let Ok(dir) = open_dir_beneath(sysroot, root) else {
            continue;
        };
        bls_directories.push(sanitize(&root.display().to_string()));
        let names = read_dir_files_fd(
            &dir,
            findings,
            root,
            "BOOT_ENTRIES_UNREADABLE",
            MAX_BOOT_ENTRIES,
        );
        *truncated |= names.truncated;
        for name in names.values {
            if entries.len() >= MAX_BOOT_ENTRIES {
                *truncated = true;
                break;
            }
            let filename = sanitize(&root.join(&name).display().to_string());
            let order = entries.len();
            let Some(contents) =
                read_limited_at(&dir, name.as_ref(), total, findings, truncated, &filename)
            else {
                entries.push(unparsed_boot_entry(filename, source, order));
                continue;
            };
            match parse_bls_config(&contents) {
                Ok(config) => {
                    let (linux, initrd, efi, composefs) = bls_fields(&config);
                    for path in linux.iter().chain(initrd.iter()).chain(efi.iter()) {
                        artifacts.insert(path.clone());
                    }
                    entries.push(BootEntryReport {
                        filename,
                        source,
                        kind: "bls",
                        order,
                        title: config.title.as_ref().map(|v| sanitize(v)),
                        version: Some(sanitize(&config.version().to_string())),
                        sort_key: config.sort_key.as_ref().map(|v| sanitize(v)),
                        linux,
                        initrd,
                        efi,
                        menu_index: None,
                        chainloader: None,
                        search: None,
                        composefs,
                        parse: "parsed",
                    });
                }
                Err(e) => {
                    findings.push(finding("BLS_ENTRY_INVALID", &filename, &e.to_string()));
                    entries.push(unparsed_boot_entry(filename, source, order));
                }
            }
        }
    }
    let mut grub_directories = Vec::new();
    for root in [Path::new("boot/grub2"), Path::new("boot/grub")] {
        if metadata_beneath(sysroot, root)
            .ok()
            .is_some_and(|metadata| metadata.file_type == EntryType::Symlink)
        {
            findings.push(finding(
                "GRUB_DIRECTORY_SYMLINK",
                &root.display().to_string(),
                "refusing symlink",
            ));
            continue;
        }
        let Ok(dir) = open_dir_beneath(sysroot, root) else {
            continue;
        };
        grub_directories.push(sanitize(&root.display().to_string()));
        for (source, name) in [("active", USER_CFG), ("staged", USER_CFG_STAGED)] {
            let metadata = match metadata_at(&dir, name.as_ref()) {
                Ok(metadata) => metadata,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    findings.push(finding(
                        "GRUB_DIRECTORY_UNREADABLE",
                        &root.display().to_string(),
                        &e.to_string(),
                    ));
                    continue;
                }
            };
            if metadata.file_type == EntryType::Symlink {
                findings.push(finding(
                    "GRUB_CONFIG_SYMLINK",
                    &root.join(name).display().to_string(),
                    "refusing symlink",
                ));
                continue;
            }
            let filename = sanitize(&root.join(name).display().to_string());
            let Some(contents) =
                read_limited_at(&dir, name.as_ref(), total, findings, truncated, &filename)
            else {
                continue;
            };
            match parse_grub_menuentry_file(&contents) {
                Ok(menuentries) => {
                    for (menu_index, menu) in menuentries.into_iter().enumerate() {
                        if entries.len() >= MAX_BOOT_ENTRIES {
                            *truncated = true;
                            break;
                        }
                        let chainloader = sanitize(&menu.body.chainloader);
                        if !chainloader.is_empty() {
                            artifacts.insert(chainloader.clone());
                        }
                        let identity = menu.get_verity().ok();
                        entries.push(BootEntryReport {
                            filename: filename.clone(),
                            source,
                            kind: "grub",
                            order: entries.len(),
                            title: Some(sanitize(&menu.title)),
                            version: None,
                            sort_key: None,
                            linux: None,
                            initrd: Vec::new(),
                            efi: None,
                            menu_index: Some(menu_index),
                            chainloader: (!chainloader.is_empty()).then_some(chainloader),
                            search: (!menu.body.search.is_empty())
                                .then_some("<redacted-search>".into()),
                            composefs: ComposefsIdentity {
                                value: identity.map(|v| sanitize(&v)),
                                allow_missing: None,
                                status: "parsed-from-chainloader",
                            },
                            parse: "parsed",
                        });
                    }
                }
                Err(e) => findings.push(finding("GRUB_MENU_INVALID", &filename, &e.to_string())),
            }
        }
    }
    let esp = collect_visible_esp(sysroot, host_root, findings, truncated, total);
    let loader_info = read_loader_info(host_root, total, findings, truncated);
    let classification = match (!grub_directories.is_empty(), loader_info.is_some()) {
        (true, true) => "mixed-grub-systemd-boot-evidence",
        (true, false) => "grub-evidence",
        (false, true) => "systemd-boot-evidence",
        (false, false) => "unknown",
    };
    let efi = match metadata_beneath(host_root, Path::new("sys/firmware/efi")) {
        Ok(metadata) if metadata.file_type == EntryType::Directory => "present",
        Ok(metadata) if metadata.file_type == EntryType::Symlink => {
            findings.push(finding(
                "EFI_DIRECTORY_SYMLINK",
                "sys/firmware/efi",
                "refusing symlink",
            ));
            "absent-or-unavailable"
        }
        Ok(_) => "absent-or-unavailable",
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "absent-or-unavailable",
        Err(e) => {
            findings.push(finding(
                "EFI_DIRECTORY_UNREADABLE",
                "sys/firmware/efi",
                &e.to_string(),
            ));
            "absent-or-unavailable"
        }
    };
    let bootloader = BootloaderReport {
        classification,
        grub_directories,
        bls_directories,
        loader_info,
        efi,
        esp,
    };
    if artifacts.truncated {
        *truncated = true;
        findings.push(finding(
            "BOOT_ARTIFACT_LIMIT_EXCEEDED",
            "boot artifacts",
            "1 or more omitted",
        ));
    }
    let artifacts = artifacts
        .values
        .into_iter()
        .map(|path| collect_artifact(sysroot, &path, findings, truncated, total))
        .collect();
    let _ = deployments; // Graph construction validates deployment targets after all entries are collected.
    (bootloader, entries, artifacts)
}

fn unparsed_boot_entry(filename: String, source: &'static str, order: usize) -> BootEntryReport {
    BootEntryReport {
        filename,
        source,
        kind: "bls",
        order,
        title: None,
        version: None,
        sort_key: None,
        linux: None,
        initrd: Vec::new(),
        efi: None,
        menu_index: None,
        chainloader: None,
        search: None,
        composefs: ComposefsIdentity {
            value: None,
            allow_missing: None,
            status: "unavailable",
        },
        parse: "invalid-or-unreadable",
    }
}

fn bls_fields(
    config: &crate::parsers::bls_config::BLSConfig,
) -> (
    Option<String>,
    Vec<String>,
    Option<String>,
    ComposefsIdentity,
) {
    let cmdline_identity = config.get_cmdline().ok().and_then(|cmdline| {
        match ComposefsCmdline::find_in_cmdline(&Cmdline::from(cmdline)) {
            Ok(identity) => identity,
            Err(error) => {
                tracing::debug!(%error, "Unable to parse composefs command line in BLS entry");
                None
            }
        }
    });
    let identity = cmdline_identity
        .as_ref()
        .map(|v| sanitize(&v.digest))
        .or_else(|| config.get_verity().ok().map(|v| sanitize(&v)));
    let allow_missing = cmdline_identity.map(|v| v.allow_missing_fsverity);
    match &config.cfg_type {
        BLSConfigType::NonEFI { linux, initrd, .. } => (
            Some(sanitize(linux.as_str())),
            initrd.iter().map(|v| sanitize(v.as_str())).collect(),
            None,
            ComposefsIdentity {
                value: identity,
                allow_missing,
                status: "parsed",
            },
        ),
        BLSConfigType::EFI { key } => {
            let path = match key {
                EFIKey::Efi(v) | EFIKey::Uki(v) => v,
            };
            (
                None,
                Vec::new(),
                Some(sanitize(path.as_str())),
                ComposefsIdentity {
                    value: identity,
                    allow_missing: None,
                    status: "parsed",
                },
            )
        }
        BLSConfigType::Unknown => (
            None,
            Vec::new(),
            None,
            ComposefsIdentity {
                value: None,
                allow_missing: None,
                status: "unknown",
            },
        ),
    }
}

fn collect_visible_esp(
    sysroot: &Dir,
    host_root: &Dir,
    findings: &mut Vec<Finding>,
    truncated: &mut bool,
    total: &mut u64,
) -> EspReport {
    let mountinfo = host_read_string(
        host_root,
        &format!("proc/{}/mountinfo", std::process::id()),
        "mountinfo",
        total,
        findings,
        truncated,
    )
    .unwrap_or_default();
    let candidates = ["/sysroot/boot/efi", "/sysroot/efi"];
    let Some(mountpoint) = visible_mountpoint(&mountinfo, &candidates) else {
        return EspReport {
            status: "unavailable-not-mounted",
            mountpoint: None,
            entries: Vec::new(),
        };
    };
    let relative = if mountpoint == "/sysroot/boot/efi" {
        Path::new("boot/efi")
    } else {
        Path::new("efi")
    };
    let names = match open_dir_beneath(sysroot, relative) {
        Ok(dir) => read_dir_entries_fd(
            &dir,
            findings,
            relative,
            "ESP_UNREADABLE",
            MAX_REPOSITORY_ENTRIES,
        ),
        Err(e) => {
            findings.push(finding(
                "ESP_UNREADABLE",
                &relative.display().to_string(),
                &e.to_string(),
            ));
            BoundedNames::default()
        }
    };
    *truncated |= names.truncated;
    EspReport {
        status: "visible",
        mountpoint: Some(sanitize(relative.to_string_lossy().as_ref())),
        entries: names.values,
    }
}

fn visible_mountpoint(mountinfo: &str, candidates: &[&str]) -> Option<String> {
    mountinfo.lines().find_map(|line| {
        let mountpoint = line.split(" - ").next()?.split_whitespace().nth(4)?;
        candidates
            .iter()
            .find(|path| **path == mountpoint)
            .map(|path| (*path).to_owned())
    })
}

fn read_dir_entries_fd(
    dir: &Dir,
    findings: &mut Vec<Finding>,
    path: &Path,
    code: &'static str,
    limit: usize,
) -> BoundedNames {
    let mut result = BoundedNames {
        values: Vec::with_capacity(limit),
        truncated: false,
    };
    let dir = match dir.try_clone() {
        Ok(dir) => dir,
        Err(e) => {
            findings.push(finding(code, &path.display().to_string(), &e.to_string()));
            return result;
        }
    };
    match dir.entries() {
        Ok(entries) => {
            for entry in entries.take(limit + 1) {
                match entry {
                    Ok(_) if result.values.len() >= limit => result.truncated = true,
                    Ok(entry) => match entry.file_name().into_string() {
                        Ok(name) if result.values.len() < limit => {
                            result.values.push(sanitize(&name))
                        }
                        Ok(_) => result.truncated = true,
                        Err(_) => findings.push(finding(
                            code,
                            &path.display().to_string(),
                            "non-UTF-8 entry",
                        )),
                    },
                    Err(e) => {
                        findings.push(finding(code, &path.display().to_string(), &e.to_string()))
                    }
                }
            }
        }
        Err(e) => findings.push(finding(code, &path.display().to_string(), &e.to_string())),
    }
    result.values.sort();
    result
}

fn collect_artifact(
    sysroot: &Dir,
    name: &str,
    findings: &mut Vec<Finding>,
    truncated: &mut bool,
    total: &mut u64,
) -> ArtifactReport {
    let Ok(relative) = artifact_relative(name) else {
        findings.push(finding(
            "BOOT_ARTIFACT_PATH_INVALID",
            "boot artifact",
            "path escapes or is ambiguous",
        ));
        return ArtifactReport {
            path: "<invalid-artifact-path>".into(),
            kind: "unsupported",
            present: false,
            size: None,
            file_type: "unavailable",
            uki: None,
        };
    };
    let efi_candidate = Path::new("boot/efi").join(&relative);
    let boot_candidate = Path::new("boot").join(&relative);
    // GRUB BLS entries are relative to the filesystem holding /boot; when /boot is
    // not its own partition they are written as `/boot/...` against the physical root.
    let root_candidate = relative.starts_with("boot").then(|| relative.clone());
    let found = [
        Some(&efi_candidate),
        Some(&boot_candidate),
        root_candidate.as_ref(),
    ]
    .into_iter()
    .flatten()
    .find(|candidate| metadata_beneath(sysroot, candidate).is_ok())
    .cloned();
    let relative = found.unwrap_or(boot_candidate);
    let metadata = metadata_beneath(sysroot, &relative).ok();
    let present = metadata
        .as_ref()
        .is_some_and(|m| m.file_type == EntryType::File);
    if metadata
        .as_ref()
        .is_some_and(|m| m.file_type == EntryType::Symlink)
    {
        findings.push(finding("BOOT_ARTIFACT_SYMLINK", name, "refusing symlink"));
    } else if metadata.is_some() && !present {
        findings.push(finding(
            "BOOT_ARTIFACT_NONREGULAR",
            name,
            "refusing non-regular file",
        ));
    } else if !present {
        findings.push(finding(
            "BOOT_ARTIFACT_MISSING",
            name,
            "referenced artifact is absent",
        ));
    }
    let uki = name.ends_with(".efi").then(|| {
        collect_uki(
            sysroot, &relative, present, findings, truncated, name, total,
        )
    });
    ArtifactReport {
        path: sanitize(name),
        kind: if name.ends_with(".efi") {
            "uki-or-efi"
        } else {
            "boot-file"
        },
        present,
        size: metadata.as_ref().map(|m| m.size),
        file_type: match metadata {
            Some(m) if m.file_type == EntryType::File => "file",
            Some(m) if m.file_type == EntryType::Symlink => "symlink",
            Some(_) => "other",
            None => "absent",
        },
        uki,
    }
}

fn artifact_relative(value: &str) -> anyhow::Result<std::path::PathBuf> {
    if value.is_empty() || value.starts_with("//") || value.contains('\0') {
        anyhow::bail!("empty or ambiguous path")
    }
    let path = Path::new(value);
    let mut result = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) if !value.is_empty() => result.push(value),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                anyhow::bail!("non-normal path component")
            }
            _ => anyhow::bail!("empty path component"),
        }
    }
    if result.as_os_str().is_empty() {
        anyhow::bail!("empty path")
    }
    Ok(result)
}

/// Limit bytes physically read by the buffered UKI parser across all sections.
struct BudgetedUkiReader<'a> {
    file: File,
    total: &'a mut u64,
    exhausted: bool,
}

impl<'a> BudgetedUkiReader<'a> {
    fn new(file: File, total: &'a mut u64) -> Self {
        Self {
            file,
            total,
            exhausted: false,
        }
    }
}

impl std::io::Read for BudgetedUkiReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = MAX_READ_BYTES.saturating_sub(*self.total);
        if remaining == 0 && !buf.is_empty() {
            self.exhausted = true;
            return Err(std::io::Error::other("global read budget exhausted"));
        }
        let limit = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let read = self.file.read(&mut buf[..limit])?;
        *self.total += read as u64;
        Ok(read)
    }
}

impl std::io::Seek for BudgetedUkiReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}

#[derive(Default)]
struct UkiTextSections {
    uname: Option<String>,
    os_release: Option<String>,
    cmdline: Option<String>,
}

enum UkiTextSectionError {
    LimitExceeded,
    Invalid,
}

/// Read UKI text sections without trusting PE offsets or section sizes for allocation.
///
/// `composefs_boot::uki::get_text_section_buffered()` allocates based on a PE section's
/// `virtual_size`, so it is unsuitable for untrusted UKIs. Validate the on-disk range
/// before allocating each text section instead.
fn read_uki_text_sections(
    file: &mut BudgetedUkiReader<'_>,
    file_len: u64,
) -> Result<UkiTextSections, UkiTextSectionError> {
    fn read_exact(
        file: &mut BudgetedUkiReader<'_>,
        buf: &mut [u8],
    ) -> Result<(), UkiTextSectionError> {
        file.read_exact(buf).map_err(|_| {
            if file.exhausted {
                UkiTextSectionError::LimitExceeded
            } else {
                UkiTextSectionError::Invalid
            }
        })
    }

    fn le_u16(bytes: &[u8]) -> u16 {
        u16::from_le_bytes(bytes.try_into().expect("fixed-size PE field"))
    }

    fn le_u32(bytes: &[u8]) -> u32 {
        u32::from_le_bytes(bytes.try_into().expect("fixed-size PE field"))
    }

    let mut dos_stub = [0; PE_DOS_STUB_SIZE];
    file.seek(SeekFrom::Start(0))
        .map_err(|_| UkiTextSectionError::Invalid)?;
    read_exact(file, &mut dos_stub)?;
    let pe_offset = u64::from(le_u32(&dos_stub[60..64]));
    let pe_header_end = pe_offset
        .checked_add(PE_HEADER_SIZE as u64)
        .filter(|end| *end <= file_len)
        .ok_or(UkiTextSectionError::Invalid)?;

    let mut pe_header = [0; PE_HEADER_SIZE];
    file.seek(SeekFrom::Start(pe_offset))
        .map_err(|_| UkiTextSectionError::Invalid)?;
    read_exact(file, &mut pe_header)?;
    if pe_header[..4] != *b"PE\0\0" {
        return Err(UkiTextSectionError::Invalid);
    }
    let section_count = u64::from(le_u16(&pe_header[6..8]));
    let optional_header_size = u64::from(le_u16(&pe_header[20..22]));
    let section_headers_offset = pe_header_end
        .checked_add(optional_header_size)
        .ok_or(UkiTextSectionError::Invalid)?;
    let section_headers_size = section_count
        .checked_mul(PE_SECTION_HEADER_SIZE as u64)
        .ok_or(UkiTextSectionError::Invalid)?;
    section_headers_offset
        .checked_add(section_headers_size)
        .filter(|end| *end <= file_len)
        .ok_or(UkiTextSectionError::Invalid)?;

    let mut sections = UkiTextSections::default();
    file.seek(SeekFrom::Start(section_headers_offset))
        .map_err(|_| UkiTextSectionError::Invalid)?;
    for index in 0..section_count {
        let mut header = [0; PE_SECTION_HEADER_SIZE];
        let header_offset = section_headers_offset + index * PE_SECTION_HEADER_SIZE as u64;
        file.seek(SeekFrom::Start(header_offset))
            .map_err(|_| UkiTextSectionError::Invalid)?;
        read_exact(file, &mut header)?;
        let name = &header[..8];
        let target = match name {
            b".uname\0\0" => &mut sections.uname,
            b".osrel\0\0" => &mut sections.os_release,
            b".cmdline" => &mut sections.cmdline,
            _ => continue,
        };
        // Match composefs_boot's first-match behavior if a malformed UKI has duplicates.
        if target.is_some() {
            continue;
        }
        let size = u64::from(le_u32(&header[8..12]));
        let offset = u64::from(le_u32(&header[20..24]));
        let Some(section_end) = offset.checked_add(size) else {
            return Err(UkiTextSectionError::Invalid);
        };
        if size > MAX_FILE_BYTES || section_end > file_len {
            return Err(UkiTextSectionError::LimitExceeded);
        }
        let mut contents = vec![0; usize::try_from(size).expect("section size is bounded")];
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| UkiTextSectionError::Invalid)?;
        read_exact(file, &mut contents)?;
        *target = String::from_utf8(contents).ok();
    }
    Ok(sections)
}

fn collect_uki(
    sysroot: &Dir,
    path: &Path,
    present: bool,
    findings: &mut Vec<Finding>,
    truncated: &mut bool,
    subject: &str,
    total: &mut u64,
) -> UkiReport {
    if !present {
        return UkiReport {
            parse: "unavailable",
            uname: None,
            os_release: None,
            composefs: ComposefsIdentity {
                value: None,
                allow_missing: None,
                status: "unavailable",
            },
            sections: "not-read",
        };
    }
    let Ok(file) = open_beneath(sysroot, path) else {
        return UkiReport {
            parse: "unreadable",
            uname: None,
            os_release: None,
            composefs: ComposefsIdentity {
                value: None,
                allow_missing: None,
                status: "unavailable",
            },
            sections: "not-read",
        };
    };
    let Ok(metadata) = file.metadata() else {
        return UkiReport {
            parse: "unreadable",
            uname: None,
            os_release: None,
            composefs: ComposefsIdentity {
                value: None,
                allow_missing: None,
                status: "unavailable",
            },
            sections: "not-read",
        };
    };
    if metadata.len() > MAX_FILE_BYTES {
        findings.push(finding(
            "UKI_READ_LIMIT_EXCEEDED",
            subject,
            "UKI exceeds per-file read limit",
        ));
        return UkiReport {
            parse: "limit-exceeded",
            uname: None,
            os_release: None,
            composefs: ComposefsIdentity {
                value: None,
                allow_missing: None,
                status: "unavailable",
            },
            sections: "not-read",
        };
    }
    let mut file = BudgetedUkiReader::new(file, total);
    let sections = read_uki_text_sections(&mut file, metadata.len());
    if matches!(sections, Err(UkiTextSectionError::LimitExceeded)) || file.exhausted {
        *truncated = true;
        findings.push(finding(
            "UKI_READ_LIMIT_EXCEEDED",
            subject,
            "UKI text section exceeds read limit",
        ));
        return UkiReport {
            parse: "limit-exceeded",
            uname: None,
            os_release: None,
            composefs: ComposefsIdentity {
                value: None,
                allow_missing: None,
                status: "unavailable",
            },
            sections: "partially-read",
        };
    }
    let sections = sections.unwrap_or_default();
    let uname = sections.uname.map(|v| sanitize(v.trim()));
    let os_release = sections.os_release.map(|v| sanitize(v.trim()));
    let cmdline = sections.cmdline;
    let composefs = cmdline
        .and_then(
            |v| match ComposefsCmdline::find_in_cmdline(&Cmdline::from(v.as_str())) {
                Ok(identity) => identity,
                Err(error) => {
                    tracing::debug!(%error, "Unable to parse composefs command line in UKI");
                    None
                }
            },
        )
        .map(|v| ComposefsIdentity {
            value: Some(sanitize(&v.digest)),
            allow_missing: Some(v.allow_missing_fsverity),
            status: "parsed",
        })
        .unwrap_or(ComposefsIdentity {
            value: None,
            allow_missing: None,
            status: "absent-or-unsupported",
        });
    UkiReport {
        parse: "parsed-text-sections",
        uname,
        os_release,
        composefs,
        sections: "binary-payloads-not-read",
    }
}

fn collect_boot_edges(
    edges: &mut Vec<GraphEdge>,
    entries: &[BootEntryReport],
    artifacts: &[ArtifactReport],
    deployments: &[DeploymentReport],
) {
    let artifact_paths: BTreeSet<_> = artifacts
        .iter()
        .filter(|a| a.present)
        .map(|a| a.path.as_str())
        .collect();
    for entry in entries {
        let from = format!("boot-entry:{}:{}", entry.source, entry.filename);
        for artifact in entry
            .linux
            .iter()
            .chain(entry.initrd.iter())
            .chain(entry.efi.iter())
            .chain(entry.chainloader.iter())
        {
            edges.push(GraphEdge {
                from: from.clone(),
                to: format!("artifact:{artifact}"),
                kind: "entry-artifact",
                resolution: if artifact_paths.contains(artifact.as_str()) {
                    Resolution::Present
                } else {
                    Resolution::Missing
                },
            });
        }
        if let Some(identity) = &entry.composefs.value {
            edges.push(GraphEdge {
                from: from.clone(),
                to: format!("composefs:{identity}"),
                kind: "entry-composefs",
                resolution: Resolution::Unknown,
            });
            edges.push(GraphEdge {
                from: format!("composefs:{identity}"),
                to: format!("deployment:{identity}"),
                kind: "composefs-deployment",
                resolution: if deployments.iter().any(|d| d.id == *identity) {
                    Resolution::Present
                } else {
                    Resolution::Missing
                },
            });
        }
    }
    for artifact in artifacts {
        if let Some(uki) = &artifact.uki {
            if let Some(identity) = &uki.composefs.value {
                edges.push(GraphEdge {
                    from: format!("artifact:{}", artifact.path),
                    to: format!("composefs:{identity}"),
                    kind: "uki-composefs",
                    resolution: Resolution::Unknown,
                });
            }
        }
    }
}
fn os_release_id(
    host_root: &Dir,
    total: &mut u64,
    findings: &mut Vec<Finding>,
    truncated: &mut bool,
) -> Option<String> {
    read_os_release(host_root, total, findings, truncated)?
        .lines()
        .find_map(|l| l.strip_prefix("ID="))
        .map(|v| sanitize(v.trim_matches('"')))
}

fn read_os_release(
    host_root: &Dir,
    total: &mut u64,
    findings: &mut Vec<Finding>,
    truncated: &mut bool,
) -> Option<String> {
    let etc = match open_dir_beneath(host_root, Path::new("etc")) {
        Ok(etc) => etc,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return host_read_string(
                host_root,
                "usr/lib/os-release",
                "os-release",
                total,
                findings,
                truncated,
            );
        }
        Err(e) => {
            findings.push(finding(
                "HOST_READ_UNREADABLE",
                "os-release",
                &e.to_string(),
            ));
            return None;
        }
    };
    match metadata_at(&etc, "os-release".as_ref()) {
        Ok(EntryMetadata {
            file_type: EntryType::File,
            ..
        }) => host_read_string(
            host_root,
            "etc/os-release",
            "os-release",
            total,
            findings,
            truncated,
        ),
        Ok(EntryMetadata {
            file_type: EntryType::Symlink,
            ..
        }) => {
            let target = rustix::fs::readlinkat(&etc, "os-release", Vec::new())
                .map(|target| target.into_bytes());
            match target.as_deref() {
                Ok(b"../usr/lib/os-release" | b"/usr/lib/os-release") => host_read_string(
                    host_root,
                    "usr/lib/os-release",
                    "os-release",
                    total,
                    findings,
                    truncated,
                ),
                Ok(_) => {
                    findings.push(finding(
                        "HOST_OS_RELEASE_SYMLINK_REJECTED",
                        "os-release",
                        "non-standard symlink target",
                    ));
                    None
                }
                Err(e) => {
                    findings.push(finding(
                        "HOST_READ_UNREADABLE",
                        "os-release",
                        &e.to_string(),
                    ));
                    None
                }
            }
        }
        Ok(_) => {
            findings.push(finding(
                "HOST_READ_LIMIT_EXCEEDED",
                "os-release",
                "refusing non-regular file",
            ));
            None
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => host_read_string(
            host_root,
            "usr/lib/os-release",
            "os-release",
            total,
            findings,
            truncated,
        ),
        Err(e) => {
            findings.push(finding(
                "HOST_READ_UNREADABLE",
                "os-release",
                &e.to_string(),
            ));
            None
        }
    }
}

fn read_loader_info(
    host_root: &Dir,
    total: &mut u64,
    findings: &mut Vec<Finding>,
    truncated: &mut bool,
) -> Option<String> {
    let path = Path::new("sys/firmware/efi/efivars").join(EFI_LOADER_INFO);
    match read_bytes_beneath(host_root, &path, total) {
        BoundedRead::Present(bytes) => match decode_efivarfs_string(&bytes) {
            Ok(value) => Some(sanitize(&value)),
            Err(detail) => {
                findings.push(finding("LOADER_INFO_MALFORMED", "LoaderInfo", detail));
                None
            }
        },
        BoundedRead::Absent => None,
        BoundedRead::NonRegular => {
            findings.push(finding(
                "LOADER_INFO_UNREADABLE",
                "LoaderInfo",
                "refusing non-regular file",
            ));
            None
        }
        BoundedRead::Oversized
        | BoundedRead::BudgetExhausted
        | BoundedRead::BudgetInsufficient
        | BoundedRead::Truncated => {
            *truncated = true;
            findings.push(finding(
                "LOADER_INFO_READ_LIMIT_EXCEEDED",
                "LoaderInfo",
                "efivarfs value exceeds the read budget",
            ));
            None
        }
        BoundedRead::Io(error) => {
            findings.push(finding("LOADER_INFO_UNREADABLE", "LoaderInfo", &error));
            None
        }
    }
}

fn decode_efivarfs_string(bytes: &[u8]) -> Result<String, &'static str> {
    let Some(value) = bytes.get(4..) else {
        return Err("efivarfs value is shorter than attributes");
    };
    let chunks = value.chunks_exact(2);
    if !chunks.remainder().is_empty() {
        return Err("efivarfs UTF-16 value has an odd length");
    }
    let value = chunks
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    let value = String::from_utf16(&value).map_err(|_| "efivarfs UTF-16 value is invalid")?;
    Ok(value.trim_end_matches('\0').to_string())
}
fn read_dir_files_fd(
    dir: &Dir,
    findings: &mut Vec<Finding>,
    path: &Path,
    code: &'static str,
    limit: usize,
) -> BoundedNames {
    let mut result = BoundedNames {
        values: Vec::with_capacity(limit),
        truncated: false,
    };
    let dir = match dir.try_clone() {
        Ok(dir) => dir,
        Err(e) => {
            findings.push(finding(code, &path.display().to_string(), &e.to_string()));
            return result;
        }
    };
    match dir.entries() {
        Ok(entries) => {
            for entry in entries.take(limit + 1) {
                match entry {
                    Ok(_) if result.values.len() >= limit => result.truncated = true,
                    Ok(entry) => match entry.file_type() {
                        Ok(t) if t.is_file() => match entry.file_name().into_string() {
                            Ok(name) if result.values.len() < limit => result.values.push(name),
                            Ok(_) => result.truncated = true,
                            Err(_) => findings.push(finding(
                                "BOOT_ENTRY_NAME_INVALID",
                                &path.display().to_string(),
                                "non-UTF-8 entry",
                            )),
                        },
                        Ok(t) if t.is_symlink() => findings.push(finding(
                            "BOOT_ENTRY_SYMLINK",
                            &path.join(entry.file_name()).display().to_string(),
                            "refusing symlink",
                        )),
                        Ok(_) => {}
                        Err(e) => findings.push(finding(
                            code,
                            &path.display().to_string(),
                            &e.to_string(),
                        )),
                    },
                    Err(e) => {
                        findings.push(finding(code, &path.display().to_string(), &e.to_string()))
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => findings.push(finding(code, &path.display().to_string(), &e.to_string())),
    }
    result.values.sort();
    result
}
enum ManifestStreamResolution {
    Present,
    Missing,
    RepositoryUnavailable(String),
    Unchecked(String),
}

fn manifest_stream_resolution(sysroot: &Dir, digest: &str) -> ManifestStreamResolution {
    let repo = match open_dir_beneath(sysroot, Path::new("composefs")) {
        Ok(repo) => repo,
        Err(error) => return ManifestStreamResolution::RepositoryUnavailable(error.to_string()),
    };
    let id = format!("oci-manifest-{digest}");
    match open_oci_object(&repo, &id) {
        Ok(_) => ManifestStreamResolution::Present,
        Err(OciReadError::Missing) => ManifestStreamResolution::Missing,
        Err(error) => ManifestStreamResolution::Unchecked(error.detail().into()),
    }
}

enum OciReadError {
    Missing,
    Limited,
    Invalid(String),
    Symlink,
    NonRegular,
    Io(String),
}
impl OciReadError {
    fn finding(&self) -> &'static str {
        match self {
            Self::Missing => "OCI_OBJECT_MISSING",
            Self::Limited => "OCI_OBJECT_READ_LIMIT_EXCEEDED",
            Self::Invalid(_) => "OCI_OBJECT_INVALID",
            Self::Symlink => "OCI_OBJECT_SYMLINK",
            Self::NonRegular => "OCI_OBJECT_NONREGULAR",
            Self::Io(_) => "OCI_OBJECT_UNREADABLE",
        }
    }
    fn detail(&self) -> &str {
        match self {
            Self::Missing => "object is absent",
            Self::Limited => "object exceeds the read budget",
            Self::Symlink => "object is a symlink",
            Self::NonRegular => "object is not a regular file",
            Self::Invalid(value) | Self::Io(value) => value,
        }
    }
    fn is_limited(&self) -> bool {
        matches!(self, Self::Limited)
    }
}

fn oci_object_path(repo: &Dir, stream: &str) -> Result<std::path::PathBuf, OciReadError> {
    let streams = open_dir_from(repo, Path::new("streams")).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            OciReadError::Missing
        } else {
            OciReadError::Io(e.to_string())
        }
    })?;
    let target = rustix::fs::readlinkat(&streams, stream, Vec::new()).map_err(|e| {
        if std::io::Error::from(e).kind() == std::io::ErrorKind::NotFound {
            OciReadError::Missing
        } else {
            OciReadError::Io(e.to_string())
        }
    })?;
    let target = std::path::PathBuf::from(std::ffi::OsString::from_vec(target.into_bytes()));
    let components: Vec<_> = target.components().collect();
    match components.as_slice() {
        [
            Component::ParentDir,
            Component::Normal(objects),
            Component::Normal(directory),
            Component::Normal(name),
        ] if *objects == "objects"
            && directory.len() == 2
            && name.len() > 2
            && directory
                .as_encoded_bytes()
                .iter()
                .chain(name.as_encoded_bytes())
                .all(u8::is_ascii_hexdigit) =>
        {
            Ok(Path::new("objects").join(directory).join(name))
        }
        _ => Err(OciReadError::Invalid(
            "stream does not name a repository object".into(),
        )),
    }
}

fn open_oci_object(repo: &Dir, stream: &str) -> Result<File, OciReadError> {
    open_repo_object(repo, &oci_object_path(repo, stream)?)
}

/// Open `path` (an `objects/xx/...` path) beneath the repository, refusing
/// symlinks and non-regular files.
fn open_repo_object(repo: &Dir, path: &Path) -> Result<File, OciReadError> {
    let Some(parent_path) = path.parent() else {
        return Err(OciReadError::Invalid("object path has no parent".into()));
    };
    let Some(name) = path.file_name() else {
        return Err(OciReadError::Invalid("object path has no filename".into()));
    };
    let parent = open_dir_from(repo, parent_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            OciReadError::Missing
        } else {
            OciReadError::Io(e.to_string())
        }
    })?;
    let metadata = metadata_at(&parent, name).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            OciReadError::Missing
        } else {
            OciReadError::Io(e.to_string())
        }
    })?;
    match metadata.file_type {
        EntryType::File => {}
        EntryType::Symlink => return Err(OciReadError::Symlink),
        _ => return Err(OciReadError::NonRegular),
    }
    open_from(repo, path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            OciReadError::Missing
        } else if e.raw_os_error() == Some(libc::ELOOP) {
            OciReadError::Symlink
        } else {
            OciReadError::Io(e.to_string())
        }
    })
}

/// Read the original bytes of an OCI manifest or config stored in the repository.
///
/// composefs stores these as a splitstream whose single external object holds
/// the JSON exactly as it was pulled; the stream file itself is a binary
/// container and never matches the OCI digest.
fn read_oci_object(repo: &Dir, stream: &str, total: &mut u64) -> Result<Vec<u8>, OciReadError> {
    let file = open_oci_object(repo, stream)?;
    let len = file
        .metadata()
        .map_err(|e| OciReadError::Io(e.to_string()))?
        .len();
    // The splitstream header is parsed straight from the file, so charge its
    // full size against the budget up front.
    if len > MAX_FILE_BYTES || len > MAX_READ_BYTES.saturating_sub(*total) {
        return Err(OciReadError::Limited);
    }
    *total += len;
    let mut reader = SplitStreamReader::<Sha512HashValue>::new(file.into_std(), None)
        .map_err(|e| OciReadError::Invalid(format!("{e:#}")))?;
    let mut object_refs = Vec::new();
    reader
        .get_object_refs(|id| object_refs.push(id.clone()))
        .map_err(|e| OciReadError::Invalid(format!("{e:#}")))?;
    let [object] = object_refs.as_slice() else {
        return Err(OciReadError::Invalid(format!(
            "expected exactly 1 external object in splitstream, found {}",
            object_refs.len()
        )));
    };
    let path = Path::new("objects").join(object.to_object_pathname());
    read_repo_object(repo, &path, total)
}

/// Read a repository object, counting its bytes against the global budget.
fn read_repo_object(repo: &Dir, path: &Path, total: &mut u64) -> Result<Vec<u8>, OciReadError> {
    let file = open_repo_object(repo, path)?;
    let metadata = file
        .metadata()
        .map_err(|e| OciReadError::Io(e.to_string()))?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES || *total >= MAX_READ_BYTES {
        return Err(OciReadError::Limited);
    }
    let available = (MAX_READ_BYTES - *total).min(MAX_FILE_BYTES);
    if metadata.len() > available {
        return Err(OciReadError::Limited);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(available).unwrap_or(0));
    (&file)
        .take(available)
        .read_to_end(&mut bytes)
        .map_err(|e| OciReadError::Io(e.to_string()))?;
    // Count bytes before decoding so malformed objects consume the budget.
    *total += bytes.len() as u64;
    if bytes.len() as u64 == available
        && (metadata.len() < available || file.metadata().map_or(true, |m| m.len() > available))
    {
        return Err(OciReadError::Limited);
    }
    Ok(bytes)
}

#[cfg(test)]
mod readonly_tests {
    use super::*;
    use cap_std_ext::cap_tempfile::TempDir;

    fn tempdir() -> TempDir {
        crate::testutils::test_tempdir().unwrap()
    }

    fn fixture(deployments: &[(&str, Option<&str>)]) -> TempDir {
        let root = tempdir();
        for (id, origin) in deployments {
            let dir = format!("state/deploy/{id}");
            root.create_dir_all(&dir).unwrap();
            if let Some(origin) = origin {
                root.atomic_write(format!("{dir}/{id}.origin"), origin.as_bytes())
                    .unwrap();
            }
        }
        root
    }

    fn collect(root: &Dir) -> ReadonlyReport {
        collect_readonly(root)
    }

    fn symlink(dir: &Dir, target: &str, name: &str) {
        rustix::fs::symlinkat(target, dir.as_fd(), name).unwrap();
    }

    fn uki_with_text_sections() -> Vec<u8> {
        const PE_OFFSET: usize = 64;
        const SECTION_HEADERS_OFFSET: usize = PE_OFFSET + 24;
        const SECTION_DATA_OFFSET: usize = SECTION_HEADERS_OFFSET + 3 * 40;
        let mut uki = vec![0; SECTION_DATA_OFFSET + 3];
        uki[60..64].copy_from_slice(&(PE_OFFSET as u32).to_le_bytes());
        uki[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
        uki[PE_OFFSET + 6..PE_OFFSET + 8].copy_from_slice(&3u16.to_le_bytes());
        for (index, name) in [".uname", ".osrel", ".cmdline"].iter().enumerate() {
            let header = SECTION_HEADERS_OFFSET + index * 40;
            uki[header..header + name.len()].copy_from_slice(name.as_bytes());
            uki[header + 8..header + 12].copy_from_slice(&1u32.to_le_bytes());
            uki[header + 20..header + 24]
                .copy_from_slice(&((SECTION_DATA_OFFSET + index) as u32).to_le_bytes());
            uki[SECTION_DATA_OFFSET + index] = b'x';
        }
        uki
    }

    fn uki_with_oversized_declared_section() -> Vec<u8> {
        const SECTION_HEADERS_OFFSET: usize = 64 + 24;
        let mut uki = uki_with_text_sections();
        // Keep the file small while declaring a section that would previously drive a
        // multi-gigabyte allocation in get_text_section_buffered().
        uki[SECTION_HEADERS_OFFSET + 8..SECTION_HEADERS_OFFSET + 12]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        uki
    }

    #[test]
    fn collector_accepts_capability_root_only() {
        let root = fixture(&[]);
        let _: fn(&Dir) -> ReadonlyReport = collect_readonly;
        assert!(collect(&root).deployments.is_empty());
    }

    #[test]
    fn report_collects_each_deployment_after_errors() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let origin = format!(
            "[origin]\ncontainer=registry:quay.io/example/image\n[image]\nmanifest_digest={digest}\n"
        );
        let root = fixture(&[
            ("a-missing", None),
            ("b-invalid", Some("not ini")),
            ("c-stream", Some(&origin)),
        ]);
        let report = collect(&root);
        assert_eq!(
            report
                .deployments
                .iter()
                .map(|d| d.id.as_str())
                .collect::<Vec<_>>(),
            ["a-missing", "b-invalid", "c-stream"]
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == "DEPLOYMENT_ORIGIN_MISSING")
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == "DEPLOYMENT_ORIGIN_INVALID")
        );
    }

    #[test]
    fn report_redacts_missing_repository_streams() {
        let root = fixture(&[(
            "deployment",
            Some(&format!(
                "[origin]\ncontainer=registry:https://user:password@example/image\n[image]\nmanifest_digest=sha256:{}\n",
                "b".repeat(64)
            )),
        )]);
        root.create_dir("composefs").unwrap();
        let report = collect(&root);
        assert_eq!(report.deployments[0].manifest_stream_resolution, "missing");
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == "DEPLOYMENT_MANIFEST_STREAM_MISSING")
        );
        assert!(!serde_json::to_string(&report).unwrap().contains("password"));
    }

    #[test]
    fn report_collects_boot_entries_artifacts_and_grub() {
        let root = fixture(&[("digest", None)]);
        root.create_dir_all("boot/loader/entries").unwrap();
        root.atomic_write("boot/loader/entries/test.conf", b"title Test\nversion 1\nlinux /vmlinuz\ninitrd /initrd\noptions composefs=?digest secret=value\n").unwrap();
        root.create_dir_all("boot/grub2").unwrap();
        root.atomic_write(format!("boot/grub2/{USER_CFG}"), b"menuentry \"Boot\" {\n search --fs-uuid secret\n chainloader /EFI/Linux/bootc_composefs-digest.efi\n}\n").unwrap();
        root.atomic_write("boot/vmlinuz", b"kernel").unwrap();
        root.atomic_write("boot/initrd", b"initrd").unwrap();
        let report = collect(&root);
        assert_eq!(report.boot_entries[0].version.as_deref(), Some("1"));
        assert!(
            report
                .edges
                .iter()
                .any(|e| e.kind == "entry-artifact" && e.resolution == Resolution::Present)
        );
        assert!(
            report
                .boot_entries
                .iter()
                .any(|e| e.kind == "grub" && e.search.as_deref() == Some("<redacted-search>"))
        );
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("secret=value")
        );
    }

    #[test]
    fn report_marks_unmounted_esp_and_bounds_uki() {
        let root = fixture(&[]);
        root.create_dir_all("boot/efi/EFI/Linux").unwrap();
        root.atomic_write(
            "boot/efi/EFI/Linux/too-large.efi",
            &vec![0; MAX_FILE_BYTES as usize + 1],
        )
        .unwrap();
        root.create_dir_all("boot/loader/entries").unwrap();
        root.atomic_write(
            "boot/loader/entries/test.conf",
            b"title Test\nversion 1\nefi /EFI/Linux/too-large.efi\n",
        )
        .unwrap();
        let report = collect(&root);
        assert_eq!(report.bootloader.esp.status, "unavailable-not-mounted");
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == "UKI_READ_LIMIT_EXCEEDED")
        );
        let esp = "/sysroot/boot/efi";
        assert_eq!(
            visible_mountpoint(&format!("1 2 0:1 / {esp} rw - vfat /dev/loop0 rw"), &[esp]),
            Some(esp.into())
        );
    }

    #[test]
    fn collector_refuses_symlink_substitutions_without_disclosure() {
        let root = fixture(&[("deployment", None)]);
        let deployment = root.open_dir("state/deploy/deployment").unwrap();
        symlink(&deployment, "/outside/secret", "deployment.origin");
        root.create_dir_all("boot/loader/entries").unwrap();
        root.atomic_write(
            "boot/loader/entries/test.conf",
            b"title Test\nversion 1\nefi /EFI/Linux/test.efi\n",
        )
        .unwrap();
        root.create_dir_all("boot/efi/EFI/Linux").unwrap();
        let linux = root.open_dir("boot/efi/EFI/Linux").unwrap();
        symlink(&linux, "/outside/artifact-target-secret", "test.efi");
        root.create_dir_all("composefs").unwrap();
        let composefs = root.open_dir("composefs").unwrap();
        symlink(&composefs, "/outside/streams", "streams");
        let report = collect(&root);
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == "DEPLOYMENT_ORIGIN_SYMLINK")
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == "BOOT_ARTIFACT_SYMLINK")
        );
        assert_eq!(report.repository.inventory["streams"].status, "unreadable");
        assert!(!json.contains("artifact-target-secret"));
    }

    #[test]
    fn collector_refuses_directory_symlink_substitutions() {
        let root = fixture(&[]);
        root.create_dir_all("boot/loader").unwrap();
        let loader = root.open_dir("boot/loader").unwrap();
        symlink(&loader, "/outside/entries", "entries");
        root.create_dir_all("sys/firmware").unwrap();
        let firmware = root.open_dir("sys/firmware").unwrap();
        symlink(&firmware, "/outside/efi", "efi");
        let report = collect(&root);
        assert!(report.boot_entries.is_empty());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == "BLS_DIRECTORY_SYMLINK")
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == "EFI_DIRECTORY_SYMLINK")
        );
    }

    #[test]
    fn host_inputs_cover_proc_os_release_and_loader_info() {
        let host = tempdir();
        let pid = std::process::id();
        host.create_dir_all(format!("proc/{pid}")).unwrap();
        host.atomic_write(format!("proc/{pid}/mountinfo"), b"")
            .unwrap();
        host.create_dir_all("usr/lib").unwrap();
        host.atomic_write("usr/lib/os-release", b"ID=test\n")
            .unwrap();
        host.create_dir("etc").unwrap();
        let etc = host.open_dir("etc").unwrap();
        symlink(&etc, "../usr/lib/os-release", "os-release");
        host.create_dir_all("sys/firmware/efi/efivars").unwrap();
        host.atomic_write(
            format!("sys/firmware/efi/efivars/{EFI_LOADER_INFO}"),
            &[
                vec![7, 0, 0, 0],
                "systemd-boot\0"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            ]
            .concat(),
        )
        .unwrap();
        let sysroot = fixture(&[]);
        let roots = ReadonlyRoots {
            repo: None,
            deploy: None,
            run: None,
            boot: None,
            esp: None,
            host: &host,
            sysroot: sysroot.try_clone().unwrap(),
        };
        let report = collect_readonly_with_roots(&roots);
        assert_eq!(report.host.os_release_id.as_deref(), Some("test"));
        assert_eq!(
            report.bootloader.loader_info.as_deref(),
            Some("systemd-boot")
        );
        assert_eq!(report.bootloader.efi, "present");
        assert!(report.findings.is_empty());
    }

    #[test]
    fn oci_streams_and_bounds_are_checked() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let root = fixture(&[(
            "deployment",
            Some(&format!("[image]\nmanifest_digest={digest}\n")),
        )]);
        root.create_dir_all("composefs/objects/aa").unwrap();
        root.create_dir("composefs/streams").unwrap();
        root.atomic_write(
            "composefs/objects/aa/bbbb",
            &vec![b'x'; MAX_FILE_BYTES as usize + 1],
        )
        .unwrap();
        let streams = root.open_dir("composefs/streams").unwrap();
        symlink(
            &streams,
            "../objects/aa/bbbb",
            &format!("oci-manifest-{digest}"),
        );
        let report = collect(&root);
        assert!(report.collection.truncated);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == "OCI_OBJECT_READ_LIMIT_EXCEEDED")
        );
    }

    #[test]
    fn bounded_reads_never_exceed_the_global_limit() {
        let root = tempdir();
        root.create_dir_all("objects/aa").unwrap();
        root.create_dir("streams").unwrap();
        root.atomic_write("objects/aa/bbbb", b"ab").unwrap();
        root.atomic_write("objects/aa/cccc", b"a").unwrap();
        root.atomic_write("first", b"ab").unwrap();
        root.atomic_write("second", b"ab").unwrap();
        let streams = root.open_dir("streams").unwrap();
        symlink(&streams, "../objects/aa/bbbb", "oci-manifest-test");

        // Repeated inputs larger than the remaining budget must not allow the
        // bounded read probe to consume an extra byte.
        let mut bounded_total = MAX_READ_BYTES - 1;
        for name in ["first", "second"] {
            assert_eq!(
                read_bounded_file(root.open(name).unwrap(), &mut bounded_total),
                BoundedRead::BudgetInsufficient
            );
            assert!(bounded_total <= MAX_READ_BYTES);
        }
        let mut oci_total = MAX_READ_BYTES - 1;
        for _ in 0..2 {
            assert!(matches!(
                read_oci_object(&root, "oci-manifest-test", &mut oci_total),
                Err(OciReadError::Limited)
            ));
            assert!(oci_total <= MAX_READ_BYTES);
        }

        root.atomic_write("exact", b"a").unwrap();
        assert_eq!(
            read_bounded_file(root.open("exact").unwrap(), &mut bounded_total),
            BoundedRead::Present(b"a".to_vec())
        );
        assert_eq!(bounded_total, MAX_READ_BYTES);

        assert!(matches!(
            read_repo_object(&root, Path::new("objects/aa/cccc"), &mut oci_total),
            Ok(bytes) if bytes == b"a"
        ));
        assert_eq!(oci_total, MAX_READ_BYTES);
    }

    /// Write a minimal image the way a pull does, so manifest and config live
    /// behind real splitstreams rather than hand-made fixtures.
    fn write_real_image(root: &Dir) -> String {
        use composefs::repository::RepositoryConfig;
        use std::collections::HashMap;
        use std::sync::Arc;

        root.create_dir_all("composefs").unwrap();
        let config = RepositoryConfig::new(composefs::fsverity::Algorithm::SHA512).set_insecure();
        let (repo, _) = crate::store::ComposefsRepository::init_path(
            &root.open_dir("composefs").unwrap(),
            ".",
            config,
        )
        .unwrap();
        let repo = Arc::new(repo);
        let image_config: ImageConfiguration = serde_json::from_value(serde_json::json!({
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": []},
        }))
        .unwrap();
        let (config_digest, config_verity) = composefs_oci::write_config(
            &repo,
            &image_config,
            HashMap::new(),
            None,
            None,
            &HashMap::new(),
        )
        .unwrap();
        let manifest: ImageManifest = serde_json::from_value(serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest.to_string(),
                "size": image_config.to_string().unwrap().len(),
            },
            "layers": [],
        }))
        .unwrap();
        let manifest_digest =
            composefs_oci::sha256_content_digest(manifest.to_string().unwrap().as_bytes());
        composefs_oci::oci_image::write_manifest(
            &repo,
            &manifest,
            &manifest_digest,
            &config_verity,
            &[] as &[(&str, Sha512HashValue)],
            None,
        )
        .unwrap();
        manifest_digest.to_string()
    }

    #[test]
    fn oci_manifest_and_config_are_read_through_splitstreams() {
        let root = fixture(&[]);
        let digest = write_real_image(&root);
        root.create_dir_all("state/deploy/deployment").unwrap();
        root.atomic_write(
            "state/deploy/deployment/deployment.origin",
            format!("[image]\nmanifest_digest={digest}\n"),
        )
        .unwrap();
        let report = collect(&root);
        let oci_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.code.starts_with("OCI_"))
            .map(|f| f.code)
            .collect();
        assert!(oci_findings.is_empty(), "{oci_findings:?}");
        let image = report
            .images
            .iter()
            .find(|i| i.manifest == digest)
            .expect("image reported");
        assert_eq!(image.availability, "available");
    }

    #[test]
    fn grub_bls_paths_resolve_with_and_without_boot_partition() {
        // With a separate /boot partition GRUB entries are relative to it; otherwise
        // they carry a `/boot/` prefix relative to the physical root.
        for linux in [
            "/bootc_composefs-a/vmlinuz",
            "/boot/bootc_composefs-a/vmlinuz",
        ] {
            let root = fixture(&[]);
            root.create_dir_all("boot/loader/entries").unwrap();
            root.create_dir_all("boot/bootc_composefs-a").unwrap();
            root.atomic_write("boot/bootc_composefs-a/vmlinuz", b"kernel")
                .unwrap();
            root.atomic_write(
                "boot/loader/entries/test.conf",
                format!("title Test\nversion 1\nlinux {linux}\n"),
            )
            .unwrap();
            let report = collect(&root);
            let codes: Vec<_> = report.findings.iter().map(|f| f.code).collect();
            assert!(
                !codes.contains(&"BOOT_ARTIFACT_MISSING"),
                "{linux}: {codes:?}"
            );
            assert!(
                !report.artifacts.is_empty() && report.artifacts.iter().all(|a| a.present),
                "{linux}"
            );
        }
    }

    #[test]
    fn bounded_static_read_reports_the_remaining_budget() {
        let root = tempdir();
        root.atomic_write("input", b"ab").unwrap();
        let mut total = MAX_READ_BYTES - 1;
        let mut findings = Vec::new();
        let mut truncated = false;
        assert_eq!(
            record_string_read(
                read_bounded_file(root.open("input").unwrap(), &mut total),
                &mut findings,
                &mut truncated,
                "input",
                false,
            ),
            None
        );
        assert!(truncated);
        assert_eq!(
            findings[0].detail,
            "file exceeds remaining global read budget"
        );
    }

    #[test]
    fn uki_sections_obey_the_global_read_budget() {
        let root = tempdir();
        root.atomic_write("uki.efi", &uki_with_text_sections())
            .unwrap();
        let mut total = MAX_READ_BYTES - 200;
        let mut findings = Vec::new();
        let mut truncated = false;
        let uki = collect_uki(
            &root,
            Path::new("uki.efi"),
            true,
            &mut findings,
            &mut truncated,
            "uki.efi",
            &mut total,
        );
        assert_eq!(total, MAX_READ_BYTES);
        assert!(truncated);
        assert_eq!(uki.parse, "limit-exceeded");
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "UKI_READ_LIMIT_EXCEEDED")
        );
    }

    #[test]
    fn uki_sections_parse_from_a_valid_fixture() {
        let root = tempdir();
        root.atomic_write("uki.efi", &uki_with_text_sections())
            .unwrap();
        let mut total = 0;
        let uki = collect_uki(
            &root,
            Path::new("uki.efi"),
            true,
            &mut Vec::new(),
            &mut false,
            "uki.efi",
            &mut total,
        );
        assert_eq!(uki.parse, "parsed-text-sections");
        assert_eq!(uki.uname.as_deref(), Some("x"));
        assert_eq!(uki.os_release.as_deref(), Some("x"));
        assert!(total <= MAX_READ_BYTES);
    }

    #[test]
    fn uki_oversized_declared_section_is_bounded() {
        let root = tempdir();
        root.atomic_write("uki.efi", &uki_with_oversized_declared_section())
            .unwrap();
        let mut total = 0;
        let mut findings = Vec::new();
        let mut truncated = false;
        let uki = collect_uki(
            &root,
            Path::new("uki.efi"),
            true,
            &mut findings,
            &mut truncated,
            "uki.efi",
            &mut total,
        );
        assert_eq!(uki.parse, "limit-exceeded");
        assert!(truncated);
        assert!(total <= MAX_READ_BYTES);
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "UKI_READ_LIMIT_EXCEEDED")
        );
    }

    #[test]
    fn collector_bounds_and_races_are_reported() {
        let root = fixture(&[]);
        for n in 0..=MAX_DEPLOYMENTS {
            root.create_dir_all(format!("state/deploy/{n:03}")).unwrap();
        }
        let report = collect(&root);
        assert_eq!(report.deployments.len(), MAX_DEPLOYMENTS);
        assert!(report.collection.truncated);
    }

    #[tokio::test]
    async fn report_writer_emits_json_without_human_prefix() {
        let root = tempdir();
        root.create_dir("sysroot").unwrap();
        let mut output = Vec::new();
        let _ = fsck_readonly(&root, true, &mut output).await;
        let output = String::from_utf8(output).unwrap();
        assert!(output.starts_with('{'));
        assert!(serde_json::from_str::<serde_json::Value>(&output).is_ok());
    }
}

/// A lint check has failed.
#[derive(thiserror::Error, Debug)]
pub(crate) struct FsckError(String);

/// The outer error is for unexpected fatal runtime problems; the
/// inner error is for the check failing in an expected way.
pub(crate) type FsckResult = anyhow::Result<std::result::Result<(), FsckError>>;

/// Everything is OK - we didn't encounter a runtime error, and
/// the targeted check passed.
pub(crate) fn fsck_ok() -> FsckResult {
    Ok(Ok(()))
}

/// We successfully found a failure.
pub(crate) fn fsck_err(msg: impl AsRef<str>) -> FsckResult {
    Ok(Err(FsckError::new(msg)))
}

impl std::fmt::Display for FsckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FsckError {
    fn new(msg: impl AsRef<str>) -> Self {
        Self(msg.as_ref().to_owned())
    }
}

pub(crate) type FsckFn = fn(&Storage) -> FsckResult;
pub(crate) type AsyncFsckFn = fn(&Storage) -> Pin<Box<dyn Future<Output = FsckResult> + '_>>;
#[derive(Debug)]
pub(crate) enum FsckFnImpl {
    Sync(FsckFn),
    Async(AsyncFsckFn),
}

impl From<FsckFn> for FsckFnImpl {
    fn from(value: FsckFn) -> Self {
        Self::Sync(value)
    }
}

impl From<AsyncFsckFn> for FsckFnImpl {
    fn from(value: AsyncFsckFn) -> Self {
        Self::Async(value)
    }
}

#[derive(Debug)]
pub(crate) struct FsckCheck {
    name: &'static str,
    ordering: u16,
    f: FsckFnImpl,
}

#[distributed_slice]
pub(crate) static FSCK_CHECKS: [FsckCheck];

impl FsckCheck {
    pub(crate) const fn new(name: &'static str, ordering: u16, f: FsckFnImpl) -> Self {
        FsckCheck { name, ordering, f }
    }
}

#[distributed_slice(FSCK_CHECKS)]
static CHECK_RESOLVCONF: FsckCheck =
    FsckCheck::new("etc-resolvconf", 5, FsckFnImpl::Sync(check_resolvconf));
/// See <https://github.com/bootc-dev/bootc/pull/1096> and <https://github.com/containers/bootc/pull/1167>
/// Basically verify that if /usr/etc/resolv.conf exists, it is not a zero-sized file that was
/// probably injected by buildah and that bootc should have removed.
///
/// Note that this fsck check can fail for systems upgraded from old bootc right now, as
/// we need the *new* bootc to fix it.
///
/// But at the current time fsck is an experimental feature that we should only be running
/// in our CI.
fn check_resolvconf(storage: &Storage) -> FsckResult {
    let ostree = match storage.get_ostree() {
        Ok(o) => o,
        Err(_) => return fsck_ok(), // Not an ostree system (e.g. composefs-only)
    };
    // For now we only check the booted deployment.
    if ostree.booted_deployment().is_none() {
        return fsck_ok();
    }
    // Read usr/etc/resolv.conf directly.
    let usr = Dir::open_ambient_dir("/usr", cap_std_ext::cap_std::ambient_authority())?;
    let Some(meta) = usr.symlink_metadata_optional("etc/resolv.conf")? else {
        return fsck_ok();
    };
    if meta.is_file() && meta.size() == 0 {
        return fsck_err("Found usr/etc/resolv.conf as zero-sized file");
    }
    fsck_ok()
}

#[derive(Debug, Default)]
struct ObjectsVerityState {
    /// Count of objects with fsverity
    enabled: u64,
    /// Count of objects without fsverity
    disabled: u64,
    /// Objects which should have fsverity but do not
    missing: Vec<String>,
}

/// Check the fsverity state of all regular files in this object directory.
#[context("Computing verity state")]
fn verity_state_of_objects(
    d: &Dir,
    prefix: &str,
    expected: bool,
) -> anyhow::Result<ObjectsVerityState> {
    let mut enabled = 0;
    let mut disabled = 0;
    let mut missing = Vec::new();
    for ent in d.entries()? {
        let ent = ent?;
        if !ent.file_type()?.is_file() {
            continue;
        }
        let name = ent.file_name();
        let name = name
            .into_string()
            .map(Utf8PathBuf::from)
            .map_err(|_| anyhow::anyhow!("Invalid UTF-8"))?;
        let Some("file") = name.extension() else {
            continue;
        };
        let f = d.open(&name)?;
        let r: Option<composefs::fsverity::Sha256HashValue> =
            composefs::fsverity::measure_verity_opt(f.as_fd())?;
        drop(f);
        if r.is_some() {
            enabled += 1;
        } else {
            disabled += 1;
            if expected {
                missing.push(format!("{prefix}{name}"));
            }
        }
    }
    let r = ObjectsVerityState {
        enabled,
        disabled,
        missing,
    };
    Ok(r)
}

async fn verity_state_of_all_objects(
    repo: &ostree::Repo,
    expected: bool,
) -> anyhow::Result<ObjectsVerityState> {
    // Limit concurrency here
    const MAX_CONCURRENT: usize = 3;

    let repodir = Dir::reopen_dir(&repo.dfd_borrow())?;

    // It's convenient here to reuse tokio's spawn_blocking as a threadpool basically.
    let mut joinset = tokio::task::JoinSet::new();
    let mut results = Vec::new();

    for ent in repodir.read_dir("objects")? {
        // Block here if the queue is full
        while joinset.len() >= MAX_CONCURRENT {
            results.push(joinset.join_next().await.unwrap()??);
        }
        let ent = ent?;
        if !ent.file_type()?.is_dir() {
            continue;
        }
        let name = ent.file_name();
        let name = name
            .into_string()
            .map(Utf8PathBuf::from)
            .map_err(|_| anyhow::anyhow!("Invalid UTF-8"))?;

        let objdir = ent.open_dir()?;
        joinset.spawn_blocking(move || verity_state_of_objects(&objdir, name.as_str(), expected));
    }

    // Drain the remaining tasks.
    while let Some(output) = joinset.join_next().await {
        results.push(output??);
    }
    // Fold the results.
    let r = results
        .into_iter()
        .fold(ObjectsVerityState::default(), |mut acc, v| {
            acc.enabled += v.enabled;
            acc.disabled += v.disabled;
            acc.missing.extend(v.missing);
            acc
        });
    Ok(r)
}

#[distributed_slice(FSCK_CHECKS)]
static CHECK_FSVERITY: FsckCheck =
    FsckCheck::new("fsverity", 10, FsckFnImpl::Async(check_fsverity));
fn check_fsverity(storage: &Storage) -> Pin<Box<dyn Future<Output = FsckResult> + '_>> {
    Box::pin(check_fsverity_inner(storage))
}

async fn check_fsverity_inner(storage: &Storage) -> FsckResult {
    let ostree = match storage.get_ostree() {
        Ok(o) => o,
        Err(_) => return fsck_ok(), // Not an ostree system (e.g. composefs-only)
    };
    let repo = &ostree.repo();
    let verity_state = ostree_ext::fsverity::is_verity_enabled(repo)?;
    tracing::debug!(
        "verity: expected={:?} found={:?}",
        verity_state.desired,
        verity_state.enabled
    );

    let verity_found_state =
        verity_state_of_all_objects(&ostree.repo(), verity_state.desired == Tristate::Enabled)
            .await?;
    let Some((missing, rest)) = collect_until(
        verity_found_state.missing.iter(),
        const { NonZeroUsize::new(5).unwrap() },
    ) else {
        return fsck_ok();
    };
    let mut err = String::from("fsverity enabled, but objects without fsverity:\n");
    for obj in missing {
        // SAFETY: Writing into a String
        writeln!(err, "  {obj}").unwrap();
    }
    if rest > 0 {
        // SAFETY: Writing into a String
        writeln!(err, "  ...and {rest} more").unwrap();
    }
    fsck_err(err)
}

pub(crate) async fn fsck(storage: &Storage, mut output: impl std::io::Write) -> anyhow::Result<()> {
    let mut checks = FSCK_CHECKS.static_slice().iter().collect::<Vec<_>>();
    checks.sort_by(|a, b| a.ordering.cmp(&b.ordering));

    let mut errors = false;
    for check in checks.iter() {
        let name = check.name;
        let r = match check.f {
            FsckFnImpl::Sync(f) => f(&storage),
            FsckFnImpl::Async(f) => f(&storage).await,
        };
        match r {
            Ok(Ok(())) => {
                println!("ok: {name}");
            }
            Ok(Err(e)) => {
                errors = true;
                writeln!(output, "fsck error: {name}: {e}")?;
            }
            Err(e) => {
                errors = true;
                writeln!(output, "Unexpected runtime error in check {name}: {e}")?;
            }
        }
    }
    if errors {
        anyhow::bail!("Encountered errors")
    }

    // Run an `ostree fsck` (yes, ostree exposes enough APIs
    // that we could reimplement this in Rust, but eh)
    // TODO: Fix https://github.com/bootc-dev/bootc/issues/1216 so we can
    // do this.
    // let st = Command::new("ostree")
    //     .arg("fsck")
    //     .stdin(std::process::Stdio::inherit())
    //     .status()?;
    // if !st.success() {
    //     anyhow::bail!("ostree fsck failed");
    // }

    Ok(())
}
