//! This module handles the bootc-owned kernel argument lists in `/usr/lib/bootc/kargs.d`.
use anyhow::{Context, Result};
use bootc_kernel_cmdline::utf8::{Cmdline, CmdlineOwned};
use camino::Utf8Path;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::cap_std::fs_utf8::Dir as DirUtf8;
use cap_std_ext::dirext::CapStdExtDirExt;
use cap_std_ext::dirext::CapStdExtDirExtUtf8;
use ostree::gio;
use ostree_ext::ostree;
use ostree_ext::ostree::Deployment;
use ostree_ext::prelude::Cast;
use ostree_ext::prelude::FileEnumeratorExt;
use ostree_ext::prelude::FileExt;
use serde::Deserialize;

use crate::deploy::ImageState;
use crate::store::Storage;

/// The relative path to the kernel arguments which may be embedded in an image.
const KARGS_PATH: &str = "usr/lib/bootc/kargs.d";

/// The default root filesystem mount specification.
pub(crate) const ROOT_KEY: &str = "root";
/// This is used by dracut.
pub(crate) const INITRD_ARG_PREFIX: &str = "rd.";
/// The kernel argument for configuring the rootfs flags.
pub(crate) const ROOTFLAGS_KEY: &str = "rootflags";

/// The kargs.d configuration file.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct Config {
    /// Ordered list of kernel arguments.
    kargs: Vec<String>,
    /// Optional list of architectures (using the Rust naming conventions);
    /// if present and the current architecture doesn't match, the file is skipped.
    match_architectures: Option<Vec<String>>,
}

impl Config {
    /// Return true if the filename is one we should parse.
    fn filename_matches(name: &str) -> bool {
        matches!(Utf8Path::new(name).extension(), Some("toml"))
    }
}

/// Looks for files in usr/lib/bootc/kargs.d and parses cmdline agruments
pub(crate) fn kargs_from_composefs_filesystem(
    new_fs: &Dir,
    cmdline: &mut Cmdline,
) -> Result<()> {
    let remote_kargs = get_kargs_in_root(new_fs, std::env::consts::ARCH)?;
    cmdline.extend(&remote_kargs);
    Ok(())
}

/// Load and parse all bootc kargs.d files in the specified root, returning
/// a combined list.
pub(crate) fn get_kargs_in_root(d: &Dir, sys_arch: &str) -> Result<CmdlineOwned> {
    // If the directory doesn't exist, that's OK.
    let Some(d) = d.open_dir_optional(KARGS_PATH)?.map(DirUtf8::from_cap_std) else {
        return Ok(Default::default());
    };
    let mut ret = Cmdline::new();
    let entries = d.filenames_filtered_sorted(|_, name| Config::filename_matches(name))?;
    for name in entries {
        let buf = d.read_to_string(&name)?;
        if let Some(kargs) =
            parse_kargs_toml(&buf, sys_arch).with_context(|| format!("Parsing {name}"))?
        {
            ret.extend(&kargs)
        }
    }
    Ok(ret)
}

pub(crate) fn root_args_from_cmdline(cmdline: &Cmdline) -> CmdlineOwned {
    let mut result = Cmdline::new();
    for param in cmdline {
        let key = param.key();
        if key == ROOT_KEY.into()
            || key == ROOTFLAGS_KEY.into()
            || key.starts_with(INITRD_ARG_PREFIX)
        {
            result.add(&param);
        }
    }
    result
}

/// Load kargs.d files from the target ostree commit root
pub(crate) fn get_kargs_from_ostree_root(
    repo: &ostree::Repo,
    root: &ostree::RepoFile,
    sys_arch: &str,
) -> Result<CmdlineOwned> {
    let kargsd = root.resolve_relative_path(KARGS_PATH);
    let kargsd = kargsd.downcast_ref::<ostree::RepoFile>().expect("downcast");
    if !kargsd.query_exists(gio::Cancellable::NONE) {
        return Ok(Default::default());
    }
    get_kargs_from_ostree(repo, kargsd, sys_arch)
}

/// Load kargs.d files from the target dir
fn get_kargs_from_ostree(
    repo: &ostree::Repo,
    fetched_tree: &ostree::RepoFile,
    sys_arch: &str,
) -> Result<CmdlineOwned> {
    let cancellable = gio::Cancellable::NONE;
    let queryattrs = "standard::name,standard::type";
    let queryflags = gio::FileQueryInfoFlags::NOFOLLOW_SYMLINKS;
    let fetched_iter = fetched_tree.enumerate_children(queryattrs, queryflags, cancellable)?;
    let mut ret = Cmdline::new();
    while let Some(fetched_info) = fetched_iter.next_file(cancellable)? {
        // only read and parse the file if it is a toml file
        let name = fetched_info.name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !Config::filename_matches(name) {
            continue;
        }

        let fetched_child = fetched_iter.child(&fetched_info);
        let fetched_child = fetched_child
            .downcast::<ostree::RepoFile>()
            .expect("downcast");
        fetched_child.ensure_resolved()?;
        let fetched_contents_checksum = fetched_child.checksum();
        let f = ostree::Repo::load_file(repo, fetched_contents_checksum.as_str(), cancellable)?;
        let file_content = f.0;
        let mut reader =
            ostree_ext::prelude::InputStreamExtManual::into_read(file_content.unwrap());
        let s = std::io::read_to_string(&mut reader)?;
        if let Some(parsed_kargs) =
            parse_kargs_toml(&s, sys_arch).with_context(|| format!("Parsing {name}"))?
        {
            ret.extend(&parsed_kargs);
        }
    }
    Ok(ret)
}

/// Compute the kernel arguments for the new deployment. This starts from the booted
/// karg, but applies the diff between the bootc karg files in /usr/lib/bootc/kargs.d
/// between the booted deployment and the new one.
pub(crate) fn get_kargs(
    sysroot: &Storage,
    merge_deployment: &Deployment,
    fetched: &ImageState,
) -> Result<CmdlineOwned> {
    let cancellable = gio::Cancellable::NONE;
    let ostree = sysroot.get_ostree()?;
    let repo = &ostree.repo();
    let sys_arch = std::env::consts::ARCH;

    // Get the kargs used for the merge in the bootloader config
    let mut kargs = ostree::Deployment::bootconfig(merge_deployment)
        .and_then(|bootconfig| {
            ostree::BootconfigParser::get(&bootconfig, "options")
                .map(|options| Cmdline::from(options.to_string()))
        })
        .unwrap_or_default();

    // Get the kargs in kargs.d of the merge
    let merge_root = &crate::utils::deployment_fd(ostree, merge_deployment)?;
    let existing_kargs = get_kargs_in_root(merge_root, sys_arch)?;

    // Get the kargs in kargs.d of the pending image
    let (fetched_tree, _) = repo.read_commit(fetched.ostree_commit.as_str(), cancellable)?;
    let fetched_tree = fetched_tree.resolve_relative_path(KARGS_PATH);
    let fetched_tree = fetched_tree
        .downcast::<ostree::RepoFile>()
        .expect("downcast");
    // A special case: if there's no kargs.d directory in the pending (fetched) image,
    // then we can just use the combined current kargs + kargs from booted
    if !fetched_tree.query_exists(cancellable) {
        kargs.extend(&existing_kargs);
        return Ok(kargs);
    }

    // Fetch the kernel arguments from the new root
    let remote_kargs = get_kargs_from_ostree(repo, &fetched_tree, sys_arch)?;

    // Calculate the diff between the existing and remote kargs
    let added_kargs: Vec<_> = remote_kargs
        .iter()
        .filter(|item| !existing_kargs.iter().any(|existing| *item == existing))
        .collect();
    let removed_kargs: Vec<_> = existing_kargs
        .iter()
        .filter(|item| !remote_kargs.iter().any(|remote| *item == remote))
        .collect();

    tracing::debug!(
        "kargs: added={:?} removed={:?}",
        &added_kargs,
        removed_kargs
    );

    // Apply the diff to the system kargs
    for arg in &removed_kargs {
        kargs.remove_exact(arg);
    }
    for arg in &added_kargs {
        kargs.add(arg);
    }

    Ok(kargs)
}

/// This parses a bootc kargs.d toml file, returning the resulting
/// vector of kernel arguments. Architecture matching is performed using
/// `sys_arch`.
fn parse_kargs_toml(contents: &str, sys_arch: &str) -> Result<Option<CmdlineOwned>> {
    let de: Config = toml::from_str(contents)?;
    // if arch specified, apply kargs only if the arch matches
    // if arch not specified, apply kargs unconditionally
    let matched = de
        .match_architectures
        .map(|arches| arches.iter().any(|s| s == sys_arch))
        .unwrap_or(true);
    let r = if matched {
        Some(Cmdline::from(de.kargs.join(" ")))
    } else {
        None
    };
    Ok(r)
}

#[cfg(test)]
mod tests {
    use cap_std_ext::cap_std;
    use fn_error_context::context;
    use rustix::fd::{AsFd, AsRawFd};

    use super::*;

    fn assert_cmdline_eq(cmdline: &Cmdline, expected_params: &[&str]) {
        let actual_params: Vec<_> = cmdline.iter_str().collect();
        assert_eq!(actual_params, expected_params);
    }

    #[test]
    /// Verify that kargs are only applied to supported architectures
    fn test_arch() {
        // no arch specified, kargs ensure that kargs are applied unconditionally
        let sys_arch = "x86_64";
        let file_content = r##"kargs = ["console=tty0", "nosmt"]"##.to_string();
        let parsed_kargs = parse_kargs_toml(&file_content, sys_arch).unwrap().unwrap();
        assert_cmdline_eq(&parsed_kargs, &["console=tty0", "nosmt"]);

        let sys_arch = "aarch64";
        let parsed_kargs = parse_kargs_toml(&file_content, sys_arch).unwrap().unwrap();
        assert_cmdline_eq(&parsed_kargs, &["console=tty0", "nosmt"]);

        // one arch matches and one doesn't, ensure that kargs are only applied for the matching arch
        let sys_arch = "aarch64";
        let file_content = r##"kargs = ["console=tty0", "nosmt"]
match-architectures = ["x86_64"]
"##
        .to_string();
        let parsed_kargs = parse_kargs_toml(&file_content, sys_arch).unwrap();
        assert!(parsed_kargs.is_none());
        let file_content = r##"kargs = ["console=tty0", "nosmt"]
match-architectures = ["aarch64"]
"##
        .to_string();
        let parsed_kargs = parse_kargs_toml(&file_content, sys_arch).unwrap().unwrap();
        assert_cmdline_eq(&parsed_kargs, &["console=tty0", "nosmt"]);

        // multiple arch specified, ensure that kargs are applied to both archs
        let sys_arch = "x86_64";
        let file_content = r##"kargs = ["console=tty0", "nosmt"]
match-architectures = ["x86_64", "aarch64"]
"##
        .to_string();
        let parsed_kargs = parse_kargs_toml(&file_content, sys_arch).unwrap().unwrap();
        assert_cmdline_eq(&parsed_kargs, &["console=tty0", "nosmt"]);

        let sys_arch = "aarch64";
        let parsed_kargs = parse_kargs_toml(&file_content, sys_arch).unwrap().unwrap();
        assert_cmdline_eq(&parsed_kargs, &["console=tty0", "nosmt"]);
    }

    #[test]
    /// Verify some error cases
    fn test_invalid() {
        let test_invalid_extra = r#"kargs = ["console=tty0", "nosmt"]\nfoo=bar"#;
        assert!(parse_kargs_toml(test_invalid_extra, "x86_64").is_err());

        let test_missing = r#"foo=bar"#;
        assert!(parse_kargs_toml(test_missing, "x86_64").is_err());
    }

    #[context("writing test kargs")]
    fn write_test_kargs(td: &Dir) -> Result<()> {
        td.write(
            "usr/lib/bootc/kargs.d/01-foo.toml",
            r##"kargs = ["console=tty0", "nosmt"]"##,
        )?;
        td.write(
            "usr/lib/bootc/kargs.d/02-bar.toml",
            r##"kargs = ["console=ttyS1"]"##,
        )?;

        Ok(())
    }

    #[test]
    fn test_get_kargs_in_root() -> Result<()> {
        let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;

        // No directory
        assert_eq!(get_kargs_in_root(&td, "x86_64").unwrap().iter().count(), 0);
        // Empty directory
        td.create_dir_all("usr/lib/bootc/kargs.d")?;
        assert_eq!(get_kargs_in_root(&td, "x86_64").unwrap().iter().count(), 0);
        // Non-toml file
        td.write("usr/lib/bootc/kargs.d/somegarbage", "garbage")?;
        assert_eq!(get_kargs_in_root(&td, "x86_64").unwrap().iter().count(), 0);

        write_test_kargs(&td)?;

        let args = get_kargs_in_root(&td, "x86_64").unwrap();
        assert_cmdline_eq(&args, &["console=tty0", "nosmt", "console=ttyS1"]);

        Ok(())
    }

    #[context("ostree commit")]
    fn ostree_commit(
        repo: &ostree::Repo,
        d: &Dir,
        path: &Utf8Path,
        ostree_ref: &str,
    ) -> Result<()> {
        let cancellable = gio::Cancellable::NONE;
        let txn = repo.auto_transaction(cancellable)?;

        let mt = ostree::MutableTree::new();
        let commitmod_flags = ostree::RepoCommitModifierFlags::SKIP_XATTRS;
        let commitmod = ostree::RepoCommitModifier::new(commitmod_flags, None);
        repo.write_dfd_to_mtree(
            d.as_fd().as_raw_fd(),
            path.as_str(),
            &mt,
            Some(&commitmod),
            cancellable,
        )
        .context("Writing merged filesystem to mtree")?;

        let merged_root = repo
            .write_mtree(&mt, cancellable)
            .context("Writing mtree")?;
        let merged_root = merged_root.downcast::<ostree::RepoFile>().unwrap();
        let merged_commit = repo
            .write_commit(None, None, None, None, &merged_root, cancellable)
            .context("Writing commit")?;
        repo.transaction_set_ref(None, &ostree_ref, Some(merged_commit.as_str()));
        txn.commit(cancellable)?;
        Ok(())
    }

    #[test]
    fn test_get_kargs_in_ostree() -> Result<()> {
        let cancellable = gio::Cancellable::NONE;
        let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;

        td.create_dir("repo")?;
        let repo = &ostree::Repo::create_at(
            td.as_fd().as_raw_fd(),
            "repo",
            ostree::RepoMode::Bare,
            None,
            gio::Cancellable::NONE,
        )?;

        td.create_dir("rootfs")?;
        let test_rootfs = &td.open_dir("rootfs")?;

        ostree_commit(repo, &test_rootfs, ".".into(), "testref")?;
        // Helper closure to read the kargs
        let get_kargs = |sys_arch: &str| -> Result<CmdlineOwned> {
            let rootfs = repo.read_commit("testref", cancellable)?.0;
            let rootfs = rootfs.downcast_ref::<ostree::RepoFile>().unwrap();
            let fetched_tree = rootfs.resolve_relative_path("/usr/lib/bootc/kargs.d");
            let fetched_tree = fetched_tree
                .downcast::<ostree::RepoFile>()
                .expect("downcast");
            if !fetched_tree.query_exists(cancellable) {
                return Ok(Default::default());
            }
            get_kargs_from_ostree(repo, &fetched_tree, sys_arch)
        };

        // rootfs is empty
        assert_eq!(get_kargs("x86_64").unwrap().iter().count(), 0);

        test_rootfs.create_dir_all("usr/lib/bootc/kargs.d")?;
        write_test_kargs(&test_rootfs).unwrap();
        ostree_commit(repo, &test_rootfs, ".".into(), "testref")?;

        let args = get_kargs("x86_64").unwrap();
        assert_cmdline_eq(&args, &["console=tty0", "nosmt", "console=ttyS1"]);

        Ok(())
    }
}
