//! # Finalize a rootfs for bootc compatibility
//!
//! This module implements `bootc container finalize-rootfs`, which transforms
//! a `dnf --installroot` output into a layout that bootc can deploy.
//!
//! This enables building bootc base images without rpm-ostree compose.
//! The transforms applied here are equivalent to what rpm-ostree compose
//! does during image creation, validated against the official Fedora 42
//! bootc image.
//!
//! ## Transforms applied
//!
//! 1. **Toplevel symlinks**: ostree filesystem layout (/home -> /var/home, etc.)
//! 2. **/var -> tmpfiles.d**: Convert /var contents to tmpfiles.d entries, clean /var
//! 3. **rpmdb relocation**: Move rpmdb to /usr/share/rpm with hardlinks
//! 4. **Config injection**: prepare-root.conf, dracut.conf.d, kernel install.conf, etc.
//! 5. **Post-chroot cleanup**: Clean artifacts left by chroot operations

use anyhow::{Context, Result};
use camino::Utf8Path;
use cap_std::fs::Dir;
use cap_std_ext::cap_std;
use cap_std_ext::dirext::CapStdExtDirExt as _;
use fn_error_context::context;

/// Symlinks that define the ostree filesystem layout.
const OSTREE_SYMLINKS: &[(&str, &str)] = &[
    ("home", "var/home"),
    ("root", "var/roothome"),
    ("media", "run/media"),
    ("mnt", "var/mnt"),
    ("srv", "var/srv"),
    ("ostree", "sysroot/ostree"),
];

/// Directories to remove if empty (artifacts of the filesystem RPM).
const REMOVE_IF_EMPTY: &[&str] = &["afs"];

/// Files to remove from the rootfs (remove-from-packages equivalent).
const REMOVE_FILES: &[&str] = &[
    "usr/lib/systemd/system/sysinit.target.wants/systemd-firstboot.service",
    "usr/lib/systemd/system-generators/systemd-gpt-auto-generator",
];

/// Apply all transforms to convert a dnf --installroot rootfs into a
/// bootc-compatible layout.
///
/// If `check` is true, only report what would change without modifying.
#[context("Finalizing rootfs")]
pub(crate) fn finalize_rootfs(rootfs_path: &Utf8Path, check: bool) -> Result<()> {
    let rootfs = &Dir::open_ambient_dir(rootfs_path, cap_std::ambient_authority())
        .with_context(|| format!("Opening rootfs {rootfs_path}"))?;

    if check {
        tracing::info!("Check mode: reporting changes without modifying");
    }

    apply_toplevel_symlinks(rootfs, check)?;
    apply_var_tmpfiles(rootfs, check)?;
    apply_rpmdb_relocation(rootfs, check)?;
    apply_config_injection(rootfs, check)?;

    tracing::info!("All transforms complete");
    Ok(())
}

/// Post-chroot cleanup: remove artifacts left by chroot operations
/// (dracut, dnf reinstall, systemctl preset-all, bootupd).
///
/// Run this AFTER all chroot operations and BEFORE building the OCI image.
#[context("Post-chroot cleanup")]
pub(crate) fn post_chroot_cleanup(rootfs_path: &Utf8Path, check: bool) -> Result<()> {
    let rootfs = &Dir::open_ambient_dir(rootfs_path, cap_std::ambient_authority())
        .with_context(|| format!("Opening rootfs {rootfs_path}"))?;

    clean_var_artifacts(rootfs, check)?;
    normalize_rpmdb(rootfs, check)?;
    clean_runtime_dirs(rootfs, check)?;

    // Ensure machine-id is empty
    if let Ok(content) = rootfs.read_to_string("etc/machine-id") {
        if !content.trim().is_empty() {
            if check {
                tracing::info!("Would empty etc/machine-id");
            } else {
                rootfs.write("etc/machine-id", "")?;
                tracing::info!("Emptied etc/machine-id");
            }
        }
    }

    tracing::info!("Post-chroot cleanup complete");
    Ok(())
}

// ---------------------------------------------------------------------------
// Transform 1: Toplevel symlinks
// ---------------------------------------------------------------------------

#[context("Applying toplevel symlinks")]
fn apply_toplevel_symlinks(rootfs: &Dir, check: bool) -> Result<()> {
    tracing::info!("Applying toplevel symlinks");

    if !rootfs.try_exists("sysroot/ostree")? {
        if check {
            tracing::info!("Would create sysroot/ostree/");
        } else {
            rootfs.create_dir_all("sysroot/ostree")?;
        }
    }

    for (link, target) in OSTREE_SYMLINKS {
        if let Some(meta) = rootfs.symlink_metadata_optional(link)? {
            if meta.is_symlink() {
                let existing = rootfs.read_link(link)?;
                if existing.to_str() == Some(target) {
                    tracing::debug!("{link} -> {target} (already correct)");
                    continue;
                }
                if !check {
                    rootfs.remove_file(link)?;
                    rootfs.symlink(target, link)?;
                }
                tracing::info!("Fixed symlink: {link} -> {target}");
            } else {
                // Real directory -- replace with symlink
                if !check {
                    rootfs.remove_dir_all(link)?;
                    rootfs.symlink(target, link)?;
                }
                tracing::info!("Replaced dir with symlink: {link} -> {target}");
            }
        } else {
            if !check {
                rootfs.symlink(target, link)?;
            }
            tracing::info!("Created symlink: {link} -> {target}");
        }
    }

    for dir in REMOVE_IF_EMPTY {
        if rootfs.try_exists(dir)? && rootfs.remove_dir(dir).is_ok() {
            tracing::info!("Removed empty dir: {dir}");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Transform 2: /var -> tmpfiles.d conversion
// ---------------------------------------------------------------------------

const TMPFILES_INTEGRATION: &str = "\
d /var/home 0755 root root -
d /var/srv 0755 root root -
d /var/roothome 0700 root root -
d /var/mnt 0755 root root -
d /run/media 0755 root root -
L /var/lib/rpm - - - - ../../usr/share/rpm
d /usr/local/bin 0755 root root -
d /usr/local/etc 0755 root root -
d /usr/local/games 0755 root root -
d /usr/local/include 0755 root root -
d /usr/local/lib 0755 root root -
d /usr/local/sbin 0755 root root -
d /usr/local/share 0755 root root -
d /usr/local/src 0755 root root -
";

const TMPFILES_OPT_USRLOCAL: &str = "\
d /var/opt 0755 root root -
d /var/usrlocal 0755 root root -
";

const TMPFILES_RPMSTATE: &str = "\
# Workaround for https://bugzilla.redhat.com/show_bug.cgi?id=771713
d /var/lib/rpm-state 0755 - - -
";

#[context("Converting /var to tmpfiles.d")]
fn apply_var_tmpfiles(rootfs: &Dir, check: bool) -> Result<()> {
    tracing::info!("Converting /var to tmpfiles.d entries");

    let tmpfiles_dir = "usr/lib/tmpfiles.d";
    if !check {
        rootfs.create_dir_all(tmpfiles_dir)?;
    }

    let static_files = [
        ("rpm-ostree-0-integration.conf", TMPFILES_INTEGRATION),
        (
            "rpm-ostree-0-integration-opt-usrlocal.conf",
            TMPFILES_OPT_USRLOCAL,
        ),
        ("bootc-base-rpmstate.conf", TMPFILES_RPMSTATE),
    ];

    for (name, content) in &static_files {
        let path = format!("{tmpfiles_dir}/{name}");
        if check {
            tracing::info!("Would write {path}");
        } else {
            rootfs.write(&path, content)?;
            tracing::debug!("Wrote {path}");
        }
    }

    let home_conf = format!("{tmpfiles_dir}/home.conf");
    if rootfs.try_exists(&home_conf)? {
        if check {
            tracing::info!("Would remove {home_conf}");
        } else {
            rootfs.remove_file(&home_conf)?;
            tracing::debug!("Removed {home_conf}");
        }
    }

    if !check {
        clean_var(rootfs)?;
    } else {
        tracing::info!("Would clean /var (keep run symlink, lib/rpm-state, tmp)");
    }

    Ok(())
}

fn clean_var(rootfs: &Dir) -> Result<()> {
    if let Ok(var) = rootfs.open_dir("var") {
        for entry in var.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if entry.file_type()?.is_dir() {
                var.remove_dir_all(name.as_ref())?;
            } else {
                var.remove_file(name.as_ref())?;
            }
        }
    }

    rootfs.symlink("../run", "var/run")?;
    rootfs.create_dir_all("var/lib/rpm-state")?;
    rootfs.create_dir("var/tmp")?;
    use cap_std_ext::cap_std::fs::PermissionsExt;
    let tmp_perms = cap_std::fs::Permissions::from_mode(0o1777);
    rootfs.set_permissions("var/tmp", tmp_perms)?;

    tracing::info!("/var cleaned (run->../run, lib/rpm-state, tmp)");
    Ok(())
}

// ---------------------------------------------------------------------------
// Transform 3: rpmdb relocation
// ---------------------------------------------------------------------------

#[context("Relocating rpmdb")]
fn apply_rpmdb_relocation(rootfs: &Dir, check: bool) -> Result<()> {
    tracing::info!("Relocating rpmdb");

    let sysimage_rpm = "usr/lib/sysimage/rpm";
    let rpmdb_src = format!("{sysimage_rpm}/rpmdb.sqlite");

    if !rootfs.try_exists(&rpmdb_src)? {
        tracing::warn!("No rpmdb.sqlite found at {sysimage_rpm}");
        return Ok(());
    }

    for suffix in ["sqlite-wal", "sqlite-shm"] {
        let path = format!("{sysimage_rpm}/rpmdb.{suffix}");
        if rootfs.try_exists(&path)? {
            if !check {
                rootfs.remove_file(&path)?;
            }
            tracing::debug!("Removed {path}");
        }
    }
    let lock = format!("{sysimage_rpm}/.rpm.lock");
    if rootfs.try_exists(&lock)? && !check {
        rootfs.remove_file(&lock)?;
    }

    if check {
        tracing::info!("Would relocate rpmdb to usr/share/rpm");
    } else {
        let rpmdb_content = rootfs.read(&rpmdb_src)?;

        rootfs.create_dir_all("usr/share/rpm")?;
        rootfs.write("usr/share/rpm/rpmdb.sqlite", &rpmdb_content)?;

        // Overwrite original with same content (can't hardlink via cap-std)
        rootfs.write(&rpmdb_src, &rpmdb_content)?;

        rootfs.create_dir_all("usr/lib/sysimage/rpm-ostree-base-db")?;
        rootfs.write(
            "usr/lib/sysimage/rpm-ostree-base-db/rpmdb.sqlite",
            &rpmdb_content,
        )?;

        tracing::info!("rpmdb relocated to usr/share/rpm");
    }

    let macro_path = "usr/lib/rpm/macros.d/macros.rpm-ostree";
    if check {
        tracing::info!("Would write {macro_path}");
    } else {
        rootfs.create_dir_all("usr/lib/rpm/macros.d")?;
        rootfs.write(macro_path, "%_dbpath /usr/share/rpm\n")?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Transform 4: Config injection
// ---------------------------------------------------------------------------

const CONFIG_FILES: &[(&str, &str)] = &[
    (
        "usr/lib/ostree/prepare-root.conf",
        "[composefs]\nenabled = yes\n[sysroot]\nreadonly = true\n",
    ),
    ("usr/lib/kernel/install.conf", "layout=ostree\n"),
    (
        "usr/lib/kernel/install.conf.d/00-bootc-kernel-layout.conf",
        "layout=ostree\n",
    ),
    (
        "usr/share/dnf5/libdnf.conf.d/20-ostree-installonlypkgs.conf",
        "[main]\ninstallonlypkgs=''\n",
    ),
    (
        "usr/share/dnf5/libdnf.conf.d/20-ostree-protect_running_kernel.conf",
        "[main]\nprotect_running_kernel=False\n",
    ),
    (
        "usr/lib/bootc/install/00-default.toml",
        "[install]\nroot-fs-type = \"xfs\"\n",
    ),
];

const DRACUT_CONFIGS: &[(&str, &str)] = &[
    (
        "20-bootc-base.conf",
        "# Generic image; hostonly makes no sense for server-side builds\nhostonly=no\n# Dracut fails to set security.selinux xattrs at build time\nexport DRACUT_NO_XATTR=1\nadd_dracutmodules+=\" kernel-modules dracut-systemd systemd-initrd base ostree bootc \"\n",
    ),
    (
        "22-bootc-generic.conf",
        "# Extra modules for generic hardware support\nadd_dracutmodules+=\" virtiofs \"\n",
    ),
    (
        "49-bootc-tpm2-tss.conf",
        "# For systemd-cryptsetup tpm2 locking\nadd_dracutmodules+=\" tpm2-tss \"\n",
    ),
    (
        "59-altfiles.conf",
        "# nss-altfiles passwd/group for initramfs\ninstall_items+=\" /usr/lib/passwd /usr/lib/group \"\n",
    ),
];

#[context("Injecting config files")]
fn apply_config_injection(rootfs: &Dir, check: bool) -> Result<()> {
    tracing::info!("Injecting config files");

    for (path, content) in CONFIG_FILES {
        if check {
            tracing::info!("Would write {path}");
        } else {
            if let Some(parent) = Utf8Path::new(path).parent() {
                rootfs.create_dir_all(parent.as_str())?;
            }
            rootfs.write(path, content)?;
            tracing::debug!("Wrote {path}");
        }
    }

    let dracut_dir = "usr/lib/dracut/dracut.conf.d";
    for (name, content) in DRACUT_CONFIGS {
        let path = format!("{dracut_dir}/{name}");
        if check {
            tracing::info!("Would write {path}");
        } else {
            rootfs.create_dir_all(dracut_dir)?;
            rootfs.write(&path, content)?;
            tracing::debug!("Wrote {path}");
        }
    }

    // useradd HOME fixup
    if let Ok(content) = rootfs.read_to_string("etc/default/useradd") {
        if content.contains("HOME=/home") {
            if check {
                tracing::info!("Would fix etc/default/useradd HOME=/home -> /var/home");
            } else {
                let fixed = content.replace("HOME=/home", "HOME=/var/home");
                rootfs.write("etc/default/useradd", fixed.as_bytes())?;
                tracing::info!("Fixed useradd HOME=/var/home");
            }
        }
    }

    // Empty machine-id
    if let Ok(content) = rootfs.read_to_string("etc/machine-id") {
        if !content.trim().is_empty() {
            if check {
                tracing::info!("Would empty etc/machine-id");
            } else {
                rootfs.write("etc/machine-id", "")?;
                tracing::info!("Emptied etc/machine-id");
            }
        }
    }

    // tmp.mount enabled
    let wants_dir = "usr/lib/systemd/system/local-fs.target.wants";
    let tmp_mount = format!("{wants_dir}/tmp.mount");
    if !rootfs.try_exists(&tmp_mount)? {
        if check {
            tracing::info!("Would enable tmp.mount");
        } else {
            rootfs.create_dir_all(wants_dir)?;
            rootfs.symlink("../tmp.mount", &tmp_mount)?;
            tracing::info!("Enabled tmp.mount");
        }
    }

    // Fix provision.conf for /var/roothome
    if let Ok(content) = rootfs.read_to_string("usr/lib/tmpfiles.d/provision.conf") {
        if content.contains(" /root") {
            if check {
                tracing::info!("Would fix provision.conf /root -> /var/roothome");
            } else {
                let fixed = content
                    .replace(" /root", " /var/roothome")
                    .lines()
                    .filter(|l| !l.starts_with("d- /var/roothome "))
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n";
                rootfs.write("usr/lib/tmpfiles.d/provision.conf", fixed.as_bytes())?;
                tracing::info!("Fixed provision.conf");
            }
        }
    }

    // Remove files that shouldn't be in a bootc image
    for path in REMOVE_FILES {
        if rootfs.try_exists(path)? {
            if check {
                tracing::info!("Would remove {path}");
            } else {
                rootfs.remove_file(path)?;
                tracing::info!("Removed {path}");
            }
        }
    }

    // systemd preset file
    let preset_path = "usr/lib/systemd/system-preset/85-bootc.preset";
    if !rootfs.try_exists(preset_path)? {
        if check {
            tracing::info!("Would write {preset_path}");
        } else {
            rootfs.create_dir_all("usr/lib/systemd/system-preset")?;
            rootfs.write(
                preset_path,
                "# Disable dnf-makecache.timer on bootc/image mode systems\ndisable dnf-makecache.timer\n",
            )?;
            tracing::info!("Wrote {preset_path}");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Post-chroot cleanup helpers
// ---------------------------------------------------------------------------

#[context("Cleaning /var artifacts")]
fn clean_var_artifacts(rootfs: &Dir, check: bool) -> Result<()> {
    tracing::info!("Cleaning /var artifacts from chroot operations");

    if let Ok(var) = rootfs.open_dir("var") {
        for entry in var.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            match name_str.as_ref() {
                "run" | "tmp" | "lib" => continue,
                _ => {
                    if check {
                        tracing::info!("Would remove var/{name_str}");
                    } else {
                        if entry.file_type()?.is_dir() {
                            var.remove_dir_all(name_str.as_ref())?;
                        } else {
                            var.remove_file(name_str.as_ref())?;
                        }
                        tracing::debug!("Removed var/{name_str}");
                    }
                }
            }
        }

        if let Ok(var_lib) = var.open_dir("lib") {
            for entry in var_lib.entries()? {
                let entry = entry?;
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.as_ref() != "rpm-state" {
                    if check {
                        tracing::info!("Would remove var/lib/{name_str}");
                    } else {
                        if entry.file_type()?.is_dir() {
                            var_lib.remove_dir_all(name_str.as_ref())?;
                        } else {
                            var_lib.remove_file(name_str.as_ref())?;
                        }
                        tracing::debug!("Removed var/lib/{name_str}");
                    }
                }
            }
        }
    }

    Ok(())
}

#[context("Normalizing rpmdb")]
fn normalize_rpmdb(rootfs: &Dir, check: bool) -> Result<()> {
    tracing::info!("Normalizing rpmdb (removing WAL/SHM/lock)");

    let rpmdb_dirs = [
        "usr/share/rpm",
        "usr/lib/sysimage/rpm",
        "usr/lib/sysimage/rpm-ostree-base-db",
    ];

    for dir in &rpmdb_dirs {
        if !rootfs.try_exists(dir)? {
            continue;
        }
        for suffix in ["sqlite-wal", "sqlite-shm"] {
            let path = format!("{dir}/rpmdb.{suffix}");
            if rootfs.try_exists(&path)? {
                if !check {
                    rootfs.remove_file(&path)?;
                }
                tracing::debug!("Removed {path}");
            }
        }
        let lock = format!("{dir}/.rpm.lock");
        if rootfs.try_exists(&lock)? {
            if !check {
                rootfs.remove_file(&lock)?;
            }
            tracing::debug!("Removed {lock}");
        }
    }

    Ok(())
}

#[context("Cleaning runtime directories")]
fn clean_runtime_dirs(rootfs: &Dir, check: bool) -> Result<()> {
    tracing::info!("Cleaning /run and /tmp artifacts");

    for dir_name in ["run", "tmp"] {
        if let Ok(dir) = rootfs.open_dir(dir_name) {
            for entry in dir.entries()? {
                let entry = entry?;
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if check {
                    tracing::info!("Would remove {dir_name}/{name_str}");
                } else {
                    if entry.file_type()?.is_dir() {
                        dir.remove_dir_all(name_str.as_ref())?;
                    } else {
                        dir.remove_file(name_str.as_ref())?;
                    }
                    tracing::debug!("Removed {dir_name}/{name_str}");
                }
            }
        }
    }

    Ok(())
}
