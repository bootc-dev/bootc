//! # Configuration for `bootc install`
//!
//! This module handles the TOML configuration file for `bootc install`.

use anyhow::{Context, Result};
use clap::ValueEnum;
use fn_error_context::context;
use serde::{Deserialize, Serialize};

#[cfg(feature = "install-to-disk")]
use super::baseline::BlockSetup;

/// Properties of the environment, such as the system architecture
/// Left open for future properties such as `platform.id`
pub(crate) struct EnvProperties {
    pub(crate) sys_arch: String,
}

/// A well known filesystem type.
#[derive(clap::ValueEnum, Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Filesystem {
    Xfs,
    Ext4,
    Btrfs,
}

impl std::fmt::Display for Filesystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value().unwrap().get_name().fmt(f)
    }
}

/// The toplevel config entry for installation configs stored
/// in bootc/install (e.g. /etc/bootc/install/05-custom.toml)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallConfigurationToplevel {
    pub(crate) install: Option<InstallConfiguration>,
}

/// Configuration for a filesystem
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootFS {
    #[serde(rename = "type")]
    pub(crate) fstype: Option<Filesystem>,
}

/// This structure should only define "system" or "basic" filesystems; we are
/// not trying to generalize this into e.g. supporting `/var` or other ones.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct BasicFilesystems {
    pub(crate) root: Option<RootFS>,
    // TODO allow configuration of these other filesystems too
    // pub(crate) xbootldr: Option<FilesystemCustomization>,
    // pub(crate) esp: Option<FilesystemCustomization>,
}

/// Configuration for ostree repository
pub(crate) type OstreeRepoOpts = ostree_ext::repo_options::RepoOptions;

/// Configuration options for bootupd, responsible for setting up the bootloader.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct Bootupd {
    /// Whether to skip writing the boot partition UUID to the bootloader configuration.
    /// When true, bootupd is invoked with `--with-static-configs` instead of `--write-uuid`.
    /// Defaults to false (UUIDs are written by default).
    pub(crate) skip_boot_uuid: Option<bool>,
}

/// The serialized `[install]` section
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename = "install", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct InstallConfiguration {
    /// Root filesystem type
    pub(crate) root_fs_type: Option<Filesystem>,
    /// Enabled block storage configurations
    #[cfg(feature = "install-to-disk")]
    pub(crate) block: Option<Vec<BlockSetup>>,
    pub(crate) filesystem: Option<BasicFilesystems>,
    /// Kernel arguments, applied at installation time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kargs: Option<Vec<String>>,
    /// Supported architectures for this configuration
    pub(crate) match_architectures: Option<Vec<String>>,
    /// Ostree repository configuration
    pub(crate) ostree: Option<OstreeRepoOpts>,
    /// The stateroot name to use. Defaults to `default`
    pub(crate) stateroot: Option<String>,
    /// Source device specification for the root filesystem.
    /// For example, `UUID=2e9f4241-229b-4202-8429-62d2302382e1` or `LABEL=rootfs`.
    pub(crate) root_mount_spec: Option<String>,
    /// Mount specification for the /boot filesystem.
    pub(crate) boot_mount_spec: Option<String>,
    /// Bootupd configuration
    pub(crate) bootupd: Option<Bootupd>,
}

fn merge_basic<T>(s: &mut Option<T>, o: Option<T>, _env: &EnvProperties) {
    if let Some(o) = o {
        *s = Some(o);
    }
}

trait Mergeable {
    fn merge(&mut self, other: Self, env: &EnvProperties)
    where
        Self: Sized;
}

impl<T> Mergeable for Option<T>
where
    T: Mergeable,
{
    fn merge(&mut self, other: Self, env: &EnvProperties)
    where
        Self: Sized,
    {
        if let Some(other) = other {
            if let Some(s) = self.as_mut() {
                s.merge(other, env)
            } else {
                *self = Some(other);
            }
        }
    }
}

impl Mergeable for RootFS {
    /// Apply any values in other, overriding any existing values in `self`.
    fn merge(&mut self, other: Self, env: &EnvProperties) {
        merge_basic(&mut self.fstype, other.fstype, env)
    }
}

impl Mergeable for BasicFilesystems {
    /// Apply any values in other, overriding any existing values in `self`.
    fn merge(&mut self, other: Self, env: &EnvProperties) {
        self.root.merge(other.root, env)
    }
}

impl Mergeable for OstreeRepoOpts {
    /// Apply any values in other, overriding any existing values in `self`.
    fn merge(&mut self, other: Self, env: &EnvProperties) {
        merge_basic(
            &mut self.bls_append_except_default,
            other.bls_append_except_default,
            env,
        )
    }
}

impl Mergeable for Bootupd {
    /// Apply any values in other, overriding any existing values in `self`.
    fn merge(&mut self, other: Self, env: &EnvProperties) {
        merge_basic(&mut self.skip_boot_uuid, other.skip_boot_uuid, env)
    }
}

impl Mergeable for InstallConfiguration {
    /// Apply any values in other, overriding any existing values in `self`.
    fn merge(&mut self, other: Self, env: &EnvProperties) {
        // if arch is specified, only merge config if it matches the current arch
        // if arch is not specified, merge config unconditionally
        if other
            .match_architectures
            .map(|a| a.contains(&env.sys_arch))
            .unwrap_or(true)
        {
            merge_basic(&mut self.root_fs_type, other.root_fs_type, env);
            #[cfg(feature = "install-to-disk")]
            merge_basic(&mut self.block, other.block, env);
            self.filesystem.merge(other.filesystem, env);
            self.ostree.merge(other.ostree, env);
            merge_basic(&mut self.stateroot, other.stateroot, env);
            merge_basic(&mut self.root_mount_spec, other.root_mount_spec, env);
            merge_basic(&mut self.boot_mount_spec, other.boot_mount_spec, env);
            self.bootupd.merge(other.bootupd, env);
            if let Some(other_kargs) = other.kargs {
                self.kargs
                    .get_or_insert_with(Default::default)
                    .extend(other_kargs)
            }
        }
    }
}

impl InstallConfiguration {
    /// Set defaults (e.g. `block`), and also handle fields that can be specified multiple ways
    /// by synchronizing the values of the fields to ensure they're the same.
    ///
    /// - install.root-fs-type is synchronized with install.filesystems.root.type; if
    ///   both are set, then the latter takes precedence
    pub(crate) fn canonicalize(&mut self) {
        // New canonical form wins.
        if let Some(rootfs_type) = self.filesystem_root().and_then(|f| f.fstype.as_ref()) {
            self.root_fs_type = Some(*rootfs_type)
        } else if let Some(rootfs) = self.root_fs_type.as_ref() {
            let fs = self.filesystem.get_or_insert_with(Default::default);
            let root = fs.root.get_or_insert_with(Default::default);
            root.fstype = Some(*rootfs);
        }

        #[cfg(feature = "install-to-disk")]
        if self.block.is_none() {
            self.block = Some(vec![BlockSetup::Direct]);
        }
    }

    /// Convenience helper to access the root filesystem
    pub(crate) fn filesystem_root(&self) -> Option<&RootFS> {
        self.filesystem.as_ref().and_then(|fs| fs.root.as_ref())
    }

    // Remove all configuration which is handled by `install to-filesystem`.
    pub(crate) fn filter_to_external(&mut self) {
        self.kargs.take();
    }

    #[cfg(feature = "install-to-disk")]
    pub(crate) fn get_block_setup(&self, default: Option<BlockSetup>) -> Result<BlockSetup> {
        let valid_block_setups = self.block.as_deref().unwrap_or_default();
        let default_block = valid_block_setups.iter().next().ok_or_else(|| {
            anyhow::anyhow!("Empty block storage configuration in install configuration")
        })?;
        let block_setup = default.as_ref().unwrap_or(default_block);
        if !valid_block_setups.contains(block_setup) {
            anyhow::bail!("Block setup {block_setup:?} is not enabled in installation config");
        }
        Ok(*block_setup)
    }
}

#[context("Loading configuration")]
/// Load the install configuration, merging all found configuration files.
pub(crate) fn load_config() -> Result<Option<InstallConfiguration>> {
    let env = EnvProperties {
        sys_arch: std::env::consts::ARCH.to_string(),
    };
    const SYSTEMD_CONVENTIONAL_BASES: &[&str] = &["/usr/lib", "/usr/local/lib", "/etc", "/run"];
    let fragments = liboverdrop::scan(SYSTEMD_CONVENTIONAL_BASES, "bootc/install", &["toml"], true);
    let mut config: Option<InstallConfiguration> = None;
    for (_name, path) in fragments {
        let buf = std::fs::read_to_string(&path)?;
        let mut unused = std::collections::HashSet::new();
        let de = toml::Deserializer::parse(&buf).with_context(|| format!("Parsing {path:?}"))?;
        let mut c: InstallConfigurationToplevel = serde_ignored::deserialize(de, |path| {
            unused.insert(path.to_string());
        })
        .with_context(|| format!("Parsing {path:?}"))?;
        for key in unused {
            eprintln!("warning: {path:?}: Unknown key {key}");
        }
        if let Some(config) = config.as_mut() {
            if let Some(install) = c.install {
                tracing::debug!("Merging install config: {install:?}");
                config.merge(install, &env);
            }
        } else {
            // Only set the config if it matches the current arch
            // If no arch is specified, set the config unconditionally
            if let Some(ref mut install) = c.install {
                if install
                    .match_architectures
                    .as_ref()
                    .map(|a| a.contains(&env.sys_arch))
                    .unwrap_or(true)
                {
                    config = c.install;
                }
            }
        }
    }
    if let Some(config) = config.as_mut() {
        config.canonicalize();
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Verify that we can parse our default config file
    fn test_parse_config() {
        let env = EnvProperties {
            sys_arch: "x86_64".to_string(),
        };
        let c: InstallConfigurationToplevel = toml::from_str(
            r##"[install]
root-fs-type = "xfs"
"##,
        )
        .unwrap();
        let mut install = c.install.unwrap();
        assert_eq!(install.root_fs_type.unwrap(), Filesystem::Xfs);
        let other = InstallConfigurationToplevel {
            install: Some(InstallConfiguration {
                root_fs_type: Some(Filesystem::Ext4),
                ..Default::default()
            }),
        };
        install.merge(other.install.unwrap(), &env);
        assert_eq!(
            install.root_fs_type.as_ref().copied().unwrap(),
            Filesystem::Ext4
        );
        // This one shouldn't have been set
        assert!(install.filesystem_root().is_none());
        install.canonicalize();
        assert_eq!(install.root_fs_type.as_ref().unwrap(), &Filesystem::Ext4);
        assert_eq!(
            install.filesystem_root().unwrap().fstype.unwrap(),
            Filesystem::Ext4
        );

        let c: InstallConfigurationToplevel = toml::from_str(
            r##"[install]
root-fs-type = "ext4"
kargs = ["console=ttyS0", "foo=bar"]
"##,
        )
        .unwrap();
        let mut install = c.install.unwrap();
        assert_eq!(install.root_fs_type.unwrap(), Filesystem::Ext4);
        let other = InstallConfigurationToplevel {
            install: Some(InstallConfiguration {
                kargs: Some(
                    ["console=tty0", "nosmt"]
                        .into_iter()
                        .map(ToOwned::to_owned)
                        .collect(),
                ),
                ..Default::default()
            }),
        };
        install.merge(other.install.unwrap(), &env);
        assert_eq!(install.root_fs_type.unwrap(), Filesystem::Ext4);
        assert_eq!(
            install.kargs,
            Some(
                ["console=ttyS0", "foo=bar", "console=tty0", "nosmt"]
                    .into_iter()
                    .map(ToOwned::to_owned)
                    .collect()
            )
        )
    }

    #[test]
    fn test_parse_filesystems() {
        let env = EnvProperties {
            sys_arch: "x86_64".to_string(),
        };
        let c: InstallConfigurationToplevel = toml::from_str(
            r##"[install.filesystem.root]
type = "xfs"
"##,
        )
        .unwrap();
        let mut install = c.install.unwrap();
        assert_eq!(
            install.filesystem_root().unwrap().fstype.unwrap(),
            Filesystem::Xfs
        );
        let other = InstallConfigurationToplevel {
            install: Some(InstallConfiguration {
                filesystem: Some(BasicFilesystems {
                    root: Some(RootFS {
                        fstype: Some(Filesystem::Ext4),
                    }),
                }),
                ..Default::default()
            }),
        };
        install.merge(other.install.unwrap(), &env);
        assert_eq!(
            install.filesystem_root().unwrap().fstype.unwrap(),
            Filesystem::Ext4
        );
    }

    #[test]
    fn test_parse_block() {
        let env = EnvProperties {
            sys_arch: "x86_64".to_string(),
        };
        let c: InstallConfigurationToplevel = toml::from_str(
            r##"[install.filesystem.root]
type = "xfs"
"##,
        )
        .unwrap();
        let mut install = c.install.unwrap();
        // Verify the default (but note canonicalization mutates)
        {
            let mut install = install.clone();
            install.canonicalize();
            assert_eq!(install.get_block_setup(None).unwrap(), BlockSetup::Direct);
        }
        let other = InstallConfigurationToplevel {
            install: Some(InstallConfiguration {
                block: Some(vec![]),
                ..Default::default()
            }),
        };
        install.merge(other.install.unwrap(), &env);
        // Should be set, but zero length
        assert_eq!(install.block.as_ref().unwrap().len(), 0);
        assert!(install.get_block_setup(None).is_err());

        let c: InstallConfigurationToplevel = toml::from_str(
            r##"[install]
block = ["tpm2-luks"]"##,
        )
        .unwrap();
        let mut install = c.install.unwrap();
        install.canonicalize();
        assert_eq!(install.block.as_ref().unwrap().len(), 1);
        assert_eq!(install.get_block_setup(None).unwrap(), BlockSetup::Tpm2Luks);

        // And verify passing a disallowed config is an error
        assert!(install.get_block_setup(Some(BlockSetup::Direct)).is_err());
    }

    #[test]
    /// Verify that kargs are only applied to supported architectures
    fn test_arch() {
        // no arch specified, kargs ensure that kargs are applied unconditionally
        let env = EnvProperties {
            sys_arch: "x86_64".to_string(),
        };
        let c: InstallConfigurationToplevel = toml::from_str(
            r##"[install]
root-fs-type = "xfs"
"##,
        )
        .unwrap();
        let mut install = c.install.unwrap();
        let other = InstallConfigurationToplevel {
            install: Some(InstallConfiguration {
                kargs: Some(
                    ["console=tty0", "nosmt"]
                        .into_iter()
                        .map(ToOwned::to_owned)
                        .collect(),
                ),
                ..Default::default()
            }),
        };
        install.merge(other.install.unwrap(), &env);
        assert_eq!(
            install.kargs,
            Some(
                ["console=tty0", "nosmt"]
                    .into_iter()
                    .map(ToOwned::to_owned)
                    .collect()
            )
        );
        let env = EnvProperties {
            sys_arch: "aarch64".to_string(),
        };
        let c: InstallConfigurationToplevel = toml::from_str(
            r##"[install]
root-fs-type = "xfs"
"##,
        )
        .unwrap();
        let mut install = c.install.unwrap();
        let other = InstallConfigurationToplevel {
            install: Some(InstallConfiguration {
                kargs: Some(
                    ["console=tty0", "nosmt"]
                        .into_iter()
                        .map(ToOwned::to_owned)
                        .collect(),
                ),
                ..Default::default()
            }),
        };
        install.merge(other.install.unwrap(), &env);
        assert_eq!(
            install.kargs,
            Some(
                ["console=tty0", "nosmt"]
                    .into_iter()
                    .map(ToOwned::to_owned)
                    .collect()
            )
        );

        // one arch matches and one doesn't, ensure that kargs are only applied for the matching arch
        let env = EnvProperties {
            sys_arch: "aarch64".to_string(),
        };
        let c: InstallConfigurationToplevel = toml::from_str(
            r##"[install]
root-fs-type = "xfs"
"##,
        )
        .unwrap();
        let mut install = c.install.unwrap();
        let other = InstallConfigurationToplevel {
            install: Some(InstallConfiguration {
                kargs: Some(
                    ["console=ttyS0", "foo=bar"]
                        .into_iter()
                        .map(ToOwned::to_owned)
                        .collect(),
                ),
                match_architectures: Some(["x86_64"].into_iter().map(ToOwned::to_owned).collect()),
                ..Default::default()
            }),
        };
        install.merge(other.install.unwrap(), &env);
        assert_eq!(install.kargs, None);
        let other = InstallConfigurationToplevel {
            install: Some(InstallConfiguration {
                kargs: Some(
                    ["console=tty0", "nosmt"]
                        .into_iter()
                        .map(ToOwned::to_owned)
                        .collect(),
                ),
                match_architectures: Some(["aarch64"].into_iter().map(ToOwned::to_owned).collect()),
                ..Default::default()
            }),
        };
        install.merge(other.install.unwrap(), &env);
        assert_eq!(
            install.kargs,
            Some(
                ["console=tty0", "nosmt"]
                    .into_iter()
                    .map(ToOwned::to_owned)
                    .collect()
            )
        );

        // multiple arch specified, ensure that kargs are applied to both archs
        let env = EnvProperties {
            sys_arch: "x86_64".to_string(),
        };
        let c: InstallConfigurationToplevel = toml::from_str(
            r##"[install]
root-fs-type = "xfs"
"##,
        )
        .unwrap();
        let mut install = c.install.unwrap();
        let other = InstallConfigurationToplevel {
            install: Some(InstallConfiguration {
                kargs: Some(
                    ["console=tty0", "nosmt"]
                        .into_iter()
                        .map(ToOwned::to_owned)
                        .collect(),
                ),
                match_architectures: Some(
                    ["x86_64", "aarch64"]
                        .into_iter()
                        .map(ToOwned::to_owned)
                        .collect(),
                ),
                ..Default::default()
            }),
        };
        install.merge(other.install.unwrap(), &env);
        assert_eq!(
            install.kargs,
            Some(
                ["console=tty0", "nosmt"]
                    .into_iter()
                    .map(ToOwned::to_owned)
                    .collect()
            )
        );
        let env = EnvProperties {
            sys_arch: "aarch64".to_string(),
        };
        let c: InstallConfigurationToplevel = toml::from_str(
            r##"[install]
root-fs-type = "xfs"
"##,
        )
        .unwrap();
        let mut install = c.install.unwrap();
        let other = InstallConfigurationToplevel {
            install: Some(InstallConfiguration {
                kargs: Some(
                    ["console=tty0", "nosmt"]
                        .into_iter()
                        .map(ToOwned::to_owned)
                        .collect(),
                ),
                match_architectures: Some(
                    ["x86_64", "aarch64"]
                        .into_iter()
                        .map(ToOwned::to_owned)
                        .collect(),
                ),
                ..Default::default()
            }),
        };
        install.merge(other.install.unwrap(), &env);
        assert_eq!(
            install.kargs,
            Some(
                ["console=tty0", "nosmt"]
                    .into_iter()
                    .map(ToOwned::to_owned)
                    .collect()
            )
        );
    }

    #[test]
    fn test_parse_ostree() {
        let env = EnvProperties {
            sys_arch: "x86_64".to_string(),
        };

        // Table-driven test cases for parsing bls-append-except-default
        let parse_cases = [
            ("console=ttyS0", "console=ttyS0"),
            ("console=ttyS0,115200n8", "console=ttyS0,115200n8"),
            ("rd.lvm.lv=vg/root", "rd.lvm.lv=vg/root"),
        ];
        for (input, expected) in parse_cases {
            let toml_str = format!(
                r#"[install.ostree]
bls-append-except-default = "{input}"
"#
            );
            let c: InstallConfigurationToplevel = toml::from_str(&toml_str).unwrap();
            assert_eq!(
                c.install
                    .unwrap()
                    .ostree
                    .unwrap()
                    .bls_append_except_default
                    .unwrap(),
                expected
            );
        }

        // Test merging: other config should override original
        let mut install: InstallConfiguration = toml::from_str(
            r#"[ostree]
bls-append-except-default = "console=ttyS0"
"#,
        )
        .unwrap();
        let other = InstallConfiguration {
            ostree: Some(OstreeRepoOpts {
                bls_append_except_default: Some("console=tty0".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        install.merge(other, &env);
        assert_eq!(
            install.ostree.unwrap().bls_append_except_default.unwrap(),
            "console=tty0"
        );
    }

    #[test]
    fn test_parse_stateroot() {
        let c: InstallConfigurationToplevel = toml::from_str(
            r#"[install]
stateroot = "custom"
"#,
        )
        .unwrap();
        assert_eq!(c.install.unwrap().stateroot.unwrap(), "custom");
    }

    #[test]
    fn test_merge_stateroot() {
        let env = EnvProperties {
            sys_arch: "x86_64".to_string(),
        };
        let mut install: InstallConfiguration = toml::from_str(
            r#"stateroot = "original"
"#,
        )
        .unwrap();
        let other = InstallConfiguration {
            stateroot: Some("newroot".to_string()),
            ..Default::default()
        };
        install.merge(other, &env);
        assert_eq!(install.stateroot.unwrap(), "newroot");
    }

    #[test]
    fn test_parse_mount_specs() {
        let c: InstallConfigurationToplevel = toml::from_str(
            r#"[install]
root-mount-spec = "LABEL=rootfs"
boot-mount-spec = "UUID=abcd-1234"
"#,
        )
        .unwrap();
        let install = c.install.unwrap();
        assert_eq!(install.root_mount_spec.unwrap(), "LABEL=rootfs");
        assert_eq!(install.boot_mount_spec.unwrap(), "UUID=abcd-1234");
    }

    #[test]
    fn test_merge_mount_specs() {
        let env = EnvProperties {
            sys_arch: "x86_64".to_string(),
        };
        let mut install: InstallConfiguration = toml::from_str(
            r#"root-mount-spec = "UUID=old"
boot-mount-spec = "UUID=oldboot"
"#,
        )
        .unwrap();
        let other = InstallConfiguration {
            root_mount_spec: Some("LABEL=newroot".to_string()),
            ..Default::default()
        };
        install.merge(other, &env);
        // root_mount_spec should be overridden
        assert_eq!(install.root_mount_spec.as_deref().unwrap(), "LABEL=newroot");
        // boot_mount_spec should remain unchanged
        assert_eq!(install.boot_mount_spec.as_deref().unwrap(), "UUID=oldboot");
    }

    /// Empty mount specs are valid and signal to omit mount kargs entirely.
    /// See https://github.com/bootc-dev/bootc/issues/1441
    #[test]
    fn test_parse_empty_mount_specs() {
        let c: InstallConfigurationToplevel = toml::from_str(
            r#"[install]
root-mount-spec = ""
boot-mount-spec = ""
"#,
        )
        .unwrap();
        let install = c.install.unwrap();
        assert_eq!(install.root_mount_spec.as_deref().unwrap(), "");
        assert_eq!(install.boot_mount_spec.as_deref().unwrap(), "");
    }

    #[test]
    fn test_parse_bootupd_skip_boot_uuid() {
        // Test parsing true
        let c: InstallConfigurationToplevel = toml::from_str(
            r#"[install.bootupd]
skip-boot-uuid = true
"#,
        )
        .unwrap();
        assert_eq!(
            c.install.unwrap().bootupd.unwrap().skip_boot_uuid.unwrap(),
            true
        );

        // Test parsing false
        let c: InstallConfigurationToplevel = toml::from_str(
            r#"[install.bootupd]
skip-boot-uuid = false
"#,
        )
        .unwrap();
        assert_eq!(
            c.install.unwrap().bootupd.unwrap().skip_boot_uuid.unwrap(),
            false
        );

        // Test default (not specified) is None
        let c: InstallConfigurationToplevel = toml::from_str(
            r#"[install]
root-fs-type = "xfs"
"#,
        )
        .unwrap();
        assert!(c.install.unwrap().bootupd.is_none());
    }

    #[test]
    fn test_merge_bootupd_skip_boot_uuid() {
        let env = EnvProperties {
            sys_arch: "x86_64".to_string(),
        };
        let mut install: InstallConfiguration = toml::from_str(
            r#"[bootupd]
skip-boot-uuid = false
"#,
        )
        .unwrap();
        let other = InstallConfiguration {
            bootupd: Some(Bootupd {
                skip_boot_uuid: Some(true),
            }),
            ..Default::default()
        };
        install.merge(other, &env);
        // skip_boot_uuid should be overridden to true
        assert_eq!(install.bootupd.unwrap().skip_boot_uuid.unwrap(), true);
    }
}
