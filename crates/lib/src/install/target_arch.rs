//! The architecture an installation targets.
//!
//! An install normally targets the architecture bootc itself runs on, and
//! that remains the default. Building a disk image for another architecture
//! only needs the decisions below to follow the image rather than the host:
//! none of them executes code from the target.

use std::fmt;

use anyhow::Result;
use clap::ValueEnum;
use ocidir::oci_spec::image::{Arch, Os, Platform, PlatformBuilder};
use serde::{Deserialize, Serialize};

/// An architecture bootc can install for.
#[derive(ValueEnum, Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum TargetArch {
    #[value(name = "x86_64")]
    #[serde(rename = "x86_64")]
    X86_64,
    #[value(name = "aarch64")]
    #[serde(rename = "aarch64")]
    Aarch64,
    #[value(name = "s390x")]
    #[serde(rename = "s390x")]
    S390x,
    #[value(name = "powerpc64")]
    #[serde(rename = "powerpc64")]
    Powerpc64,
    #[value(name = "powerpc64le")]
    #[serde(rename = "powerpc64le")]
    Powerpc64le,
    #[value(name = "riscv64")]
    #[serde(rename = "riscv64")]
    Riscv64,
    #[value(name = "arm")]
    #[serde(rename = "arm")]
    Arm,
}

#[cfg(target_arch = "x86_64")]
const HOST: TargetArch = TargetArch::X86_64;
#[cfg(target_arch = "aarch64")]
const HOST: TargetArch = TargetArch::Aarch64;
#[cfg(target_arch = "s390x")]
const HOST: TargetArch = TargetArch::S390x;
#[cfg(all(target_arch = "powerpc64", target_endian = "big"))]
const HOST: TargetArch = TargetArch::Powerpc64;
#[cfg(all(target_arch = "powerpc64", target_endian = "little"))]
const HOST: TargetArch = TargetArch::Powerpc64le;
#[cfg(target_arch = "riscv64")]
const HOST: TargetArch = TargetArch::Riscv64;
#[cfg(target_arch = "arm")]
const HOST: TargetArch = TargetArch::Arm;

/// The partition, before the ESP, that an architecture's firmware boots from.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum FirmwareBootPartition {
    /// A BIOS boot partition for GRUB on legacy-BIOS x86.
    BiosBoot,
    /// A PReP boot partition for OpenFirmware on PowerPC.
    PrepBoot,
}

impl TargetArch {
    /// The architecture bootc was built for.
    pub(crate) const fn host() -> Self {
        HOST
    }

    /// Whether this architecture is the one bootc runs on.
    pub(crate) fn is_host(self) -> bool {
        self == Self::host()
    }

    /// The Discoverable Partitions root partition type for this architecture.
    pub(crate) const fn root_partition_type(self) -> &'static str {
        use bootc_blockdev::dps;
        match self {
            Self::X86_64 => dps::ROOT_X86_64,
            Self::Aarch64 => dps::ROOT_ARM64,
            Self::S390x => dps::ROOT_S390X,
            Self::Powerpc64 => dps::ROOT_PPC64,
            Self::Powerpc64le => dps::ROOT_PPC64_LE,
            Self::Riscv64 => dps::ROOT_RISCV64,
            Self::Arm => dps::ROOT_ARM,
        }
    }

    /// Whether this architecture boots through an EFI system partition.
    pub(crate) const fn uses_efi(self) -> bool {
        matches!(self, Self::X86_64 | Self::Aarch64)
    }

    /// The firmware boot partition this architecture needs ahead of the ESP,
    /// if any. Errors for an architecture whose disk layout bootc does not
    /// know.
    pub(crate) fn firmware_boot_partition(self) -> Result<Option<FirmwareBootPartition>> {
        match self {
            Self::X86_64 => Ok(Some(FirmwareBootPartition::BiosBoot)),
            Self::Powerpc64 | Self::Powerpc64le => Ok(Some(FirmwareBootPartition::PrepBoot)),
            Self::Aarch64 | Self::S390x => Ok(None),
            Self::Riscv64 | Self::Arm => anyhow::bail!("Unsupported architecture: {self}"),
        }
    }

    /// The OCI platform whose image this install reads.
    pub(crate) fn oci_platform(self) -> Result<Platform> {
        let arch = match self {
            Self::X86_64 => Arch::Amd64,
            Self::Aarch64 => Arch::ARM64,
            Self::S390x => Arch::s390x,
            Self::Powerpc64 => Arch::PowerPC64,
            Self::Powerpc64le => Arch::PowerPC64le,
            Self::Riscv64 => Arch::RISCV64,
            Self::Arm => Arch::ARM,
        };
        Ok(PlatformBuilder::default()
            .architecture(arch)
            .os(Os::Linux)
            .build()?)
    }
}

impl fmt::Display for TargetArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_possible_value().unwrap().get_name().fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_matches_build_target() {
        assert_eq!(
            TargetArch::host().root_partition_type(),
            bootc_blockdev::dps::this_arch_root()
        );
        assert!(TargetArch::host().is_host());
    }

    #[test]
    fn cross_layouts() {
        assert_eq!(
            TargetArch::Aarch64.root_partition_type(),
            bootc_blockdev::dps::ROOT_ARM64
        );
        assert_eq!(TargetArch::Aarch64.firmware_boot_partition().unwrap(), None);
        assert_eq!(
            TargetArch::X86_64.firmware_boot_partition().unwrap(),
            Some(FirmwareBootPartition::BiosBoot)
        );
        assert!(TargetArch::Aarch64.uses_efi());
        assert!(!TargetArch::S390x.uses_efi());
        assert_eq!(
            TargetArch::Aarch64.oci_platform().unwrap().architecture(),
            &Arch::ARM64
        );
    }
}
