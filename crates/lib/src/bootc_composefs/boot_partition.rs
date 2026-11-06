//! Selecting the partition that holds the composefs boot entries.
//!
//! Per the Boot Loader Specification, boot entries go on the Extended Boot
//! Loader Partition (XBOOTLDR) on the ESP's disk if there is one, and on the
//! ESP otherwise. bootc follows that for bootloaders that read entries that
//! way (see [`Bootloader::is_bls_conformant`]), with one exception: systems
//! installed by a bootc that didn't use XBOOTLDR partitions keep their entries
//! on the ESP, so a booted system keeps using the partition holding the booted
//! deployment's entries.

use anyhow::Result;
use bootc_mount::tempmount::TempMount;
use camino::Utf8Path;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;

use crate::composefs_consts::{BLS_ENTRY_FILE_PREFIX, TYPE1_ENT_PATH, TYPE1_ENT_PATH_STAGED};
use crate::parsers::bls_config::parse_bls_config;
use crate::spec::Bootloader;

/// The partition holding UKIs, Type #1 entries and their kernels and
/// initramfs images.
#[derive(Debug, Clone)]
pub(crate) enum BootPartition {
    /// The EFI System Partition
    Esp(String),
    /// An Extended Boot Loader Partition on the ESP's disk. It holds UKIs
    /// that don't fit on a small ESP, such as one shared with Windows.
    Xbootldr(String),
}

impl BootPartition {
    /// The partition to install entries to, given the ESP at `esp`: the VFAT
    /// XBOOTLDR partition next to it if `bootloader` reads one and there is
    /// one, and the ESP otherwise.
    pub(crate) fn for_install(esp: String, bootloader: Bootloader) -> Result<Self> {
        Ok(match sibling_xbootldr(&esp, bootloader)? {
            Some(xbootldr) => Self::Xbootldr(xbootldr),
            None => Self::Esp(esp),
        })
    }

    /// Find and mount, with `mount`, the partition holding the entries of
    /// the booted deployment `booted_verity`, given the ESP at `esp` it was
    /// booted from.
    pub(crate) fn mount_booted(
        esp: String,
        bootloader: Bootloader,
        booted_verity: &str,
        mount: impl Fn(&str) -> Result<TempMount>,
    ) -> Result<(Self, TempMount)> {
        if let Some(xbootldr) = sibling_xbootldr(&esp, bootloader)? {
            let mounted = mount(&xbootldr)?;
            if has_type1_entry_for(&mounted.fd, booted_verity)? {
                return Ok((Self::Xbootldr(xbootldr), mounted));
            }
            tracing::debug!(
                "The booted deployment has no entry on XBOOTLDR partition {xbootldr}, using {esp}"
            );
        }
        let mounted = mount(&esp)?;
        Ok((Self::Esp(esp), mounted))
    }

    /// The partition's device path
    pub(crate) fn device(&self) -> &str {
        match self {
            Self::Esp(device) | Self::Xbootldr(device) => device,
        }
    }
}

fn sibling_xbootldr(esp: &str, bootloader: Bootloader) -> Result<Option<String>> {
    if !bootloader.is_bls_conformant() {
        return Ok(None);
    }
    let xbootldr = bootc_blockdev::list_dev(Utf8Path::new(esp))?.find_sibling_xbootldr()?;
    Ok(xbootldr.map(|xbootldr| {
        tracing::debug!("Found XBOOTLDR partition {} next to {esp}", xbootldr.path());
        xbootldr.path()
    }))
}

/// Whether `boot_dir` has one of our Type #1 entries, staged or not, for the
/// deployment `verity`.
fn has_type1_entry_for(boot_dir: &Dir, verity: &str) -> Result<bool> {
    for path in [TYPE1_ENT_PATH, TYPE1_ENT_PATH_STAGED] {
        let Some(entries) = boot_dir.open_dir_optional(path)? else {
            continue;
        };
        for entry in entries.entries_utf8()? {
            let name = entry?.file_name()?;
            if !(name.starts_with(BLS_ENTRY_FILE_PREFIX) && name.ends_with(".conf")) {
                continue;
            }
            let entry = parse_bls_config(&entries.read_to_string(&name)?)?;
            if entry.get_verity().is_ok_and(|v| v == verity) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutils::{ChangeType, TestRoot, fake_digest_version};

    #[test]
    fn test_has_type1_entry_for() -> Result<()> {
        let mut root = TestRoot::new()?;
        let installed = root.current().verity.clone();
        root.upgrade(1, ChangeType::Kernel)?;
        let upgraded = root.current().verity.clone();
        let boot_dir = root.boot_dir()?;

        assert!(has_type1_entry_for(&boot_dir, &installed)?);
        assert!(has_type1_entry_for(&boot_dir, &upgraded)?);
        assert!(!has_type1_entry_for(&boot_dir, &fake_digest_version(2))?);
        Ok(())
    }

    #[test]
    fn test_has_type1_entry_for_staged() -> Result<()> {
        let root = TestRoot::new()?;
        let verity = root.current().verity.clone();
        let boot_dir = root.boot_dir()?;
        boot_dir.rename(TYPE1_ENT_PATH, &boot_dir, TYPE1_ENT_PATH_STAGED)?;

        assert!(has_type1_entry_for(&boot_dir, &verity)?);
        Ok(())
    }

    #[test]
    fn test_has_type1_entry_for_other_os() -> Result<()> {
        let dir = cap_std_ext::cap_tempfile::tempdir(cap_std_ext::cap_std::ambient_authority())?;
        let verity = fake_digest_version(0);
        assert!(!has_type1_entry_for(&dir, &verity)?);

        dir.create_dir_all(TYPE1_ENT_PATH)?;
        dir.atomic_write(
            format!("{TYPE1_ENT_PATH}/other-os.conf"),
            "title Other\nlinux /vmlinuz\noptions root=UUID=other rw\n",
        )?;
        assert!(!has_type1_entry_for(&dir, &verity)?);
        Ok(())
    }
}
