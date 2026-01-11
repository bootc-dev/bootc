//! System repair functionality

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;

use anyhow::{Context, Result, anyhow};
use cap_std::fs::{Dir, MetadataExt};
use cap_std_ext::cap_std;
use fn_error_context::context;
use serde::{Deserialize, Serialize};

use crate::sysroot::SysrootLock;

// Find the inode numbers for objects
fn gather_inodes(
    prefix: &str,
    dir: &Dir,
    little_inodes: &mut BTreeMap<u32, String>,
    big_inodes: &mut BTreeMap<u64, String>,
) -> Result<()> {
    for child in dir.entries()? {
        let child = child?;
        let metadata = child.metadata()?;
        if !(metadata.is_file() || metadata.is_symlink()) {
            continue;
        }
        let name = child.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid {name:?}"))?;
        let object_rest = name
            .split_once('.')
            .ok_or_else(|| anyhow!("Invalid object {name}"))?
            .0;
        let checksum = format!("{prefix}{object_rest}");
        let inode = metadata.ino();
        if let Ok(little) = u32::try_from(inode) {
            little_inodes.insert(little, checksum);
        } else {
            big_inodes.insert(inode, checksum);
        }
    }
    Ok(())
}

#[derive(Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RepairResult {
    /// Result of inode checking
    pub inodes: InodeCheck,
    // Whether we detected a likely corrupted merge commit
    pub likely_corrupted_container_image_merges: Vec<String>,
    // Whether the booted deployment is likely corrupted
    pub booted_is_likely_corrupted: bool,
    // Whether the staged deployment is likely corrupted
    pub staged_is_likely_corrupted: bool,
}

#[derive(Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct InodeCheck {
    // Number of >32 bit inodes found
    pub inode64: u64,
    // Number of <= 32 bit inodes found
    pub inode32: u64,
    // Number of collisions found (when 64 bit inode is truncated to 32 bit)
    pub collisions: BTreeSet<u64>,
}

impl Display for InodeCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ostree inode check:\n  64bit inodes: {}\n  32 bit inodes: {}\n  collisions: {}\n",
            self.inode64,
            self.inode32,
            self.collisions.len()
        )
    }
}

impl InodeCheck {
    pub fn is_ok(&self) -> bool {
        self.collisions.is_empty()
    }
}

#[context("Checking inodes")]
#[doc(hidden)]
/// Detect if any commits are potentially incorrect due to inode truncations.
pub fn check_inode_collision(repo: &ostree::Repo, verbose: bool) -> Result<InodeCheck> {
    let repo_dir = Dir::reopen_dir(&repo.dfd_borrow())?;
    let objects = repo_dir.open_dir("objects")?;

    println!(
        r#"Attempting analysis of ostree state for files that may be incorrectly linked.
For more information, see https://github.com/ostreedev/ostree/pull/2874/commits/de6fddc6adee09a93901243dc7074090828a1912
"#
    );

    println!("Gathering inodes for ostree objects...");
    let mut little_inodes = BTreeMap::new();
    let mut big_inodes = BTreeMap::new();

    for child in objects.entries()? {
        let child = child?;
        if !child.file_type()?.is_dir() {
            continue;
        }
        let name = child.file_name();
        if name.len() != 2 {
            continue;
        }
        let name = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid {name:?}"))?;
        let objdir = child.open_dir()?;
        gather_inodes(name, &objdir, &mut little_inodes, &mut big_inodes)
            .with_context(|| format!("Processing {name:?}"))?;
    }

    let mut colliding_inodes = BTreeMap::new();
    for (big_inum, big_inum_checksum) in big_inodes.iter() {
        let truncated = *big_inum as u32;
        if let Some(small_inum_object) = little_inodes.get(&truncated) {
            // Don't output each collision unless verbose mode is enabled.  It's actually
            // quite interesting to see data, but only for development and deep introspection
            // use cases.
            if verbose {
                eprintln!(
                    r#"collision:
  inode (>32 bit): {big_inum}
  object: {big_inum_checksum}
  inode (truncated): {truncated}
  object: {small_inum_object}
"#
                );
            }
            colliding_inodes.insert(big_inum, big_inum_checksum);
        }
    }

    // From here let's just track the possibly-colliding 64 bit inode, not also
    // the checksum.
    let collisions = colliding_inodes
        .keys()
        .map(|&&v| v)
        .collect::<BTreeSet<u64>>();

    let inode32 = little_inodes.len() as u64;
    let inode64 = big_inodes.len() as u64;
    Ok(InodeCheck {
        inode32,
        inode64,
        collisions,
    })
}

/// Attempt to automatically repair any corruption from inode collisions.
#[doc(hidden)]
pub fn analyze_for_repair(sysroot: &SysrootLock, verbose: bool) -> Result<RepairResult> {
    use crate::container::store as container_store;
    let repo = &sysroot.repo();

    // Query booted and pending state
    let booted_deployment = sysroot.booted_deployment();
    let booted_checksum = booted_deployment.as_ref().map(|b| b.csum());
    let booted_checksum = booted_checksum.as_ref().map(|s| s.as_str());
    let staged_deployment = sysroot.staged_deployment();
    let staged_checksum = staged_deployment.as_ref().map(|b| b.csum());
    let staged_checksum = staged_checksum.as_ref().map(|s| s.as_str());

    let inodes = check_inode_collision(repo, verbose)?;
    println!("{inodes}");
    if inodes.is_ok() {
        println!("OK no colliding inodes found");
        return Ok(RepairResult {
            inodes,
            ..Default::default()
        });
    }

    let all_images = container_store::list_images(repo)?;
    let all_images = all_images
        .into_iter()
        .map(|img| crate::container::ImageReference::try_from(img.as_str()))
        .collect::<Result<Vec<_>>>()?;
    println!("Verifying ostree-container images: {}", all_images.len());
    let mut likely_corrupted_container_image_merges = Vec::new();
    let mut booted_is_likely_corrupted = false;
    let mut staged_is_likely_corrupted = false;
    for imgref in all_images {
        if let Some(state) = container_store::query_image(repo, &imgref)? {
            if !container_store::verify_container_image(
                sysroot,
                &imgref,
                &state,
                &inodes.collisions,
                verbose,
            )? {
                eprintln!("warning: Corrupted image {imgref}");
                likely_corrupted_container_image_merges.push(imgref.to_string());
                let merge_commit = state.merge_commit.as_str();
                if booted_checksum == Some(merge_commit) {
                    booted_is_likely_corrupted = true;
                    eprintln!("warning: booted deployment is likely corrupted");
                } else if staged_checksum == Some(merge_commit) {
                    staged_is_likely_corrupted = true;
                    eprintln!("warning: staged deployment is likely corrupted");
                }
            }
        } else {
            // This really shouldn't happen
            eprintln!("warning: Image was removed from underneath us: {imgref}");
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
    Ok(RepairResult {
        inodes,
        likely_corrupted_container_image_merges,
        booted_is_likely_corrupted,
        staged_is_likely_corrupted,
    })
}

impl RepairResult {
    pub fn check(&self) -> anyhow::Result<()> {
        if self.booted_is_likely_corrupted {
            eprintln!("warning: booted deployment is likely corrupted");
        }
        if self.booted_is_likely_corrupted {
            eprintln!("warning: staged deployment is likely corrupted");
        }
        match self.likely_corrupted_container_image_merges.len() {
            0 => {
                println!("OK no corruption found");
                Ok(())
            }
            n => {
                anyhow::bail!("Found corruption in images: {n}")
            }
        }
    }

    #[context("Repairing")]
    pub fn repair(self, sysroot: &SysrootLock) -> Result<()> {
        let repo = &sysroot.repo();
        for imgref in self.likely_corrupted_container_image_merges {
            let imgref = crate::container::ImageReference::try_from(imgref.as_str())?;
            eprintln!("Flushing cached state for corrupted merged image: {imgref}");
            crate::container::store::remove_images(repo, [&imgref])?;
        }
        if self.booted_is_likely_corrupted {
            anyhow::bail!("TODO redeploy and reboot for booted deployment corruption");
        }
        if self.staged_is_likely_corrupted {
            anyhow::bail!("TODO undeploy for staged deployment corruption");
        }
        Ok(())
    }
}
