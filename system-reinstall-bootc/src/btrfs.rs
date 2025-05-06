use anyhow::Result;
use bootc_mount::Filesystem;

use crate::prompt::press_enter;

pub(crate) struct ProblemMount {
    target: String,
    fs_type: String,
    source: String,
}

impl std::fmt::Display for ProblemMount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            format!(
                "Type: {}, Target: {}, Source: {}",
                self.fs_type, self.target, self.source
            )
            .as_str(),
        )
    }
}

pub(crate) fn check_root_siblings() -> Result<Vec<ProblemMount>> {
    let mounts = bootc_mount::run_findmnt(&[], None)?;
    let problem_filesystems: Vec<ProblemMount> = mounts
        .filesystems
        .iter()
        .filter(|fs| fs.target == "/")
        .flat_map(|root| {
            let children: Vec<&Filesystem> = root
                .children
                .iter()
                .flatten()
                .filter(|child| child.source == root.source)
                .collect();
            children
        })
        .map(|fs| ProblemMount {
            target: fs.target.clone(),
            fs_type: fs.fstype.clone(),
            source: fs.source.clone(),
        })
        .collect();
    Ok(problem_filesystems)
}

pub(crate) fn print_warning(mounts: Vec<ProblemMount>) {
    if !mounts.is_empty() {
        println!();
        println!("NOTICE: the following filesystems are currently mounted on the same drive as root. After reboot, these will not be automatically mounted unless defined in the bootc image. The filesystems will be preserved and continue to consume disk space. Consult the bootc documentation to determine the appropriate action for your system.");
        println!();
        for m in mounts {
            println!("{}", m);
        }
        press_enter();
    }
}
