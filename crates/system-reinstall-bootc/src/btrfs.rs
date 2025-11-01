use anyhow::Result;
use bootc_mount::Filesystem;
use fn_error_context::context;

#[context("check_root_siblings")]
pub(crate) fn check_root_siblings() -> Result<Vec<String>> {
    let mounts = bootc_mount::run_findmnt(&[], None, None)?;
    let problem_filesystems: Vec<String> = mounts
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
        .map(|zs| {
            format!(
                "Type: {}, Mount Point: {}, Source: {}",
                zs.fstype, zs.target, zs.source
            )
        })
        .collect();
    Ok(problem_filesystems)
}
