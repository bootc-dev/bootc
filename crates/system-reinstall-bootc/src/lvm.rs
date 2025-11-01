use std::process::Command;

use anyhow::Result;
use bootc_mount::run_findmnt;
use bootc_utils::{CommandRunExt, ResultExt};
use fn_error_context::context;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct Lvs {
    report: Vec<LvsReport>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LvsReport {
    lv: Vec<LogicalVolume>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct LogicalVolume {
    lv_name: String,
    lv_size: String,
    lv_path: String,
    vg_name: String,
}

#[context("parse_volumes")]
pub(crate) fn parse_volumes(group: Option<&str>) -> Result<Vec<LogicalVolume>> {
    if which::which("lvs").is_err() {
        tracing::debug!("lvs binary not found. Skipping logical volume check.");
        return Ok(Vec::<LogicalVolume>::new());
    }

    let mut cmd = Command::new("lvs");
    cmd.args([
        "--reportformat=json",
        "-o",
        "lv_name,lv_size,lv_path,vg_name",
    ])
    .args(group);

    let output: Lvs = cmd.run_and_parse_json()?;

    Ok(output
        .report
        .iter()
        .flat_map(|r| r.lv.iter().cloned())
        .collect())
}

#[context("check_root_siblings")]
pub(crate) fn check_root_siblings() -> Result<Vec<String>> {
    let all_volumes = parse_volumes(None)?;

    // first look for a lv mounted to '/'
    // then gather all the sibling lvs in the vg along with their mount points
    let siblings: Vec<String> = all_volumes
        .iter()
        .filter(|lv| {
            let mount = run_findmnt(&["-S", &lv.lv_path], None, None).log_err_default();
            if let Some(fs) = mount.filesystems.first() {
                &fs.target == "/"
            } else {
                false
            }
        })
        .flat_map(|root_lv| parse_volumes(Some(root_lv.vg_name.as_str())).unwrap_or_default())
        .try_fold(Vec::new(), |mut acc, r| -> anyhow::Result<_> {
            let mount = run_findmnt(&["-S", &r.lv_path], None, None).log_err_default();
            let mount_path = if let Some(fs) = mount.filesystems.first() {
                &fs.target
            } else {
                ""
            };

            if mount_path != "/" && !mount_path.is_empty() {
                acc.push(format!(
                    "Type: LVM, Mount Point: {}, LV: {}, VG: {}, Size: {}",
                    mount_path, r.lv_name, r.vg_name, r.lv_size
                ))
            };

            Ok(acc)
        })?;

    Ok(siblings)
}
