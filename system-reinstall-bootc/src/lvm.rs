use std::process::Command;

use anyhow::Result;
use bootc_mount::run_findmnt;
use bootc_utils::CommandRunExt;
use serde::Deserialize;

use crate::prompt::press_enter;

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
    #[serde(default)]
    mount_path: String,
}

pub(crate) fn parse_volumes(group: Option<String>) -> Result<Vec<LogicalVolume>> {
    let mut cmd = Command::new("lvs");
    cmd.args([
        "--reportformat=json",
        "-o",
        "lv_name,lv_size,lv_path,vg_name",
    ]);

    if let Some(group) = group {
        cmd.arg(group);
    }

    let output: Lvs = cmd.run_and_parse_json()?;

    Ok(output
        .report
        .iter()
        .flat_map(|r| r.lv.iter().cloned())
        .collect())
}

pub(crate) fn check_root_siblings() -> Result<Vec<LogicalVolume>> {
    let all_volumes = parse_volumes(None)?;

    // first look for a lv mounted to '/'
    // then gather all the sibling lvs in the vg along with their mount points
    let siblings: Vec<LogicalVolume> = all_volumes
        .iter()
        .filter(|lv| {
            let mount = run_findmnt(&["-S", &lv.lv_path], None).unwrap_or_default();
            if let Some(fs) = mount.filesystems.first() {
                &fs.target == "/"
            } else {
                false
            }
        })
        .flat_map(|root_lv| {
            tracing::warn!("inside flat_map");
            parse_volumes(Some(root_lv.vg_name.clone())).unwrap_or_default()
        })
        .map(|lv| {
            tracing::warn!("inside map");
            let mount = run_findmnt(&["-S", &lv.lv_path], None).unwrap();
            let mount_path = if let Some(fs) = mount.filesystems.first() {
                &fs.target
            } else {
                ""
            };
            LogicalVolume {
                lv_name: lv.lv_name,
                lv_size: lv.lv_size,
                lv_path: lv.lv_path,
                vg_name: lv.vg_name,
                mount_path: mount_path.to_string(),
            }
        })
        .filter(|lv| lv.mount_path != "/")
        .collect();

    Ok(siblings)
}

pub(crate) fn print_warning(volumes: Vec<LogicalVolume>) {
    println!();
    println!("NOTICE: the following logical volumes are in the same volume group as root. After reboot, these will not be automatically mounted unless defined in the bootc image. The filesystems will be preserved and continue to consume disk space. Consult the bootc documentation to determine the appropriate action for your system.");
    println!();
    for vol in volumes {
        println!(
            "Mount Path: {}, Name: {}, Size: {}, Group: {}",
            vol.mount_path, vol.lv_name, vol.lv_size, vol.vg_name
        );
    }
    press_enter();
}
