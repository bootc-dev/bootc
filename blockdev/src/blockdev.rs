use std::collections::HashMap;
use std::env;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

use anyhow::{anyhow, Context, Result};
use camino::Utf8Path;
use camino::Utf8PathBuf;
use fn_error_context::context;
use libc;
use regex::Regex;
use serde::Deserialize;

use bootc_utils::CommandRunExt;

#[derive(Debug, Deserialize)]
struct DevicesOutput {
    blockdevices: Vec<Device>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Device {
    pub name: String,
    pub serial: Option<String>,
    pub model: Option<String>,
    pub partlabel: Option<String>,
    pub parttype: Option<String>,
    pub partuuid: Option<String>,
    pub children: Option<Vec<Device>>,
    pub size: u64,
    #[serde(rename = "maj:min")]
    pub maj_min: Option<String>,
    // NOTE this one is not available on older util-linux, and
    // will also not exist for whole blockdevs (as opposed to partitions).
    pub start: Option<u64>,

    // Filesystem-related properties
    pub label: Option<String>,
    pub fstype: Option<String>,
    pub path: Option<String>,
}

impl Device {
    #[allow(dead_code)]
    // RHEL8's lsblk doesn't have PATH, so we do it
    pub fn path(&self) -> String {
        self.path.clone().unwrap_or(format!("/dev/{}", &self.name))
    }

    #[allow(dead_code)]
    pub fn has_children(&self) -> bool {
        self.children.as_ref().map_or(false, |v| !v.is_empty())
    }

    // The "start" parameter was only added in a version of util-linux that's only
    // in Fedora 40 as of this writing.
    fn backfill_start(&mut self) -> Result<()> {
        let Some(majmin) = self.maj_min.as_deref() else {
            // This shouldn't happen
            return Ok(());
        };
        let sysfs_start_path = format!("/sys/dev/block/{majmin}/start");
        if Utf8Path::new(&sysfs_start_path).try_exists()? {
            let start = std::fs::read_to_string(&sysfs_start_path)
                .with_context(|| format!("Reading {sysfs_start_path}"))?;
            tracing::debug!("backfilled start to {start}");
            self.start = Some(
                start
                    .trim()
                    .parse()
                    .context("Parsing sysfs start property")?,
            );
        }
        Ok(())
    }

    /// Older versions of util-linux may be missing some properties. Backfill them if they're missing.
    pub fn backfill_missing(&mut self) -> Result<()> {
        // Add new properties to backfill here
        self.backfill_start()?;
        // And recurse to child devices
        for child in self.children.iter_mut().flatten() {
            child.backfill_missing()?;
        }
        Ok(())
    }
}

#[context("Listing device {dev}")]
pub fn list_dev(dev: &Utf8Path) -> Result<Device> {
    let mut devs: DevicesOutput = Command::new("lsblk")
        .args(["-J", "-b", "-O"])
        .arg(dev)
        .log_debug()
        .run_and_parse_json()?;
    for dev in devs.blockdevices.iter_mut() {
        dev.backfill_missing()?;
    }
    devs.blockdevices
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no device output from lsblk for {dev}"))
}

#[derive(Debug, Deserialize)]
struct SfDiskOutput {
    partitiontable: PartitionTable,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Partition {
    pub node: String,
    pub start: u64,
    pub size: u64,
    #[serde(rename = "type")]
    pub parttype: String,
    pub uuid: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PartitionType {
    Dos,
    Gpt,
    Unknown(String),
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PartitionTable {
    pub label: PartitionType,
    pub id: String,
    pub device: String,
    // We're not using these fields
    // pub unit: String,
    // pub firstlba: u64,
    // pub lastlba: u64,
    // pub sectorsize: u64,
    pub partitions: Vec<Partition>,
}

impl PartitionTable {
    /// Find the partition with the given device name
    #[allow(dead_code)]
    pub fn find<'a>(&'a self, devname: &str) -> Option<&'a Partition> {
        self.partitions.iter().find(|p| p.node.as_str() == devname)
    }

    pub fn path(&self) -> &Utf8Path {
        self.device.as_str().into()
    }

    // Find the partition with the given offset (starting at 1)
    #[allow(dead_code)]
    pub fn find_partno(&self, partno: u32) -> Result<&Partition> {
        let r = self
            .partitions
            .get(partno.checked_sub(1).expect("1 based partition offset") as usize)
            .ok_or_else(|| anyhow::anyhow!("Missing partition for index {partno}"))?;
        Ok(r)
    }
}

impl Partition {
    #[allow(dead_code)]
    pub fn path(&self) -> &Utf8Path {
        self.node.as_str().into()
    }
}

#[context("Listing partitions of {dev}")]
pub fn partitions_of(dev: &Utf8Path) -> Result<PartitionTable> {
    let o: SfDiskOutput = Command::new("sfdisk")
        .args(["-J", dev.as_str()])
        .run_and_parse_json()?;
    Ok(o.partitiontable)
}

pub struct LoopbackDevice {
    pub dev: Option<Utf8PathBuf>,
    // Handle to the cleanup helper process
    cleanup_handle: Option<LoopbackCleanupHandle>,
}

/// Handle to manage the cleanup helper process for loopback devices
struct LoopbackCleanupHandle {
    /// Process ID of the cleanup helper
    helper_pid: u32,
}

impl LoopbackDevice {
    // Create a new loopback block device targeting the provided file path.
    pub fn new(path: &Path) -> Result<Self> {
        let direct_io = match env::var("BOOTC_DIRECT_IO") {
            Ok(val) => {
                if val == "on" {
                    "on"
                } else {
                    "off"
                }
            }
            Err(_e) => "off",
        };

        let dev = Command::new("losetup")
            .args([
                "--show",
                format!("--direct-io={direct_io}").as_str(),
                "-P",
                "--find",
            ])
            .arg(path)
            .run_get_string()?;
        let dev = Utf8PathBuf::from(dev.trim());
        tracing::debug!("Allocated loopback {dev}");

        // Try to spawn cleanup helper process - if it fails, continue without it
        let cleanup_handle = Self::spawn_cleanup_helper(dev.as_str())
            .map_err(|e| {
                tracing::warn!("Failed to spawn loopback cleanup helper: {}, continuing without signal protection", e);
                e
            })
            .ok();

        Ok(Self {
            dev: Some(dev),
            cleanup_handle,
        })
    }

    // Access the path to the loopback block device.
    pub fn path(&self) -> &Utf8Path {
        // SAFETY: The option cannot be destructured until we are dropped
        self.dev.as_deref().unwrap()
    }

    /// Spawn a cleanup helper process that will clean up the loopback device
    /// if the parent process dies unexpectedly
    fn spawn_cleanup_helper(device_path: &str) -> Result<LoopbackCleanupHandle> {
        use std::os::unix::process::CommandExt;
        use std::process::Command;

        // Get the path to our own executable
        let self_exe = std::fs::read_link("/proc/self/exe")
            .context("Failed to read /proc/self/exe")?;

        // Create the helper process using exec
        let mut cmd = Command::new(self_exe);
        cmd.args([
            "loopback-cleanup-helper",
            "--device",
            device_path,
            "--parent-pid",
            &std::process::id().to_string(),
        ]);

        // Set environment variable to indicate this is a cleanup helper
        cmd.env("BOOTC_LOOPBACK_CLEANUP_HELPER", "1");

        // Spawn the process
        let child = cmd.spawn()
            .context("Failed to spawn loopback cleanup helper")?;

        Ok(LoopbackCleanupHandle {
            helper_pid: child.id(),
        })
    }

    // Shared backend for our `close` and `drop` implementations.
    fn impl_close(&mut self) -> Result<()> {
        // SAFETY: This is the only place we take the option
        let Some(dev) = self.dev.take() else {
            tracing::trace!("loopback device already deallocated");
            return Ok(());
        };

        // Kill the cleanup helper since we're cleaning up normally
        if let Some(cleanup_handle) = self.cleanup_handle.take() {
            // Kill the helper process since we're doing normal cleanup
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &cleanup_handle.helper_pid.to_string()])
                .output();
        }

        Command::new("losetup").args(["-d", dev.as_str()]).run()
    }

    /// Consume this device, unmounting it.
    pub fn close(mut self) -> Result<()> {
        self.impl_close()
    }
}

impl Drop for LoopbackDevice {
    fn drop(&mut self) {
        // Best effort to unmount if we're dropped without invoking `close`
        let _ = self.impl_close();
    }
}

/// Main function for the loopback cleanup helper process
/// This function does not return - it either exits normally or via signal
pub fn run_loopback_cleanup_helper(device_path: &str, parent_pid: u32) -> Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    // Check if we're running as a cleanup helper
    if std::env::var("BOOTC_LOOPBACK_CLEANUP_HELPER").is_err() {
        anyhow::bail!("This function should only be called as a cleanup helper");
    }

    // Close stdin, stdout, stderr and redirect to /dev/null
    let null_fd = std::fs::File::open("/dev/null")?;
    let null_fd = null_fd.as_raw_fd();
    unsafe {
        libc::dup2(null_fd, 0);
        libc::dup2(null_fd, 1);
        libc::dup2(null_fd, 2);
    }
    
    // Set up death signal notification - we want to be notified when parent dies
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGUSR1) != 0 {
            std::process::exit(1);
        }
    }

    // Mask most signals to avoid being killed accidentally
    // But leave SIGUSR1 unmasked so we can receive the death notification
    unsafe {
        let mut sigset: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut sigset);
        // Don't mask SIGKILL, SIGSTOP (can't be masked anyway), or our death signal
        libc::sigdelset(&mut sigset, libc::SIGKILL);
        libc::sigdelset(&mut sigset, libc::SIGSTOP);
        libc::sigdelset(&mut sigset, libc::SIGUSR1); // We'll use SIGUSR1 as our death signal

        if libc::pthread_sigmask(libc::SIG_SETMASK, &sigset, std::ptr::null_mut()) != 0 {
            let err = std::io::Error::last_os_error();
            tracing::error!("pthread_sigmask failed: {}", err);
            std::process::exit(1);
        }
    }

    // Wait for death signal or normal termination
    let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let sigset = {
        let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut sigset);
            libc::sigaddset(&mut sigset, libc::SIGUSR1);
            libc::sigaddset(&mut sigset, libc::SIGTERM); // Also listen for SIGTERM (normal cleanup)
        }
        sigset
    };

    // Wait for a signal
    let result = unsafe {
        let result = libc::sigwaitinfo(&sigset, &mut siginfo);
        if result == -1 {
            let err = std::io::Error::last_os_error();
            tracing::error!("sigwaitinfo failed: {}", err);
            std::process::exit(1);
        }
        result
    };

    if result > 0 {
        if siginfo.si_signo == libc::SIGUSR1 {
            // Parent died unexpectedly, clean up the loopback device
            let status = std::process::Command::new("losetup")
                .args(["-d", device_path])
                .status();

            match status {
                Ok(exit_status) if exit_status.success() => {
                    // Write to stderr since we closed stdout
                    let _ = std::io::Write::write_all(
                        &mut std::io::stderr(),
                        format!("bootc: cleaned up leaked loopback device {}\n", device_path)
                            .as_bytes(),
                    );
                    std::process::exit(0);
                }
                Ok(_) => {
                    let _ = std::io::Write::write_all(
                        &mut std::io::stderr(),
                        format!(
                            "bootc: failed to clean up loopback device {}\n",
                            device_path
                        )
                        .as_bytes(),
                    );
                    std::process::exit(1);
                }
                Err(e) => {
                    let _ = std::io::Write::write_all(
                        &mut std::io::stderr(),
                        format!(
                            "bootc: error cleaning up loopback device {}: {}\n",
                            device_path, e
                        )
                        .as_bytes(),
                    );
                    std::process::exit(1);
                }
            }
        } else if siginfo.si_signo == libc::SIGTERM {
            // Normal cleanup signal from parent
            std::process::exit(0);
        }
    }

    // If we get here, something went wrong
    std::process::exit(1);
}

/// Parse key-value pairs from lsblk --pairs.
/// Newer versions of lsblk support JSON but the one in CentOS 7 doesn't.
fn split_lsblk_line(line: &str) -> HashMap<String, String> {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = REGEX.get_or_init(|| Regex::new(r#"([A-Z-_]+)="([^"]+)""#).unwrap());
    let mut fields: HashMap<String, String> = HashMap::new();
    for cap in regex.captures_iter(line) {
        fields.insert(cap[1].to_string(), cap[2].to_string());
    }
    fields
}

/// This is a bit fuzzy, but... this function will return every block device in the parent
/// hierarchy of `device` capable of containing other partitions. So e.g. parent devices of type
/// "part" doesn't match, but "disk" and "mpath" does.
pub fn find_parent_devices(device: &str) -> Result<Vec<String>> {
    let output = Command::new("lsblk")
        // Older lsblk, e.g. in CentOS 7.6, doesn't support PATH, but --paths option
        .arg("--pairs")
        .arg("--paths")
        .arg("--inverse")
        .arg("--output")
        .arg("NAME,TYPE")
        .arg(device)
        .run_get_string()?;
    let mut parents = Vec::new();
    // skip first line, which is the device itself
    for line in output.lines().skip(1) {
        let dev = split_lsblk_line(line);
        let name = dev
            .get("NAME")
            .with_context(|| format!("device in hierarchy of {device} missing NAME"))?;
        let kind = dev
            .get("TYPE")
            .with_context(|| format!("device in hierarchy of {device} missing TYPE"))?;
        if kind == "disk" || kind == "loop" {
            parents.push(name.clone());
        } else if kind == "mpath" {
            parents.push(name.clone());
            // we don't need to know what disks back the multipath
            break;
        }
    }
    Ok(parents)
}

/// Parse a string into mibibytes
pub fn parse_size_mib(mut s: &str) -> Result<u64> {
    let suffixes = [
        ("MiB", 1u64),
        ("M", 1u64),
        ("GiB", 1024),
        ("G", 1024),
        ("TiB", 1024 * 1024),
        ("T", 1024 * 1024),
    ];
    let mut mul = 1u64;
    for (suffix, imul) in suffixes {
        if let Some((sv, rest)) = s.rsplit_once(suffix) {
            if !rest.is_empty() {
                anyhow::bail!("Trailing text after size: {rest}");
            }
            s = sv;
            mul = imul;
        }
    }
    let v = s.parse::<u64>()?;
    Ok(v * mul)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::io::AsRawFd;
    use tempfile::NamedTempFile;

    #[test]
    fn test_loopback_cleanup_helper_spawn() {
        // Test that we can spawn the cleanup helper process
        // This test doesn't require root privileges and just verifies the spawn mechanism works
        
        // Create a temporary file to use as the "device"
        let temp_file = NamedTempFile::new().unwrap();
        let device_path = temp_file.path().to_string_lossy().to_string();
        
        // Try to spawn the cleanup helper
        let result = LoopbackDevice::spawn_cleanup_helper(&device_path);
        
        // The spawn should succeed (though the helper will exit quickly since parent doesn't exist)
        assert!(result.is_ok());
        
        // Clean up the temp file
        drop(temp_file);
    }

    #[test]
    fn test_parse_lsblk() {
        let data = fs::read_to_string("tests/fixtures/lsblk.json").unwrap();
        let devices: DevicesOutput = serde_json::from_str(&data).unwrap();
        assert_eq!(devices.blockdevices.len(), 1);
        let device = &devices.blockdevices[0];
        assert_eq!(device.name, "vda");
        assert_eq!(device.size, 10737418240);
        assert_eq!(device.children.as_ref().unwrap().len(), 3);
        let child = &device.children.as_ref().unwrap()[0];
        assert_eq!(child.name, "vda1");
        assert_eq!(child.size, 1048576);
    }
}
