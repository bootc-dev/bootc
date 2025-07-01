use anyhow::Result;
use fn_error_context::context;

/// The default root filesystem mount specification.
pub(crate) const ROOT: &str = "root=";
/// This is used by dracut.
pub(crate) const INITRD_ARG_PREFIX: &str = "rd.";
/// The kernel argument for configuring the rootfs flags.
pub(crate) const ROOTFLAGS: &str = "rootflags=";

/// Parse the kernel command line.  This is strictly
/// speaking not a correct parser, as the Linux kernel
/// supports quotes.  However, we don't yet need that here.
///
/// See systemd's code for one userspace parser.
#[context("Reading /proc/cmdline")]
pub(crate) fn parse_cmdline() -> Result<Vec<String>> {
    let cmdline = std::fs::read_to_string("/proc/cmdline")?;
    let r = cmdline
        .split_ascii_whitespace()
        .map(ToOwned::to_owned)
        .collect();
    Ok(r)
}

/// Return the value for the string in the vector which has the form target_key=value
pub(crate) fn find_first_cmdline_arg<'a>(
    args: impl Iterator<Item = &'a str>,
    target_key: &str,
) -> Option<&'a str> {
    args.filter_map(|arg| {
        if let Some((k, v)) = arg.split_once('=') {
            if target_key == k {
                return Some(v);
            }
        }
        None
    })
    .next()
}

/// Find the subset of kernel argumetns which describe how to mount the root filesystem.
pub(crate) fn root_args_from_cmdline<'a>(cmdline: &'a [&str]) -> Vec<&'a str> {
    cmdline
        .iter()
        .filter(|arg| {
            arg.starts_with(ROOT)
                || arg.starts_with(ROOTFLAGS)
                || arg.starts_with(INITRD_ARG_PREFIX)
        })
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_first() {
        let kargs = &["foo=bar", "root=/dev/vda", "blah", "root=/dev/other"];
        let kargs = || kargs.iter().copied();
        assert_eq!(find_first_cmdline_arg(kargs(), "root"), Some("/dev/vda"));
        assert_eq!(find_first_cmdline_arg(kargs(), "nonexistent"), None);
    }
}
