use std::process::Command;
use std::sync::OnceLock;

pub(crate) const DEFAULT_UNPRIVILEGED_USER: &str = "nobody";

/// Checks if the current process is (apparently at least)
/// running under systemd.  We use this in various places
/// to e.g. log to the journal instead of printing to stdout.
pub(crate) fn running_in_systemd() -> bool {
    static RUNNING_IN_SYSTEMD: OnceLock<bool> = OnceLock::new();
    *RUNNING_IN_SYSTEMD.get_or_init(|| {
        // See https://www.freedesktop.org/software/systemd/man/systemd.exec.html#%24INVOCATION_ID
        std::env::var_os("INVOCATION_ID")
            .filter(|s| !s.is_empty())
            .is_some()
    })
}

/// Return a prepared subprocess configuration that will run as an unprivileged user if possible.
///
/// This currently only drops privileges when run under systemd with DynamicUser.
///
/// If `keep_dac_read_search` is true, the CAP_DAC_READ_SEARCH capability is retained.
/// This is needed when passing file descriptors via /proc/self/fd that the subprocess
/// needs to re-open (e.g., auth files for skopeo).
pub(crate) fn unprivileged_subprocess(
    binary: &str,
    user: &str,
    keep_dac_read_search: bool,
) -> Command {
    // TODO: if we detect we're running in a container as uid 0, perhaps at least switch to the
    // "bin" user if we can?
    if !running_in_systemd() {
        return Command::new(binary);
    }
    let mut cmd = Command::new("setpriv");
    // Clear some strategic environment variables that may cause the containers/image stack
    // to look in the wrong places for things.
    cmd.env_remove("HOME");
    cmd.env_remove("XDG_DATA_DIR");
    cmd.env_remove("USER");

    // Determine which capabilities to keep
    let cap_set = if keep_dac_read_search {
        "-all,+dac_read_search"
    } else {
        "-all"
    };

    cmd.args([
        "--no-new-privs",
        "--init-groups",
        "--reuid",
        user,
        "--bounding-set",
        cap_set,
        "--pdeathsig",
        "TERM",
        "--",
        binary,
    ]);
    cmd
}
