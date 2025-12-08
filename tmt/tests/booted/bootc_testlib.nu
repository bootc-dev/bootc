# A simple nushell "library" for the

# This is a workaround for what must be a systemd bug
# that seems to have appeared in C10S
# TODO diagnose and fill in here
export def reboot [] {
    # Sometimes systemd daemons are still running old binaries and response "Access denied" when send reboot request
    # Force a full sync before reboot
    sync
    # Allow more delay for bootc to settle
    sleep 30sec

    tmt-reboot
}

# True if we're running in bcvk with `--bind-storage-ro` and
# we can expect to be able to pull container images from the host.
# See xtask.rs
export def have_hostexports [] {
    $env.BCVK_EXPORT? == "1"
}

# Parse the kernel commandline into a list.
# This is not a proper parser, but good enough
# for what we need here.
export def parse_cmdline []  {
    open /proc/cmdline | str trim | split row " "
}
