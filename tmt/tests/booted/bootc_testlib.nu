# A simple nushell "library" for the

# This is a workaround for what must be a systemd bug
# that seems to have appeared in C10S
# TODO diagnose and fill in here
export def reboot [] {
    # Allow more delay for bootc to settle
    sleep 120sec

    tmt-reboot
}

# True if we're running in bcvk with `--bind-storage-ro` and
# we can expect to be able to pull container images from the host.
# See xtask.rs
export def have_hostexports [] {
    $env.BCVK_EXPORT? == "1"
}
