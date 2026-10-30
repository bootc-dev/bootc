# NAME

bootc-composefs-finalize-staged - Finalize a staged composefs deployment

# SYNOPSIS

**bootc composefs-finalize-staged** \[*OPTIONS...*\]

# DESCRIPTION

Finalize a staged composefs deployment. This is an internal command
invoked at shutdown by **bootc-finalize-staged.service**; it is not
intended to be run directly.

When `bootc upgrade` or `bootc switch` stages a new deployment on a
composefs system, it starts **bootc-finalize-staged.service**, whose
`ExecStop` runs this command as the system shuts down. It merges the
current `/etc` into the staged deployment and updates the bootloader
configuration so that the next boot uses it. If no deployment is
staged, it does nothing. It fails on systems using the ostree
backend, where **ostree-finalize-staged.service** does this instead.

The finalize service also pulls in
**bootc-finalize-staged-hold.service**, which runs this command with
`--hold` to keep `/boot` open while a deployment is staged. Otherwise
an automounted `/boot` (such as the ESP set up by
**systemd-gpt-auto-generator**(8)) could expire while idle, and then
either deadlock with shutdown or be unavailable when finalization
runs.

# OPTIONS

**--hold**

    Hold /boot open until terminated, instead of finalizing

# EXAMPLES

Check whether a staged deployment is waiting to be finalized at the
next shutdown:

    systemctl status bootc-finalize-staged.service bootc-finalize-staged-hold.service

# SEE ALSO

**bootc**(8), **bootc-upgrade**(8), **bootc-switch**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
