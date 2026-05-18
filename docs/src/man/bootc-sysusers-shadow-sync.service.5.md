# NAME

bootc-sysusers-shadow-sync.service

# DESCRIPTION

This systemd service removes orphaned and duplicate entries from
`/etc/shadow` and `/etc/gshadow` before `systemd-sysusers.service` runs.

If users or groups are dropped out from pristine `/etc` or `/usr/lib`
copies of `passwd` or `group`, and they have systemd-sysusers entries,
it's possible that stale data in the shadow files will cause systemd-sysusers
to fail.

This service runs before systemd-sysusers.service, and trims stale
data.

The service is only enabled on ostree and composefs boots; it has no
effect on conventional package-managed systems.
# SEE ALSO

**bootc**(8), **bootc-systemd-generator**(8), **systemd-sysusers.service**(8), **lckpwdf**(3)

# VERSION

<!-- VERSION PLACEHOLDER -->
