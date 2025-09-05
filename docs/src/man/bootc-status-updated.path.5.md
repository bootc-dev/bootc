% bootc-status-updated.path(8)

# NAME

bootc-status-updated.path

# DESCRIPTION

This unit watches the `bootc` root directory (/ostree/bootc) for
modification, and triggers the companion `bootc-status-updated.target`
systemd unit.

The `bootc` program updates the mtime on its root directory when the
contents of `bootc status` changes as a result of an
update/upgrade/edit/switch/rollback operation.

# SEE ALSO

**bootc**(1), **bootc-status-updated.target**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
