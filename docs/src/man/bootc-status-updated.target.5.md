% bootc-status-updated.target(8)

# NAME

bootc-status-updated.target

# DESCRIPTION

This unit is triggered by the companion `bootc-status-updated.path`
systemd unit.  This target is intended to enable users to add custom
services to trigger as a result of `bootc status` changing.

Add the following to your unit configuration to active it when `bootc
status` changes:

```
[Install]
WantedBy=bootc-status-updated.target
```

# SEE ALSO

**bootc**(1), **bootc-status-updated.path**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
