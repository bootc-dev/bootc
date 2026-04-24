# NAME

bootc-finalize-staged.service

# DESCRIPTION

This service finalizes a staged composefs deployment at shutdown, making
it active for the next boot. It is the composefs equivalent of
`ostree-finalize-staged.service`.

The service runs as `ExecStop=/usr/bin/bootc composefs-finalize-staged`,
meaning finalization happens during the shutdown/reboot sequence. It is
started when `bootc upgrade` or `bootc switch` stages a new deployment.

The finalization process:

1. Reads the staged deployment record from `/run/composefs/staged-deployment`
   (a JSON file written during `bootc upgrade`/`switch`). If no staged
   deployment exists, the service exits successfully with no action.

2. If the staged deployment is marked download-only (from
   `bootc upgrade --download-only`), exits without finalizing.

3. Performs a three-way merge of `/etc`: the pristine `/etc` from the
   currently booted EROFS image, the running system's `/etc` (which may
   have local modifications), and the new deployment's `/etc`.

4. Atomically swaps the boot loader entries: `loader/entries.staged` is
   exchanged with `loader/entries` via a single `RENAME_EXCHANGE` syscall,
   then the old staged directory is removed. For UKI entries, the `.staged`
   suffix is removed from the UKI files on the ESP.

After finalization, the next boot uses the new deployment's boot entries.
If finalization fails, the old boot entries remain in place and the system
boots the previous deployment.

# DIAGNOSTICS

Check the journal for finalization results from the previous boot:

```
journalctl -u bootc-finalize-staged.service -b -1
```

There is not currently a `bootc-boot-complete.service` equivalent (unlike
the ostree backend's `ostree-boot-complete.service`). Monitoring the
journal is the recommended way to detect finalization failures.

# SEE ALSO

**bootc**(8), **bootc-upgrade**(8), **bootc-switch**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
