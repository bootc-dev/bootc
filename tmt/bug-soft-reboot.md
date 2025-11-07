# TMT soft-reboot limitation

TMT does not currently support systemd soft-reboots. It detects reboots by checking
if the `/proc/stat` btime (boot time) field changes, which does not happen during
a systemd soft-reboot.

See: <https://github.com/teemtee/tmt/issues/3143>

Note: This same issue affects Testing Farm as documented in `plans/integration.fmf`
where `test-27-custom-selinux-policy` is disabled for Packit (AWS) testing.

## Impact on bootc testing

This means that when testing `bootc switch --soft-reboot=auto` or `bootc upgrade --soft-reboot=auto`:

1. The bootc commands will correctly prepare for a soft-reboot (staging the deployment in `/run/nextroot`)
2. However, TMT cannot detect or properly handle the soft-reboot
3. Tests must explicitly reset the soft-reboot preparation before calling `tmt-reboot`

## Workaround

After calling bootc with `--soft-reboot=auto`, use:

```nushell
ostree admin prepare-soft-reboot --reset
tmt-reboot
```

This forces a full reboot instead of a soft-reboot, which TMT can properly detect.

## Testing environments

- **testcloud**: Accidentally worked because libvirt forced a full VM power cycle, overriding systemd's soft-reboot attempt
- **bcvk**: Exposes the real issue because it allows actual systemd soft-reboots
- **Production (AWS, bare metal, etc.)**: Not affected - TMT is purely a testing framework; soft-reboots work correctly in production
