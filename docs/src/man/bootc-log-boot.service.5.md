# NAME

bootc-log-boot.service

# DESCRIPTION

This systemd service writes one journal entry on every boot that records
which container image the system booted. It gives an audit trail of the
booted image even on systems that are installed once and never updated.

The entry has `MESSAGE_ID=66797517e29842bfa048064146ec92c2` and these
fields:

- `BOOTC_BACKEND`: the storage backend; currently always `composefs`
- `BOOTC_DEPLOYMENT`: the deployment identifier; for composefs, the
  fs-verity digest of the root image
- `BOOTC_IMAGE`: the container image reference
- `BOOTC_TRANSPORT`: the transport of the image reference, e.g. `registry`
- `BOOTC_MANIFEST_DIGEST`: the digest of the image manifest
- `BOOTC_ARCHITECTURE`: the architecture of the image
- `BOOTC_VERSION`: the image version, when the image has one
- `BOOTC_TIMESTAMP`: the image build timestamp in RFC 3339 format, when
  the image has one

The image fields are omitted if the booted deployment was not created
from a container image.

To list the images this system booted, newest first:

```
journalctl -r MESSAGE_ID=66797517e29842bfa048064146ec92c2
```

To find the first boot of a deployment, filter on its identifier and take
the oldest entry:

```
journalctl -o json MESSAGE_ID=66797517e29842bfa048064146ec92c2 BOOTC_DEPLOYMENT=<id> | head -n 1
```

The service reads only the deployment's state under `/sysroot` and the
image in the composefs repository. Unlike **bootc-status**(8), it does not
mount the ESP or modify boot entries.

The record survives only as long as the journal keeps it. Configure
persistent journal storage and retention to fit your audit requirements.

The bootc systemd generator enables this service on composefs boots
only.

# SEE ALSO

**bootc**(8), **bootc-status**(8), **journalctl**(1), **journald.conf**(5)

# VERSION

<!-- VERSION PLACEHOLDER -->
