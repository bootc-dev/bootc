# NAME

bootc-container-inspect - Output JSON to stdout containing the container image metadata

# SYNOPSIS

bootc container inspect

# DESCRIPTION

Output JSON to stdout containing the container image metadata.

# OUTPUT

The command outputs a JSON object with the following fields:

- `kargs`: An array of kernel arguments embedded in the container image.
- `kernel`: An object containing kernel information (or `null` if no kernel is found):
  - `version`: The kernel version identifier. For vmlinuz kernels, this is derived from the `/usr/lib/modules/<version>` directory name (equivalent to `uname -r`). For UKI images, this is the UKI filename without the `.efi` extension - which should usually be the same as the uname.
  - `unified`: A boolean indicating whether the kernel is packaged as a UKI (Unified Kernel Image).

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**--rootfs**=*ROOTFS*

    Operate on the provided rootfs

    Default: /

**--json**

    Output in JSON format

**--format**=*FORMAT*

    The output format

    Possible values:
    - humanreadable
    - yaml
    - json

<!-- END GENERATED OPTIONS -->

# EXAMPLES

Inspect container image metadata:

    bootc container inspect

Example output (vmlinuz kernel):

```json
{
  "kargs": [
    "console=ttyS0",
    "quiet"
  ],
  "kernel": {
    "version": "6.12.0-0.rc6.51.fc42.x86_64",
    "unified": false
  }
}
```

Example output (UKI):

```json
{
  "kargs": [],
  "kernel": {
    "version": "7e11ac46e3e022053e7226a20104ac656bf72d1a",
    "unified": true
  }
}
```

# SEE ALSO

**bootc**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
