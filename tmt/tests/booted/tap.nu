# A simple nushell "library" for the
# "Test anything protocol":
# https://testanything.org/tap-version-14-specification.html
export def begin [description] {
  print "TAP version 14"
  print $description
}

export def ok [] {
  print "ok"
}

export def fail [] {
  print "not ok"
}

export def is_composefs [] {
    let st = bootc status --json | from json
    $st.status.booted.composefs? != null
}

# Get the target image for install tests based on the running OS
# This ensures the target image matches the host OS to avoid version mismatches
# (e.g., XFS features created by newer mkfs.xfs not recognized by older grub2)
export def get_target_image [] {
    # Parse os-release to get ID and VERSION_ID
    let os = open /usr/lib/os-release
        | lines
        | filter {|l| $l != "" and not ($l | str starts-with "#") }
        | parse "{key}={value}"
        | reduce -f {} {|it, acc|
            $acc | upsert $it.key ($it.value | str trim -c '"')
        }

    let key = $"($os.ID)-($os.VERSION_ID)"

    # Load the os-image-map.json - installed location in image
    let map_path = "/usr/share/bootc/os-image-map.json"

    # If map not found, use default centos-9 image
    if not ($map_path | path exists) {
        return "docker://quay.io/centos-bootc/centos-bootc:stream9"
    }

    let image_map = (open $map_path)

    let image = $image_map.base | get -i $key
    if ($image | is-empty) {
        # Fallback to centos-9 if key not found
        $"docker://($image_map.base.centos-9)"
    } else {
        $"docker://($image)"
    }
}

# Run a bootc install command in an isolated mount namespace.
# This handles the common setup needed for install tests run outside a container.
# For ostree: masks off bootupd updates and /sysroot/ostree to reproduce
# https://github.com/bootc-dev/bootc/issues/1778
# For composefs: only removes bound images (bootupd metadata and boot
# binaries under /sysroot/ostree are needed for installation).
export def run_install [cmd: string] {
    let is_cfs = (is_composefs)
    let mask_cmds = if $is_cfs {
        "true"
    } else {
        "if test -d /sysroot/ostree; then mount --bind /usr/share/empty /sysroot/ostree; fi\nrm -vrf /usr/lib/bootupd/updates"
    }
    systemd-run -p MountFlags=slave -qdPG -- /bin/sh -c $"
set -xeuo pipefail
bootc usr-overlay
($mask_cmds)
rm -vrf /usr/lib/bootc/bound-images.d
($cmd)
"
}
