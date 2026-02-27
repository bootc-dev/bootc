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

    let id = $os.ID
    let version_id = $os.VERSION_ID

    # Construct the key for os-image-map.json
    let key = if $id == "centos" {
        # CentOS uses "centos-9" or "centos-10" format
        $"centos-($version_id)"
    } else if $id == "fedora" {
        $"fedora-($version_id)"
    } else if $id == "rhel" {
        # RHEL uses "rhel-9.8" or "rhel-10.2" format
        $"rhel-($version_id)"
    } else {
        # Fallback to centos-9 for unknown distros
        "centos-9"
    }

    # Load the os-image-map.json - try multiple possible locations
    let possible_paths = [
        "hack/os-image-map.json",
        "../../../hack/os-image-map.json",
        "/var/home/bootc/hack/os-image-map.json"
    ]

    mut image_map = null
    for p in $possible_paths {
        if ($p | path exists) {
            $image_map = (open $p)
            break
        }
    }

    # If map not found, use default centos-9 image
    if ($image_map == null) {
        return "docker://quay.io/centos-bootc/centos-bootc:stream9"
    }

    let image = $image_map.base | get -i $key
    if ($image | is-empty) {
        # Fallback to centos-9 if key not found
        $"docker://($image_map.base.centos-9)"
    } else {
        $"docker://($image)"
    }
}
