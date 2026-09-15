# number: 49
# tmt:
#   summary: Test the bootc 1.16 composefs UKI bridge
#   duration: 45m
#   enabled: false
#   adjust:
#     - when: composefs_bridge == true
#       enabled: true
# extra:
#   skip_if_ostree: true
#   try_bind_storage: true

# This deliberately starts disabled.  The bridge fixtures are large and are
# supplied from the host's read-only containers-storage mount only on request.
use std assert
use tap.nu

def bridge-image [] {
    let image = ($env.BOOTC_bridge_image? | default "")
    if $image == "" {
        error make { msg: "BOOTC_bridge_image is required; run with --bridge-image and --bind-storage-ro" }
    }
    $image
}

def upgrade-image [] {
    let image = ($env.BOOTC_upgrade_image? | default "")
    if $image == "" {
        error make { msg: "BOOTC_upgrade_image is required for old-stager mode" }
    }
    $image
}

def mode [] {
    let mode = ($env.BOOTC_composefs_bridge_mode? | default "")
    if not ($mode in ["old-stager" "old-initramfs"]) {
        error make { msg: "BOOTC_composefs_bridge_mode must be old-stager or old-initramfs" }
    }
    $mode
}

def cmdline [] { open /proc/cmdline | str trim | split row " " }

def required-old-bootc-sha256 [] {
    let checksum = ($env.BOOTC_1160_bootc_sha256? | default "")
    if ($checksum | str length) != 64 {
        error make { msg: "BOOTC_1160_bootc_sha256 must be the required 64-character fixture checksum" }
    }
    $checksum | str downcase
}

def assert-old-fixture [] {
    let version = (bootc --version | str trim)
    assert equal $version "bootc 1.16.0"
    let rpm_version = (rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' bootc | str trim)
    let binary_sha256 = (sha256sum /usr/bin/bootc | split row " " | first | str downcase)
    assert equal $binary_sha256 (required-old-bootc-sha256)
    { bootc_version: $version, rpm_version: $rpm_version, bootc_sha256: $binary_sha256 }
        | to json
        | save --force /var/composefs-1-16-bootc-proof.json
    print $"bootc 1.16 fixture proof: version=($version) rpm=($rpm_version) sha256=($binary_sha256)"
}

def assert-booted-image [expected: string] {
    let st = bootc status --json | from json
    let booted = $st.status.booted.image
    assert equal $booted.image.transport "containers-storage"
    assert equal $booted.image.image $expected
}

# Verify the identity actually selected by the running initramfs, as well as
# the corresponding repository image and deployment state directory.
def assert-selected-format [format: string, expect_dual: bool] {
    if not ($format in ["v1" "v2"]) {
        error make { msg: $"Unsupported expected composefs format: ($format)" }
    }
    let st = bootc status --json | from json
    assert ((($st.status.booted.composefs.bootType | into string | str downcase) == "uki"))
    let selected = $st.status.booted.composefs.verity
    assert equal ($selected | str length) 128

    let root = findmnt --json --mountpoint / --output SOURCE | from json
    let root_source = ($root.filesystems | first | get source | into string)
    assert ($root_source | str starts-with "composefs:") "normal bridge boots must mount / directly from composefs"
    assert equal $root_source $"composefs:($selected)"

    let params = cmdline
    let v2_params = ($params | where { |p| $p | into string | str starts-with "composefs=" })
    assert (($v2_params | length) == 1) "UKI must contain one V2 fallback argument"
    let v2_value = ($v2_params | first | str replace "composefs=" "" | into string)
    let v2 = ($v2_value | str replace "?" "")
    let v1_params = ($params | where { |p| $p | into string | str starts-with "composefs.digest=" })
    let v1 = if $expect_dual {
        assert (($v1_params | length) == 1) "current automatic UKI must retain one V1 argument"
        let v1_value = ($v1_params | first | str replace "composefs.digest=" "" | into string)
        let v1_value = ($v1_value | str replace "?" "")
        let parsed_v1 = ($v1_value | split row ":" | last)
        assert ($parsed_v1 != $v2) "dual-format UKI must contain distinct V1 and V2 identities"
        $parsed_v1
    } else {
        assert (($v1_params | length) == 0) "old automatic UKI must be V2-only"
        ""
    }

    let expected = if $format == "v1" { $v1 } else { $v2 }
    assert equal $expected $selected "selected UKI identity must match bootc status"
    assert ($"/sysroot/composefs/images/($selected)" | path exists) "selected composefs image must exist"
    assert ($"/sysroot/state/deploy/($selected)" | path exists) "selected deployment state must exist"
    { selected: $selected, v1: $v1, v2: $v2 }
}

def write-sentinels [] {
    "composefs-1-16-bridge-etc" | save --force /etc/bootc-composefs-bridge-sentinel
    "composefs-1-16-bridge-var" | save --force /var/lib/bootc-composefs-bridge-sentinel
}

def assert-sentinels [] {
    assert equal (open /etc/bootc-composefs-bridge-sentinel | str trim) "composefs-1-16-bridge-etc"
    assert equal (open /var/lib/bootc-composefs-bridge-sentinel | str trim) "composefs-1-16-bridge-var"
}

def stage [image: string, save_as: string] {
    bootc switch --transport containers-storage $image
    let staged = (bootc status --json | from json).status.staged
    let staged_image = $staged.image
    assert equal $staged_image.image.transport "containers-storage"
    assert equal $staged_image.image.image $image
    assert (($staged.composefs.verity | str length) == 128)
    assert ("/run/composefs/staged-deployment" | path exists) "staging must create transient composefs deployment state"
    $staged.composefs.verity | save --force $save_as
}

def old_stager_boot0 [] {
    tap begin "bootc 1.16 stager to current dual-UKI bridge"
    assert-old-fixture
    write-sentinels
    stage (bridge-image) /var/composefs-bridge-v2-identity
    tmt-reboot
}

def old_stager_boot1 [] {
    assert-booted-image (bridge-image)
    assert (not ((bootc --version) | str starts-with "bootc 1.16.0")) "bridge userspace must be current"
    let identity = assert-selected-format v2 true
    assert equal $identity.selected (open /var/composefs-bridge-v2-identity | str trim)
    assert (not ($"/sysroot/composefs/images/($identity.v1)" | path exists)) "the old-initramfs first hop must not materialize the V1 image"
    assert-sentinels
    stage (upgrade-image) /var/composefs-bridge-v1-identity
    tmt-reboot
}

def old_stager_boot2 [] {
    assert-booted-image (upgrade-image)
    assert (not ((bootc --version) | str starts-with "bootc 1.16.0")) "upgraded userspace must be current"
    let identity = assert-selected-format v1 true
    assert equal $identity.selected (open /var/composefs-bridge-v1-identity | str trim)
    assert-sentinels
    bootc rollback
    assert equal ((bootc status --json | from json).status.rollbackQueued) true
    tmt-reboot
}

def old_stager_boot3 [] {
    assert-booted-image (bridge-image)
    let identity = assert-selected-format v2 true
    assert equal $identity.selected (open /var/composefs-bridge-v2-identity | str trim)
    assert-sentinels
    assert equal ((bootc status --json | from json).status.rollbackQueued) false
    bootc internals composefs-gc --assert-no-op
    tap ok
}

def old_initramfs_boot0 [] {
    tap begin "current stager to old-initramfs V2-only UKI"
    assert (not ((bootc --version) | str starts-with "bootc 1.16.0")) "the V2-only fixture must retain current userspace"
    assert-selected-format v1 true | ignore
    write-sentinels
    stage (bridge-image) /var/composefs-old-initramfs-v2-identity
    tmt-reboot
}

def old_initramfs_boot1 [] {
    assert-booted-image (bridge-image)
    assert (not ((bootc --version) | str starts-with "bootc 1.16.0")) "the V2-only fixture must retain current userspace"
    let identity = assert-selected-format v2 false
    assert equal $identity.selected (open /var/composefs-old-initramfs-v2-identity | str trim)
    assert-sentinels
    tap ok
}

def main [] {
    match [ (mode) ($env.TMT_REBOOT_COUNT? | default "0") ] {
        ["old-stager" "0"] => old_stager_boot0,
        ["old-stager" "1"] => old_stager_boot1,
        ["old-stager" "2"] => old_stager_boot2,
        ["old-stager" "3"] => old_stager_boot3,
        ["old-initramfs" "0"] => old_initramfs_boot0,
        ["old-initramfs" "1"] => old_initramfs_boot1,
        [$selected_mode $count] => { error make { msg: $"Invalid bridge mode/reboot count: ($selected_mode)/($count)" } },
    }
}
