# number: 49
# tmt:
#   summary: Test bootc 1.16 old-stager migration for sealed and unsealed UKIs
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

def integrity-mode [] {
    let mode = ($env.BOOTC_composefs_bridge_integrity_mode? | default "")
    if not ($mode in ["sealed" "unsealed"]) {
        error make { msg: "BOOTC_composefs_bridge_integrity_mode must be sealed or unsealed" }
    }
    $mode
}

def assert-fixture-label [image: string, expected: string] {
    let label = (podman image inspect --format '{{ index .Config.Labels "bootc.test.fixture" }}' $image | str trim)
    assert equal $label $expected $"($image) has the wrong bridge fixture label"
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
def assert-selected-format [format: string] {
    if not ($format in ["v1" "v2"]) {
        error make { msg: $"Unsupported expected composefs format: ($format)" }
    }
    let st = bootc status --json | from json
    assert ((($st.status.booted.composefs.bootType | into string | str downcase) == "uki"))
    assert equal $st.status.booted.composefs.missingVerityAllowed ((integrity-mode) == "unsealed") "booted composefs policy must match the requested integrity mode"
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
    let v2_is_unsealed = ($v2_value | str starts-with "?")
    assert equal $v2_is_unsealed ((integrity-mode) == "unsealed") "UKI integrity marker must match the fixture mode"
    let v2 = ($v2_value | str replace --regex "^\\?" "")
    let v1_params = ($params | where { |p| $p | into string | str starts-with "composefs.digest=" })
    assert (($v1_params | length) == 1) "current automatic UKI must retain one V1 argument"
    let v1_value = ($v1_params | first | str replace "composefs.digest=" "" | into string)
    # The V1 compatibility argument has no insecure marker; the V2 argument
    # above is the UKI's authoritative integrity policy marker.
    let v1 = ($v1_value | split row ":" | last)
    assert ($v1 != $v2) "dual-format UKI must contain distinct V1 and V2 identities"

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
    tap begin $"bootc 1.16 stager to current dual-UKI bridge ((integrity-mode))"
    assert-old-fixture
    let initial = (bootc status --json | from json).status.booted.image.image.image
    assert-fixture-label $initial "bootc-1.16.0-stager"
    assert-fixture-label (bridge-image) $"current-dual-uki-((integrity-mode))"
    write-sentinels
    stage (bridge-image) /var/composefs-bridge-v2-identity
    tmt-reboot
}

def old_stager_boot1 [] {
    assert-booted-image (bridge-image)
    assert (not ((bootc --version) | str starts-with "bootc 1.16.0")) "bridge userspace must be current"
    let identity = assert-selected-format v2
    assert equal $identity.selected (open /var/composefs-bridge-v2-identity | str trim)
    assert-sentinels
    assert-fixture-label (upgrade-image) $"current-dual-uki-upgrade-((integrity-mode))"
    stage (upgrade-image) /var/composefs-bridge-v1-identity
    tmt-reboot
}

def old_stager_boot2 [] {
    assert-booted-image (upgrade-image)
    assert (not ((bootc --version) | str starts-with "bootc 1.16.0")) "upgraded userspace must be current"
    let identity = assert-selected-format v1
    assert equal $identity.selected (open /var/composefs-bridge-v1-identity | str trim)
    assert-sentinels
    bootc rollback
    assert equal ((bootc status --json | from json).status.rollbackQueued) true
    tmt-reboot
}

def old_stager_boot3 [] {
    assert-booted-image (bridge-image)
    let identity = assert-selected-format v2
    assert equal $identity.selected (open /var/composefs-bridge-v2-identity | str trim)
    assert-sentinels
    assert equal ((bootc status --json | from json).status.rollbackQueued) false
    bootc internals composefs-gc --assert-no-op
    tap ok
}

def main [] {
    match ($env.TMT_REBOOT_COUNT? | default "0") {
        "0" => old_stager_boot0,
        "1" => old_stager_boot1,
        "2" => old_stager_boot2,
        "3" => old_stager_boot3,
        $count => { error make { msg: $"Invalid bridge reboot count: ($count)" } },
    }
}
