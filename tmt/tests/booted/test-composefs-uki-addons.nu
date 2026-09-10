# number: 49
# tmt:
#   summary: Test composefs UKI Addons
#   duration: 30m
# extra:
#   skip_if_ostree: true


use std assert
use tap.nu

bootc status
let st = bootc status --json | from json
let booted = $st.status.booted.image

let is_uki = (($st.status.booted.composefs.bootType | str downcase) == "uki")

if not $is_uki {
    exit 0
}

def first_boot [] {
    bootc image copy-to-storage

    mut containerfile = $"
        FROM localhost/bootc as base
        RUN touch /usr/share/first
    "

    let cmds = "
      ukify build --cmdline 'johan=liebert' --output /out/${kver}.efi.extra.d/monster-cmdline.addon.efi
      mkdir -p '/out/loader/addons'
      ukify build --cmdline 'kenzo=tenma' --output /out/loader/addons/global-cmdline.addon.efi
    "

    $containerfile = (tap make_uki_containerfile $containerfile --addon-cmds $cmds)

    echo $containerfile | podman build -t localhost/bootc-uki-addons . -f -

    # No addons should be included
    bootc switch --transport containers-storage localhost/bootc-uki-addons

    tmt-reboot
}

def second_boot [] {
    mkdir /var/tmp/efi
    mount /dev/disk/by-partlabel/EFI-SYSTEM /var/tmp/efi

    # Make sure no addons were included
    assert ((^find /var/tmp/efi -type f -name '*addon.efi' | ^wc -l | str trim | into int) == 0)

    mut containerfile = $"
        FROM localhost/bootc as base
        RUN touch /usr/share/second
    "

    let cmds = "
      mkdir -p /out/${kver}.efi.extra.d
      ukify build --cmdline 'johan=liebert' --output /out/${kver}.efi.extra.d/monster-cmdline.addon.efi
      mkdir -p '/out/loader/addons'
      ukify build --cmdline 'kenzo=tenma' --output /out/loader/addons/global-cmdline.addon.efi
    "

    $containerfile = (tap make_uki_containerfile $containerfile --addon-cmds $cmds)

    echo $containerfile | podman build -t localhost/bootc-uki-addons-2 . -f -

    # Include two addons
    bootc switch --transport containers-storage --uki-addon monster-cmdline --global-uki-addon global-cmdline localhost/bootc-uki-addons-2

    tmt-reboot
}


def third_boot [] {
    mkdir /var/tmp/efi
    mount /dev/disk/by-partlabel/EFI-SYSTEM /var/tmp/efi

    # We should have two addons
    assert ((^find /var/tmp/efi -type f -name '*addon.efi' | ^wc -l | str trim | into int) == 2)

    # We should have those in the cmdline
    assert (open /proc/cmdline | str contains "johan=liebert")
    assert (open /proc/cmdline | str contains "kenzo=tenma")

    mut containerfile = $"
        FROM localhost/bootc as base
        RUN touch /usr/share/third
    "

    let cmds = "
      mkdir -p /out/${kver}.efi.extra.d
      ukify build --cmdline 'berserk=guts' --output /out/${kver}.efi.extra.d/berserk-cmdline.addon.efi
      mkdir -p '/out/loader/addons'
      ukify build --cmdline 'pink=floyd' --output /out/loader/addons/global-cmdline.addon.efi
    "

    $containerfile = (tap make_uki_containerfile $containerfile --addon-cmds $cmds)

    echo $containerfile | podman build -t localhost/bootc-uki-addons-3 . -f -

    # This should update the global cmdline because we have the same name
    bootc switch --transport containers-storage --uki-addon berserk-cmdline localhost/bootc-uki-addons-3

    tmt-reboot
}

def fourth_boot [] {
    mkdir /var/tmp/efi
    mount /dev/disk/by-partlabel/EFI-SYSTEM /var/tmp/efi

    # We should have three addons
    # One from the previous deployment
    # One global addon and one from the current deployment
    assert ((^find /var/tmp/efi -type f -name '*addon.efi' | ^wc -l | str trim | into int) == 3)

    # Addon should be present, but not for this deployment
    assert (not (open /proc/cmdline | str contains "johan=liebert"))
    # Global addon should've been updated
    assert (not (open /proc/cmdline | str contains "kenzo=tenma"))

    assert (open /proc/cmdline | str contains "berserk=guts")
    # Global addon should've been updated
    assert (open /proc/cmdline | str contains "pink=floyd")

    # --- CLI tests ---

    # list --json should return 3 addons
    let addons = bootc uki-addon list --json | from json
    assert (($addons | length) == 3)

    # Verify the global addon is present
    let globals = $addons | where addon_type.type == "global"
    assert (($globals | length) == 1)
    assert ($globals.0.name == "global-cmdline")

    # Verify we have two scoped addons
    let scoped = $addons | where addon_type.type == "scoped"
    assert (($scoped | length) == 2)

    # Human-readable list should not error
    bootc uki-addon list

    # Remove the global addon
    bootc uki-addon remove global-cmdline
    let addons_after_remove = bootc uki-addon list --json | from json
    assert (($addons_after_remove | length) == 2)
    let globals_after = $addons_after_remove | where addon_type.type == "global"
    assert (($globals_after | length) == 0)

    # Add it back from the booted image
    bootc uki-addon add global-cmdline global
    let addons_after_add = bootc uki-addon list --json | from json
    assert (($addons_after_add | length) == 3)
    let globals_readded = $addons_after_add | where addon_type.type == "global"
    assert (($globals_readded | length) == 1)
    assert ($globals_readded.0.name == "global-cmdline")

    # Adding the same addon again should be a no-op
    bootc uki-addon add global-cmdline global

    # Remove a scoped addon from the old deployment
    let old_scoped = $scoped | where name == "monster-cmdline"
    assert (($old_scoped | length) == 1)
    let old_depl_id = $old_scoped.0.addon_type.depl_id
    bootc uki-addon remove monster-cmdline $old_depl_id
    let addons_final = bootc uki-addon list --json | from json
    assert (($addons_final | length) == 2)

    # Removing a non-existent addon should fail
    let failed = (do { bootc uki-addon remove nonexistent-addon } | complete)
    assert ($failed.exit_code != 0)

    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        "2" => third_boot,
        "3" => fourth_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
