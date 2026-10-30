# number: 48
# tmt:
#   summary: Test composefs UKI dumpfile diff print
#   duration: 30m
# extra:
#   skip_if_ostree: true

use std assert
use tap.nu

# bootc status
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
        RUN touch /usr/share/accepted-file
    "

    $containerfile = (tap make_uki_containerfile $containerfile)

    $containerfile += "
        RUN touch /usr/share/new-file
    "

    echo $containerfile | podman build -t localhost/dump-diff . -f -

    let result = do { bootc switch --transport containers-storage localhost/dump-diff } | complete

    assert ($result.exit_code != 0) "bootc switch should fail"

    print ($result.stderr)

    assert ($result.stderr | str contains "embedded composefs= digest") "Expected an embedded composefs digest mismatch in stderr"
    assert ($result.stderr | str contains "doesn't match any") "Expected no compatible composefs image in stderr"
    assert ($result.stderr | str contains "/usr/share/new-file") $"Expected '/usr/share/new-file' in stderr"

    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
