# number: 64
# tmt:
#   summary: Offline switch preserves the update origin and survives repeated requests
#   duration: 40m
#
use std assert
use tap.nu

const source = "localhost/target-imgref-source:v2"
const origin = "localhost/target-imgref:latest"
const next_origin = "localhost/target-imgref:redirected"
const archive = "/var/tmp/target-imgref-source.tar"
const marker = "/usr/share/testing-target-imgref"

def status [] { bootc status --json | from json }

def build_image [version: string, image: string] {
    let containerfile = $"FROM localhost/bootc as base\nRUN echo ($version) > ($marker)\n"
    (tap make_uki_containerfile $containerfile) | save --force Containerfile
    podman build -t $image -f Containerfile .
}

def stage [] {
    bootc switch --download-only --transport containers-storage --target-imgref $"containers-storage:($origin)" $source
}

def first_boot [] {
    tap begin "offline source and persistent update origin"
    bootc image copy-to-storage
    cd (mktemp -d)
    build_image "v1" "localhost/target-imgref-source:v1"
    build_image "v2" $source

    podman save --format oci-archive -o $archive $source
    # Normalize the source to the archive's manifest before comparing digests
    # across subsequent loads; saving can convert a Docker manifest to OCI.
    podman rmi $source
    podman load -i $archive

    bootc switch --download-only --transport containers-storage --target-imgref $"containers-storage:($origin)" localhost/target-imgref-source:v1
    let original_stage = (status).status.staged
    if (tap is_composefs) {
        let collision = do { bootc switch --download-only --transport containers-storage --target-imgref $"containers-storage:($next_origin)" localhost/target-imgref-source:v1 } | complete
        assert ($collision.exit_code != 0)
        assert ($collision.stderr | str contains "same fs-verity digest")
        assert equal (status).status.staged $original_stage
    } else {
        # OSTree can stage cached content with a different update origin.
        bootc switch --download-only --transport containers-storage --target-imgref $"containers-storage:($next_origin)" localhost/target-imgref-source:v1
        assert equal (status).status.staged.image.imageDigest $original_stage.image.imageDigest
        assert equal (status).status.staged.image.image.image $next_origin
        bootc switch --download-only --transport containers-storage --target-imgref $"containers-storage:($origin)" localhost/target-imgref-source:v1
    }
    let previous = (status).status.staged.image.imageDigest
    # A new source must still be processed when the update origin is unchanged.
    stage
    let staged = (status).status.staged
    assert ($staged.image.imageDigest != $previous)
    assert equal $staged.image.image.image $origin
    assert equal $staged.image.image.transport "containers-storage"
    assert $staged.downloadOnly

    # The target is absent. Remove the source too: repeats must use deployment metadata.
    podman rmi $source
    stage
    bootc switch --transport containers-storage $origin
    assert equal (status).status.staged $staged
    let applied = do { bootc switch --apply --transport containers-storage --target-imgref $"containers-storage:($origin)" $source } | complete
    assert ($applied.exit_code != 0) "--apply must not bypass a download-only lock"
    assert equal (status).status.staged $staged

    bootc switch --from-downloaded
    assert (not (status).status.staged.downloadOnly)
    tmt-reboot
}

def second_boot [] {
    let booted = (status).status.booted
    let rollback = (status).status.rollback
    assert equal $booted.image.image.image $origin
    assert equal (open $marker | str trim) "v2"

    # Provenance survives reboot, with both source and target absent.
    bootc switch --transport containers-storage --target-imgref $"containers-storage:($origin)" $source
    bootc switch --transport containers-storage $origin
    assert equal (status).status.booted $booted
    assert equal (status).status.staged null

    podman load -i $archive
    if (tap is_composefs) {
        let collision = do { bootc switch --download-only --transport containers-storage --target-imgref $"containers-storage:($next_origin)" $source } | complete
        assert ($collision.exit_code != 0)
        assert ($collision.stderr | str contains "same fs-verity digest")
        assert equal (status).status.booted $booted
        assert equal (status).status.rollback $rollback
        assert equal (status).status.staged null
        podman rmi $source
        verify_updates $origin
        tmt-reboot
        return
    }

    # OSTree supports a separate deployment of the identical booted image.
    bootc switch --download-only --transport containers-storage --target-imgref $"containers-storage:($next_origin)" $source
    assert equal (status).status.booted $booted
    assert equal (status).status.staged.image.imageDigest $booted.image.imageDigest
    assert equal (status).status.staged.image.image.image $next_origin
    assert (status).status.staged.downloadOnly
    podman rmi $source
    bootc switch --download-only --transport containers-storage --target-imgref $"containers-storage:($next_origin)" $source
    tmt-reboot
}

def third_boot [] {
    assert equal (status).status.booted.image.image.image $origin
    # libostree discards an unfinalized staged deployment across reboot.
    # Restore it from the offline delivery before explicitly unlocking it.
    podman load -i $archive
    bootc switch --download-only --transport containers-storage --target-imgref $"containers-storage:($next_origin)" $source
    podman rmi $source
    assert equal (status).status.staged.image.image.image $next_origin
    assert (status).status.staged.downloadOnly
    bootc switch --download-only --transport containers-storage --target-imgref $"containers-storage:($next_origin)" $source
    bootc switch --from-downloaded
    assert (not (status).status.staged.downloadOnly)
    tmt-reboot
}

def fourth_boot [] {
    let booted = (status).status.booted
    assert equal $booted.image.image.image $next_origin
    assert equal (status).status.staged null
    assert equal (open $marker | str trim) "v2"
    bootc switch --transport containers-storage --target-imgref $"containers-storage:($next_origin)" $source
    verify_updates $next_origin
    tmt-reboot
}

# Ordinary updates must use the recorded origin after the delivery source is gone.
def verify_updates [update_origin: string] {
    let booted = (status).status.booted
    podman load -i $archive
    podman tag $source $update_origin
    podman rmi $source
    bootc update
    assert equal (status).status.staged null

    cd (mktemp -d)
    build_image "v3" $update_origin
    bootc update
    let staged = (status).status.staged
    assert equal $staged.image.image.image $update_origin
    assert ($staged.image.imageDigest != $booted.image.imageDigest)
}

def finish [update_origin: string] {
    assert equal (open $marker | str trim) "v3"
    assert equal (status).status.booted.image.image.image $update_origin
    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        "2" => {
            if (tap is_composefs) {
                finish $origin
            } else {
                third_boot
            }
        },
        "3" => fourth_boot,
        "4" => { finish $next_origin },
        $n => { error make { msg: $"Invalid reboot count ($n)" } },
    }
}
