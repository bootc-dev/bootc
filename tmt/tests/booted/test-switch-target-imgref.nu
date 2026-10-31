# number: 64
# tmt:
#   summary: Offline switch preserves the update origin and survives repeated requests
#   duration: 40m
#
use std assert
use tap.nu

const source = "localhost/target-imgref-source:v2"
const origin = "localhost:5555/target-imgref:latest"
const next_origin = "localhost:5555/target-imgref:redirected"
const archive = "/var/tmp/target-imgref-source.tar"
const registry = "bootc-target-imgref-registry"
const marker = "/usr/share/testing-target-imgref"

def status [] { bootc status --json | from json }

def build_image [version: string, image: string] {
    let containerfile = $"FROM localhost/bootc as base\nRUN echo ($version) > ($marker)\n"
    (tap make_uki_containerfile $containerfile) | save --force Containerfile
    podman build -t $image -f Containerfile .
}

def stage [] {
    bootc switch --download-only --transport containers-storage --target-imgref $origin $source
}

def first_boot [] {
    tap begin "offline source and persistent update origin"
    bootc image copy-to-storage
    cd (mktemp -d)
    build_image "v1" "localhost/target-imgref-source:v1"
    build_image "v2" $source

    mkdir /etc/containers/registries.conf.d
    '[[registry]]
location = "localhost:5555"
insecure = true
' | save /etc/containers/registries.conf.d/target-imgref-test.conf
    podman run -d --name $registry -p 127.0.0.1:5555:5000 docker.io/library/registry:2
    # Retry startup readiness through podman's push retry handling.
    podman push --tls-verify=false $source $origin
    # Deliver the exact registry manifest through local storage, as with an
    # offline archive. A push can change layer compression and manifest digests.
    podman pull --tls-verify=false $origin
    podman tag $origin $source
    podman rmi $origin
    podman save --format oci-archive -o $archive $source
    podman stop $registry

    # Re-origin an identical staged image. Also exercises OSTree cache retention.
    bootc switch --download-only --transport containers-storage localhost/target-imgref-source:v1
    bootc switch --download-only --transport containers-storage --target-imgref $origin localhost/target-imgref-source:v1
    let previous = (status).status.staged.image.imageDigest
    # A new source must still be processed when the update origin is unchanged.
    stage
    let staged = (status).status.staged
    assert ($staged.image.imageDigest != $previous)
    assert equal $staged.image.image.image $origin
    assert equal $staged.image.image.transport "registry"
    assert $staged.downloadOnly

    # Remove the source while the target registry is also unavailable. A repeat
    # must use deployment metadata without contacting either image location.
    podman rmi $source
    stage
    bootc switch $origin
    assert equal (status).status.staged $staged
    let applied = do { bootc switch --apply --transport containers-storage --target-imgref $origin $source } | complete
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

    # Provenance survives reboot. The source remains absent and registry stopped.
    bootc switch --transport containers-storage --target-imgref $origin $source
    bootc switch $origin
    assert equal (status).status.booted $booted
    assert equal (status).status.staged null

    # Recover an identical booted image with a different future origin. Keep
    # the registry unavailable throughout staging and the locked reboot.
    podman load -i $archive
    bootc switch --download-only --transport containers-storage --target-imgref $next_origin $source
    if (tap is_composefs) {
        let staged = (status).status.staged
        assert equal (status).status.rollback $rollback
        if ($booted.composefs.bootType | str downcase) == "uki" {
            for command in ["add" "remove"] {
                let result = do { bootc uki-addon $command nonexistent global } | complete
                assert ($result.exit_code != 0)
                assert ($result.stderr | str contains "origin change is pending")
            }
        }

        cd (mktemp -d)
        # A different OCI manifest with the same filesystem is still rejected.
        $"FROM ($source)\nLABEL bootc.test.origin-collision=true\n" | save Containerfile
        podman build -t localhost/target-imgref-collision .
        let collision = do { bootc switch --transport containers-storage --target-imgref $origin localhost/target-imgref-collision } | complete
        assert ($collision.exit_code != 0)
        assert ($collision.stderr | str contains "same fs-verity digest")
        assert equal (status).status.staged $staged

        # Failure after pulling must preserve the previously staged origin change.
        "local" | save /etc/target-imgref-conflict
        let containerfile = $"FROM ($source) as base\nRUN mkdir /etc/target-imgref-conflict && echo changed > ($marker)\n"
        (tap make_uki_containerfile $containerfile) | save --force Containerfile
        podman build -t localhost/target-imgref-conflict .
        let conflict = do { bootc switch --soft-reboot=auto --transport containers-storage localhost/target-imgref-conflict } | complete
        assert ($conflict.exit_code != 0)
        assert ($conflict.stderr | str contains "Merge conflicts found in etc")
        assert equal (status).status.staged $staged
        rm /etc/target-imgref-conflict

        let id = $booted.composefs.verity
        bootc delete-deployment $id
        assert equal (status).status.staged null
        assert equal (status).status.booted $booted
        bootc switch --download-only --transport containers-storage --target-imgref $next_origin $source
        bootc rollback
        assert equal (status).status.staged null
        bootc rollback
        bootc switch --download-only --transport containers-storage --target-imgref $next_origin $source
    }
    assert equal (status).status.booted $booted
    assert equal (status).status.staged.image.imageDigest $booted.image.imageDigest
    assert equal (status).status.staged.image.image.image $next_origin
    assert (status).status.staged.downloadOnly
    podman rmi $source
    bootc switch --download-only --transport containers-storage --target-imgref $next_origin $source
    tmt-reboot
}

def third_boot [] {
    assert equal (status).status.booted.image.image.image $origin
    if not (tap is_composefs) {
        # libostree discards an unfinalized staged deployment across reboot.
        # Restore it from the offline delivery before explicitly unlocking it.
        podman load -i $archive
        bootc switch --download-only --transport containers-storage --target-imgref $next_origin $source
        podman rmi $source
    }
    assert equal (status).status.staged.image.image.image $next_origin
    assert (status).status.staged.downloadOnly
    bootc switch --download-only --transport containers-storage --target-imgref $next_origin $source
    if (tap is_composefs) {
        # Resolve the same image successfully so failure proves lock enforcement.
        podman start $registry
        skopeo copy --preserve-digests --src-tls-verify=false --dest-tls-verify=false $"docker://($origin)" $"docker://($next_origin)"
        let applied = do { bootc update --apply } | complete
        assert ($applied.exit_code != 0)
        assert ($applied.stderr | str contains "download-only")
        let required = do { bootc switch --from-downloaded --soft-reboot=required } | complete
        assert ($required.exit_code != 0)
        assert (status).status.staged.downloadOnly
        # Auto must unlock without rebooting the machine, even with --apply.
        bootc switch --from-downloaded --soft-reboot=auto --apply
        bootc update --soft-reboot=auto --apply
        podman stop $registry
        bootc switch --soft-reboot=auto --apply --transport containers-storage --target-imgref $next_origin $source
    } else {
        bootc switch --from-downloaded
    }
    assert (not (status).status.staged.downloadOnly)
    tmt-reboot
}

def fourth_boot [] {
    let booted = (status).status.booted
    assert equal $booted.image.image.image $next_origin
    assert equal (status).status.staged null
    assert equal (open $marker | str trim) "v2"
    bootc switch --transport containers-storage --target-imgref $next_origin $source
    podman start $registry
    skopeo copy --preserve-digests --src-tls-verify=false --dest-tls-verify=false $"docker://($origin)" $"docker://($next_origin)"
    bootc update
    assert equal (status).status.staged null

    # A newer image at the recorded origin must be discovered by ordinary update.
    cd (mktemp -d)
    build_image "v3" "localhost/target-imgref-update:v3"
    podman push --tls-verify=false localhost/target-imgref-update:v3 $next_origin
    bootc update
    let staged = (status).status.staged
    assert equal $staged.image.image.image $next_origin
    assert ($staged.image.imageDigest != $booted.image.imageDigest)
    tmt-reboot
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        "2" => third_boot,
        "3" => fourth_boot,
        "4" => {
            assert equal (open $marker | str trim) "v3"
            assert equal (status).status.booted.image.image.image $next_origin
            podman rm -f $registry
            tap ok
        },
        $n => { error make { msg: $"Invalid reboot count ($n)" } },
    }
}
