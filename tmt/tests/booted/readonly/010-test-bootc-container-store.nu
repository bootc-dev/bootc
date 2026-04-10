use std assert
use tap.nu

tap begin "verify bootc-owned container storage"

let st = bootc status --json | from json
let is_composefs = (tap is_composefs)

# The additional image store symlink must exist on all backends.
# After upgrading from an older bootc that didn't set up the unified
# storage layout, the on-disk symlink target may not exist yet.
let has_storage = ("/usr/lib/bootc/storage" | path exists)
if not $has_storage {
    print "# skip: /usr/lib/bootc/storage not present (upgrade from older bootc)"
} else {
    # Just verifying that the additional store works
    podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage images

    # Verify the host image is visible and can be used from the additional store.
    # This catches SELinux labeling issues: if the storage isn't labeled correctly
    # podman will fail with "cannot apply additional memory protection" errors.
    #
    # On composefs the booted image is always in bootc storage — assert it.
    # On ostree unified storage is still experimental, so only check if present.
    # Use --pull=never because "localhost/..." looks like a registry reference.
    let booted_image = $st.status.booted.image.image.image
    let image_in_store = (podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage image exists $booted_image | complete | get exit_code) == 0
    if $is_composefs {
        assert $image_in_store $"Host image ($booted_image) must be in bootc storage on composefs"
    }
    if $image_in_store {
        print $"# Verifying host image ($booted_image) is usable from additional store"
        podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage run --pull=never --rm $booted_image bootc status --json | ignore
    }

    # And verify this works
    bootc image cmd list -q o>/dev/null

    bootc image cmd pull busybox
    podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage image exists busybox
}

# TODO: Re-enable once the podman API path validates auth eagerly.
# The PodmanClient refactor (pull_with_progress via libpod HTTP API) no
# longer fails on corrupted auth for public images — podman only reads
# auth entries when credentials are actually needed.
# if not $is_composefs {
#     'corrupted JSON!@#%!@#' | save -f /run/ostree/auth.json
#     let e = bootc image cmd pull busybox | complete | get exit_code
#     assert not equal $e 0
#     rm -v /run/ostree/auth.json
# }

tap ok
