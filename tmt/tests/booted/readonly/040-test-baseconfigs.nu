use std assert
use tap.nu

tap begin "baseconfig validation tests"

# No-op when no baseconfigs are active
let baseconfigs = $env.BOOTC_baseconfigs? | default ""
if $baseconfigs == "" {
    print "# BOOTC_baseconfigs not set, skipping baseconfig tests"
    tap ok
    exit
}

let configs = ($baseconfigs | split row "," | each { |c| $c | str trim } | where { |c| $c != "" })

for config in $configs {
    match $config {
        "etc-transient" => {
            print "# Checking etc-transient: /etc should be an overlay mount"
            let mnt = (findmnt /etc -J | from json)
            let fstype = $mnt.filesystems.0.fstype
            assert equal $fstype "overlay" "/etc should be mounted as overlay when etc-transient is active"

            print "# Checking / has 755 permissions (overlay upper dir must not block traversal)"
            let perms = (stat -c "%a" / | str trim)
            assert equal $perms "755" "/ should have 755 permissions"

            print "# Checking /etc is writable (transient overlay)"
            let result = (do { ^touch /etc/bootc-baseconfig-test } | complete)
            assert equal $result.exit_code 0 "/etc should be writable with etc-transient"
            rm -f /etc/bootc-baseconfig-test
        },
        "root-transient" => {
            print "# Checking root-transient: / should be an overlay mount"
            let mnt = (findmnt / -J | from json)
            let fstype = $mnt.filesystems.0.fstype
            assert equal $fstype "overlay" "/ should be mounted as overlay when root-transient is active"

            print "# Checking / has 755 permissions"
            let perms = (stat -c "%a" / | str trim)
            assert equal $perms "755" "/ should have 755 permissions"

            print "# Checking / is writable (transient overlay)"
            let result = (do { ^touch /bootc-baseconfig-root-test } | complete)
            assert equal $result.exit_code 0 "/ should be writable with root-transient"
            rm -f /bootc-baseconfig-root-test

            # The whole point of bootc-early-overlay-relabel.service is to
            # fix the / inode label from tmpfs_t back to root_t after policy loads.
            print "# Checking / SELinux label is root_t (not tmpfs_t)"
            let label = (^stat -c "%C" / | str trim)
            assert ($label | str ends-with ":root_t:s0") $"/ SELinux label should end with :root_t:s0, got: ($label)"
        },
        "var-volatile" => {
            # /var is a fresh tmpfs on every boot via systemd.volatile=state karg.
            # It must NOT be an overlay (that would break podman's storage driver).
            print "# Checking var-volatile: /var should be a tmpfs (systemd.volatile=state)"
            let var_fstype = (findmnt /var -J -o FSTYPE | from json).filesystems.0.fstype
            assert equal $var_fstype "tmpfs" $"/var should be tmpfs with var-volatile, got: ($var_fstype)"
            print "# /var is tmpfs ✓"

            print "# Checking /var is writable"
            let result = (do { ^touch /var/bootc-baseconfig-var-volatile-test } | complete)
            assert equal $result.exit_code 0 "/var should be writable with var-volatile"
            rm -f /var/bootc-baseconfig-var-volatile-test

            # The raison d'être for using tmpfs rather than overlayfs: podman
            # must be able to use its overlay storage driver on top of /var.
            # If /var were overlayfs, podman would fall back to vfs or fail entirely.
            print "# Checking podman overlay storage driver works on tmpfs /var"
            let podman_result = (do { ^podman info --format "{{.Store.GraphDriverName}}" } | complete)
            assert equal $podman_result.exit_code 0 "podman info should succeed"
            let driver = ($podman_result.stdout | str trim)
            assert equal $driver "overlay" $"podman should use overlay driver on tmpfs /var, got: ($driver)"
            print $"# podman graph driver: ($driver) ✓"
        },
        "unified-storage" => {
            print "# Checking unified-storage: image must be in unified mode"
            # The install config (baked in at image build time) should have caused
            # bootc install to enable unified storage, so the booted image must be
            # reported as type "unified" from day 1 (no set-unified needed).
            let images = (bootc image list --format json | from json)
            let unified = ($images | where image_type == "unified")
            assert (($unified | length) > 0) "Expected booted image to be unified (installed via unified-storage baseconfig)"
            print $"# unified images: ($unified | length) ✓"

            # The bootc-owned storage symlink must be present
            assert ("/usr/lib/bootc/storage" | path exists) "/usr/lib/bootc/storage must exist"
            print "# /usr/lib/bootc/storage exists ✓"

            # The install config TOML that enabled this must be present in the image
            assert ("/usr/lib/bootc/install/00-storage.toml" | path exists) \
                "/usr/lib/bootc/install/00-storage.toml must be present in unified-storage image"
            print "# /usr/lib/bootc/install/00-storage.toml exists ✓"

            # fsck must pass
            print "# Running bootc internals fsck images"
            bootc internals fsck images
            print "# fsck passed ✓"
        },
        _ => {
            print $"# Unknown baseconfig token: ($config) — skipping"
        }
    }
}

tap ok
