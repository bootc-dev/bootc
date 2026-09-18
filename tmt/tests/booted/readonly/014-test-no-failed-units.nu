# Verify no systemd or bootc units are in a failed state.
#
# This catches first-boot ordering issues such as the race between
# systemd-tmpfiles-setup and systemd-random-seed/systemd-tpm2-setup
# when /var/lib/systemd does not yet exist (the bootc generator
# emits a drop-in to prevent this).
use std assert
use tap.nu

tap begin "verify no failed systemd/bootc units"

let selinux_enabled = ("/sys/fs/selinux/enforce" | path exists)

let failed_candidates = (systemctl list-units --failed --no-legend --plain
    | lines
    | filter { |l| $l != "" }
    | filter { |l|
        let unit = ($l | split row " " | first)
        (($unit | str starts-with "systemd-") or ($unit | str starts-with "bootc-"))
    })

let failed = if $selinux_enabled {
    # https://bugzilla.redhat.com/show_bug.cgi?id=2507393
    $failed_candidates | filter { |l|
        let unit = ($l | split row " " | first)
        if $unit == "systemd-tpm2-setup.service" {
            print "# SELinux workaround: ignoring systemd-tpm2-setup.service failure (SELinux denies writing the NvPCR credential to dosfs_t)"
            false
        } else {
            true
        }
    }
} else {
    $failed_candidates
}

if ($failed | length) > 0 {
    print $"Failed units:\n($failed | str join "\n")"
    assert equal ($failed | length) 0 "Expected zero failed systemd-*/bootc-* units"
}

print "No failed systemd-*/bootc-* units"
tap ok
