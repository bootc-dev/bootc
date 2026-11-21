# Verify no systemd or bootc units are in a failed state.
#
# This catches first-boot ordering issues such as the race between
# systemd-tmpfiles-setup and systemd-random-seed/systemd-tpm2-setup
# when /var/lib/systemd does not yet exist (the bootc generator
# emits bootc-early-tmpfiles.service to prevent this).
#
# bootc-destructive-cleanup.service is a best-effort one-shot which
# erases the previous OS installation from the old root; individual
# package scriptlets failing during that erase is expected noise, so
# its failure is tolerated (but still printed) rather than fatal.
use std assert
use tap.nu

tap begin "verify no failed systemd/bootc units"

def print-journal [unit: string] {
    print $"Journal for ($unit):"
    let journal = (try {
        do { ^journalctl --boot --unit $unit --no-pager } | complete
    } catch {|e|
        null
    })
    if $journal == null {
        print "# Unable to collect journal output"
    } else {
        if ($journal.stdout | str trim) != "" {
            print $journal.stdout
        }
        if ($journal.stderr | str trim) != "" {
            print $"journalctl stderr: ($journal.stderr)"
        }
        if $journal.exit_code != 0 {
            print $"journalctl exited with status ($journal.exit_code)"
        }
    }
}

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

# Best-effort units whose failure is tolerated, but still worth logging
let tolerated_units = ["bootc-destructive-cleanup.service"]

let tolerated = ($failed | filter { |l|
    ($l | split row " " | first) in $tolerated_units
})
let fatal = ($failed | filter { |l|
    ($l | split row " " | first) not-in $tolerated_units
})

for unit in ($tolerated | each { |l| $l | split row " " | first }) {
    print $"# WARNING: tolerated failure of best-effort unit ($unit) (ignoring for test result)"
    print-journal $unit
}

if ($fatal | length) > 0 {
    print $"Failed units:\n($fatal | str join "\n")"
    for unit in ($fatal | each { |l| $l | split row " " | first }) {
        print-journal $unit
    }
    assert equal ($fatal | length) 0 "Expected zero failed systemd-*/bootc-* units"
}

print "No failed systemd-*/bootc-* units"
tap ok
