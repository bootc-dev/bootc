use std assert
use tap.nu

# Test each directory separately for better granularity
let directories = ["/boot", "/etc", "/usr"]

for dir in $directories {
    tap begin $"Run restorecon on ($dir)"

    # Run restorecon on single directory and capture trimmed output
    let out = (restorecon -vnr $dir | str trim)

    if $dir == "/boot" {
        # /boot is expected to have incorrect labels - known issue
        # See: https://github.com/bootc-dev/bootc/issues/1622
        print $"Note: /boot restorecon output \(expected\): ($out)"
    } else {
        # Assert it's empty for other directories
        assert equal $out "" $"restorecon run found incorrect labels in ($dir): ($out)"
    }

    tap ok
}
