use std assert
use tap.nu

tap begin "Run restorecon"

# Run restorecon and capture trimmed output
let out = (restorecon -vnr /var/ /etc/ /usr/ /boot/ | str trim)

# Assert it's empty
assert equal $out "" "restorecon run found incorrect labels: ($out)"

tap ok
