use std assert
use tap.nu

tap begin "Run fsck"

# That's it, just ensure we've run a fsck on our basic install.
bootc internals fsck

tap ok
