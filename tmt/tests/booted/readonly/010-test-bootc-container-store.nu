use std assert
use tap.nu

tap begin "verify bootc-owned container storage"

# Just verifying that the additional store works
podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage images

# And verify this works
bootc image cmd list -q o>/dev/null

tap ok
