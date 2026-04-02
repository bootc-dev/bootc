use std assert
use tap.nu

tap begin "verify bootc works as non-root user"

# Verify that basic CLI operations succeed when run as an unprivileged
# dynamic user (regression test for the CAP_SYS_ADMIN gate in global_init).
systemd-run -qP -p DynamicUser=yes bootc --help

tap ok
