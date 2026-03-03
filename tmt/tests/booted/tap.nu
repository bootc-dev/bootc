# A simple nushell "library" for the
# "Test anything protocol":
# https://testanything.org/tap-version-14-specification.html
export def begin [description] {
  print "TAP version 14"
  print $description
}

export def ok [] {
  print "ok"
}

export def fail [] {
  print "not ok"
}

export def is_composefs [] {
    let st = bootc status --json | from json
    $st.status.booted.composefs? != null
}

# Run a bootc install command in an isolated mount namespace.
# This handles the common setup needed for install tests run outside a container.
export def run_install [cmd: string] {
    systemd-run -p MountFlags=slave -qdPG -- /bin/sh -c $"
set -xeuo pipefail
bootc usr-overlay
if test -d /sysroot/ostree; then mount --bind /usr/share/empty /sysroot/ostree; fi
rm -vrf /usr/lib/bootupd/updates
rm -vrf /usr/lib/bootc/bound-images.d
($cmd)
"
}
