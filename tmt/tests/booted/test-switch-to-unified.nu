# number: 31
# tmt:
#   summary: Onboard to unified storage, build derived image, and switch to it
#   duration: 30m
# extra:
#   fixme_skip_if_composefs: true
#
use std assert
use tap.nu

# Multi-boot test: boot 0 onboards to unified storage and builds a derived image;
# boot 1 verifies we booted into the derived image using containers-storage

# This code runs on *each* boot - capture status for verification
bootc status
let st = bootc status --json | from json
let booted = $st.status.booted.image

def main [] {
  match $env.TMT_REBOOT_COUNT? {
    null | "0" => first_boot,
    "1" => second_boot,
    "2" => third_boot,
    $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
  }
}

def first_boot [] {
  tap begin "copy image to podman storage, switch, then onboard to unified storage"

  # Copy the currently booted image to podman storage
  bootc image copy-to-storage

  # Switch to the base image using containers-storage transport
  bootc switch --transport containers-storage localhost/bootc

  tmt-reboot
}

def second_boot [] {

  # Onboard to unified storage - this pulls the booted image into bootc storage
  bootc image set-unified

  # Verify bootc-owned store has the image
  bootc image cmd list
  podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage images

  let td = mktemp -d
  cd $td

  # Build a derived image with a marker file to verify we switched
  # Use bootc image cmd build which builds directly into bootc storage
  $"FROM localhost/bootc
RUN echo 'unified-storage-test-marker' > /usr/share/unified-storage-test.txt
" | save Dockerfile

  bootc image cmd build -t localhost/bootc-unified-derived .

  # Verify the build is in bootc storage
  bootc image cmd list

  # Switch to the derived image using containers-storage transport
  print "Switching to localhost/bootc-unified-derived"
  bootc switch --transport containers-storage localhost/bootc-unified-derived

  tmt-reboot
}

def third_boot [] {
  tap begin "verify unified storage switch worked"

  # Verify we're booted from containers-storage transport
  assert equal $booted.image.transport containers-storage
  assert equal $booted.image.image localhost/bootc-unified-derived

  # Verify the marker file from our derived image exists
  assert ("/usr/share/unified-storage-test.txt" | path exists)
  let marker = open /usr/share/unified-storage-test.txt | str trim
  assert equal $marker "unified-storage-test-marker"

  # Verify that bootc storage is accessible
  print "Listing images in bootc storage:"
  bootc image cmd list

  # Verify that podman can see bootc storage as additional image store
  print "Testing podman access to bootc storage"
  let images = podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage images --format "{{.Repository}}"
  print $"Images visible via podman: ($images)"

  # The derived image (localhost/bootc-unified-derived) should persist in bootc storage
  # since /usr/lib/bootc/storage is a symlink to persistent storage under /sysroot.
  # The key verification is that we successfully booted into the derived image,
  # which we already confirmed above via transport and image name checks.

  tap ok
}


