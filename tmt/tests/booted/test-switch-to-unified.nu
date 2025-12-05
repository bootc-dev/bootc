use std assert
use tap.nu

# Multi-boot test: boot 0 onboards to unified storage; boot 1 verifies we use containers-storage

def main [] {
  match $env.TMT_REBOOT_COUNT? {
    null | "0" => first_boot,
    "1" => second_boot,
    $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
  }
}

def first_boot [] {
  tap begin "onboard to unified storage"
  # Sanity: booted status
  let st = (bootc status --json | from json)
  # Run the onboarding command
  bootc image set-unified
  # Verify bootc-owned store is usable
  podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage images
  # Stage a no-op upgrade to exercise the unified path; tolerate no-update
  try { bootc upgrade }
  tmt-reboot
}

def second_boot [] {
  tap begin "verify unified usage after onboarding"
  let st = (bootc status --json | from json)
  let booted = $st.status.booted.image
  # After onboarding, future pulls may use containers-storage; assert transport is either registry or containers-storage
  # The transport is nested under image.image.transport in the JSON structure
  assert ($booted.image.transport in [registry containers-storage])

  # Verify that podman can run the booted image from bootc storage
  # This is one of the key goals of unified storage (Issue #20)
  let image_name = $booted.image.image
  print $"Testing podman run with booted image: ($image_name)"
  let os_release = (podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage run --rm $image_name cat /etc/os-release)
  # Verify we got some os-release content (should contain ID= at minimum)
  assert ($os_release | str contains "ID=")
  print "Successfully ran booted image via podman with bootc storage"

  tap ok
}


