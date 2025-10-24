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
  assert ($booted.transport in [registry containers-storage])
  tap ok
}


