# number: 62
# tmt:
#   summary: Test ukiboot A/B update and rollback
#   duration: 30m
#   enabled: false
#   adjust:
#     - when: boot_type == aboot
#       enabled: true
# extra:
#   skip_if_ostree: true
#   try_bind_storage: true

import json
import os
from pathlib import Path
import subprocess

from aboot_testlib import run, status, verify_boot

ORIGINAL = Path("/var/tmp/bootc-aboot-original.json")
ABOOT_CONFIG = Path("/etc/aboot.cfg")
ABOOT_CONFIG_BACKUP = Path("/var/tmp/bootc-aboot-original.cfg")
ABOOT_STATE = Path("/sysroot/state/boot/aboot")


def main():
    print("TAP version 14\nukiboot update and rollback")
    count = int(os.environ.get("TMT_REBOOT_COUNT", "0"))
    target = os.environ["BOOTC_upgrade_image"]
    if count == 0:
        initial = verify_boot("a", 1)
        ORIGINAL.write_text(json.dumps(initial["booted"]))
        run("bootc", "switch", "--transport", "containers-storage", target)
        staged = status()
        assert staged["booted"] == initial["booted"], staged
        assert staged["staged"]["image"]["image"]["image"] == target, staged
        assert staged["staged"]["composefs"]["bootType"] == "Aboot", staged
        assert staged["staged"]["composefs"]["verity"] != initial["booted"]["composefs"]["verity"], staged
        # Make aboot-deploy fail while reading its configuration, before flashing.
        original_config = ABOOT_CONFIG.read_bytes()
        ABOOT_CONFIG_BACKUP.write_bytes(original_config)
        ABOOT_CONFIG.write_bytes(original_config + b"\nBOOTC_TEST_FAIL_DEPLOY=1\n")
        subprocess.run(["tmt-reboot"], check=True)
    elif count == 1:
        ABOOT_CONFIG.write_bytes(ABOOT_CONFIG_BACKUP.read_bytes())
        ABOOT_CONFIG_BACKUP.unlink()
        failed = verify_boot("a", 1, staged=True)
        attempted = (ABOOT_STATE / "attempted").read_bytes()
        pending = (ABOOT_STATE / "pending").read_bytes()
        attempt = json.loads(attempted)
        assert attempt["depl_id"] == failed["staged"]["composefs"]["verity"], attempt
        assert attempt["boot_id"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip(), attempt
        assert not (ABOOT_STATE / "slots/b").exists()
        run("bootc", "upgrade", "--check")
        assert (ABOOT_STATE / "attempted").read_bytes() == attempted
        assert (ABOOT_STATE / "pending").read_bytes() == pending
        # Even with the configuration repaired, another reboot must not retry it.
        subprocess.run(["tmt-reboot"], check=True)
    elif count == 2:
        failed = verify_boot("a", 1, staged=True)
        assert (ABOOT_STATE / "attempted").exists()
        run("bootc", "upgrade")
        retried = status()
        assert retried["staged"]["image"]["image"]["image"] == target, retried
        assert retried["staged"]["composefs"]["verity"] == failed["staged"]["composefs"]["verity"], retried
        assert not (ABOOT_STATE / "attempted").exists()
        subprocess.run(["tmt-reboot"], check=True)
    elif count == 3:
        original = json.loads(ORIGINAL.read_text())
        updated = verify_boot("b", 2)
        assert updated["booted"]["image"]["image"]["image"] == target, updated
        assert updated["booted"]["composefs"]["verity"] != original["composefs"]["verity"], updated
        assert updated["rollback"]["image"] == original["image"], updated
        assert updated["rollback"]["composefs"]["verity"] == original["composefs"]["verity"], updated
        run("bootc", "rollback")
        assert status()["rollbackQueued"]
        subprocess.run(["tmt-reboot"], check=True)
    elif count == 4:
        original = json.loads(ORIGINAL.read_text())
        restored = verify_boot("a", 1)
        assert restored["booted"]["image"] == original["image"], restored
        assert restored["booted"]["composefs"]["verity"] == original["composefs"]["verity"], restored
        ORIGINAL.unlink()
        print("ok 1 - ukiboot A/B update and rollback")
    else:
        raise AssertionError(f"Unexpected reboot count {count}")


if __name__ == "__main__":
    main()
