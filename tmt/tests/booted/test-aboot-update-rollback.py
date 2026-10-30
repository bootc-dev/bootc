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
        subprocess.run(["tmt-reboot"], check=True)
    elif count == 1:
        original = json.loads(ORIGINAL.read_text())
        updated = verify_boot("b", 2)
        assert updated["booted"]["image"]["image"]["image"] == target, updated
        assert updated["booted"]["composefs"]["verity"] != original["composefs"]["verity"], updated
        assert updated["rollback"]["image"] == original["image"], updated
        assert updated["rollback"]["composefs"]["verity"] == original["composefs"]["verity"], updated
        run("bootc", "rollback")
        assert status()["rollbackQueued"]
        subprocess.run(["tmt-reboot"], check=True)
    elif count == 2:
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
