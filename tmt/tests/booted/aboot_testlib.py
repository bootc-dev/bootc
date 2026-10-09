import json
from pathlib import Path
import re
import subprocess
import time


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def status():
    return json.loads(run("bootc", "status", "--json"))["status"]


def verify_boot(slot, version):
    assert run("systemctl", "is-enabled", "ukiboot-set-success.service") == "enabled"
    for service in ("ukiboot-set-success.service", "bootc-aboot-reconcile.service"):
        for attempt in range(60):
            active = run("systemctl", "show", "--property=ActiveState", "--value", service)
            assert active != "failed", service
            if active == "active":
                break
            time.sleep(1)
        else:
            raise AssertionError(f"{service} did not finish at boot")
        assert run("systemctl", "show", "--property=Result", "--value", service) == "success"
    st = status()
    booted = st["booted"]
    assert booted["ostree"] is None, booted
    assert booted["composefs"]["bootType"] == "Aboot", booted
    assert run("findmnt", "--noheadings", "--output", "FSTYPE", "--target", "/sysroot") == "ext4"
    assert st["staged"] is None, st
    assert not st["rollbackQueued"], st
    assert Path("/usr/share/bootc-aboot-test-version").read_text().strip() == str(version)
    assert f"androidboot.slot_suffix=_{slot}" in Path("/proc/cmdline").read_text().split()
    mapping = Path(f"/sysroot/state/boot/aboot/slots/{slot}").read_text().strip()
    assert mapping == booted["composefs"]["verity"], (mapping, booted)
    control = run("ukibootctl", "dump")
    print(control)
    slot_number = {"a": 0, "b": 1}[slot]
    assert re.search(rf"^Slot {slot_number}: .*successful_boot: 1$", control, re.MULTILINE), control
    return st
