# number: 61
# tmt:
#   summary: Test artifact-selected ukiboot installation
#   duration: 30m
#   enabled: false
#   adjust:
#     - when: boot_type == aboot
#       enabled: true
# extra:
#   skip_if_ostree: true

import hashlib
import json
from pathlib import Path

from aboot_testlib import run, verify_boot


def main():
    print("TAP version 14\nukiboot installation and boot")
    verify_boot("a", 1)
    root_disk = Path("/dev/disk/by-partlabel/root").resolve()
    parent = run("lsblk", "--noheadings", "--output", "PKNAME", str(root_disk))
    table = json.loads(run("sfdisk", "--json", f"/dev/{parent}"))["partitiontable"]
    parts = table["partitions"]
    expected = {
        "efi": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
        "ukiboot_a": "df331e4d-be00-463f-b4a7-8b43e18fb53a",
        "ukiboot_b": "df331e4d-be00-463f-b4a7-8b43e18fb53a",
        "ukibootctl": "fefd9070-346f-4c9a-85e6-17f07f922773",
        "root": "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
    }
    assert len(parts) == len(expected), parts
    assert {p["name"]: p["type"].lower() for p in parts} == expected, parts
    payloads = []
    for slot in ("a", "b"):
        part = next(p for p in parts if p["name"] == f"ukiboot_{slot}")
        assert part["size"] * table["sectorsize"] == 192 * 1024 * 1024, part
        with open(f"/dev/disk/by-partlabel/ukiboot_{slot}", "rb") as payload:
            assert payload.read(2) == b"MZ"
            payload.seek(0)
            payloads.append(hashlib.file_digest(payload, "sha256").hexdigest())
    assert payloads[0] == payloads[1], payloads
    esp = Path(run("findmnt", "--noheadings", "--output", "TARGET", "--source", "/dev/disk/by-partlabel/efi"))
    assert (esp / "EFI/BOOT/BOOTX64.EFI").is_file()
    for slot in ("a", "b"):
        assert list(esp.glob(f"EFI/*/ukiboot_{slot}.efi.extra.d/slot_{slot}.addon.efi"))
    print("ok 1 - ukiboot installation and boot")


if __name__ == "__main__":
    main()
