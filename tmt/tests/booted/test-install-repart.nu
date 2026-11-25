# number: 52
# tmt:
#   summary: Test bootc install to-disk with systemd-repart partitioning
#   duration: 30m

use std assert
use tap.nu

# DPS UUIDs
const ESP_DPS_UUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
const XBOOTLDR_DPS_UUID = "bc13c2ff-59e6-4262-a352-b275fd6f7172"
const BIOS_BOOT_DPS_UUID = "21686148-6449-6e6f-744e-656564454649"
const HOME_DPS_UUID = "933ac7e1-2eb4-4f13-b844-0e14e2aef915"
const SWAP_DPS_UUID = "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f"
# NOTE: This is DPS UUID for x86 root
const ROOT_DPS_UUID = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"

let st = bootc status --json | from json

let bootloader = if ($st.status.booted.composefs? != null) {
    $st.status.booted.composefs.bootloader | str downcase
} else {
    "grub"
}

# We need this for grub and grub-cc installation as grub-cc
# installation currently is just a frankeinstined version of grub  
# install so we need BIOS partition
let bios = if $bootloader == "grub" or $bootloader == "grub-cc" {
        $"
RUN <<EOF cat > /usr/lib/repart.d/00-bios.conf
[Partition]
Type=($BIOS_BOOT_DPS_UUID)
Label=BIOS-BOOT
SizeMinBytes=1M
SizeMaxBytes=1M
EOF
        "
    } else {
        ""
    }

def run_install_to_disk [
    target_image: string
    extra_bootc_args: list<string>
] {
    # Remove usr overlay state for ostree
    # We still need this even though we now have usr-overlay check in ostree branch
    # as well, because ostree checks for a file inside /run/ostree/deployment-state/...
    # for usr-overlay status
    rm -rvf /run/ostree/deployment-state

    let composefs_args = if (tap is_composefs) {
        ["--composefs-backend", "--bootloader", $bootloader]
    } else {
        ""
    }

    let volume = $"-v /dev:/dev -v /run/udev:/run/udev -v /var/disk.img:/disk.img"
    let base = $"podman run --rm --privileged ($volume) --pid=host --security-opt label=type:unconfined_t --env BOOTC_BOOTLOADER_DEBUG=1 ($target_image)"
    let args = $"($composefs_args | str join ' ') ($extra_bootc_args | str join ' ')"
    let bootc = $"bootc install to-disk ($args) --disable-selinux --via-loopback --wipe --source-imgref containers-storage:($target_image) /disk.img"

    tap run_install $"($base) ($bootc)"
}

def test_repart_full [] {
    tap begin "install with systemd-repart (ESP + root defined)"

    bootc image copy-to-storage

    let dockerfile = $"FROM localhost/bootc as base
RUN rm -rf /etc/repart.d /usr/lib/repart.d /usr/local/lib/repart.d /run/repart.d
RUN rm -rf /usr/lib/bootc/bound-images.d/*

RUN mkdir -p /usr/lib/repart.d
($bios)
RUN <<'EOF' cat > /usr/lib/repart.d/00-esp.conf
[Partition]
Type=esp
Format=vfat
SizeMinBytes=1024M
SizeMaxBytes=1024M
EOF
RUN <<'EOF' cat > /usr/lib/repart.d/10-root.conf
[Partition]
Type=root
Format=ext4
EOF
"
    (tap make_uki_containerfile $dockerfile) | podman build -t localhost/bootc-repart . -f -

    truncate -s 10G /var/disk.img
    setenforce 0

    run_install_to_disk localhost/bootc-repart []

    # since `--no-repart` wasn't passed in, sfdisk should've been used
    let loop = (losetup -f --show /var/disk.img | str trim)
    try {
        partx -u $loop
        udevadm settle
        let parts = (lsblk -J -b -o name,parttype,partuuid,size $loop | from json)
        let children = ($parts.blockdevices.0.children)
        let part_types = ($children | get parttype)

        assert ($part_types | any {|t| ($t | str downcase) == $ESP_DPS_UUID }) "ESP partition not found"

        let esp_mb = if (tap is_composefs) { 2048 } else { 512 }
        # Verify ESP size
        let esp_part = ($children | where {|t| ($t.parttype | str downcase) == $ESP_DPS_UUID } | first)
        let esp_size_bytes = ($esp_part.size | into int)
        let esp_expected = ($esp_mb * 1024 * 1024)                                                                                                                                       

        assert ($esp_size_bytes == $esp_expected) $"ESP should be ($esp_mb)M from sfdisk, got ($esp_size_bytes) bytes"                                                                   

        print "PASS: sfdisk created BIOS + ESP + root partitions"
    } catch { |e|
        losetup -d $loop
        error make { msg: $"No-repart verification failed: ($e.msg)" }
    }

    losetup -d $loop

    rm -rvf /var/disk.img
    truncate -s 10G /var/disk.img

    run_install_to_disk localhost/bootc-repart ["--run-repart"]

    # Verify partition layout
    let loop = (losetup -f --show /var/disk.img | str trim)
    try {
        partx -u $loop
        udevadm settle
        let parts = (lsblk -J -o name,parttype,partuuid $loop | from json)
        let children = ($parts.blockdevices.0.children)
        let part_types = ($children | get parttype)

        assert ($part_types | any {|t| ($t | str downcase) == $ESP_DPS_UUID }) "ESP partition not found"

        # Root partition (architecture-specific, just check it exists beyond ESP)
        assert (($children | length) >= 2) "Expected at least 2 partitions (ESP + root)"

        print "PASS: repart created ESP + root partitions"
    } catch { |e|
        losetup -d $loop
        error make { msg: $"Verification failed: ($e.msg)" }
    }

    losetup -d $loop
    rm -rvf /var/disk.img
}

def verify_part_layout_second_boot [] {
    # Verify partition layout
    let loop = (losetup -f --show /var/disk.img | str trim)
    try {
        partx -u $loop
        udevadm settle
        let parts = (lsblk -J --bytes -o name,parttype,partuuid,size $loop | from json)
        print $parts
        let children = ($parts.blockdevices.0.children)
        let part_types = ($children | get parttype)

        assert ($part_types | any {|t| ($t | str downcase) == $ESP_DPS_UUID }) "ESP partition not found"

        # Should have ESP + root (and Bios for grub)
        assert (($children | length) >= 2) "Expected at least 2 partitions"

        # Verify root is not using all disk space (--root-size 7G was specified)
        let root_part = ($children | last)
        let root_size_bytes = ($root_part.size | into int)
        let seven_gb = (7 * 1024 * 1024 * 1024)
        assert ($root_size_bytes <= $seven_gb) $"Root partition should be ~7G, got ($root_part.size)"

        print "PASS: repart created ESP, bootc generated root with correct size"
    } catch { |e|
        losetup -d $loop
        error make { msg: $"Verification failed: ($e.msg)" }
    }

    losetup -d $loop
}

def test_repart_no_root [] {
    tap begin "install with systemd-repart (ESP only, root generated by bootc)"

    # Image has ESP + home in repart.d, but no root partition definition
    let dockerfile = $"FROM localhost/bootc as base
RUN rm -rf /etc/repart.d /usr/lib/repart.d /usr/local/lib/repart.d /run/repart.d
RUN rm -rf /usr/lib/bootc/bound-images.d/*

RUN mkdir -p /usr/lib/repart.d
($bios)
RUN <<'EOF' cat > /usr/lib/repart.d/00-esp.conf
[Partition]
Type=esp
Format=vfat
SizeMinBytes=1024M
SizeMaxBytes=1024M
EOF

RUN <<'EOF' cat > /usr/lib/repart.d/20-home.conf
[Partition]
Type=home
Format=ext4
SizeMinBytes=1024M
SizeMaxBytes=1024M
EOF

RUN <<'EOF' cat > /usr/lib/repart.d/30-swap.conf
[Partition]
Type=swap
Format=swap
SizeMinBytes=1024M
SizeMaxBytes=1024M
EOF
"
    (tap make_uki_containerfile $dockerfile) | podman build -t localhost/bootc-repart-noroot . -f -

    truncate -s 10G /var/disk.img
    setenforce 0

    run_install_to_disk localhost/bootc-repart-noroot ["--run-repart" "--filesystem" "ext4" "--root-size" "7G"]

    # Verify partition layout
    verify_part_layout_second_boot

    # Install again without passing in root-size make sure it works
    run_install_to_disk localhost/bootc-repart-noroot ["--run-repart" "--filesystem" "ext4"]

    # Verify partition layout (again)
    verify_part_layout_second_boot

    verify_first_boot localhost/bootc-repart-noroot
    rm -rvf /var/disk.img
}

# Run systemd-repart on the disk again to simulate what would happen on first
# boot, and check that it creates the home and swap partitions the install
# left to it
def verify_first_boot [image: string] {
    print "Running systemd-repart to simulate first boot"
    (
      podman run --privileged --rm
      -v /dev:/dev
      -v /var/disk.img:/output/disk.img
      $image
      systemd-repart --dry-run=no --json=pretty --no-pager /output/disk.img
    )

    let loop = (losetup -f --show /var/disk.img | str trim)
    try {
        partx -u $loop
        udevadm settle
        let parts = (lsblk -J --bytes -o name,parttype,partuuid,size $loop | from json)
        print $parts
        let children = ($parts.blockdevices.0.children)
        let part_types = ($children | get parttype)

        # Should have ESP + root + home + swap (and Bios for grub)
        assert (($children | length) >= 4) "Expected at least 4 partitions"

        assert ($part_types | any {|t| ($t | str downcase) == $HOME_DPS_UUID }) "home partition not found"

        assert ($part_types | any {|t| ($t | str downcase) == $SWAP_DPS_UUID }) "swap partition not found"

        print "PASS: repart first boot verified"
    } catch { |e|
        losetup -d $loop
        error make { msg: $"repart first boot verification failed: ($e.msg)" }
    }

    losetup -d $loop
}

def test_repart_no_root_growable_esp [] {
    tap begin "install with systemd-repart (growable ESP, root generated by bootc)"

    # The install creates only root and the ESP (and BIOS boot); an ESP that
    # can grow must leave the space planned for home and swap to first boot.
    # Its sizes come from a drop-in of the image, which must not override the
    # size bootc pins. Its low weight keeps most of the disk for root.
    let dockerfile = $"FROM localhost/bootc as base
RUN rm -rf /etc/repart.d /usr/lib/repart.d /usr/local/lib/repart.d /run/repart.d
RUN rm -rf /usr/lib/bootc/bound-images.d/*

RUN mkdir -p /usr/lib/repart.d/00-esp.conf.d
($bios)
RUN <<'EOF' cat > /usr/lib/repart.d/00-esp.conf
[Partition]
Type=esp
Format=vfat
EOF

RUN <<'EOF' cat > /usr/lib/repart.d/00-esp.conf.d/size.conf
[Partition]
SizeMinBytes=512M
SizeMaxBytes=100G
Weight=100
EOF

RUN <<'EOF' cat > /usr/lib/repart.d/20-home.conf
[Partition]
Type=home
Format=ext4
SizeMinBytes=1024M
SizeMaxBytes=1024M
EOF

RUN <<'EOF' cat > /usr/lib/repart.d/30-swap.conf
[Partition]
Type=swap
Format=swap
SizeMinBytes=1024M
SizeMaxBytes=1024M
EOF
"
    (tap make_uki_containerfile $dockerfile) | podman build -t localhost/bootc-repart-growable-esp . -f -

    truncate -s 10G /var/disk.img
    setenforce 0

    run_install_to_disk localhost/bootc-repart-growable-esp ["--run-repart" "--filesystem" "ext4"]
    verify_first_boot localhost/bootc-repart-growable-esp
    rm -rvf /var/disk.img
}


def test_repart_luks [] {
    tap begin "install with systemd-repart (LUKS)"

    # LUKS + repart only supported for BLS complaint bootloaders
    # This also skips ostree
    if $bootloader == "grub" {
        print "SKIP: LUKS via systemd-repart requires DPS; not supported on plain grub"
        return
    }

    # repart's KeyFile= was introduced in systemd 259. On older systemd it is
    # unavailable, so encrypt the root with TPM2 instead of a keyfile
    # This works as bcvk starts a VM with emulated TPM
    let systemd_version = (systemctl --version | lines | first | split row ' ' | get 1 | into int)
    let use_keyfile = $systemd_version >= 259

    # NOTE: This would usually be in a tmp volume, but okay for testing
    let keyfile_setup = if $use_keyfile {
        "
RUN printf '%s' 'luks-test-passphrase' > /etc/luks-keyfile
"
    } else {
        ""
    }

    let root_conf = if $use_keyfile {
        "
RUN <<'EOF' cat > /usr/lib/repart.d/10-root.conf
[Partition]
Type=root
Format=ext4
Encrypt=key-file
KeyFile=/etc/luks-keyfile
EOF
"
    } else {
        "
RUN <<'EOF' cat > /usr/lib/repart.d/10-root.conf
[Partition]
Type=root
Format=ext4
Encrypt=tpm2
EOF
"
    }

    # Root partition is LUKS-encrypted. On systemd >= 259 repart enrolls the
    # keyfile baked into the image (bootc opens it via KeyFile= during install);
    # on older systemd it is sealed to the TPM instead.
    let dockerfile = $"FROM localhost/bootc as base
RUN rm -rf /etc/repart.d /usr/lib/repart.d /usr/local/lib/repart.d /run/repart.d
RUN rm -rf /usr/lib/bootc/bound-images.d/*

RUN mkdir -p /usr/lib/repart.d
($bios)
($keyfile_setup)
RUN <<'EOF' cat > /usr/lib/repart.d/00-esp.conf
[Partition]
Type=esp
Format=vfat
SizeMinBytes=1024M
SizeMaxBytes=1024M
EOF
($root_conf)
"
    (tap make_uki_containerfile $dockerfile) | podman build -t localhost/bootc-repart-luks . -f -

    truncate -s 10G /var/disk.img
    setenforce 0

    run_install_to_disk localhost/bootc-repart-luks ["--run-repart"]

    # Verify the root partition is LUKS-encrypted
    let loop = (losetup -f --show /var/disk.img | str trim)
    try {
        partx -u $loop
        udevadm settle
        let parts = (lsblk -J -o name,parttype,fstype $loop | from json)
        let children = ($parts.blockdevices.0.children)
        let part_types = ($children | get parttype)

        assert ($part_types | any {|t| ($t | str downcase) == $ESP_DPS_UUID }) "ESP partition not found"

        # Root partition must be LUKS encrypted
        assert ($children | any {|c| ($c.fstype? | default "") == "crypto_LUKS" }) "Root partition is not LUKS encrypted"

        # Root ptn number
        let root = (
            $children
            | enumerate
            | where {|c| ($c.item.parttype? | default "" | str downcase) == $ROOT_DPS_UUID }
            | first
        )
        
        let rootdev = $"($loop)p($root.index + 1)"
        if $use_keyfile {
            # Make sure the partition opens with the enrolled keyfile passphrase
            printf '%s' luks-test-passphrase | cryptsetup luksOpen --key-file=- $rootdev root
            assert ("/dev/mapper/root" | path exists) "LUKS root failed to open"
        } else {
            # TPM2-sealed: unlock via the enrolled systemd-tpm2 token. CentOS 9
            # ships no standalone systemd-cryptsetup binary, so use cryptsetup's
            # token handler
            cryptsetup luksOpen --token-only $rootdev root
            assert ("/dev/mapper/root" | path exists) "LUKS root failed to open via TPM"
        }

        cryptsetup luksClose root

        print "PASS: repart created a LUKS-encrypted root"
    } catch { |e|
        losetup -d $loop
        error make { msg: $"LUKS verification failed: ($e.msg)" }
    }

    losetup -d $loop
    rm -rvf /var/disk.img
}

def main [] {
    test_repart_full
    test_repart_no_root
    test_repart_no_root_growable_esp
    test_repart_luks
    tap ok
}
