# number: 70
# tmt:
#   summary: Merge a systemd-sysext and a systemd-confext on a host whose separate /var starts out empty
#   duration: 30m
#   enabled: false
#   adjust:
#     - when: distro == centos-9, centos-10 and running_env == image_mode
#       enabled: true
#       because: extensions on the RHEL 9 long tail and on RHEL 10 are the cases to cover, in one matrix cell each
# extra:
#   fixme_skip_if_composefs: scope choice, not a bug; the CentOS Stream 9 cell is ostree, and one cell per distribution is enough
#
# A system extension (sysext, over /usr) and a configuration extension
# (confext, over /etc) stacked on the bootc image, on the disk layout such
# hosts use: /var is its own partition, which holds nothing when the host
# first boots from it, and holds the extensions. fs-verity and the SELinux
# labels of the extensions' own content are out of scope, and so are bootc
# upgrades and switches with extensions merged. It runs on the ostree
# backend only (see fixme_skip_if_composefs above); there /etc is a plain
# directory, so a confext is the only overlay on it.
#
# Boot 0: booting a disk installed inside the VM isn't possible here, and
#   root takes the rest of the VM's disk, so like test-composefs-xbootldr.nu
#   this shrinks the ESP (CentOS Stream's is 512M, with about 8M on it) and
#   puts a /var partition in the space that frees, mounted on /var through
#   /etc/fstab. Of the old /var, only tmt's own files are copied over (this
#   plan's directory and tmt's scripts), so that tmt can resume the test
#   after the reboot. This depends on tmt not needing what it writes there
#   after the copy (such as tmt-reboot's request, which it reads before
#   rebooting); true of tmt 1.80, which CI pins.
# Boot 1: check the layout, then for each of the sysext in
#   /var/lib/extensions and the confext in /var/lib/confexts: merge and
#   unmerge it from a shell, merge it again and refresh it after replacing
#   it with a new version, then merge it with its service. systemd-confext
#   only exists from systemd 254 on, so CentOS Stream 9 (systemd 252) covers
#   the sysext only; on newer systemd a missing systemd-confext fails.
# Boot 2: check that the services merged both at boot, from the separate
#   /var, that no unit failed once that boot settled, and unmerge them.
#
# Every failure starts with the component that broke: [layout] for the
# partition and /var mount, [bootc] for bootc on that layout,
# [systemd-sysext] or [systemd-confext] for an extension, and
# [test harness] for tmt's files that the test moves.
use tap.nu

const VAR_LABEL = "bootc-var"
const VAR_PARTLABEL = "bootc-test-var"
# The Discoverable Partitions Specification type for /var
const VAR_PART_TYPE = "4D21B016-B534-45C2-A9FB-5C16E091FD2D"
const ESP_TYPE = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
const SECTOR_SIZE = 512
# What the ESP keeps; the rest of it becomes /var
const ESP_MIB = 128
# mkfs.xfs needs 300M
const VAR_MIN_MIB = 300
# Written to the original /var only; it must not show up on the new one
const OLD_VAR_MARKER = "/var/bootc-test-old-var"
# The SELinux labels of /usr and /etc before any merge, kept across reboots
const LABELS_FILE = "/var/lib/bootc-test-labels.json"
# Where an extension goes when it is replaced under a live overlay, outside
# the tools' search paths
const REPLACED_DIR = "/var/lib/bootc-test-replaced"
# systemd-confext is part of systemd from this version on
const CONFEXT_SINCE = 254
# How long the last boot may take to settle before failed units are checked
const BOOT_WAIT_SECS = 300

const EXT_NAME = "bootc-test"
# What each kind of extension carries: one file, under its hierarchy
const SYSEXT = {
    tool: "systemd-sysext"
    hierarchy: "/usr"
    dir: "/var/lib/extensions/bootc-test"
    release_dir: "usr/lib/extension-release.d"
    file: "/usr/bin/bootc-test-sysext"
    content: "#!/bin/sh\necho 'hello from the bootc-test sysext {version}'\n"
}
const CONFEXT = {
    tool: "systemd-confext"
    hierarchy: "/etc"
    dir: "/var/lib/confexts/bootc-test"
    release_dir: "etc/extension-release.d"
    file: "/etc/bootc-test-confext.conf"
    content: "hello from the bootc-test confext {version}\n"
}

# Before this version, merging gives the hierarchy the label of the
# temporary directory it was merged from
# (https://github.com/systemd/systemd/issues/34387, fixed by
# https://github.com/systemd/systemd/pull/35132): user_tmp_t when merged
# from a shell, tmpfs_t when merged by the service.
# TODO: a RHEL/CentOS Stream backport of systemd#35132 would keep the version
# at 252, so this gate can't tell; drop the exception once CentOS Stream 9
# ships the fix, and the test then checks the label like on newer systemd.
const KEEPS_LABEL_SINCE = 257

const SHELL_MERGE_BUG_TYPE = "user_tmp_t"
const SERVICE_MERGE_BUG_TYPE = "tmpfs_t"

def fail_in [component: string, msg: string] {
    error make { msg: $"[($component)] ($msg)" }
}

# Run a command, with any pipeline input as its stdin; on failure, report
# it against the component that broke.
def --wrapped run_in [component: string, ...cmd: string] {
    let input = $in
    let r = $input | do { ^($cmd | first) ...($cmd | skip 1) } | complete
    print $"$ ($cmd | str join ' ')"
    for out in [$r.stdout $r.stderr] {
        if $out != "" { print ($out | str trim --right) }
    }
    if $r.exit_code != 0 {
        fail_in $component $"`($cmd | str join ' ')` failed with exit code ($r.exit_code): ($r.stderr | str trim)"
    }
    $r.stdout
}

def os_release [] {
    open /usr/lib/os-release
    | lines
    | where {|l| $l =~ '^[A-Z_]+=' }
    | parse "{key}={value}"
    | reduce -f {} {|it, acc| $acc | upsert $it.key ($it.value | str trim -c '"') }
}

def systemd_version [] {
    ^systemctl --version | lines | first | parse "systemd {version} {rest}" | get 0.version | into int
}

def label_of [path: string] {
    ^stat -c %C $path | str trim
}

def has_tool [ext: record] {
    (which $ext.tool | is-not-empty)
}

# The extensions to test: both, except on systemd older than CONFEXT_SINCE,
# which has no systemd-confext. A missing tool is a failure otherwise.
def extensions [] {
    if not (has_tool $SYSEXT) {
        fail_in systemd-sysext "systemd-sysext is not installed"
    }
    if (has_tool $CONFEXT) {
        return [$SYSEXT $CONFEXT]
    }
    let version = systemd_version
    if $version >= $CONFEXT_SINCE {
        fail_in systemd-confext $"systemd ($version) should have systemd-confext \(part of systemd since ($CONFEXT_SINCE)\), but it is not installed"
    }
    [$SYSEXT]
}

def content_of [ext: record, version: string] {
    $ext.content | str replace "{version}" $version
}

def diagnostics [ext: record] {
    for cmd in [
        [$ext.tool status]
        [systemctl status --no-pager $"($ext.tool).service"]
        [journalctl -b --no-pager -u $"($ext.tool).service"]
        [findmnt $ext.hierarchy]
    ] {
        let r = do { ^($cmd | first) ...($cmd | skip 1) } | complete
        print $"--- ($cmd | str join ' ')" $r.stdout $r.stderr
    }
}

# A directory extension carrying one file, with `version` in its content.
# The extension-release file must match the host's os-release for the tool
# to take it.
def make_extension [ext: record, version: string] {
    let os = os_release
    let release_dir = $"($ext.dir)/($ext.release_dir)"
    let file = $"($ext.dir)($ext.file)"
    mkdir $release_dir ($file | path dirname)
    content_of $ext $version | save $file
    chmod 0755 $file
    $"ID=($os.ID)\nVERSION_ID=($os.VERSION_ID)\n" | save $"($release_dir)/extension-release.($EXT_NAME)"
}

# Merging must leave the SELinux label of the hierarchy alone: confined
# services can't use a /usr or /etc labeled as a temporary directory. On
# CentOS Stream 9, a sysext merged from a shell labels /usr user_tmp_t, and
# sshd then refuses logins ("chroot(/usr/share/empty.sshd): Permission
# denied"). Known on systemd releases without the fix, as long as the label
# is the one that bug gives for how the extension was merged
# (`known_bug_type`); a failure otherwise. tmt and the harness have no
# result that warns and still passes (a warn fails the plan), so a known
# issue is only in the test's output.
def check_label [ext: record, known_bug_type: string] {
    let expected = open $LABELS_FILE | get $ext.hierarchy
    let actual = label_of $ext.hierarchy
    if $actual == $expected {
        return
    }
    let version = systemd_version
    let actual_type = $actual | split row ":" | get 2?
    let msg = $"merging relabeled ($ext.hierarchy) from ($expected) to ($actual), see https://github.com/systemd/systemd/issues/34387"
    if $version < $KEEPS_LABEL_SINCE and $actual_type == $known_bug_type {
        print $"KNOWN ISSUE in systemd ($version) \(fixed in ($KEEPS_LABEL_SINCE)\): [($ext.tool)] ($msg)"
    } else {
        fail_in $ext.tool $msg
    }
}

# Check that the `version` of the extension is merged. `known_bug_type`:
# see check_label
def check_merged [ext: record, version: string, known_bug_type: string] {
    if not ($ext.file | path exists) {
        diagnostics $ext
        fail_in $ext.tool $"($ext.file) from the ($EXT_NAME) extension is not visible under ($ext.hierarchy); see the diagnostics above"
    }
    let content = open --raw $ext.file | str trim
    let expected = content_of $ext $version | str trim
    if $content != $expected {
        fail_in $ext.tool $"($ext.file) holds '($content)', expected '($expected)'"
    }
    if $ext == $SYSEXT {
        run_in $ext.tool $ext.file | ignore
    }
    # The topmost mount: on ostree /etc is a bind mount, which the confext
    # overlay goes on top of
    let fs = run_in $ext.tool findmnt --json --output FSTYPE $ext.hierarchy | from json | get filesystems | last
    if $fs.fstype != "overlay" {
        fail_in $ext.tool $"($ext.hierarchy) is ($fs.fstype), expected the ($ext.tool) overlay"
    }
    check_label $ext $known_bug_type
}

def check_unmerged [ext: record] {
    if ($ext.file | path exists) {
        diagnostics $ext
        fail_in $ext.tool $"($ext.file) is still visible under ($ext.hierarchy) after unmerge"
    }
    let expected = open $LABELS_FILE | get $ext.hierarchy
    let actual = label_of $ext.hierarchy
    if $actual != $expected {
        fail_in $ext.tool $"($ext.hierarchy) is labeled ($actual) after unmerge, was ($expected)"
    }
}

def check_layout [] {
    let var = run_in layout findmnt --json --output SOURCE,FSTYPE,LABEL --target /var | from json | get filesystems.0
    print $"/var: ($var)"
    if $var.label != $VAR_LABEL {
        fail_in layout $"/var is ($var.source) \(label ($var.label)\), not the ($VAR_LABEL) partition; is it listed in /etc/fstab?"
    }
    let root = run_in layout findmnt --json --output SOURCE --target /sysroot | from json | get filesystems.0
    if $var.source == $root.source {
        fail_in layout $"/var is on the root filesystem ($root.source)"
    }
}

def check_bootc [] {
    let st = run_in bootc bootc status --json | from json
    if $st.status.booted? == null {
        fail_in bootc "bootc status shows no booted deployment"
    }
}

# What tmt needs on the guest after a reboot: this plan's directory, which
# holds the test tree, the plan's data and the tests' own directories, and
# tmt's helper scripts (TMT_SCRIPTS_DIR, which xtask sets).
def tmt_dirs [] {
    let vars = [TMT_TREE TMT_PLAN_DATA TMT_SCRIPTS_DIR]
    let missing = $vars | where {|v| ($env | get -i $v) == null }
    if ($missing | is-not-empty) {
        fail_in "test harness" $"($missing | str join ', ') not set; run this test through `cargo xtask run-tmt`"
    }
    # The plan's directory holds both its tree and its data.
    let tree = $env.TMT_TREE | path split
    let data = $env.TMT_PLAN_DATA | path split
    let common = $tree | zip $data | take while {|p| $p.0 == $p.1 } | each {|p| $p.0 }
    let dirs = [($common | path join) $env.TMT_SCRIPTS_DIR]
    print $"tmt's files: ($dirs)"
    for d in $dirs {
        if not ($d | str starts-with "/var/") or not ($d | path exists) {
            fail_in "test harness" $"($d) from tmt's environment is not a directory under /var, where the test expects tmt's files"
        }
    }
    $dirs
}

def partitions [disk: string] {
    let r = do { ^sfdisk --json $disk } | complete
    if $r.exit_code != 0 {
        fail_in layout $"`sfdisk --json ($disk)` failed: ($r.stderr | str trim)"
    }
    $r.stdout | from json | get partitiontable.partitions
}

# Like test-composefs-xbootldr.nu, stop what could mount the ESP again while
# it is rewritten, then unmount it. Only units that mount the ESP itself: on
# ostree, boot.mount is a bind mount of the root filesystem's /boot, which
# must stay.
def release_esp [esp_dev: string] {
    let esp_real = ^readlink -f $esp_dev | str trim
    let automounts = ^systemctl list-units --all --type=automount --plain --no-legend --full
        | lines | where {|l| $l != "" } | each {|l| $l | split row " " | first }
    for automount in $automounts {
        let where = ^systemctl show -P Where $automount | str trim
        let mount = ^systemd-escape -p --suffix=mount $where | str trim
        let what = ^systemctl show -P What $mount | str trim
        if $what != "" and (^readlink -f $what | str trim) == $esp_real {
            run_in layout systemctl stop $automount $mount
        }
    }
    for t in (^findmnt -rn -o TARGET -S $esp_dev | lines) {
        run_in layout umount $t
    }
}

# Shrink the ESP to ESP_MIB and put an empty /var partition after it, in the
# rest of its space. Returns the new partition's device.
def make_var_partition [disk: string] {
    let esp = partitions $disk | where {|p| ($p.type | str upcase) == $ESP_TYPE } | first
    let esp_nr = $esp.node | str replace -r '.*[^0-9]' '' | into int
    let esp_uuid = run_in layout blkid -s UUID -o value $esp.node | str trim
    let esp_partuuid = run_in layout blkid -s PARTUUID -o value $esp.node | str trim
    let esp_sectors = $ESP_MIB * 1024 * 1024 / $SECTOR_SIZE
    let var_sectors = $esp.size - $esp_sectors
    if $var_sectors * $SECTOR_SIZE < $VAR_MIN_MIB * 1024 * 1024 {
        fail_in layout $"the ESP ($esp.node) has ($esp.size) sectors, too few to make a ($VAR_MIN_MIB)M /var out of"
    }
    print $"Shrinking the ESP ($esp.node) to ($ESP_MIB)M for a /var partition after it"

    let esp_mnt = "/run/bootc-test-esp"
    let esp_backup = "/run/bootc-test-esp-backup"
    release_esp $esp.node
    mkdir $esp_mnt
    run_in layout mount $esp.node $esp_mnt
    run_in layout cp -a -T $esp_mnt $esp_backup
    run_in layout umount $esp_mnt

    let var_start = $esp.start + $esp_sectors
    let used_nrs = partitions $disk | each {|p| $p.node | str replace -r '.*[^0-9]' '' | into int }
    let var_nr = 1..128 | where {|n| $n not-in $used_nrs } | first
    # As in test-composefs-xbootldr.nu: root is mounted, so update the
    # kernel's partitions one at a time while holding the disk's lock
    # against systemd-udevd.
    let script = '
        set -euo pipefail
        disk=$1 esp_nr=$2 esp_spec=$3 var_nr=$4 var_spec=$5
        echo "$esp_spec" | sfdisk --lock=no --no-reread -N "$esp_nr" "$disk"
        echo "$var_spec" | sfdisk --lock=no --no-reread -N "$var_nr" "$disk"
        partx -u --nr "$esp_nr" "$disk"
        partx -a --nr "$var_nr" "$disk"
    '
    (run_in layout udevadm lock $"--device=($disk)" bash -c $script bash $disk $"($esp_nr)"
        $"start=($esp.start), size=($esp_sectors), type=($ESP_TYPE)"
        $"($var_nr)" $"start=($var_start), size=($var_sectors), type=($VAR_PART_TYPE), name=($VAR_PARTLABEL)")
    run_in layout udevadm settle
    let var_dev = partitions $disk | where start == $var_start | first | get node
    for p in [[node sectors]; [$esp.node $esp_sectors] [$var_dev $var_sectors]] {
        let sysfs = $"/sys/class/block/($p.node | path basename)/size"
        if not ($sysfs | path exists) {
            fail_in layout $"the kernel doesn't know ($p.node) after repartitioning"
        }
        let size = open --raw $sysfs | str trim | into int
        if $size != $p.sectors {
            fail_in layout $"the kernel has ($p.node) at ($size) sectors, expected ($p.sectors)"
        }
    }
    let partuuid = run_in layout blkid -s PARTUUID -o value $esp.node | str trim
    if $partuuid != $esp_partuuid {
        fail_in layout $"the ESP's PARTUUID changed from ($esp_partuuid) to ($partuuid)"
    }

    # Keep the ESP's filesystem UUID, in case something refers to it.
    run_in layout mkfs.vfat -F 32 -n EFI-SYSTEM -i ($esp_uuid | str replace "-" "") $esp.node
    run_in layout udevadm settle
    run_in layout mount $esp.node $esp_mnt
    run_in layout cp -r -T $esp_backup $esp_mnt
    run_in layout umount $esp_mnt
    rm -rf $esp_backup

    run_in layout mkfs.xfs -q -L $VAR_LABEL $var_dev
    run_in layout sfdisk -l $disk | ignore
    $var_dev
}

def first_boot [] {
    tap begin "systemd-sysext and systemd-confext on a separate, initially empty /var"

    let root_dev = run_in layout findmnt --noheadings --nofsroot --output SOURCE --target /sysroot | str trim
    let disk = "/dev/" + (run_in layout lsblk --nodeps --noheadings --output PKNAME $root_dev | str trim)
    print $"Root is ($root_dev) on ($disk)"
    let var_dev = make_var_partition $disk

    # Carry over tmt's files and nothing else, with their SELinux labels.
    let srcs = tmt_dirs | each {|d| $"/var/./($d | path relative-to /var)" }
    let mnt = "/run/bootc-test-var"
    mkdir $mnt
    run_in layout mount $var_dev $mnt
    if (do { ^selinuxenabled } | complete).exit_code == 0 {
        run_in layout chcon --reference=/var $mnt
    }
    run_in "test harness" rsync -aRX ...$srcs $"($mnt)/"
    run_in layout umount $mnt

    "" | save $OLD_VAR_MARKER
    # No nofail: it doesn't help, boot still waits for /var's device
    # without a time limit, and tmt times out on the reboot.
    $"LABEL=($VAR_LABEL) /var xfs defaults 0 0\n" | save --append /etc/fstab
    print (open /etc/fstab)

    tmt-reboot
}

def second_boot [] {
    check_layout
    if ($OLD_VAR_MARKER | path exists) {
        fail_in layout $"($OLD_VAR_MARKER) is on the new /var, so it is not the empty partition"
    }
    for d in [$SYSEXT.dir $CONFEXT.dir] {
        if ($d | path dirname | path exists) {
            fail_in layout $"($d | path dirname) already exists on the new /var"
        }
    }
    check_bootc

    { "/usr": (label_of /usr), "/etc": (label_of /etc) } | to json | save $LABELS_FILE
    print $"systemd (systemd_version), labels before merging: (open $LABELS_FILE)"
    let exts = extensions
    if $CONFEXT not-in $exts {
        print $"SKIP [systemd-confext] systemd (systemd_version) has no systemd-confext \(part of systemd since ($CONFEXT_SINCE)\); testing the sysext only"
    }

    for ext in $exts {
        make_extension $ext v1
        run_in $ext.tool $ext.tool merge
        check_merged $ext v1 $SHELL_MERGE_BUG_TYPE
        # bootc still works with the hierarchy overlaid
        check_bootc

        run_in $ext.tool $ext.tool unmerge
        check_unmerged $ext

        # Refresh a live overlay: replace the merged extension with a new
        # version, which only a refresh makes visible.
        run_in $ext.tool $ext.tool merge
        check_merged $ext v1 $SHELL_MERGE_BUG_TYPE
        mkdir $REPLACED_DIR
        mv $ext.dir $"($REPLACED_DIR)/($ext.tool)"
        make_extension $ext v2
        run_in $ext.tool $ext.tool refresh
        check_merged $ext v2 $SHELL_MERGE_BUG_TYPE
        rm -rf $"($REPLACED_DIR)/($ext.tool)"
        # Unmerge again before tmt logs in for the reboot (see check_label),
        # and leave merging to the service from here on.
        run_in $ext.tool $ext.tool unmerge
        check_unmerged $ext
    }

    # Enable both services before either merges: a merged confext makes /etc
    # read-only.
    let services = $exts | each {|e| $"($e.tool).service" }
    run_in systemd systemctl enable ...$services
    for ext in $exts {
        run_in $ext.tool systemctl start $"($ext.tool).service"
        check_merged $ext v2 $SERVICE_MERGE_BUG_TYPE
    }

    tmt-reboot
}

# No unit may fail in a boot with the extensions merged. bootc's own are
# reported as [bootc], the others against the extension most likely to have
# caused it: the confext, which makes /etc read-only, if there is one.
def check_failed_units [] {
    let exts = extensions
    let blamed = ($exts | last).tool
    # Units still starting can fail later, so wait for the boot to settle
    # first; degraded means some failed, which is checked below.
    let state = do { ^timeout $"($BOOT_WAIT_SECS)" systemctl is-system-running --wait } | complete | get stdout | str trim
    if $state not-in [running degraded] {
        let jobs = do { ^systemctl list-jobs --no-pager } | complete | get stdout | str trim
        fail_in $blamed $"the boot with the extensions merged didn't settle within ($BOOT_WAIT_SECS)s, systemd is '($state)':\n($jobs)"
    }
    let failed = ^systemctl list-units --failed --plain --no-legend --full
        | lines | where {|l| $l != "" } | each {|l| $l | split row " " | first }
    for unit in $failed {
        let log = do { ^journalctl -b --no-pager -n 5 -u $unit } | complete | get stdout | str trim
        let component = if ($unit | str starts-with "bootc") { "bootc" } else { $blamed }
        fail_in $component $"($unit) failed in a boot with ($exts | each {|e| $e.tool } | str join ' and ') merged:\n($log)"
    }
}

def third_boot [] {
    check_layout
    for ext in (extensions) {
        let service = $"($ext.tool).service"
        let state = do { ^systemctl is-active $service } | complete | get stdout | str trim
        if $state != "active" {
            diagnostics $ext
            fail_in $ext.tool $"($service) is ($state) after boot, not active"
        }
        check_merged $ext v2 $SERVICE_MERGE_BUG_TYPE
    }
    check_bootc
    check_failed_units

    for ext in (extensions) {
        run_in $ext.tool systemctl stop $"($ext.tool).service"
        check_unmerged $ext
    }

    tap ok
}

def main [] {
    try {
        match $env.TMT_REBOOT_COUNT? {
            null | "0" => first_boot,
            "1" => second_boot,
            "2" => third_boot,
            $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
        }
    } catch {|err|
        # A /usr merged from a shell can lock tmt out (see check_label), so
        # unmerge before failing: tmt has to log in again to collect the
        # results.
        # Not `extensions`, which can fail itself
        for ext in ([$SYSEXT $CONFEXT] | where {|e| has_tool $e }) {
            let r = do { run-external $ext.tool unmerge } | complete
            if $r.exit_code != 0 {
                print $"($ext.tool) unmerge after the failure failed too, tmt may not be able to log in: ($r.stderr | str trim)"
            }
        }
        # fail_in's own errors start with the component; anything else is a
        # runtime error, whose location is in the debug form.
        if not ($err.msg | str starts-with "[") {
            print $"Error details: ($err.debug)"
        }
        error make { msg: $err.msg }
    }
}
