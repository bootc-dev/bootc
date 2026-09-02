use std assert
use tap.nu

tap begin "Run fsck"

# The readonly variants do not initialize storage and work on either backend.
bootc internals fsck --readonly
let report = bootc internals fsck --report | from json
assert equal $report.collection.mode readonly
assert equal $report.report_version 1
# Parsing the command output proves that report mode leaves stdout as JSON only.
assert ($report.bootloader.classification | is-not-empty)
assert ($report.bootloader.esp.status | is-not-empty)
# nushell describes a non-empty list of records as a table
assert (($report.boot_entries | describe) =~ '^(list|table)')

tap ok
