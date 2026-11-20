# bootc internals fsck

Experimental features are subject to change or removal. Please
do provide feedback on them.

## Using `bootc internals fsck`

The default command is a legacy CI check. It initializes normal bootc storage
and therefore may prepare `/sysroot` for writes; it is not a readonly
diagnostic interface.

Use `bootc internals fsck --readonly` to inspect only existing state and
already-visible mounts. It never initializes or upgrades composefs, mounts an
ESP, migrates state, or remounts `/sysroot`.

Use `bootc internals fsck --report` for a bounded, pretty JSON report on
standard output. `--report` implies `--readonly`; diagnostic messages are sent
only to standard error. The report is intentionally an experimental document,
not a versioned JSON schema, and it redacts credentials and kernel arguments.
It reports incomplete collection and findings with exit status 1; healthy
collection exits 0.

Collection is deliberately bounded: deployment and boot-entry enumeration,
findings, individual files, and total file reads have bounded limits recorded in
the report. The collector refuses symlinks and non-regular report inputs,
reports unavailable APIs rather than using unbounded repository enumeration,
and marks a report incomplete when a limit, read error, or collection race is
observed.

The report includes classification evidence rather than assuming a bootloader
from BLS entries alone. It inventories active and staged BLS entries and GRUB
`user.cfg` menus using bootc's parsers, with kernel arguments and GRUB search
arguments redacted. Referenced regular boot artifacts are statted without
reading payloads; small UKIs may expose bounded text metadata only. An ESP is
inventoried only when it is already mounted in the caller's mount namespace;
the command never mounts or remounts it. Parse failures, unavailable data, and
missing artifacts are recorded as findings and graph edges identify the related
entry, deployment, artifact, or composefs identity.
