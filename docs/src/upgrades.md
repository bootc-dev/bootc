# Managing upgrades

Right now, bootc is a quite simple tool that is designed to do just
a few things well.  One of those is transactionally fetching new operating system
updates from a registry and booting into them, while supporting rollback.

## The `bootc upgrade` verb

This will query the registry and queue an updated container image for the next boot.

This is backed today by ostree, implementing an A/B style upgrade system.
Changes to the base image are staged, and the running system is not
changed by default.

Use `bootc upgrade --apply` to auto-apply if there are queued changes.

### Staged updates with `--download-only`

The `--download-only` flag allows you to prepare updates without automatically applying
them on the next reboot:

```shell
bootc upgrade --download-only
```

This will pull the new container image from the registry and create a staged deployment
that is **locked** from automatic application. The deployment will not be applied on
shutdown or reboot until it is explicitly unlocked.

#### Checking lock status

To see whether a staged deployment is locked, use:

```shell
bootc status --verbose
```

In the output, you'll see `Locked: yes` for locked deployments or `Locked: no` for unlocked
deployments. The lock status is only shown in verbose mode.

#### Applying locked updates

There are two ways to apply a locked staged update:

**Option 1: Apply immediately with reboot**

```shell
bootc upgrade --apply
```

This will unlock the staged deployment (if locked) and immediately reboot into it.

**Option 2: Unlock for automatic application**

```shell
bootc upgrade
```

Running `bootc upgrade` without flags on an already-staged locked deployment will unlock it.
The deployment will then be applied automatically on the next shutdown or reboot.

#### Checking for updates without side effects

To check if updates are available without modifying the lock state:

```shell
bootc upgrade --check
```

This only downloads updated metadata without changing the finalization lock state.

#### Example workflow

A typical workflow for controlled updates:

```shell
# 1. Download and lock the update
bootc upgrade --download-only

# 2. Verify the staged deployment
bootc status --verbose
# Output shows: Locked: yes

# 3. Test or wait for maintenance window...

# 4. Apply the update (choose one):
# Option A: Unlock and let it apply on next shutdown
bootc upgrade

# Option B: Apply immediately with reboot
bootc upgrade --apply
```

**Important**: If you reboot before applying a locked update, the system will boot into the
current deployment and the staged deployment will be discarded. However, the downloaded image
data remains cached, so re-running `bootc upgrade --download-only` will be fast and won't
re-download the container image.

There is also an opinionated `bootc-fetch-apply-updates.timer` and corresponding
service available in upstream for operating systems and distributions
to enable.

Man page: [bootc-upgrade](man/bootc-upgrade.8.md).

## Changing the container image source

Another useful pattern to implement can be to use a management agent
to invoke `bootc switch` (or declaratively via `bootc edit`)
to implement e.g. blue/green deployments,
where some hosts are rolled onto a new image independently of others.

```shell
bootc switch quay.io/examplecorp/os-prod-blue:latest
```

`bootc switch` has the same effect as `bootc upgrade`; there is no
semantic difference between the two other than changing the
container image being tracked.

This will preserve existing state in `/etc` and `/var` - for example,
host SSH keys and home directories.

Man page: [bootc-switch](man/bootc-switch.8.md).

## Rollback

There is a  `bootc rollback` verb, and associated declarative interface
accessible to tools via `bootc edit`.  This will swap the bootloader
ordering to the previous boot entry.

Man page: [bootc-rollback](man/bootc-rollback.8.md).


