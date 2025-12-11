# Managing upgrades

Right now, bootc is a quite simple tool that is designed to do just
a few things well.  One of those is transactionally fetching new operating system
updates from a registry and booting into them, while supporting rollback.

## The `bootc upgrade` verb

This will query the container image source and queue an updated container image for the next boot.

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

This will pull the new container image from the container image source and create a staged deployment
in download-only mode. The deployment will not be applied on shutdown or reboot until
you explicitly apply it.

#### Checking download-only status

To see whether a staged deployment is in download-only mode, use:

```shell
bootc status --verbose
```

In the output, you'll see `Download-only: yes` for deployments in download-only mode or
`Download-only: no` for deployments that will apply automatically. This status is only shown in verbose mode.

#### Applying download-only updates

There are three ways to apply a staged update that is in download-only mode:

**Option 1: Apply the staged update without checking for newer updates**

```shell
bootc upgrade --from-downloaded
```

This unlocks the staged deployment for automatic application on the next shutdown or reboot,
without fetching updates from the container image source. This is useful when you want to apply the
already-downloaded update at a scheduled time.

**Option 2: Apply the staged update and reboot immediately**

```shell
bootc upgrade --from-downloaded --apply
```

This unlocks the staged deployment and immediately reboots into it, without checking for
newer updates.

**Option 3: Check for newer updates and apply**

```shell
bootc upgrade
```

Running `bootc upgrade` without flags will pull from the container image source to check for updates.
If the staged deployment matches the latest available update, it will be unlocked. If a newer update is
available, the staged deployment will be replaced with the newer version.

#### Checking for updates without side effects

To check if updates are available without modifying the download-only state:

```shell
bootc upgrade --check
```

This only downloads updated metadata without changing the download-only state.

#### Example workflow

A typical workflow for controlled updates:

```shell
# 1. Download the update in download-only mode
bootc upgrade --download-only

# 2. Verify the staged deployment
bootc status --verbose
# Output shows: Download-only: yes

# 3. Test or wait for maintenance window...

# 4. Apply the update (choose one):
# Option A: Apply staged update without fetching from image source
bootc upgrade --from-downloaded

# Option B: Apply staged update and reboot immediately (without fetching from image source)
bootc upgrade --from-downloaded --apply

# Option C: Check for newer updates first, then apply
bootc upgrade
```

**Important notes**:

- **Image source check difference**: `bootc upgrade --from-downloaded` does NOT fetch from the
  container image source to check for newer updates, while `bootc upgrade` always does.
  Use `--from-downloaded` when you want to apply the specific version you already downloaded,
  regardless of whether newer updates are available.

- If you reboot before applying a download-only update, the system will boot into the
  current deployment and the staged deployment will be discarded. However, the downloaded image
  data remains cached, so re-running `bootc upgrade --download-only` will be fast and won't
  re-download the container image.

- If you switch to a different image (using `bootc switch` or `bootc upgrade` to a different
  image), the new staged deployment will replace the previous download-only deployment, and the
  previously cached image will become eligible for garbage collection.

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


