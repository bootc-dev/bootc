#!/bin/bash
# Both local and Packit runs prepare one package-mode guest, then migrate and
# reboot that same guest. Local TMT workdirs are staged under preserved /var.
set -xeuo pipefail

target_image=localhost/bootc-preserve-var-test
var_state=/var/lib/bootc-tmt-preserve-var
app_state=$var_state/app-state/state
log_fs_image=$var_state/logfs.img
empty_tmpfs=$var_state/empty_tmpfs
empty_tmpfs_marker=$empty_tmpfs/marker
bind_dir=/var/lib/bootc-tmt-preserve-var-bind
bind_source=$bind_dir/source
bind_target=$bind_dir/target
preflight_mountpoint=$var_state/preflight-special
tmt_plan_data_suffix=/tmt/plans/package-mode/data
tmt_plan_data_sentinel_name=plan-workdir-persistence-sentinel
tmt_artifacts_parent=/var/ARTIFACTS
tmt_test_data_sentinel_name=workdir-persistence-sentinel
tmt_test_data_post_reboot_marker_name=post-reboot-marker
postgres_version_file=/var/lib/pgsql/data/PG_VERSION
freeze_may_be_active=0
persistent_tmt_root=
persistent_run_dir=

is_always_excluded_var_path() {
    case $1 in
        /var/tmp|/var/tmp/*|/var/cache|/var/cache/*|/var/log/journal|/var/log/journal/*|/var/lib/containers|/var/lib/containers/*)
            return 0
            ;;
    esac
    return 1
}

verify_tmt_workdir_directory() {
    local run_dir=$1
    local canonical_run_dir=$2

    if [[ ! -d $run_dir || -L $run_dir ]]; then
        printf 'TMT workdir is missing or not a real directory: %s\n' "$run_dir" >&2
        return 1
    fi
    if is_always_excluded_var_path "$canonical_run_dir"; then
        printf 'TMT workdir is excluded from preserve-var: %s\n' \
            "$canonical_run_dir" >&2
        return 1
    fi
}

cleanup_log_freeze() {
    local status=$?

    # Prevent a second signal from interrupting or reentering the thaw attempt.
    trap '' HUP INT TERM
    trap - EXIT
    set +e
    if (( freeze_may_be_active )); then
        if fsfreeze -u /var/log; then
            freeze_may_be_active=0
        else
            printf 'Failed to thaw /var/log during cleanup\n' >&2
            if (( status == 0 )); then
                status=1
            fi
        fi
    fi
    exit "$status"
}

get_tmt_run_dir() {
    local plan_data=${TMT_PLAN_DATA:-}
    local run_dir
    local resolved_plan_data
    local resolved_run_dir
    local workdir_root=${PACKAGE_MODE_TMT_WORKDIR_ROOT:-}
    local resolved_workdir_root
    local run_id

    if [[ $plan_data != *"$tmt_plan_data_suffix" ]]; then
        printf 'TMT_PLAN_DATA must end in %s (got %q)\n' "$tmt_plan_data_suffix" "$plan_data" >&2
        return 1
    fi
    run_dir=${plan_data%"$tmt_plan_data_suffix"}
    if [[ -n $workdir_root ]]; then
        if [[ $workdir_root != /* || $workdir_root == */ ]]; then
            printf 'PACKAGE_MODE_TMT_WORKDIR_ROOT must be an absolute path without a trailing slash (got %q)\n' \
                "$workdir_root" >&2
            return 1
        fi
        resolved_workdir_root=$(realpath -e -- "$workdir_root") || {
            printf 'TMT workdir root does not exist: %s\n' "$workdir_root" >&2
            return 1
        }
        if [[ $resolved_workdir_root == /var/* ]] && \
            is_always_excluded_var_path "$resolved_workdir_root"; then
            printf 'TMT workdir root is excluded from preserve-var: %s\n' \
                "$resolved_workdir_root" >&2
            return 1
        fi
        case $run_dir in
            "$workdir_root"/run-*)
                run_id=${run_dir#"$workdir_root"/}
                ;;
            "$resolved_workdir_root"/run-*)
                run_id=${run_dir#"$resolved_workdir_root"/}
                ;;
            *)
                printf 'Expected TMT run directory under configured root %q (got %q)\n' \
                    "$workdir_root" "$run_dir" >&2
                return 1
                ;;
        esac
        if [[ ! $run_id =~ ^run-[[:alnum:]_.-]+$ ]]; then
            printf 'Unexpected TMT run directory under configured root: %q\n' \
                "$run_dir" >&2
            return 1
        fi
        resolved_run_dir=$(realpath -e -- "$run_dir") || {
            printf 'TMT run directory does not exist: %s\n' "$run_dir" >&2
            return 1
        }
        if [[ $resolved_run_dir != "$resolved_workdir_root/$run_id" ]]; then
            printf 'TMT run directory must be a real directory below its configured root (got %q -> %q)\n' \
                "$run_dir" "$resolved_run_dir" >&2
            return 1
        fi
        verify_tmt_workdir_directory "$run_dir" "$resolved_run_dir" || return 1
        case $resolved_run_dir in
            /var/*) verify_tmt_workdir_in_preserved_var "$resolved_run_dir" || return 1 ;;
        esac
        resolved_plan_data=$(realpath -e -- "$plan_data") || {
            printf 'TMT_PLAN_DATA does not exist: %s\n' "$plan_data" >&2
            return 1
        }
        if [[ $resolved_plan_data != "$resolved_run_dir$tmt_plan_data_suffix" ]]; then
            printf 'TMT_PLAN_DATA resolves outside its run directory (got %q -> %q)\n' \
                "$plan_data" "$resolved_plan_data" >&2
            return 1
        fi
    elif [[ $run_dir =~ ^/var/ARTIFACTS/work-[[:alnum:]_.-]+$ ]]; then
        resolved_run_dir=$(realpath -e -- "$run_dir") || {
            printf 'TMT artifact workdir does not exist: %s\n' "$run_dir" >&2
            return 1
        }
        verify_tmt_workdir_directory "$run_dir" "$resolved_run_dir" || return 1
        if [[ $resolved_run_dir != "$run_dir" ]]; then
            printf 'TMT artifact workdir must be canonical (got %q -> %q)\n' \
                "$run_dir" "$resolved_run_dir" >&2
            return 1
        fi
        case $resolved_run_dir in
            /var/*) ;;
            *)
                printf 'TMT artifact workdir must resolve under /var (got %q)\n' \
                    "$resolved_run_dir" >&2
                return 1
                ;;
        esac
        resolved_plan_data=$(realpath -e -- "$plan_data") || {
            printf 'TMT_PLAN_DATA does not exist: %s\n' "$plan_data" >&2
            return 1
        }
        if [[ $resolved_plan_data != "$resolved_run_dir$tmt_plan_data_suffix" ]]; then
            printf 'TMT_PLAN_DATA resolves outside its run directory (got %q -> %q)\n' \
                "$plan_data" "$resolved_plan_data" >&2
            return 1
        fi
    else
        printf 'Expected TMT workdir under PACKAGE_MODE_TMT_WORKDIR_ROOT or %s (got %q)\n' \
            "$tmt_artifacts_parent" "$run_dir" >&2
        return 1
    fi
    case ${TMT_REBOOT_COUNT:-0} in
        0|1|2) ;;
        *)
            printf 'Unexpected TMT_REBOOT_COUNT=%s\n' "${TMT_REBOOT_COUNT}" >&2
            return 1
            ;;
    esac
    printf '%s\n' "$run_dir"
}

verify_tmt_workdir_in_preserved_var() {
    local run_dir=$1
    local resolved_run_dir
    local mount_target

    if ! resolved_run_dir=$(realpath -e -- "$run_dir"); then
        printf 'TMT workdir path does not exist: %s\n' "$run_dir" >&2
        return 1
    fi
    case $resolved_run_dir in
        /var/*) ;;
        *)
            printf 'TMT workdir must resolve under preserved /var (got %q -> %q)\n' \
                "$run_dir" "$resolved_run_dir" >&2
            return 1
            ;;
    esac
    if is_always_excluded_var_path "$resolved_run_dir"; then
        printf 'TMT workdir is excluded from preserve-var: %s\n' \
            "$resolved_run_dir" >&2
        return 1
    fi
    if ! mount_target=$(findmnt --noheadings --output TARGET --target "$resolved_run_dir"); then
        printf 'Could not determine the filesystem containing TMT workdir %s\n' \
            "$run_dir" >&2
        return 1
    fi
    # A nested mount is excluded from preserve-var even if it is below /var.
    if [[ $mount_target != / && $mount_target != /var ]]; then
        printf 'TMT workdir %s is on nested mount %s, which --preserve-var does not copy\n' \
            "$run_dir" "$mount_target" >&2
        return 1
    fi
}

prepare_tmt_workdir_persistence() {
    local run_dir=$1
    local resolved_run_dir
    local canonical_plan_data
    local canonical_test_data
    local canonical_metadata
    local stage_parent
    local stage_run_dir
    local plan_sentinel
    local test_sentinel
    local data_path

    resolved_run_dir=$(realpath -e -- "$run_dir") || return 1
    set_persistent_tmt_paths "$run_dir" || return 1

    canonical_plan_data=$(realpath -e -- "$TMT_PLAN_DATA") || return 1
    canonical_test_data=$(realpath -e -- "$TMT_TEST_DATA") || return 1
    canonical_metadata=$(realpath -e -- "$TMT_TEST_METADATA") || return 1
    for data_path in "$canonical_plan_data" "$canonical_test_data" "$canonical_metadata"; do
        case $data_path in
            "$resolved_run_dir"/*) ;;
            *)
                printf 'TMT data path is outside its run directory: %s\n' \
                    "$data_path" >&2
                return 1
                ;;
        esac
    done
    if [[ ! -d $canonical_plan_data || ! -d $canonical_test_data || ! -f $canonical_metadata ]]; then
        printf 'TMT plan data, test data, or metadata is missing from %s\n' \
            "$resolved_run_dir" >&2
        return 1
    fi
    plan_sentinel=$canonical_plan_data/$tmt_plan_data_sentinel_name
    test_sentinel=$canonical_test_data/$tmt_test_data_sentinel_name
    if [[ ! -f $plan_sentinel || ! -f $test_sentinel || \
        $(<"$plan_sentinel") != plan-workdir-persistence-sentinel || \
        $(<"$test_sentinel") != workdir-persistence-sentinel ]]; then
        printf 'TMT source plan/test data sentinels do not match expected values\n' >&2
        return 1
    fi

    if is_always_excluded_var_path "$persistent_run_dir"; then
        printf 'Persistent TMT workdir is excluded from preserve-var: %s\n' \
            "$persistent_run_dir" >&2
        return 1
    fi
    if [[ $resolved_run_dir != "$persistent_run_dir" ]]; then
        install -d -m 0755 -- "$persistent_tmt_root"
        verify_tmt_workdir_in_preserved_var "$persistent_tmt_root"
        if [[ -L $persistent_run_dir ]]; then
            printf 'Refusing symlink at persistent TMT workdir destination: %s\n' \
                "$persistent_run_dir" >&2
            return 1
        elif [[ -e $persistent_run_dir ]]; then
            printf 'Refusing to overwrite existing persistent TMT workdir: %s\n' \
                "$persistent_run_dir" >&2
            return 1
        fi

        stage_parent=$(mktemp -d -- "$persistent_tmt_root/.${persistent_run_dir##*/}.stage.XXXXXX")
        stage_run_dir=$stage_parent/${persistent_run_dir##*/}
        (
            set -euo pipefail
            trap 'rm -rf -- "$stage_parent"' EXIT
            cp --reflink=auto -a -- "$resolved_run_dir" "$stage_run_dir"
            cmp -- "$canonical_metadata" "$stage_run_dir/${canonical_metadata#"$resolved_run_dir"/}"
            cmp -- "$plan_sentinel" \
                "$stage_run_dir/${canonical_plan_data#"$resolved_run_dir"/}/$tmt_plan_data_sentinel_name"
            cmp -- "$test_sentinel" \
                "$stage_run_dir/${canonical_test_data#"$resolved_run_dir"/}/$tmt_test_data_sentinel_name"
            if [[ -L $persistent_run_dir ]]; then
                printf 'Refusing symlink at persistent TMT workdir destination: %s\n' \
                    "$persistent_run_dir" >&2
                exit 1
            elif [[ -e $persistent_run_dir ]]; then
                printf 'Refusing to overwrite existing persistent TMT workdir: %s\n' \
                    "$persistent_run_dir" >&2
                exit 1
            fi
            mv -Tn -- "$stage_run_dir" "$persistent_run_dir"
            if [[ -e $stage_run_dir || -L $persistent_run_dir || ! -d $persistent_run_dir ]]; then
                printf 'Could not publish staged TMT workdir at %s\n' "$persistent_run_dir" >&2
                exit 1
            fi
        )
    fi
    if [[ -L $persistent_run_dir || ! -d $persistent_run_dir ]]; then
        printf 'Persistent TMT workdir is missing or is a symlink: %s\n' \
            "$persistent_run_dir" >&2
        return 1
    fi
    if [[ $(realpath -e -- "$persistent_run_dir") != "$persistent_run_dir" ]]; then
        printf 'Persistent TMT workdir does not resolve to its canonical destination: %s\n' \
            "$persistent_run_dir" >&2
        return 1
    fi
    cmp -- "$canonical_metadata" "$persistent_run_dir/${canonical_metadata#"$resolved_run_dir"/}"
    cmp -- "$plan_sentinel" \
        "$persistent_run_dir/${canonical_plan_data#"$resolved_run_dir"/}/$tmt_plan_data_sentinel_name"
    cmp -- "$test_sentinel" \
        "$persistent_run_dir/${canonical_test_data#"$resolved_run_dir"/}/$tmt_test_data_sentinel_name"
    verify_tmt_workdir_in_preserved_var "$persistent_run_dir"
}

set_persistent_tmt_paths() {
    local run_dir=$1
    local workdir_root=${PACKAGE_MODE_TMT_WORKDIR_ROOT:-}
    local canonical_root
    local canonical_run_dir
    local run_id

    if [[ -n $workdir_root ]]; then
        canonical_root=$(realpath -e -- "$workdir_root") || {
            printf 'TMT workdir root does not exist: %s\n' "$workdir_root" >&2
            return 1
        }
        case $run_dir in
            "$workdir_root"/run-*) run_id=${run_dir#"$workdir_root"/} ;;
            "$canonical_root"/run-*) run_id=${run_dir#"$canonical_root"/} ;;
            *)
                printf 'TMT run directory is not a direct run-* child of its root: %s\n' \
                    "$run_dir" >&2
                return 1
                ;;
        esac
        if [[ ! $run_id =~ ^run-[[:alnum:]_.-]+$ ]]; then
            printf 'Unexpected TMT run ID: %q\n' "$run_id" >&2
            return 1
        fi
    else
        canonical_root=$(realpath -e -- "$tmt_artifacts_parent") || {
            printf 'TMT artifact root does not exist: %s\n' "$tmt_artifacts_parent" >&2
            return 1
        }
        if [[ $canonical_root != "$tmt_artifacts_parent" ||
            ! $run_dir =~ ^/var/ARTIFACTS/work-[[:alnum:]_.-]+$ ]]; then
            printf 'Unexpected TMT artifact root or run directory: %q\n' "$run_dir" >&2
            return 1
        fi
        run_id=${run_dir##*/}
    fi

    canonical_run_dir=$(realpath -e -- "$run_dir") || {
        printf 'TMT run directory does not exist: %s\n' "$run_dir" >&2
        return 1
    }
    if [[ $canonical_run_dir != "$canonical_root/$run_id" ]]; then
        printf 'TMT run directory is not the canonical direct child of its root (%q -> %q)\n' \
            "$run_dir" "$canonical_run_dir" >&2
        return 1
    fi

    case $canonical_root in
        /home/*) persistent_tmt_root=/var/home/${canonical_root#/home/} ;;
        /var/home/*|/var/ARTIFACTS|/var/ARTIFACTS/*) persistent_tmt_root=$canonical_root ;;
        *)
            printf 'Unsupported canonical TMT root; expected /home, /var/home, or /var/ARTIFACTS: %s\n' \
                "$canonical_root" >&2
            return 1
            ;;
    esac
    persistent_run_dir=$persistent_tmt_root/$run_id
}

is_local_tmt_workdir() {
    local workdir_root=${PACKAGE_MODE_TMT_WORKDIR_ROOT:-}
    local resolved_workdir_root

    [[ -n $workdir_root ]] || return 1
    if [[ $1 == "$workdir_root"/run-* ]]; then
        return 0
    fi
    resolved_workdir_root=$(realpath -e -- "$workdir_root") || return 1
    [[ $1 == "$resolved_workdir_root"/run-* ]]
}

case ${TMT_REBOOT_COUNT:-0} in
    0)
        test ! -e /run/ostree-booted
        # Always request the disabled source boot; this is harmless when the
        # initial VM already has the argument and makes reboot accounting stable.
        grubby --update-kernel=ALL --args=selinux=0
        tmt-reboot
        ;;
    1)
        podman --remote=false image exists "$target_image"

        # This must be a real HostDisabled boot, not setenforce or a container
        # label override. /proc/1/root checks the host's SELinux filesystem.
        test ! -e /run/ostree-booted
        grep -Eq '(^|[[:space:]])selinux=0([[:space:]]|$)' /proc/cmdline
        test "$(getenforce)" = Disabled
        test ! -e /proc/1/root/sys/fs/selinux/enforce

        tmt_run_dir=$(get_tmt_run_dir)
        if [[ ! -d $tmt_run_dir || -L $tmt_run_dir ]]; then
            printf 'TMT workdir is missing or not a real directory: %s\n' "$tmt_run_dir" >&2
            exit 1
        fi

        test ! -e "$app_state"
        test ! -e "$postgres_version_file"
        install -d -m 0755 "$var_state" "${app_state%/*}" "$bind_source" "$bind_target"
        printf '%s\n' preserved-application-state > "$app_state"
        printf '%s\n' bind-source-data > "$bind_source/sentinel"
        printf '%s\n' bind-mounted-data > "$bind_source/mounted-sentinel"
        printf '%s\n' underlying-target-data > "$bind_target/underlying-sentinel"
        mount --bind "$bind_source" "$bind_target"
        test "$(<"$bind_target/mounted-sentinel")" = bind-mounted-data
        test ! -e "$bind_target/underlying-sentinel"

        # Seed a database using the new deployment's own PostgreSQL version so
        # the test also works when the guest and bootc base use different OSes.
        podman --remote=false run --rm \
            -v /var/lib/pgsql:/var/lib/pgsql "$target_image" \
            bash -euo pipefail -c '
                postgresql-setup --initdb
                runuser -u postgres -- pg_ctl -D /var/lib/pgsql/data \
                    -o "-c listen_addresses=localhost" -w start
                runuser -u postgres -- psql -v ON_ERROR_STOP=1 \
                    -c "CREATE DATABASE bootc_preserve_var"
                runuser -u postgres -- psql -v ON_ERROR_STOP=1 -d bootc_preserve_var \
                    -c "CREATE TABLE app_state (id integer PRIMARY KEY, value text NOT NULL); \
                        INSERT INTO app_state VALUES (1, \$\$postgres-state-preserved\$\$)"
                runuser -u postgres -- pg_ctl -D /var/lib/pgsql/data -m fast -w stop
            '
        test -f "$postgres_version_file"
        if getfattr --only-values -n security.selinux "$app_state" >/dev/null 2>&1; then
            printf 'Application state unexpectedly has a SELinux label on the disabled source: %s\n' \
                "$app_state" >&2
            exit 1
        fi
        if getfattr --only-values -n security.selinux "$postgres_version_file" >/dev/null 2>&1; then
            printf 'PostgreSQL state unexpectedly has a SELinux label on the disabled source: %s\n' \
                "$postgres_version_file" >&2
            exit 1
        fi

        # Exercise source preflight with a nested mount whose source is a
        # device node. No target boot configuration may be changed on failure.
        truncate -s 128M "$log_fs_image"
        mkfs.ext4 -F -m 0 "$log_fs_image"
        if mountpoint -q /var/log; then
            printf '/var/log is already a mountpoint before test setup\n' >&2
            exit 1
        fi
        mount -o loop "$log_fs_image" /var/log
        printf '%s\n' separate-var-log-filesystem > /var/log/bootc-tmt-sentinel
        install -d -m 0755 "$empty_tmpfs"
        mount -t tmpfs -o size=16m '' "$empty_tmpfs"
        test -z "$(find "$empty_tmpfs" -mindepth 1 -print -quit)"
        printf '%s\n' transient-tmpfs-data > "$empty_tmpfs_marker"
        test "$(<"$empty_tmpfs_marker")" = transient-tmpfs-data
        : > "$preflight_mountpoint"
        mount --bind /dev/null "$preflight_mountpoint"

        boot_snapshot=$(mktemp /run/boot-config-before.XXXXXX)
        boot_snapshot_after=$(mktemp /run/boot-config-after.XXXXXX)
        tar --sort=name --numeric-owner --xattrs --acls -cf "$boot_snapshot" -C /boot .
        if podman --remote=false run --rm --privileged --pid=host --user=root:root \
            -v /dev:/dev \
            -v /:/target \
            -v /boot:/target/boot \
            -v /var/lib/containers:/var/lib/containers \
            --security-opt label=type:unconfined_t \
            "$target_image" \
            bootc install to-existing-root --preserve-var --acknowledge-destructive \
            > /run/preserve-var-preflight.log 2>&1; then
            printf 'preserve-var unexpectedly accepted the special-file mountpoint\n' >&2
            exit 1
        fi
        grep -F "$preflight_mountpoint is a mountpoint that is neither a directory nor a file" \
            /run/preserve-var-preflight.log
        tar --sort=name --numeric-owner --xattrs --acls -cf "$boot_snapshot_after" -C /boot .
        cmp "$boot_snapshot" "$boot_snapshot_after"
        umount "$preflight_mountpoint"
        rm -f "$preflight_mountpoint" "$boot_snapshot" "$boot_snapshot_after"

        # Add a sentinel before copying so the full plan/test data and metadata
        # are verified in the persistent copy, not just an empty run directory.
        test -f "$TMT_TEST_METADATA"
        tmt_plan_data_sentinel=$TMT_PLAN_DATA/$tmt_plan_data_sentinel_name
        test ! -e "$tmt_plan_data_sentinel"
        printf '%s\n' plan-workdir-persistence-sentinel > "$tmt_plan_data_sentinel"
        tmt_test_data_sentinel=$TMT_TEST_DATA/$tmt_test_data_sentinel_name
        test ! -e "$tmt_test_data_sentinel"
        printf '%s\n' workdir-persistence-sentinel > "$tmt_test_data_sentinel"
        prepare_tmt_workdir_persistence "$tmt_run_dir"
        if [[ -n $persistent_run_dir ]]; then
            verify_tmt_workdir_in_preserved_var "$persistent_run_dir"
        fi

        # TMT connects as root. Preserve its authorized key in /var so it can
        # reconnect after migration; the target policy relabeler labels it.
        install -d -m 0700 /var/roothome/.ssh
        install -m 0600 /root/.ssh/authorized_keys /var/roothome/.ssh/authorized_keys

        # Keep the backing image for the separate /var/log filesystem stable
        # while preserve-var copies its image file from /var/lib.
        trap cleanup_log_freeze EXIT
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        # Set before invoking fsfreeze: it may freeze successfully and still
        # return failure or be interrupted before the shell observes success.
        freeze_may_be_active=1
        fsfreeze -f /var/log
        podman --remote=false run --rm --privileged --pid=host --user=root:root \
            -v /dev:/dev \
            -v /:/target \
            -v /boot:/target/boot \
            -v /var/lib/containers:/var/lib/containers \
            --security-opt label=type:unconfined_t \
            "$target_image" \
            bootc install to-existing-root --preserve-var --acknowledge-destructive
        if fsfreeze -u /var/log; then
            freeze_may_be_active=0
        else
            status=$?
            printf 'Failed to thaw /var/log after migration\n' >&2
            exit "$status"
        fi

        # Find the generated stateroot by the copied bind-source sentinel.
        new_var=
        for candidate in /ostree/deploy/*/var; do
            if [[ -f $candidate${bind_source#/var}/sentinel ]]; then
                new_var=$candidate
                break
            fi
        done
        test -n "$new_var"
        test "$(<"$new_var${bind_source#/var}/sentinel")" = bind-source-data
        test "$(<"$new_var${app_state#/var}")" = preserved-application-state
        test -f "$new_var${log_fs_image#/var}"
        test "$(getfattr --only-values -n security.selinux "$new_var${app_state#/var}")" = \
            "$(podman --remote=false run --rm "$target_image" matchpathcon -n "$app_state")"
        test "$(getfattr --only-values -n security.selinux "$new_var${postgres_version_file#/var}")" = \
            "$(podman --remote=false run --rm "$target_image" matchpathcon -n "$postgres_version_file")"
        bind_target_in_new_var=$new_var${bind_target#/var}
        test -d "$bind_target_in_new_var"
        test -z "$(find "$bind_target_in_new_var" -mindepth 1 -print -quit)"

        # to-existing-root does not migrate the old host's /etc. Inject
        # test-only SSH host keys and TMT tmpfiles config into the new /etc.
        # The host-key generation is only for this VM test, not product behavior.
        podman --remote=false run --rm --privileged --pid=host --user=root:root \
            -v /dev:/dev \
            -v /:/target \
            -v /boot:/target/boot \
            -v /var/lib/containers:/var/lib/containers \
            --security-opt label=type:unconfined_t \
            "$target_image" \
            bash -euo pipefail -c '
                deployment=/run/bootc-tmt-deployment
                cleanup() {
                    local status=$?
                    trap - EXIT
                    if ! umount -R "$deployment"; then
                        printf "Failed to unmount deployment target %s\n" "$deployment" >&2
                        status=1
                    fi
                    exit "$status"
                }
                trap cleanup EXIT

                local_workdir_root=$1
                run_dir=$2
                workdir_root=$3
                mkdir -p "$deployment"
                bootc install mount --sysroot /target --latest "$deployment"

                # New /etc must provide keys because old /etc/ssh is not migrated.
                install -d -m 0755 "$deployment/etc/ssh"
                ssh-keygen -q -t ed25519 -N "" \
                    -f "$deployment/etc/ssh/ssh_host_ed25519_key"
                chroot "$deployment" restorecon -RF /etc/ssh
                for ssh_path in \
                    /etc/ssh/ssh_host_ed25519_key \
                    /etc/ssh/ssh_host_ed25519_key.pub; do
                    actual_label=$(getfattr --only-values -n security.selinux \
                        "$deployment$ssh_path")
                    expected_label=$(chroot "$deployment" matchpathcon -n "$ssh_path")
                    if [[ $actual_label != "$expected_label" ]]; then
                        printf "Unexpected SELinux label on target SSH key %s: %s (expected %s)\n" \
                            "$ssh_path" "$actual_label" "$expected_label" >&2
                        exit 1
                    fi
                done

                if [[ $local_workdir_root == 1 ]]; then
                    rule=$deployment/etc/tmpfiles.d/bootc-tmt-workdir.conf
                    install -d -m 0755 "${rule%/*}"
                    tmpfiles_rule=(
                        "d $workdir_root - - - - -"
                        "d $run_dir - - - - -"
                    )
                    printf "%s\n" "${tmpfiles_rule[@]}" > "$rule"
                    printf "%s\n" "${tmpfiles_rule[@]}" | cmp - "$rule"
                fi
            ' install-test-configuration \
            "$(is_local_tmt_workdir "$tmt_run_dir" && printf 1 || printf 0)" \
            "$(if [[ -n $persistent_run_dir ]]; then printf '%s' "$persistent_run_dir"; else realpath -e -- "$tmt_run_dir"; fi)" \
            "$(if [[ -n $persistent_tmt_root ]]; then printf '%s' "$persistent_tmt_root"; elif [[ -n ${PACKAGE_MODE_TMT_WORKDIR_ROOT:-} ]]; then realpath -e -- "$PACKAGE_MODE_TMT_WORKDIR_ROOT"; fi)"

        # New target boot entries are generated by the migration; remove the
        # source-only HostDisabled argument before rebooting into the target.
        grubby --update-kernel=ALL --remove-args=selinux=0
        if grubby --info=ALL | grep -Eq '(^|[[:space:]"])selinux=0([[:space:]"]|$)'; then
            printf 'selinux=0 remains in a target boot entry after migration\n' >&2
            exit 1
        fi

        bootc status
        # Reboot the guest itself; this avoids testcloud's ACPI soft-poweroff.
        tmt-reboot -c 'systemctl reboot'
        ;;
    2)
        test -e /run/ostree-booted
        ! grep -Eq '(^|[[:space:]])selinux=0([[:space:]]|$)' /proc/cmdline
        test "$(getenforce)" = Enforcing
        test -e /proc/1/root/sys/fs/selinux/enforce
        test "$(</proc/1/root/sys/fs/selinux/enforce)" = 1
        tmt_run_dir=$(get_tmt_run_dir)
        set_persistent_tmt_paths "$tmt_run_dir"
        resolved_tmt_run_dir=$(realpath -e -- "$tmt_run_dir")
        if [[ $resolved_tmt_run_dir != "$persistent_run_dir" ]]; then
            printf 'Post-reboot TMT path resolves to %s, expected canonical persistent path %s\n' \
                "$resolved_tmt_run_dir" "$persistent_run_dir" >&2
            exit 1
        fi
        if is_local_tmt_workdir "$tmt_run_dir"; then
            test -d "$tmt_run_dir"
            test ! -L "$tmt_run_dir"
            verify_tmt_workdir_in_preserved_var "$tmt_run_dir"
            expected_tmpfiles_rule=(
                "d $persistent_tmt_root - - - - -"
                "d $persistent_run_dir - - - - -"
            )
            printf "%s\n" "${expected_tmpfiles_rule[@]}" | \
                cmp - /etc/tmpfiles.d/bootc-tmt-workdir.conf
        else
            test -d "$tmt_run_dir"
            test ! -L "$tmt_run_dir"
            verify_tmt_workdir_in_preserved_var "$tmt_run_dir"
        fi

        test -d "$TMT_PLAN_DATA"
        test -d "$TMT_TEST_DATA"
        test -f "$TMT_TEST_METADATA"
        tmt_plan_data_sentinel=$TMT_PLAN_DATA/$tmt_plan_data_sentinel_name
        tmt_test_data_sentinel=$TMT_TEST_DATA/$tmt_test_data_sentinel_name
        tmt_test_data_post_reboot_marker=$TMT_TEST_DATA/$tmt_test_data_post_reboot_marker_name
        test "$(<"$tmt_plan_data_sentinel")" = plan-workdir-persistence-sentinel
        test "$(<"$tmt_test_data_sentinel")" = workdir-persistence-sentinel
        printf '%s\n' post-reboot-workdir-writable > "$tmt_test_data_post_reboot_marker"
        test "$(<"$tmt_test_data_post_reboot_marker")" = post-reboot-workdir-writable

        mountpoint -q "$bind_target"
        test "$(<"$bind_target/mounted-sentinel")" = bind-mounted-data
        test ! -e "$bind_target/underlying-sentinel"
        mountpoint -q /var/log
        test "$(findmnt --noheadings --output FSTYPE --target /var/log)" = ext4
        test "$(</var/log/bootc-tmt-sentinel)" = separate-var-log-filesystem
        mountpoint -q "$empty_tmpfs"
        test "$(findmnt --noheadings --output FSTYPE --target "$empty_tmpfs")" = tmpfs
        test ! -e "$empty_tmpfs_marker"
        test -z "$(find "$empty_tmpfs" -mindepth 1 -print -quit)"

        systemctl is-active --quiet postgresql.service
        postgres_value=$(runuser -u postgres -- psql --tuples-only --no-align \
            -d bootc_preserve_var -c 'SELECT value FROM app_state WHERE id = 1')
        test "$postgres_value" = postgres-state-preserved
        test "$(<"$app_state")" = preserved-application-state
        test "$(getfattr --only-values -n security.selinux "$app_state")" = \
            "$(matchpathcon -n "$app_state")"
        test "$(getfattr --only-values -n security.selinux "$postgres_version_file")" = \
            "$(matchpathcon -n "$postgres_version_file")"
        for ssh_path in \
            /etc/ssh/ssh_host_ed25519_key \
            /etc/ssh/ssh_host_ed25519_key.pub; do
            test -s "$ssh_path"
            test "$(getfattr --only-values -n security.selinux "$ssh_path")" = \
                "$(matchpathcon -n "$ssh_path")"
        done

        booted_image=$(bootc status --json | jq -r '.status.booted.image.image.image')
        test "$booted_image" = "$target_image"
        ;;
    *)
        printf 'Unexpected TMT_REBOOT_COUNT=%s\n' "$TMT_REBOOT_COUNT" >&2
        exit 1
        ;;
esac
