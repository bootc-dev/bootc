#!/bin/bash
# Both local and Packit runs prepare one package-mode guest, then convert and
# reboot that same guest; local TMT workdirs live under preserved /var.
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
tmt_artifacts_parent=/var/ARTIFACTS
tmt_test_data_sentinel_name=workdir-persistence-sentinel
tmt_test_data_post_reboot_marker_name=post-reboot-marker

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
        case $resolved_workdir_root in
            /var/*) ;;
            *)
                printf 'TMT workdir root must resolve under preserved /var (got %q -> %q)\n' \
                    "$workdir_root" "$resolved_workdir_root" >&2
                return 1
                ;;
        esac
        case $resolved_workdir_root in
            /var/tmp|/var/tmp/*|/var/cache|/var/cache/*|/var/log/journal|/var/log/journal/*|/var/lib/containers|/var/lib/containers/*)
                printf 'TMT workdir root is excluded from preserve-var: %s\n' \
                    "$resolved_workdir_root" >&2
                return 1
                ;;
        esac
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
        0|1) ;;
        *)
            printf 'Unexpected TMT_REBOOT_COUNT=%s\n' "${TMT_REBOOT_COUNT}" >&2
            return 1
            ;;
    esac
    printf '%s\n' "$run_dir"
}

verify_tmt_workdir_in_preserved_var() {
    local run_dir=$1
    local mount_target

    if ! mount_target=$(findmnt --noheadings --output TARGET --target "$run_dir"); then
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
        podman --remote=false image exists "$target_image"

        # The guest is still the original package-mode system.
        test ! -e /run/ostree-booted
        tmt_run_dir=$(get_tmt_run_dir)
        if [[ ! -d $tmt_run_dir || -L $tmt_run_dir ]]; then
            printf 'TMT workdir is missing or not a real directory: %s\n' "$tmt_run_dir" >&2
            exit 1
        fi
        verify_tmt_workdir_in_preserved_var "$tmt_run_dir"

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
        podman --remote=false run --rm --security-opt label=disable \
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

        # TMT 1.69 rsyncs to the same absolute path on the guest. The configured
        # controller path resolves under /var here (including /home -> /var/home).
        test -f "$TMT_TEST_METADATA"
        tmt_test_data_sentinel=$TMT_TEST_DATA/$tmt_test_data_sentinel_name
        test ! -e "$tmt_test_data_sentinel"
        printf '%s\n' workdir-persistence-sentinel > "$tmt_test_data_sentinel"

        # TMT connects as root. Preserve its authorized key in /var so it can
        # reconnect after the migration reboot.
        install -d -m 0700 /var/roothome/.ssh
        install -m 0600 /root/.ssh/authorized_keys /var/roothome/.ssh/authorized_keys
        restorecon -RF /var/roothome/.ssh

        # Keep the backing image for the separate /var/log filesystem stable
        # while preserve-var copies its image file from /var/lib.
        fsfreeze -f /var/log
        if ! podman --remote=false run --rm --privileged --pid=host --user=root:root \
            -v /dev:/dev \
            -v /:/target \
            -v /boot:/target/boot \
            -v /var/lib/containers:/var/lib/containers \
            --security-opt label=type:unconfined_t \
            "$target_image" \
            bootc install to-existing-root --preserve-var --acknowledge-destructive; then
            fsfreeze -u /var/log
            exit 1
        fi
        fsfreeze -u /var/log

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
            "$(realpath -e -- "$tmt_run_dir")" \
            "$(if [[ -n ${PACKAGE_MODE_TMT_WORKDIR_ROOT:-} ]]; then realpath -e -- "$PACKAGE_MODE_TMT_WORKDIR_ROOT"; fi)"

        bootc status
        # Reboot the guest itself; this avoids testcloud's ACPI soft-poweroff.
        tmt-reboot -c 'systemctl reboot'
        ;;
    1)
        test -e /run/ostree-booted
        tmt_run_dir=$(get_tmt_run_dir)
        if is_local_tmt_workdir "$tmt_run_dir"; then
            test -d "$tmt_run_dir"
            test ! -L "$tmt_run_dir"
            verify_tmt_workdir_in_preserved_var "$tmt_run_dir"
            expected_tmpfiles_rule=(
                "d $(realpath -e -- "$PACKAGE_MODE_TMT_WORKDIR_ROOT") - - - - -"
                "d $(realpath -e -- "$tmt_run_dir") - - - - -"
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
        tmt_test_data_sentinel=$TMT_TEST_DATA/$tmt_test_data_sentinel_name
        tmt_test_data_post_reboot_marker=$TMT_TEST_DATA/$tmt_test_data_post_reboot_marker_name
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
        test -s /etc/ssh/ssh_host_ed25519_key
        test -s /etc/ssh/ssh_host_ed25519_key.pub

        booted_image=$(bootc status --json | jq -r '.status.booted.image.image.image')
        test "$booted_image" = "$target_image"
        ;;
    *)
        printf 'Unexpected TMT_REBOOT_COUNT=%s\n' "$TMT_REBOOT_COUNT" >&2
        exit 1
        ;;
esac
