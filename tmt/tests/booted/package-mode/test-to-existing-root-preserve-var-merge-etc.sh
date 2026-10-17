#!/bin/bash
# Both local and Packit runs prepare one package-mode guest, then convert and
# reboot that same guest; local loads the checkout image, Packit builds it.
set -xeuo pipefail

target_image=localhost/bootc-to-existing-root-preserve-var-merge-etc:latest
var_marker=/var/lib/bootc-tmt-preserve-var/sentinel
bind_dir=/var/lib/bootc-tmt-preserve-var-bind
bind_source=$bind_dir/source
bind_target=$bind_dir/target
etc_dir=/etc/bootc-tmt-merge
tmt_plan_data_suffix=/tmt/plans/package-mode/data
tmt_workdir_parent=/var/tmp/tmt
tmt_workdir_root=/var/lib/bootc-tmt-workdirs
tmt_test_data_sentinel_name=workdir-persistence-sentinel
tmt_test_data_post_reboot_marker_name=post-reboot-marker

get_tmt_run_dir() {
    local plan_data=${TMT_PLAN_DATA:-}
    local run_dir
    local resolved_plan_data
    local persistent_run_dir
    local link_target

    if [[ "$plan_data" != *"$tmt_plan_data_suffix" ]]; then
        printf 'TMT_PLAN_DATA must end in %s (got %q)\n' "$tmt_plan_data_suffix" "$plan_data" >&2
        return 1
    fi
    run_dir=${plan_data%"$tmt_plan_data_suffix"}
    if [[ ! $run_dir =~ ^/var/tmp/tmt/run-[[:alnum:]_.-]+$ || $run_dir == *..* ]]; then
        printf 'Expected a safe TMT run directory under %s (got %q)\n' \
            "$tmt_workdir_parent" "$run_dir" >&2
        return 1
    fi
    case ${TMT_REBOOT_COUNT:-0} in
        0)
            if ! resolved_plan_data=$(realpath -e -- "$plan_data"); then
                printf 'TMT_PLAN_DATA must be an existing path without symlinked components (got %q)\n' \
                    "$plan_data" >&2
                return 1
            fi
            if [[ $resolved_plan_data != "$plan_data" ]]; then
                printf 'TMT_PLAN_DATA must be a canonical path without symlinked components (got %q, resolves to %q)\n' \
                    "$plan_data" "$resolved_plan_data" >&2
                return 1
            fi
            ;;
        1)
            persistent_run_dir=$tmt_workdir_root/${run_dir##*/}
            if [[ ! -L $run_dir ]] || ! link_target=$(readlink -- "$run_dir") ||
                [[ $link_target != "$persistent_run_dir" ]]; then
                printf 'TMT run directory must link directly to %s (got %q)\n' \
                    "$persistent_run_dir" "$(readlink -- "$run_dir" 2>/dev/null || true)" >&2
                return 1
            fi
            if ! resolved_plan_data=$(realpath -e -- "$plan_data") ||
                [[ $resolved_plan_data != "$persistent_run_dir$tmt_plan_data_suffix" ]]; then
                printf 'TMT_PLAN_DATA must resolve to %s (got %q, resolves to %q)\n' \
                    "$persistent_run_dir$tmt_plan_data_suffix" "$plan_data" "${resolved_plan_data:-}" >&2
                return 1
            fi
            ;;
        *)
            printf 'Unexpected TMT_REBOOT_COUNT=%s\n' "${TMT_REBOOT_COUNT}" >&2
            return 1
            ;;
    esac

    printf '%s\n' "$run_dir"
}

case ${TMT_REBOOT_COUNT:-0} in
    0)
        podman --remote=false image exists "$target_image"

        # The guest must still be the original package-mode system.
        test ! -e /run/ostree-booted

        # Exercise both an admin-created file and an admin modification of an
        # image default. The derived image below supplies the pristine values.
        mkdir -p "$etc_dir" "${var_marker%/*}" "$bind_source" "$bind_target"

        # TMT connects as root. Package-mode hosts keep root's home at /root,
        # while bootc images link /root to /var/roothome, so preserve its key
        # under /var for TMT to reconnect after the migration reboot.
        install -d -m 0700 /var/roothome/.ssh
        install -m 0600 /root/.ssh/authorized_keys /var/roothome/.ssh/authorized_keys
        restorecon -RF /var/roothome/.ssh

        printf '%s\n' admin-modified | tee "$etc_dir/default.conf"
        printf '%s\n' admin-only | tee "$etc_dir/admin-only.conf"
        printf '%s\n' preserved-var | tee "$var_marker"
        printf '%s\n' bind-source-data | tee "$bind_source/sentinel"
        printf '%s\n' mounted-only-data | tee "$bind_source/mounted-sentinel"
        printf '%s\n' underlying-target-data | tee "$bind_target/underlying-sentinel"
        mount --bind "$bind_source" "$bind_target"
        printf '%s\n' "$bind_source $bind_target none bind 0 0" >> /etc/fstab

        tmt_run_dir=$(get_tmt_run_dir)
        tmt_run_id=${tmt_run_dir##*/}
        if [[ ! -d "$tmt_run_dir" || -L "$tmt_run_dir" ]]; then
            printf 'TMT run directory is missing or not a directory: %s\n' "$tmt_run_dir" >&2
            exit 1
        fi
        tmt_run_dir_identity=$(stat -c '%d:%i' -- "$tmt_run_dir")
        persistent_tmt_run_dir=$tmt_workdir_root/$tmt_run_id
        if [[ -e "$persistent_tmt_run_dir" || -L "$persistent_tmt_run_dir" ]]; then
            printf 'Persistent TMT workdir already exists: %s\n' "$persistent_tmt_run_dir" >&2
            exit 1
        fi
        test -d "$TMT_TEST_DATA"
        tmt_test_data_sentinel=$TMT_TEST_DATA/$tmt_test_data_sentinel_name
        test ! -e "$tmt_test_data_sentinel"
        printf '%s\n' workdir-persistence-sentinel > "$tmt_test_data_sentinel"
        # --preserve-var excludes /var/tmp. Stage a full copy on /var, then
        # redirect the original path so TMT's post-reboot writes survive.
        install -d -m 0755 "$tmt_workdir_root"
        staging_parent=$(mktemp -d "$tmt_workdir_root/.${tmt_run_id}.XXXXXX")
        trap 'if [[ -n ${staging_parent:-} ]]; then rm -rf -- "$staging_parent"; fi' EXIT
        cp -a -- "$tmt_run_dir" "$staging_parent/"
        staged_run_dir=$staging_parent/$tmt_run_id
        mv -T --no-clobber -- "$staged_run_dir" "$persistent_tmt_run_dir"
        if [[ -e "$staged_run_dir" || -L "$staged_run_dir" ]]; then
            printf 'Persistent TMT workdir appeared during staging: %s\n' \
                "$persistent_tmt_run_dir" >&2
            exit 1
        fi
        rmdir -- "$staging_parent"
        staging_parent=
        trap - EXIT

        install -d -m 0755 /etc/tmpfiles.d
        printf 'd %s 0755 root root -\nL+ %s - - - - %s\n' \
            "$tmt_workdir_parent" "$tmt_run_dir" "$persistent_tmt_run_dir" \
            > /etc/tmpfiles.d/bootc-tmt-workdir.conf

        disposable_run_dir=$tmt_workdir_parent/.${tmt_run_id}.original.$$
        if [[ -e "$disposable_run_dir" || -L "$disposable_run_dir" ]]; then
            printf 'Disposable TMT workdir already exists: %s\n' "$disposable_run_dir" >&2
            exit 1
        fi

        tmt_run_dir_moved=0
        tmt_run_dir_swap_complete=0
        cleanup_tmt_run_dir_swap() {
            local status=$?
            local disposable_identity
            local original_identity

            trap - EXIT HUP INT TERM
            if (( tmt_run_dir_moved )); then
                # A signal can arrive after ln succeeds but before the flag is
                # updated, so recognize the completed swap from the link too.
                if [[ -L $tmt_run_dir ]] &&
                    [[ $(readlink -- "$tmt_run_dir") == "$persistent_tmt_run_dir" ]]; then
                    tmt_run_dir_swap_complete=1
                fi

                if (( ! tmt_run_dir_swap_complete )); then
                    disposable_identity=$(stat -c '%d:%i' -- "$disposable_run_dir" 2>/dev/null || true)
                    if [[ $disposable_identity == "$tmt_run_dir_identity" ]]; then
                        if [[ ! -e $tmt_run_dir && ! -L $tmt_run_dir ]]; then
                            # --no-clobber ensures a replacement path created after
                            # the existence check is never overwritten.
                            mv -T --no-clobber -- "$disposable_run_dir" "$tmt_run_dir" || true
                            original_identity=$(stat -c '%d:%i' -- "$tmt_run_dir" 2>/dev/null || true)
                            if [[ $original_identity != "$tmt_run_dir_identity" ]]; then
                                disposable_identity=$(stat -c '%d:%i' -- "$disposable_run_dir" 2>/dev/null || true)
                                if [[ $disposable_identity == "$tmt_run_dir_identity" ]]; then
                                    printf 'Could not restore TMT workdir because no-replace skipped the move; the original remains at %s\n' \
                                        "$disposable_run_dir" >&2
                                else
                                    printf 'Failed to restore TMT workdir from %s to %s\n' \
                                        "$disposable_run_dir" "$tmt_run_dir" >&2
                                fi
                            fi
                        else
                            printf 'Cannot restore TMT workdir because the original path now exists; the original remains at %s\n' \
                                "$disposable_run_dir" >&2
                        fi
                    elif [[ -e $disposable_run_dir || -L $disposable_run_dir ]]; then
                        printf 'Leaving replacement at disposable TMT workdir path untouched: %s\n' \
                            "$disposable_run_dir" >&2
                    fi
                fi
            fi
            exit "$status"
        }
        trap cleanup_tmt_run_dir_swap EXIT
        trap 'exit 1' HUP INT TERM
        tmt_run_dir_moved=1
        mv -T --no-clobber -- "$tmt_run_dir" "$disposable_run_dir"
        disposable_run_dir_identity=$(stat -c '%d:%i' -- "$disposable_run_dir" 2>/dev/null || true)
        if [[ $disposable_run_dir_identity != "$tmt_run_dir_identity" ]]; then
            tmt_run_dir_moved=0
            printf 'Failed to move original TMT workdir to %s; the destination may have appeared concurrently\n' \
                "$disposable_run_dir" >&2
            exit 1
        fi
        ln -s -- "$persistent_tmt_run_dir" "$tmt_run_dir"
        tmt_run_dir_swap_complete=1
        # Keep the old tree: it is disposable under /var/tmp and vanishes on
        # reboot, while retaining it keeps this shell's cwd valid until we leave.
        tmt_run_dir_moved=0
        trap - EXIT HUP INT TERM

        # The shell may still be inside the renamed workdir; leave it before
        # installing or rebooting so the old cwd is no longer in use.
        cd /

        # The flags require the OSTree backend. Run the current build-under-test
        # as a privileged installer, with the package-mode root mounted at /target.
        podman --remote=false run --rm --privileged --pid=host --user=root:root \
            -v /dev:/dev \
            -v /:/target \
            -v /boot:/target/boot \
            -v /var/lib/containers:/var/lib/containers \
            --security-opt label=type:unconfined_t \
            "$target_image" \
            sh -ec '
                test "$(cat /target/var/lib/bootc-tmt-preserve-var-bind/target/mounted-sentinel)" = mounted-only-data
                test ! -e /target/var/lib/bootc-tmt-preserve-var-bind/target/underlying-sentinel
                exec bootc install to-existing-root \
                    --preserve-var \
                    --merge-etc \
                    --acknowledge-destructive
            '

        # Find the newly created stateroot by its copied bind-source sentinel.
        # Auto-generated stateroot names are intentionally not assumed here.
        new_var=
        for candidate in /ostree/deploy/*/var; do
            if [[ -f "$candidate${bind_source#/var}/sentinel" ]]; then
                new_var=$candidate
                break
            fi
        done
        test -n "$new_var"
        # Its /var has the ordinary sibling but only an empty directory for the
        # bind mount itself.
        test "$(<"$new_var/lib/bootc-tmt-preserve-var-bind/source/sentinel")" = bind-source-data
        test -d "$new_var/lib/bootc-tmt-preserve-var-bind/target"
        test -z "$(find "$new_var/lib/bootc-tmt-preserve-var-bind/target" -mindepth 1 -print -quit)"
        test ! -e "$new_var/lib/bootc-tmt-preserve-var-bind/target/mounted-sentinel"
        test ! -e "$new_var/lib/bootc-tmt-preserve-var-bind/target/underlying-sentinel"

        bootc status
        # Ask the guest to reboot itself; this is more reliable than
        # testcloud's ACPI soft-poweroff for a full bootc deployment reboot.
        tmt-reboot -c 'systemctl reboot'
        ;;
    1)
        test -e /run/ostree-booted

        tmt_run_dir=$(get_tmt_run_dir)
        tmt_run_id=${tmt_run_dir##*/}
        persistent_tmt_run_dir=$tmt_workdir_root/$tmt_run_id
        test -L "$tmt_run_dir"
        test "$(readlink -f -- "$tmt_run_dir")" = "$persistent_tmt_run_dir"
        test -d "$TMT_PLAN_DATA"
        test -d "$TMT_TEST_DATA"
        test -f "$TMT_TEST_METADATA"
        tmt_test_data_sentinel=$TMT_TEST_DATA/$tmt_test_data_sentinel_name
        tmt_test_data_post_reboot_marker=$TMT_TEST_DATA/$tmt_test_data_post_reboot_marker_name
        test -f "$tmt_test_data_sentinel"
        test "$(<"$tmt_test_data_sentinel")" = workdir-persistence-sentinel
        printf '%s\n' post-reboot-workdir-writable > "$tmt_test_data_post_reboot_marker"
        test "$(<"$tmt_test_data_post_reboot_marker")" = post-reboot-workdir-writable

        booted_image=$(bootc status --json | jq -r '.status.booted.image.image.image')
        test "$booted_image" = "$target_image"

        test "$(<"$var_marker")" = preserved-var
        test "$(<"$etc_dir/default.conf")" = admin-modified
        test "$(<"$etc_dir/admin-only.conf")" = admin-only
        test "$(<"$etc_dir/image-only.conf")" = image-only
        mountpoint -q "$bind_target"
        test "$(<"$bind_target/mounted-sentinel")" = mounted-only-data
        ;;
    *)
        printf 'Unexpected TMT_REBOOT_COUNT=%s\n' "$TMT_REBOOT_COUNT" >&2
        exit 1
        ;;
esac
