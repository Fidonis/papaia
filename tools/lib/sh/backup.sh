# shellcheck shell=bash
# papaia-ctl — backup / restore commands.
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

# Sidecar image used to tar/untar volumes and host directories. Pinned to a
# major so a broken :latest cannot silently change archive behaviour.
BACKUP_IMAGE="alpine:3"

# ─────────────────────────────────────────────────────────────────────────
# Pause bookkeeping
#
# Backups run hot, so a volume is archived while its containers are alive.
# Tarring a live PGDATA/WiredTiger directory copies files mid-transaction; a
# brief `docker pause` freezes the writers for the duration of the archive
# without stopping or restarting anything. Every container paused here MUST be
# unpaused again on every path -- success, tar failure, or Ctrl-C -- which is
# what _PAUSED_CONTAINERS plus the EXIT/INT/TERM trap guarantee.
# ─────────────────────────────────────────────────────────────────────────
_PAUSED_CONTAINERS=()
_BACKUP_TMPFILES=()

# ID of the restore point written by the last cmd_backup call in this process.
# `upgrade` reads it to name the point an operator can fall back to.
LAST_BACKUP_ID=""

_unpause_all() {
    local cid
    if [ ${#_PAUSED_CONTAINERS[@]} -gt 0 ]; then
        for cid in "${_PAUSED_CONTAINERS[@]}"; do
            docker unpause "$cid" >/dev/null 2>&1 || true
        done
        _PAUSED_CONTAINERS=()
    fi
    return 0
}

_backup_cleanup() {
    _unpause_all
    local f
    if [ ${#_BACKUP_TMPFILES[@]} -gt 0 ]; then
        for f in "${_BACKUP_TMPFILES[@]}"; do
            [ -f "$f" ] && rm -f "$f"
        done
        _BACKUP_TMPFILES=()
    fi
    return 0
}

# Pause every currently running container in the given ID list.
_pause_containers() {
    local cid state
    for cid in "$@"; do
        [ -z "$cid" ] && continue
        state="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || true)"
        # Only "running" is worth pausing: a container already paused by the
        # operator must stay paused when we are done, and a stopped one has no
        # writers to freeze.
        [ "$state" = "running" ] || continue
        if docker pause "$cid" >/dev/null 2>&1; then
            _PAUSED_CONTAINERS+=("$cid")
        fi
    done
    return 0
}

_containers_using_volume() {
    docker ps -q --filter "volume=$1" 2>/dev/null || true
}

_containers_of_project() {
    docker ps -q --filter "label=com.docker.compose.project=$1" 2>/dev/null || true
}

# ─────────────────────────────────────────────────────────────────────────
# Host path handling
#
# `docker run -v` needs a path the Docker daemon understands. Under Git Bash
# a checkout lives at /c/Projects/..., which the daemon cannot resolve, and
# MSYS additionally rewrites container-side paths like /volume into a Windows
# path unless MSYS_NO_PATHCONV is set.
# ─────────────────────────────────────────────────────────────────────────
_docker_hostpath() {
    local path="$1"
    # Must be absolute: docker reads a relative -v source as a *volume name*
    # and would silently mount an empty volume instead of the directory.
    case "$path" in
        /*|[A-Za-z]:[\\/]*) : ;;
        *) path="$PWD/$path" ;;
    esac
    case "$(uname -s 2>/dev/null || echo unknown)" in
        MINGW*|MSYS*|CYGWIN*)
            if command -v cygpath >/dev/null 2>&1; then
                cygpath -m "$path"
                return 0
            fi
            ;;
    esac
    printf '%s' "$path"
}

_docker_run() {
    MSYS_NO_PATHCONV=1 docker run --rm "$@"
}

_new_tmpfile() {
    local f
    f="$(mktemp)"
    _BACKUP_TMPFILES+=("$f")
    printf '%s' "$f"
}

# ─────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────
# $1 = backup dir, $2 = operation, $3 = restore point id, $4 = result,
# remaining args are appended verbatim as key=value details.
_backup_log() {
    local backup_dir="$1" op="$2" id="$3" result="$4"
    shift 4
    mkdir -p "$backup_dir" 2>/dev/null || true
    printf '%s %-7s id=%s result=%s %s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$op" "$id" "$result" "$*" \
        >> "$backup_dir/backup.log" 2>/dev/null || true
    return 0
}

# Runs inside a command substitution, so a bare `exit` here would only kill the
# subshell -- it returns instead, and both call sites turn that into an exit.
_resolve_backup_dir() {
    local override="$1" resolved
    local -a extra=()
    [ -n "$override" ] && extra+=(--backup-dir="$override")
    if ! resolved="$(py_cli backup-dir "${extra[@]}")"; then
        return 3
    fi
    printf '%s' "${resolved%$'\r'}"
}

# ─────────────────────────────────────────────────────────────────────────
# backup
# ─────────────────────────────────────────────────────────────────────────
cmd_backup() {
    local config_dir="$DEFAULT_CONFIG_DIR" backup_dir="" retention=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --backup-dir=*) backup_dir="${1#*=}" ;;
            --retention-period-days=*) retention="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for backup: $1"; exit 2 ;;
        esac
        shift
    done
    if [ -n "$retention" ] && ! [[ "$retention" =~ ^[0-9]+$ ]]; then
        error "--retention-period-days must be a whole number of days (got: $retention)"
        exit 2
    fi
    CONFIG_DIR="$config_dir"
    _require_setup_done

    trap _backup_cleanup EXIT INT TERM

    backup_dir="$(_resolve_backup_dir "$backup_dir")" || exit 3
    mkdir -p "$backup_dir"
    info "Backup target: $backup_dir"

    # One docker call yields every volume with its compose project label; the
    # planner uses it to skip declared-but-absent volumes and to pick up
    # volumes of profiles that have since been disabled.
    local volumes_file
    volumes_file="$(_new_tmpfile)"
    docker volume ls --format $'{{.Label "com.docker.compose.project"}}\t{{.Name}}' \
        > "$volumes_file" 2>/dev/null || true

    local plan_file
    plan_file="$(_new_tmpfile)"
    # `tr -d '\r'`: on Windows the Python interpreter emits CRLF, and IFS=$'\t'
    # leaves the CR attached to the last field -- a snapshot path ending in CR
    # makes docker bind-mount (and auto-create) a second, wrong directory.
    # pipefail is set, so a failing py_cli still fails the pipeline.
    if ! py_cli backup-plan --backup-dir="$backup_dir" --existing-volumes="$volumes_file" \
            | tr -d '\r' > "$plan_file"; then
        error "Could not plan the backup."
        exit 3
    fi

    local snapshot="" kind archive source owner
    local total=0 failed=0
    local started=$SECONDS

    while IFS=$'\t' read -r kind archive source owner; do
        [ -z "$kind" ] && continue
        if [ "$kind" = "SNAPSHOT" ]; then
            snapshot="$archive"
            continue
        fi
        total=$((total + 1))
        if _backup_artifact "$snapshot" "$kind" "$archive" "$source" "$owner"; then
            printf '%s\tok\n' "$archive" >> "$snapshot/results.tsv"
        else
            printf '%s\tfailed\n' "$archive" >> "$snapshot/results.tsv"
            failed=$((failed + 1))
            warn "  failed: $archive"
        fi
    done < "$plan_file"

    if [ -z "$snapshot" ]; then
        error "Backup planning produced no snapshot directory."
        exit 3
    fi

    local result="ok"
    if [ "$failed" -gt 0 ] && [ "$failed" -lt "$total" ]; then
        result="partial"
    elif [ "$failed" -gt 0 ]; then
        result="failed"
    fi

    local summary
    if ! summary="$(py_cli backup-finish --backup-dir="$backup_dir" --snapshot="$snapshot" \
            --result="$result" | tr -d '\r')"; then
        error "Could not write the backup manifest."
        _backup_log "$backup_dir" backup "$(basename "$snapshot")" failed \
            "artifacts=$total error=\"manifest write failed\""
        exit 3
    fi

    local backup_id="" size_mb="" artifacts=""
    local key value
    while IFS=$'\t' read -r key value; do
        case "$key" in
            ID) backup_id="$value" ;;
            SIZE_MB) size_mb="$value" ;;
            ARTIFACTS) artifacts="$value" ;;
        esac
    done <<< "$summary"

    # shellcheck disable=SC2034  # read by cmd_upgrade in lib/sh/upgrade.sh
    LAST_BACKUP_ID="$backup_id"

    _backup_log "$backup_dir" backup "$backup_id" "$result" \
        "artifacts=$artifacts/$total size_mb=$size_mb duration=$((SECONDS - started))s"

    if [ -n "$retention" ]; then
        info "Applying retention: keeping backups newer than $retention day(s)..."
        local removed
        while IFS= read -r removed; do
            [ -z "$removed" ] && continue
            info "  removed restore point: $removed"
            _backup_log "$backup_dir" prune "$removed" ok "reason=retention days=$retention"
        done < <(py_cli backup-prune --backup-dir="$backup_dir" \
                    --retention-period-days="$retention" 2>/dev/null | tr -d '\r')
    fi

    case "$result" in
        ok)      success "backup complete: $backup_id ($artifacts artifacts, ${size_mb} MB)" ;;
        partial) warn "backup completed with errors: $backup_id ($failed of $total artifacts failed)" ;;
        failed)  error "backup failed: $backup_id (no artifact could be written)"; exit 3 ;;
    esac
}

# $1 snapshot, $2 kind, $3 archive (relative to snapshot), $4 source, $5 owner
_backup_artifact() {
    local snapshot="$1" kind="$2" archive="$3" source="$4" owner="$5"
    local snapshot_mount
    snapshot_mount="$(_docker_hostpath "$snapshot")"
    local rc=0

    case "$kind" in
        volume)
            info "  volume $source ($owner)"
            # shellcheck disable=SC2046  # word splitting is the point: one arg per container id
            _pause_containers $(_containers_using_volume "$source")
            _docker_run \
                -v "${source}:/volume:ro" \
                -v "${snapshot_mount}:/backup" \
                "$BACKUP_IMAGE" tar czf "/backup/${archive}" -C /volume . || rc=$?
            _unpause_all
            ;;
        configdir|binddir)
            local label="config dir"
            [ "$kind" = "binddir" ] && label="bind mount"
            if [ ! -d "$source" ]; then
                warn "  $label missing, skipping: $source"
                return 1
            fi
            info "  $label $source ($owner)"
            if [ "$kind" = "binddir" ]; then
                local project="${owner#addon:}"
                # shellcheck disable=SC2046
                _pause_containers $(_containers_of_project "$project")
            fi
            _docker_run \
                -v "$(_docker_hostpath "$source"):/src:ro" \
                -v "${snapshot_mount}:/backup" \
                "$BACKUP_IMAGE" tar czf "/backup/${archive}" -C /src . || rc=$?
            _unpause_all
            ;;
        *)
            warn "  unknown artifact kind '$kind', skipping"
            return 1
            ;;
    esac
    return "$rc"
}

# ─────────────────────────────────────────────────────────────────────────
# restore
# ─────────────────────────────────────────────────────────────────────────
cmd_restore() {
    local config_dir="$DEFAULT_CONFIG_DIR" backup_dir="" restore_point="" only=""
    local no_restart=0 restart_clean=0 list_only=0 assume_yes=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --backup-dir=*) backup_dir="${1#*=}" ;;
            --restore-point=*) restore_point="${1#*=}" ;;
            --only=*) only="${1#*=}" ;;
            --no-restart) no_restart=1 ;;
            --restart-clean) restart_clean=1 ;;
            --list) list_only=1 ;;
            -y|--yes) assume_yes=1 ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for restore: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done

    backup_dir="$(_resolve_backup_dir "$backup_dir")" || exit 3

    if [ "$list_only" -eq 1 ]; then
        py_cli backup-list --backup-dir="$backup_dir"
        return 0
    fi

    # A selection restores part of the snapshot and leaves the rest of the stack
    # serving. --restart-clean deletes every named volume of the projects it
    # touches, including the ones outside the selection that nothing will
    # repopulate, so the combination is data loss with extra steps.
    if [ -n "$only" ] && [ "$restart_clean" -eq 1 ]; then
        error "--restart-clean cannot be combined with --only: it would delete volumes"
        error "outside the selection that nothing in this restore point repopulates."
        exit 2
    fi

    # --no-restart wins over --restart-clean: it is the explicit "do not touch
    # the running stack" instruction, and honouring the weaker flag as well
    # would do exactly what the operator ruled out.
    if [ "$no_restart" -eq 1 ] && [ "$restart_clean" -eq 1 ]; then
        warn "--no-restart and --restart-clean given together; --no-restart takes precedence."
        restart_clean=0
    fi

    local -a extra=()
    [ -n "$restore_point" ] && extra+=(--restore-point="$restore_point")
    [ -n "$only" ] && extra+=(--only="$only")
    local plan_file
    plan_file="$(mktemp)"
    _BACKUP_TMPFILES+=("$plan_file")
    trap _backup_cleanup EXIT INT TERM
    # tr -d '\r': see the note in cmd_backup -- a CR on the last TSV field would
    # otherwise end up inside a snapshot path or a docker volume name.
    if ! py_cli restore-resolve --backup-dir="$backup_dir" "${extra[@]}" \
            | tr -d '\r' > "$plan_file"; then
        error "Could not resolve a restore point. Use 'papaia-ctl restore --list' to see what is available."
        exit 3
    fi

    local snapshot="" restore_id="" sel_profiles="" sel_addons="" has_configdir=0
    local kind archive target owner
    local -a kinds=() archives=() targets=() owners=()
    while IFS=$'\t' read -r kind archive target owner; do
        [ -z "$kind" ] && continue
        case "$kind" in
            SNAPSHOT) snapshot="$archive"; continue ;;
            ID) restore_id="$archive"; continue ;;
            PROFILES) sel_profiles="$archive"; continue ;;
            ADDONS) sel_addons="$archive"; continue ;;
        esac
        [ "$kind" = "configdir" ] && has_configdir=1
        kinds+=("$kind"); archives+=("$archive"); targets+=("$target"); owners+=("$owner")
    done < "$plan_file"

    if [ -z "$snapshot" ] || [ ${#kinds[@]} -eq 0 ]; then
        if [ -n "$only" ]; then
            error "Selection '$only' matches nothing in restore point $restore_id."
        else
            error "Restore point $restore_id contains no restorable artifacts."
        fi
        exit 3
    fi

    # Defence in depth. The grammar cannot name a configdir artifact -- it has
    # no module and no volume name to match on -- and resolve_selection asserts
    # the same thing. This is the invariant that lets a scoped restore run
    # in-process at all, so it is checked once more on the resolved set.
    if [ -n "$only" ] && [ "$has_configdir" -eq 1 ]; then
        error "A selection resolved to the configuration directory. Refusing."
        exit 2
    fi
    if [ -n "$only" ] && _list_contains "$sel_profiles" manager; then
        error "A selection resolved to the 'manager' profile. Refusing."
        exit 2
    fi

    warn "Restore point $restore_id will overwrite:"
    if [ -n "$only" ]; then
        warn "  ${#kinds[@]} archived volumes / directories matching '$only'"
    else
        warn "  the config directory $CONFIG_DIR"
        warn "  ${#kinds[@]} archived volumes / directories"
    fi
    if [ "$no_restart" -eq 1 ]; then
        warn "  --no-restart: containers are neither stopped nor recreated. Volumes"
        warn "  will be overwritten underneath live processes, which usually corrupts"
        warn "  both, and services keep the config files they started with."
    elif [ -n "$only" ]; then
        [ -n "$sel_profiles" ] && warn "  core containers in profiles: $sel_profiles (removed and recreated)"
        [ -n "$sel_addons" ] && warn "  addon containers: $sel_addons (removed and recreated)"
        warn "  everything else keeps running"
    else
        warn "  all core and addon containers (removed and recreated)"
    fi
    if [ "$restart_clean" -eq 1 ]; then
        warn "  --restart-clean: named volumes are DELETED first. Any volume not in"
        warn "  this restore point loses its data permanently."
    fi
    if [ "$assume_yes" -eq 0 ]; then
        if ! is_tty; then
            error "Refusing to restore without confirmation. Re-run with -y in non-interactive contexts."
            exit 2
        fi
        if ! confirm "Proceed with restore of $restore_id?" "N"; then
            error "Aborted."
            exit 3
        fi
    fi

    local started=$SECONDS

    if [ "$no_restart" -eq 0 ]; then
        if [ -n "$only" ]; then
            _restore_teardown_scoped "$sel_profiles" "$sel_addons"
        else
            _restore_teardown "$restart_clean"
        fi
    fi

    local i failed=0
    for i in "${!kinds[@]}"; do
        _restore_step artifact "${targets[$i]}" begin
        # A scoped teardown leaves most of the stack up, so a volume can still
        # have a user here -- an override outside the selected profiles, or a
        # container the teardown could not reach. Wiping it underneath a live
        # process corrupts both sides, so skip it and say which containers hold it.
        if [ -n "$only" ] && [ "${kinds[$i]}" = "volume" ] && [ "$no_restart" -eq 0 ]; then
            local holders
            holders="$(_containers_using_volume "${targets[$i]}")"
            if [ -n "$holders" ]; then
                warn "  skipped ${targets[$i]}: still in use by $(echo "$holders" | tr '\n' ' ')"
                _restore_step artifact "${targets[$i]}" in-use
                failed=$((failed + 1))
                continue
            fi
        fi
        if ! _restore_artifact "$snapshot" "${kinds[$i]}" "${archives[$i]}" \
                "${targets[$i]}" "${owners[$i]}"; then
            failed=$((failed + 1))
            warn "  failed: ${archives[$i]}"
            _restore_step artifact "${targets[$i]}" failed
        else
            _restore_step artifact "${targets[$i]}" ok
        fi
    done

    local result="ok"
    [ "$failed" -gt 0 ] && result="partial"
    [ "$failed" -eq "${#kinds[@]}" ] && result="failed"

    if [ "$no_restart" -eq 0 ]; then
        if [ -n "$only" ]; then
            _restore_restart_scoped "$sel_profiles" "$sel_addons"
        else
            info "Starting the stack again..."
            cmd_start --addons --config-dir="$CONFIG_DIR"
        fi
    fi

    local op="restore"
    [ -n "$only" ] && op="restore-scoped"
    _backup_log "$backup_dir" "$op" "$restore_id" "$result" \
        "artifacts=$(( ${#kinds[@]} - failed ))/${#kinds[@]} duration=$((SECONDS - started))s"

    case "$result" in
        ok)      success "restore complete: $restore_id (${#kinds[@]} artifacts)" ;;
        partial) warn "restore completed with errors: $restore_id ($failed of ${#kinds[@]} artifacts failed)" ;;
        failed)  error "restore failed: $restore_id (no artifact could be restored)"; exit 3 ;;
    esac
}

# Tear the stack down before restoring. $1 = 1 to drop named volumes as well.
#
# Containers are REMOVED, never merely stopped. Most core services bind-mount
# individual *files* out of $PAPAIA_CONFIG_DIR (searxng/settings.yml,
# keycloak.conf, librechat.yaml, the litellm and prometheus configs, ...). A
# stopped container keeps the mount source it was created with, pinned to the
# inode behind it -- and under Docker Desktop to a bind-mount proxy path
# derived from it. Restoring the config directory replaces every one of those
# files, so starting such a container again fails in the daemon with
# "error mounting ... no such file or directory". Recreating the container
# makes Docker resolve the bind sources afresh, which is the only way the
# restored files are picked up.
# restore, narrowed so that it cannot replace the configuration directory.
#
# A caller that runs inside the stack -- papaia-manager is a service of the very
# compose project a restore tears down -- can only survive an operation that
# provably leaves $PAPAIA_CONFIG_DIR and the manager profile alone. `restore`
# with the right flags does that too, but only by argument: one missing flag or
# one empty variable and it is a whole-stack restore again. This entry point
# makes the property structural instead, so the caller's allowlist can name a
# verb rather than trust a flag combination.
#
# Everything else is cmd_restore. --only is mandatory, --restart-clean is
# rejected outright rather than silently dropped.
cmd_restore_scoped() {
    local arg only=""
    for arg in "$@"; do
        case "$arg" in
            --only=*) only="${arg#*=}" ;;
            --restart-clean)
                error "restore-scoped does not accept --restart-clean."
                exit 2
                ;;
        esac
    done
    if [ -z "$only" ]; then
        error "restore-scoped requires --only=SELECTOR[,SELECTOR]."
        error "Use 'papaia-ctl restore' to restore a point as a whole."
        exit 2
    fi
    cmd_restore "$@"
}

# Comma-separated list to one item per line. Empty input yields no lines.
#
# The trailing newline is load-bearing: `read` returns non-zero on a final line
# without one, so a `while read` loop silently drops the last item -- which here
# would mean the last add-on of a selection never being brought down.
_split_list() {
    [ -n "$1" ] || return 0
    printf '%s\n' "$1" | tr ',' '\n'
}

# Comma-separated list membership. $1 = list, $2 = needle.
_list_contains() {
    local needle="$2" item
    while IFS= read -r item; do
        [ "$item" = "$needle" ] && return 0
    done < <(_split_list "$1")
    return 1
}

# One machine-readable progress line per step, for a caller rendering per-item
# state. Deliberately not the info/warn prose above it: that text is written for
# an operator reading a terminal and is expected to be reworded, so parsing it
# would make every copy edit a breaking change.
# $1 = phase (teardown|artifact|restart), $2 = subject, $3 = state
_restore_step() {
    printf 'RESTORE-STEP\t%s\t%s\t%s\n' "$1" "$2" "$3"
}

# Tear down only what a selection touches. $1 = comma-separated core profiles,
# $2 = comma-separated addon names. Either may be empty.
#
# Same removal rationale as _restore_teardown, and the same ordering as
# cmd_start: add-ons first, because their compose projects are independent and
# a core `down` scoped by profile must not race them.
_restore_teardown_scoped() {
    local profiles="$1" addons="$2"
    local env_file="$REPO_ROOT/src/.env"
    local addon_name addon_path

    # Resolve before stopping anything. A profile subset that disables a hard
    # depends_on target makes compose fall back to project-name-only mode, where
    # a scoped down silently becomes a whole-stack down -- exactly what this
    # guard exists for. Failing here costs nothing; failing after the add-ons
    # are down leaves half a stack.
    if [ -n "$profiles" ]; then
        _require_profiles_resolve "$profiles" "$env_file" -f "$COMPOSE_FILE"
    fi

    while IFS= read -r addon_name; do
        [ -z "$addon_name" ] && continue
        _restore_step teardown "addon:$addon_name" begin
        addon_path="$(_addon_path "$addon_name" 2>/dev/null || true)"
        if [ -z "$addon_path" ] || [ ! -f "$addon_path/docker-compose.yml" ]; then
            warn "  addon $addon_name is no longer installed; skipping its teardown"
            _restore_step teardown "addon:$addon_name" missing
            continue
        fi
        info "  addon $addon_name: docker compose down"
        docker compose -f "$addon_path/docker-compose.yml" down
        _restore_step teardown "addon:$addon_name" ok
    done < <(_split_list "$addons")

    if [ -n "$profiles" ]; then
        info "Stopping and removing containers in profiles: $profiles"
        _restore_step teardown "$profiles" begin
        # The project network still carries endpoints from the profiles that
        # stay up, so compose reports it cannot be removed. That is expected and
        # is a warning, not a failure -- but the script runs under `set -e`, so
        # the status is captured and the outcome is asserted below instead.
        local status=0
        COMPOSE_PROFILES="$profiles" docker compose -f "$COMPOSE_FILE" \
            --env-file "$env_file" down || status=$?
        if [ "$status" -ne 0 ]; then
            warn "  compose down reported status $status (usually the shared network still in use)"
        fi
        _restore_step teardown "$profiles" ok
    fi
}

# Bring back only what the selection took down. $1 = profiles, $2 = addon names.
#
# Add-ons come up before the core on purpose: cmd_start only includes an
# override from $CONFIG_DIR/overrides/ when its external network already
# exists, and otherwise drops it with a warning. A still-down add-on would
# therefore lose its core-side integration until the next full start.
# cmd_start --addons orders it the same way.
_restore_restart_scoped() {
    local profiles="$1" addons="$2"
    local addon_name addon_path

    while IFS= read -r addon_name; do
        [ -z "$addon_name" ] && continue
        addon_path="$(_addon_path "$addon_name" 2>/dev/null || true)"
        if [ -z "$addon_path" ] || [ ! -f "$addon_path/docker-compose.yml" ]; then
            _restore_step restart "addon:$addon_name" missing
            continue
        fi
        info "Starting addon $addon_name from $addon_path"
        _addon_compose_up "$addon_name" "$addon_path"
        _restore_step restart "addon:$addon_name" ok
    done < <(_split_list "$addons")

    if [ -n "$profiles" ]; then
        info "Starting core profiles again: $profiles"
        _restore_step restart "$profiles" begin
        # No --addons: they were handled above, and starting the ones outside
        # the selection would turn a scoped restore into a stack-wide operation.
        cmd_start --profiles="$profiles" --config-dir="$CONFIG_DIR"
        _restore_step restart "$profiles" ok
    fi
}

_restore_teardown() {
    local with_volumes="$1"
    local env_file="$REPO_ROOT/src/.env"
    local -a extra=()
    if [ "$with_volumes" -eq 1 ]; then
        extra+=(-v)
        info "Stopping and removing containers and named volumes (core + addons)..."
    else
        info "Stopping and removing containers (core + addons)..."
    fi
    if [ -f "$CONFIG_DIR/deployment.yaml" ]; then
        _addon_compose_all down "${extra[@]}"
    fi
    docker compose -f "$COMPOSE_FILE" --env-file "$env_file" down "${extra[@]}"
}

# $1 snapshot, $2 kind, $3 archive, $4 target, $5 owner
_restore_artifact() {
    local snapshot="$1" kind="$2" archive="$3" target="$4" owner="$5"
    local snapshot_mount
    snapshot_mount="$(_docker_hostpath "$snapshot")"

    if [ ! -f "$snapshot/$archive" ]; then
        warn "  archive missing in snapshot, skipping: $archive"
        return 1
    fi

    case "$kind" in
        volume)
            info "  volume $target ($owner)"
            docker volume inspect "$target" >/dev/null 2>&1 || docker volume create "$target" >/dev/null
            _docker_run \
                -e "ARCHIVE=$archive" \
                -v "${target}:/volume" \
                -v "${snapshot_mount}:/backup" \
                "$BACKUP_IMAGE" sh -c \
                'rm -rf /volume/..?* /volume/.[!.]* /volume/* 2>/dev/null; tar xzf "/backup/$ARCHIVE" -C /volume'
            ;;
        configdir|binddir)
            if [ "$kind" = "binddir" ] && [ ! -d "$target" ]; then
                # The add-on that owned this directory is no longer installed;
                # recreating the tree would leave orphaned data behind.
                warn "  bind mount target no longer exists, skipping: $target"
                return 1
            fi
            info "  $([ "$kind" = configdir ] && echo 'config dir' || echo 'bind mount') $target ($owner)"
            mkdir -p "$target"
            _docker_run \
                -e "ARCHIVE=$archive" \
                -v "$(_docker_hostpath "$target"):/target" \
                -v "${snapshot_mount}:/backup" \
                "$BACKUP_IMAGE" sh -c \
                'rm -rf /target/..?* /target/.[!.]* /target/* 2>/dev/null; tar xzf "/backup/$ARCHIVE" -C /target'
            ;;
        *)
            warn "  unknown artifact kind '$kind', skipping"
            return 1
            ;;
    esac
}
