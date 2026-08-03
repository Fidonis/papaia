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
    local config_dir="$DEFAULT_CONFIG_DIR" backup_dir="" restore_point=""
    local no_restart=0 restart_clean=0 list_only=0 assume_yes=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --backup-dir=*) backup_dir="${1#*=}" ;;
            --restore-point=*) restore_point="${1#*=}" ;;
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

    # --no-restart wins over --restart-clean: it is the explicit "do not touch
    # the running stack" instruction, and honouring the weaker flag as well
    # would do exactly what the operator ruled out.
    if [ "$no_restart" -eq 1 ] && [ "$restart_clean" -eq 1 ]; then
        warn "--no-restart and --restart-clean given together; --no-restart takes precedence."
        restart_clean=0
    fi

    local -a extra=()
    [ -n "$restore_point" ] && extra+=(--restore-point="$restore_point")
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

    local snapshot="" restore_id=""
    local kind archive target owner
    local -a kinds=() archives=() targets=() owners=()
    while IFS=$'\t' read -r kind archive target owner; do
        [ -z "$kind" ] && continue
        case "$kind" in
            SNAPSHOT) snapshot="$archive"; continue ;;
            ID) restore_id="$archive"; continue ;;
        esac
        kinds+=("$kind"); archives+=("$archive"); targets+=("$target"); owners+=("$owner")
    done < "$plan_file"

    if [ -z "$snapshot" ] || [ ${#kinds[@]} -eq 0 ]; then
        error "Restore point $restore_id contains no restorable artifacts."
        exit 3
    fi

    warn "Restore point $restore_id will overwrite:"
    warn "  the config directory $CONFIG_DIR"
    warn "  ${#kinds[@]} archived volumes / directories"
    if [ "$no_restart" -eq 1 ]; then
        warn "  --no-restart: containers are neither stopped nor recreated. Volumes"
        warn "  will be overwritten underneath live processes, which usually corrupts"
        warn "  both, and services keep the config files they started with."
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
        _restore_teardown "$restart_clean"
    fi

    local i failed=0
    for i in "${!kinds[@]}"; do
        if ! _restore_artifact "$snapshot" "${kinds[$i]}" "${archives[$i]}" \
                "${targets[$i]}" "${owners[$i]}"; then
            failed=$((failed + 1))
            warn "  failed: ${archives[$i]}"
        fi
    done

    local result="ok"
    [ "$failed" -gt 0 ] && result="partial"
    [ "$failed" -eq "${#kinds[@]}" ] && result="failed"

    if [ "$no_restart" -eq 0 ]; then
        info "Starting the stack again..."
        cmd_start --addons --config-dir="$CONFIG_DIR"
    fi

    _backup_log "$backup_dir" restore "$restore_id" "$result" \
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
