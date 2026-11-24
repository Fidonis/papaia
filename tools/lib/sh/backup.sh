# shellcheck shell=bash
# papaia-ctl — backup / restore commands.
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

# Sidecar image used to tar/untar volumes and host directories. Pinned to a
# version and its digest so neither a moved tag nor a new release can change
# archive behaviour; lib/node_shell.py pins the same image.
BACKUP_IMAGE="alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf"

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
        for cid in ${_PAUSED_CONTAINERS[@]+"${_PAUSED_CONTAINERS[@]}"}; do
            docker unpause "$cid" >/dev/null 2>&1 || true
        done
        _PAUSED_CONTAINERS=()
    fi
    return 0
}

_backup_cleanup() {
    _unpause_all
    _restore_close_pending
    local f
    if [ ${#_BACKUP_TMPFILES[@]} -gt 0 ]; then
        for f in ${_BACKUP_TMPFILES[@]+"${_BACKUP_TMPFILES[@]}"}; do
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
    if ! resolved="$(py_cli backup-dir ${extra[@]+"${extra[@]}"})"; then
        return 3
    fi
    printf '%s' "${resolved%$'\r'}"
}

# ─────────────────────────────────────────────────────────────────────────
# backup
# ─────────────────────────────────────────────────────────────────────────
cmd_backup() {
    case "${1:-}" in
        recipients|keys|target|key-check|mirror) _backup_admin "$@"; return ;;
    esac
    local config_dir="$DEFAULT_CONFIG_DIR" backup_dir="" retention="" keep="" only="" only_given=0
    local rollback_key=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --backup-dir=*) backup_dir="${1#*=}" ;;
            # Set by `upgrade` for its restore point R0 (lib/rollback_key.py).
            --rollback-key=*) rollback_key="${1#*=}" ;;
            --retention-period-days=*) retention="${1#*=}" ;;
            --keep=*) keep="${1#*=}" ;;
            --only=*) only="${1#*=}"; only_given=1 ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for backup: $1"; exit 2 ;;
        esac
        shift
    done
    if [ -n "$retention" ] && ! [[ "$retention" =~ ^[0-9]+$ ]]; then
        error "--retention-period-days must be a whole number of days (got: $retention)"
        exit 2
    fi
    if [ -n "$keep" ] && ! [[ "$keep" =~ ^[1-9][0-9]{0,3}$ ]]; then
        error "--keep must be the number of restore points to keep, 1 or more (got: $keep)"
        exit 2
    fi
    # An empty --only= is a mistake worth stopping on: quietly backing up the
    # whole stack is the opposite of what the caller asked for.
    if [ "$only_given" -eq 1 ] && [ -z "$only" ]; then
        error "--only needs at least one selector (addon:NAME, module:NAME or volume:NAME)."
        exit 2
    fi
    CONFIG_DIR="$config_dir"
    _require_setup_done
    # One correlation id for every audit row of this run (papaia.audit/1), across the
    # separate py_cli calls below; a caller such as `upgrade` may already have set one.
    if [ -z "${PAPAIA_CORRELATION_ID:-}" ]; then
        PAPAIA_CORRELATION_ID="$(py_cli new-correlation-id | tr -d '\r')" || exit 3
    fi
    export PAPAIA_CORRELATION_ID
    local mode
    mode="$(_topology_mode)" || exit 3
    if [ "$mode" = "distributed" ]; then
        if [ -n "$rollback_key" ]; then
            error "A rollback key is not available for a distributed installation."
            exit 2
        fi
        _backup_distributed "$backup_dir" "$retention" "$only" "$only_given" "$keep"
        return
    fi

    trap _backup_cleanup EXIT INT TERM

    # No mkdir: there is no default target, and a missing directory (an unmounted share)
    # must stop the backup instead of filling the local disk (RE-33). backup-plan checks
    # the directory, its .papaia-target and the recipients before anything is written.
    backup_dir="$(_resolve_backup_dir "$backup_dir")" || exit 3
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
    local -a plan_extra=()
    [ "$only_given" -eq 1 ] && plan_extra+=(--only="$only")
    [ -n "$rollback_key" ] && plan_extra+=(--rollback-key="$rollback_key")
    # `tr -d '\r'`: on Windows the Python interpreter emits CRLF, and IFS=$'\t'
    # leaves the CR attached to the last field -- a snapshot path ending in CR
    # makes docker bind-mount (and auto-create) a second, wrong directory.
    # pipefail is set, so a failing py_cli still fails the pipeline, and its
    # status is the pipeline's: 2 means the selection cannot be met (it said why
    # on stderr and wrote nothing), anything else is a planning failure.
    local plan_rc=0
    py_cli backup-plan --backup-dir="$backup_dir" --existing-volumes="$volumes_file" \
            ${plan_extra[@]+"${plan_extra[@]}"} | tr -d '\r' > "$plan_file" || plan_rc=$?
    if [ "$plan_rc" -eq 2 ]; then
        exit 2
    elif [ "$plan_rc" -ne 0 ]; then
        error "Could not plan the backup."
        exit 3
    fi

    local snapshot="" scope="" kind archive source owner
    local total=0 failed=0
    local started=$SECONDS

    while IFS=$'\t' read -r kind archive source owner; do
        [ -z "$kind" ] && continue
        if [ "$kind" = "SNAPSHOT" ]; then
            snapshot="$archive"
            continue
        fi
        if [ "$kind" = "SCOPE" ]; then
            scope="$archive"
            info "Scope: $scope (the configuration directory and everything else is not included)"
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

    # The erasure journal to its mirror, so a copy of this target kept outside the house
    # never outlives a deletion (BE-16, RE-86).
    if ! _erasure_mirror_sync "$backup_dir" && [ "$result" = "ok" ]; then
        result="partial"
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
        "artifacts=$artifacts/$total size_mb=$size_mb duration=$((SECONDS - started))s${scope:+ scope=$scope}"

    if [ -n "$keep" ]; then
        info "Applying retention: keeping the $keep newest restore points..."
        local dropped
        while IFS= read -r dropped; do
            [ -z "$dropped" ] && continue
            info "  removed restore point: $dropped"
            _backup_log "$backup_dir" prune "$dropped" ok "reason=retention keep=$keep"
        done < <(py_cli backup-prune --backup-dir="$backup_dir" --keep="$keep" \
                    | tr -d '\r')
    fi

    if [ -n "$retention" ]; then
        info "Applying retention: keeping backups newer than $retention day(s)..."
        local removed
        while IFS= read -r removed; do
            [ -z "$removed" ] && continue
            info "  removed restore point: $removed"
            _backup_log "$backup_dir" prune "$removed" ok "reason=retention days=$retention"
        done < <(py_cli backup-prune --backup-dir="$backup_dir" \
                    --retention-period-days="$retention" | tr -d '\r')
    fi

    case "$result" in
        ok)      success "backup complete: $backup_id ($artifacts artifacts, ${size_mb} MB)" ;;
        partial) warn "backup completed with errors: $backup_id ($failed of $total artifacts failed)" ;;
        failed)  error "backup failed: $backup_id (no artifact could be written)"; exit 3 ;;
    esac
}

# backup of a distributed installation: one restore point on this controller, every node's
# data streamed into it (lib/cluster_data.py). Sets LAST_BACKUP_ID like cmd_backup.
# $1 backup dir (may be empty), $2 retention days, $3 selection, $4 1 if --only was given
_backup_distributed() {
    local backup_dir="$1" retention="$2" only="$3" only_given="$4" keep="${5:-}"
    _cluster_require_unlocked
    local -a extra=()
    [ -n "$keep" ] && extra+=(--keep="$keep")
    [ -n "$backup_dir" ] && extra+=(--backup-dir="$backup_dir")
    [ -n "$retention" ] && extra+=(--retention-period-days="$retention")
    [ "$only_given" -eq 1 ] && extra+=(--only="$only")
    local out rc=0
    out="$(mktemp)"
    py_cli cluster-backup ${extra[@]+"${extra[@]}"} | tee "$out" || rc=$?
    local key value backup_id="" result=""
    while IFS=$'\t' read -r key value; do
        case "$key" in
            ID) backup_id="${value%$'\r'}" ;;
            RESULT) result="${value%$'\r'}" ;;
        esac
    done < "$out"
    rm -f "$out"
    [ "$rc" -eq 2 ] && exit 2
    # shellcheck disable=SC2034  # read by cmd_upgrade in lib/sh/upgrade.sh
    LAST_BACKUP_ID="$backup_id"
    case "$result" in
        ok)      success "backup complete: $backup_id" ;;
        partial) warn "backup completed with errors: $backup_id" ;;
        *)       error "backup failed${backup_id:+: $backup_id}"; exit 3 ;;
    esac
}

# restore of a distributed installation. $1 backup dir, $2 restore point, $3 selection,
# $4 1 for --no-restart, $5 1 for --restart-clean, $6 1 for -y
_restore_distributed() {
    local backup_dir="$1" restore_point="$2" only="$3" no_restart="$4" restart_clean="$5"
    local assume_yes="$6"
    if [ "$restart_clean" -eq 1 ]; then
        error "--restart-clean is not available for a distributed installation."
        exit 2
    fi
    local -a extra=()
    [ -n "$backup_dir" ] && extra+=(--backup-dir="$backup_dir")
    [ -n "$restore_point" ] && extra+=(--restore-point="$restore_point")
    [ -n "$only" ] && extra+=(--only="$only")
    local plan rc=0
    plan="$(py_cli cluster-restore --plan ${extra[@]+"${extra[@]}"})" || rc=$?
    [ "$rc" -ne 0 ] && exit "$rc"
    local key value restore_id=""
    warn "This restore will overwrite:"
    while IFS=$'\t' read -r key value; do
        value="${value%$'\r'}"
        case "$key" in
            ID) restore_id="$value" ;;
            WILL) warn "  $value" ;;
        esac
    done <<< "$plan"
    if [ "$no_restart" -eq 1 ]; then
        warn "  --no-restart: containers are neither stopped nor started again."
    elif [ -n "$only" ]; then
        warn "  the services whose data it replaces are stopped and started again; nothing"
        warn "  else, and no other node, is touched"
    else
        warn "  every node is stopped, its data replaced and the installation started again"
    fi
    warn "  Nodes are restored one after another; their data comes from points a few"
    warn "  minutes apart, as it was archived."
    if [ "$assume_yes" -eq 0 ]; then
        if ! is_tty; then
            error "Refusing to restore without confirmation. Re-run with -y in non-interactive contexts."
            exit 2
        fi
        confirm "Proceed with restore of $restore_id?" "N" || { error "Aborted."; exit 3; }
    fi
    [ "$no_restart" -eq 1 ] && extra+=(--no-restart)
    local out
    out="$(mktemp)"
    rc=0
    py_cli cluster-restore ${extra[@]+"${extra[@]}"} | tee "$out" || rc=$?
    local result=""
    while IFS=$'\t' read -r key value; do
        [ "$key" = "RESULT" ] && result="${value%$'\r'}"
    done < "$out"
    rm -f "$out"
    [ "$rc" -eq 2 ] && exit 2
    case "$result" in
        ok)      success "restore complete: $restore_id" ;;
        partial) warn "restore completed with errors: $restore_id" ;;
        *)       error "restore failed: $restore_id"; exit 3 ;;
    esac
    warn "post-restore does not run in a distributed installation yet: sessions and"
    warn "delegations from the restore point stay usable until the realm's 'not before' is"
    warn "set and the consents of flow-engine and assist-gate are removed in Keycloak."
}

# The tar stream of the sidecar never touches the disk in clear: backup-seal encrypts it
# to the recipients on the way into the snapshot and refuses key material in it
# (lib/backup_crypt.py). pipefail is set, so a failing tar fails the artifact as well.
# $1 snapshot, $2 archive (relative to snapshot)
_backup_seal() {
    py_cli backup-seal --snapshot="$1" --archive="$2"
}

# $1 snapshot, $2 kind, $3 archive (relative to snapshot), $4 source, $5 owner
_backup_artifact() {
    local snapshot="$1" kind="$2" archive="$3" source="$4" owner="$5"
    local rc=0

    case "$kind" in
        volume)
            info "  volume $source ($owner)"
            # shellcheck disable=SC2046  # word splitting is the point: one arg per container id
            _pause_containers $(_containers_using_volume "$source")
            _docker_run \
                -v "${source}:/volume:ro" \
                "$BACKUP_IMAGE" tar czf - -C /volume . \
                | _backup_seal "$snapshot" "$archive" || rc=$?
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
            # The key of the test stack's hosted model never goes into an archive
            # (lib/hosted_model.py KEY_FILE); a bind mount has no such file to leave out.
            # Nor does state/ (lib/halt.py): a restore must neither lift
            # nor set the platform halt, and the rollback keys of an upgrade (state/rollback/,
            # BE-11) stay on this host. backup-seal refuses the archive should a key get through.
            local -a exclude=()
            [ "$kind" = "configdir" ] && exclude=(--exclude=./ai/litellm/test-hosted.env
                --exclude=./state)
            _docker_run \
                -v "$(_docker_hostpath "$source"):/src:ro" \
                "$BACKUP_IMAGE" tar czf - ${exclude[@]+"${exclude[@]}"} -C /src . \
                | _backup_seal "$snapshot" "$archive" || rc=$?
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
# backup recipients | keys | target | key-check
# ─────────────────────────────────────────────────────────────────────────
# Keys and the target are kept by lib/backup_crypt.py; this only maps the words of the
# command line onto it. Private keys pass through standard input or a terminal only.
_backup_admin() {
    local area="$1"; shift
    local config_dir="$DEFAULT_CONFIG_DIR" action="" name="" key="" identity="" point=""
    local backup_dir="" names="" mirror="" offsite="" mirror_given=0
    case "$area" in
        recipients|target|keys) action="${1:-}"; [ $# -gt 0 ] && shift ;;
    esac
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --backup-dir=*) backup_dir="${1#*=}" ;;
            # The one name of the source in the restore part of the handbook (RE-88).
            --from=*)
                if [ "$area" != key-check ]; then
                    error "--from is an option of 'backup key-check'; use --backup-dir here."
                    exit 2
                fi
                backup_dir="${1#*=}"
                ;;
            --name=*) name="${1#*=}" ;;
            --key=*) key="${1#*=}" ;;
            --names=*) names="${1#*=}" ;;
            --identity=*) identity="${1#*=}" ;;
            --restore-point=*) point="${1#*=}" ;;
            --erasure-mirror=*) mirror="${1#*=}"; mirror_given=1 ;;
            --offsite-retention=*) offsite="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for backup $area: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local -a extra=()
    [ -n "$backup_dir" ] && extra+=(--backup-dir="$backup_dir")
    case "$area" in
        recipients)
            case "$action" in
                list) ;;
                add) extra+=(--name="$name" --key="$key") ;;
                remove) extra+=(--name="$name") ;;
                *) error "backup recipients list|add|remove"; exit 2 ;;
            esac
            py_cli backup-recipients "$action" ${extra[@]+"${extra[@]}"}
            ;;
        keys)
            [ "$action" = "generate" ] || { error "backup keys generate [--names=A,B]"; exit 2; }
            if [ -n "$names" ]; then
                py_cli backup-keygen --names="$names"
            else
                py_cli backup-keygen
            fi
            ;;
        target)
            case "$action" in
                init|check) ;;
                *) error "backup target init|check [--backup-dir=PATH]"; exit 2 ;;
            esac
            py_cli backup-target "$action" ${extra[@]+"${extra[@]}"}
            ;;
        mirror)
            # Without values show them; with values set them (lib/erasure_mirror.py).
            action=show
            if [ "$mirror_given" -eq 1 ]; then
                action=configure
                extra+=(--erasure-mirror="$mirror")
            fi
            if [ -n "$offsite" ]; then
                action=configure
                extra+=(--offsite-retention="$offsite")
            fi
            py_cli erasure-mirror "$action" ${extra[@]+"${extra[@]}"}
            ;;
        key-check)
            if [ -z "$identity" ]; then
                error "backup key-check needs --identity=FILE or --identity=- (standard input)."
                exit 2
            fi
            [ -n "$point" ] && extra+=(--restore-point="$point")
            py_cli backup-key-check --identity="$identity" ${extra[@]+"${extra[@]}"}
            ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────
# backup-delete
# ─────────────────────────────────────────────────────────────────────────
# Remove one or more restore points -- the snapshot directory and the
# backup.yaml entry. Every id is checked against the catalogue before anything
# is removed (delete_backups in lib/backup.py), so a single unknown id aborts
# the whole call. Nothing in the running stack is touched.
cmd_backup_delete() {
    local config_dir="$DEFAULT_CONFIG_DIR" backup_dir="" assume_yes=0
    local -a points=()
    local item
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --backup-dir=*) backup_dir="${1#*=}" ;;
            --restore-point=*)
                # Repeatable, and each value may itself be comma-separated.
                while IFS= read -r item; do
                    [ -n "$item" ] && points+=("$item")
                done < <(_split_list "${1#*=}")
                ;;
            -y|--yes) assume_yes=1 ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for backup-delete: $1"; exit 2 ;;
        esac
        shift
    done

    if [ ${#points[@]} -eq 0 ]; then
        error "backup-delete requires --restore-point=ID (repeatable, or comma-separated)."
        exit 2
    fi

    CONFIG_DIR="$config_dir"
    _require_setup_done

    backup_dir="$(_resolve_backup_dir "$backup_dir")" || exit 3

    if [ "$assume_yes" -eq 0 ]; then
        if ! is_tty; then
            error "Refusing to delete without confirmation. Re-run with -y in non-interactive contexts."
            exit 2
        fi
        warn "About to permanently delete ${#points[@]} restore point(s):"
        printf '  %s\n' ${points[@]+"${points[@]}"} >&2
        if ! confirm "Delete permanently?" "N"; then
            error "Aborted."
            exit 3
        fi
    fi

    local -a args=()
    local p
    for p in ${points[@]+"${points[@]}"}; do
        args+=(--restore-point="$p")
    done

    # tr -d '\r': see the note in cmd_backup -- a CR on the id would otherwise
    # travel into the backup.log line and the info output.
    local removed
    if ! removed="$(py_cli backup-delete --backup-dir="$backup_dir" ${args[@]+"${args[@]}"} | tr -d '\r')"; then
        error "Could not delete the requested restore point(s)."
        exit 3
    fi

    local id count=0
    while IFS= read -r id; do
        [ -z "$id" ] && continue
        count=$((count + 1))
        _backup_log "$backup_dir" delete "$id" ok "reason=manual"
        info "  deleted restore point: $id"
    done <<< "$removed"

    success "Deleted $count restore point(s) from $backup_dir"
}

# ─────────────────────────────────────────────────────────────────────────
# restore
# ─────────────────────────────────────────────────────────────────────────
# Why the add-ons' restore steps run (lib/module_actions.py): `restore`, or `rollback` when
# an add-on rollback restores its data through restore-scoped.
RESTORE_TRIGGER="restore"

# Is there a setup in $CONFIG_DIR? Asks _require_setup_done itself, in a subshell so its
# exit only ends that.
_restore_setup_present() {
    ( _require_setup_done ) >/dev/null 2>&1
}

cmd_restore() {
    local config_dir="$DEFAULT_CONFIG_DIR" backup_dir="" restore_point="" only=""
    local no_restart=0 restart_clean=0 list_only=0 assume_yes=0 insecure_images=0
    local identity="" host_loss=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            # The backup target to restore from (BE-18a, RE-88). --backup-dir below is the
            # older spelling, kept for callers that still pass it.
            --from=*)
                backup_dir="${1#*=}"
                if [ -z "$backup_dir" ]; then
                    error "--from needs the backup target, for example --from=/mnt/papaia-backup."
                    exit 2
                fi
                ;;
            --identity=*)
                identity="${1#*=}"
                if [ -z "$identity" ]; then
                    error "--identity needs a key file or - (the key on standard input)."
                    exit 2
                fi
                ;;
            --insecure-images) insecure_images=1 ;;
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
    # Standard input carries the key, so it cannot also carry the answer to the
    # confirmation; refuse before the key is read.
    if [ "$identity" = "-" ] && [ "$assume_yes" -eq 0 ] && [ "$list_only" -eq 0 ]; then
        error "--identity=- reads the key from standard input, which then cannot answer"
        error "the confirmation. Add -y to confirm the restore, or pass --identity=FILE."
        exit 2
    fi
    CONFIG_DIR="$config_dir"
    # After the loss of the host there is no setup, only the target and the key: the
    # restore point brings the configuration back (BE-18a).
    if ! _restore_setup_present; then
        if [ -z "$backup_dir" ]; then
            error "No setup found at $CONFIG_DIR. Run 'papaia-ctl setup' first, or restore"
            error "after the loss of the host with 'papaia-ctl restore --from=<target>"
            error "--identity=-' (see docs/de/wiederherstellung.md)."
            exit 2
        fi
        if [ -n "$only" ]; then
            error "Without a setup only the whole restore point can be restored (no --only)."
            exit 2
        fi
        host_loss=1
    else
        _require_setup_done
    fi
    local mode
    mode="$(_topology_mode)" || exit 3
    if [ "$mode" = "distributed" ] && [ -n "$identity" ]; then
        error "--identity is not available in a distributed installation yet."
        exit 2
    fi
    if [ "$mode" = "distributed" ] && [ "$list_only" -eq 0 ]; then
        _restore_distributed "$backup_dir" "$restore_point" "$only" "$no_restart" \
            "$restart_clean" "$assume_yes"
        return
    fi

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

    # One correlation id for every audit row of this run and for the add-ons' restore steps.
    if [ -z "${PAPAIA_CORRELATION_ID:-}" ]; then
        PAPAIA_CORRELATION_ID="$(py_cli new-correlation-id | tr -d '\r')" || exit 3
    fi
    export PAPAIA_CORRELATION_ID

    # The operator's key is read once (a protected key file asks for its passphrase once)
    # and stays in this process: piped to each Python step, never into a file, an argument
    # or the environment.
    _RESTORE_IDENTITIES=""
    if [ -n "$identity" ]; then
        _RESTORE_IDENTITIES="$(py_cli backup-identities --identity="$identity")" || exit 2
    fi

    local -a extra=()
    [ -n "$restore_point" ] && extra+=(--restore-point="$restore_point")
    [ -n "$only" ] && extra+=(--only="$only")
    [ -n "$_RESTORE_IDENTITIES" ] && extra+=(--identity=-)
    [ "$host_loss" -eq 1 ] && extra+=(--host-loss)
    # The release of the point against this checkout (RE-88).
    extra+=(--check-release)
    local plan_file
    plan_file="$(mktemp)"
    _BACKUP_TMPFILES+=("$plan_file")
    trap _backup_cleanup EXIT INT TERM
    # tr -d '\r': see the note in cmd_backup -- a CR on the last TSV field would
    # otherwise end up inside a snapshot path or a docker volume name.
    # Status 2 is a request that does not fit the restore point (a scoped backup
    # asked for as a whole); the reason is already on stderr.
    # With a key, restore-resolve also checks that it opens every archive and that none
    # changed, before anything below touches the stack.
    local resolve_rc=0
    if [ -n "$_RESTORE_IDENTITIES" ]; then
        printf '%s\n' "$_RESTORE_IDENTITIES" \
            | py_cli restore-resolve --backup-dir="$backup_dir" ${extra[@]+"${extra[@]}"} \
            | tr -d '\r' > "$plan_file" || resolve_rc=$?
    else
        py_cli restore-resolve --backup-dir="$backup_dir" ${extra[@]+"${extra[@]}"} \
            | tr -d '\r' > "$plan_file" || resolve_rc=$?
    fi
    if [ "$resolve_rc" -eq 2 ]; then
        exit 2
    elif [ "$resolve_rc" -ne 0 ]; then
        error "Could not resolve a restore point. Use 'papaia-ctl restore --list' to see what is available."
        exit 3
    fi

    local snapshot="" restore_id="" sel_profiles="" sel_addons="" has_configdir=0
    _RESTORE_ENCRYPTED=0
    _RESTORE_MARKED=0
    local kind archive target owner
    local -a kinds=() archives=() targets=() owners=()
    while IFS=$'\t' read -r kind archive target owner; do
        [ -z "$kind" ] && continue
        case "$kind" in
            SNAPSHOT) snapshot="$archive"; continue ;;
            ID) restore_id="$archive"; continue ;;
            PROFILES) sel_profiles="$archive"; continue ;;
            ADDONS) sel_addons="$archive"; continue ;;
            ENCRYPTED) _RESTORE_ENCRYPTED=1; continue ;;
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
    if [ "$host_loss" -eq 1 ]; then
        warn "  no setup at $CONFIG_DIR: the restore point brings the configuration back"
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
    # Every token issued before this second belongs to the stack the restore replaces;
    # post-restore below revokes what the restore point brings back from before it.
    local since
    since="$(date +%s)"

    if [ "$host_loss" -eq 1 ]; then
        # Nothing of this installation runs here yet, and there is no configuration for
        # compose to stop it with.
        info "No setup on this host: nothing to stop."
    elif [ "$no_restart" -eq 0 ]; then
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
        # container the teardown could not reach. After a whole teardown a user is a
        # container of another compose project on the same Docker engine, such as the
        # installation this point was taken of while it is restored next to it (RS-2).
        # Wiping it underneath a live process corrupts both sides, so skip it and say
        # which containers hold it.
        if [ "${kinds[$i]}" = "volume" ] && [ "$no_restart" -eq 0 ]; then
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

    # The key is not needed after the last archive.
    _RESTORE_IDENTITIES=""

    local result="ok"
    [ "$failed" -gt 0 ] && result="partial"
    [ "$failed" -eq "${#kinds[@]}" ] && result="failed"

    local op="restore"
    [ -n "$only" ] && op="restore-scoped"
    local details="artifacts=$(( ${#kinds[@]} - failed ))/${#kinds[@]}"

    # Any restore, scoped or not, may bring back Keycloak's sessions or a holder's
    # delegations; once something was written, the step is pending until it succeeds
    # (BE-17). The marker makes every later `start` run it before the first module, and
    # the EXIT trap logs and names it should this command stop before it is done.
    local post_restore="skipped"
    POST_RESTORE_STATUS=""
    if [ "$result" != "failed" ]; then
        if ! _post_restore_mark "$since"; then
            _backup_log "$backup_dir" "$op" "$restore_id" "$result" "$details" \
                "post_restore=failed"
            error "Could not record the pending post-restore step in $CONFIG_DIR; the stack"
            error "was not started again."
            _post_restore_hint "$since"
            exit 3
        fi
        post_restore="pending"
        # The target may be an older copy (one kept outside the house): what only the
        # mirror holds goes to it first, so every module applies the union (RE-86).
        if ! _erasure_mirror_union "$backup_dir" 1; then
            _backup_log "$backup_dir" "$op" "$restore_id" "$result" "$details" \
                "post_restore=pending erasure_mirror=failed"
            error "The erasure journal mirror could not be merged into the backup target; the"
            error "stack was not started again. Mount the mirror, then run the restore again."
            exit 3
        fi
        # The erasure journal of every add-on of this restore, and the holders' own step,
        # before that add-on starts (lib/module_actions.py); _addon_compose_up runs them.
        local -a mark_flags=(--trigger="$RESTORE_TRIGGER" --restore-point="$restore_id")
        [ -n "$only" ] && mark_flags+=(--addons="$sel_addons")
        local marked="" name actions
        if ! marked="$(py_cli module-actions-mark ${mark_flags[@]+"${mark_flags[@]}"})"; then
            _backup_log "$backup_dir" "$op" "$restore_id" "$result" "$details" \
                "post_restore=pending module_actions=failed"
            error "Could not record the erasure journals due before the add-ons start; the"
            error "stack was not started again. Fix the reason above, then run the restore again."
            exit 3
        fi
        _RESTORE_MARKED=0
        while IFS=$'\t' read -r name actions; do
            [ -n "$name" ] || continue
            _RESTORE_MARKED=1
            info "  add-on $name: $actions due before it starts"
        done <<< "$marked"
        py_cli state-epoch-confirm --backup-dir="$backup_dir" --by=restore > /dev/null \
            || warn "The generation of the erasure journal was not confirmed; doctor state_epoch warns."
        _restore_open "$backup_dir" "$op" "$restore_id" "$result" "$details" "$since" "$started"
    fi

    # cmd_start and the scoped restart run the pending step themselves: Keycloak alone
    # first, then the step, and no module before it succeeded. They are called plainly so
    # `set -e` keeps applying inside them; when one fails or exits, the EXIT trap writes
    # the log entry and names the way to finish the step (_restore_close_pending).
    if [ "$no_restart" -eq 0 ]; then
        if [ -n "$only" ]; then
            _restore_restart_scoped "$sel_profiles" "$sel_addons" "$insecure_images"
        else
            info "Starting the stack again..."
            local -a start_flags=(--addons --config-dir="$CONFIG_DIR")
            [ "$insecure_images" -eq 1 ] && start_flags+=(--insecure-images)
            cmd_start ${start_flags[@]+"${start_flags[@]}"}
        fi
        if [ "$post_restore" = "pending" ]; then
            case "$POST_RESTORE_STATUS" in
                ok) post_restore="ok" ;;
                failed) post_restore="failed" ;;
            esac
        fi
    elif [ "$post_restore" = "pending" ]; then
        # The running Keycloak may answer from its cache over the database replaced
        # underneath it, so the marker stays and the next start runs the step again.
        info "Revoking the sessions and delegations of the restore point (post-restore)..."
        if _post_restore "$since"; then
            post_restore="ok"
        else
            post_restore="failed"
        fi
        warn "--no-restart: Keycloak may still serve the replaced database from its cache;"
        warn "post-restore runs again at the next start, before any module starts."
    fi

    if [ "$post_restore" = "skipped" ]; then
        _backup_log "$backup_dir" "$op" "$restore_id" "$result" \
            "$details duration=$((SECONDS - started))s" "post_restore=skipped"
        _restore_record "$op" "$restore_id" "$result" "$((SECONDS - started))" skipped none \
            "$(( ${#kinds[@]} - failed ))/${#kinds[@]}"
    else
        _restore_close "$post_restore"
    fi
    if [ "$result" != "failed" ]; then
        info "Restore took $((SECONDS - started)) s (from the confirmation to the stack being up)."
    fi
    if [ "$no_restart" -eq 1 ] && [ "${_RESTORE_MARKED:-0}" -eq 1 ]; then
        warn "--no-restart: the add-ons' erasure journals are applied at their next start,"
        warn "before they serve anything."
    fi

    if [ "$post_restore" = "failed" ] || [ "$post_restore" = "pending" ]; then
        error "Restore point $restore_id was written, but post-restore is $post_restore."
        _post_restore_hint "$since"
        exit 3
    fi

    # The modules are up and their journals applied: check that what was deleted since
    # the point is gone (RE-88).
    if [ "$post_restore" = "ok" ] && [ "$no_restart" -eq 0 ]; then
        _restore_probe "$backup_dir" "$restore_id" "$only" "$sel_addons" || exit 3
    elif [ "$result" != "failed" ]; then
        warn "The erasure probe did not run: the modules were not started again."
    fi

    case "$result" in
        ok)      success "restore complete: $restore_id (${#kinds[@]} artifacts)" ;;
        partial) warn "restore completed with errors: $restore_id ($failed of ${#kinds[@]} artifacts failed)" ;;
        failed)  error "restore failed: $restore_id (no artifact could be restored)"; exit 3 ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────
# post-restore
# ─────────────────────────────────────────────────────────────────────────
# papaia-ctl post-restore [--since=EPOCH]: the realm's "not before" past every token of
# the restore point, and the consents of flow-engine and assist-gate that predate EPOCH
# removed (lib/post_restore.py). `restore` runs it; on its own it finishes a restore whose
# step failed. A second run with the same --since changes nothing.
cmd_post_restore() {
    local config_dir="$DEFAULT_CONFIG_DIR" since=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --since=*)
                since="${1#*=}"
                if ! [[ "$since" =~ ^[1-9][0-9]{0,9}$ ]]; then
                    error "--since must be a Unix time in seconds, as restore prints it."
                    exit 2
                fi
                ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for post-restore: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local mode
    mode="$(_topology_mode)" || exit 3
    if [ "$mode" = "distributed" ]; then
        error "post-restore is not available in a distributed installation yet."
        exit 2
    fi
    local pending="" rc=0
    pending="$(_post_restore_pending)" || pending="none"
    _post_restore "$since" || rc=$?
    # A run from an earlier second than the restore recorded leaves its marker alone.
    if [ "$rc" -eq 0 ] && [ "$pending" != "none" ]; then
        if [ -z "$since" ] || [ -z "$pending" ] || [ "$since" -ge "$pending" ]; then
            _post_restore_clear
        fi
    fi
    return "$rc"
}

# ─────────────────────────────────────────────────────────────────────────
# the erasure journal mirror
# ─────────────────────────────────────────────────────────────────────────
# Before a module applies its journal (restore, recover-snapshot): the entries only the
# mirror holds go to the target first, so the replay reads the union (lib/erasure_mirror.py,
# RE-86). $1 backup dir, $2 1 to print the handbook sentence when no mirror is set.
# Sets MIRROR_ADDED; returns non-zero when a place cannot be read or written.
MIRROR_ADDED=0
_erasure_mirror_union() {
    local backup_dir="$1" sentence="${2:-0}" out="" rc=0 kind module count
    MIRROR_ADDED=0
    out="$(py_cli erasure-mirror union --backup-dir="$backup_dir" | tr -d '\r')" || rc=$?
    [ "$rc" -eq 0 ] || return "$rc"
    while IFS=$'\t' read -r kind module count; do
        case "$kind" in
            NONE)
                # The handbook sentence (BE-16) comes as the second field.
                if [ "$sentence" -eq 1 ]; then
                    warn "No mirror of the erasure journal is set ('papaia-ctl backup mirror'):"
                    warn "$module"
                fi
                return 0
                ;;
            ADDED)
                MIRROR_ADDED=$((MIRROR_ADDED + count))
                info "  erasure journal $module: $count entr(ies) taken from the mirror"
                ;;
        esac
    done <<< "$out"
    info "mirror: $MIRROR_ADDED entr(ies) the backup target lacked"
}

# After a backup: what the target holds goes to the mirror, then the mirror's retention run.
# A mirror that cannot be written is reported and makes the backup partial. $1 backup dir.
_erasure_mirror_sync() {
    local backup_dir="$1" out="" rc=0 kind module count
    out="$(py_cli erasure-mirror sync --backup-dir="$backup_dir" | tr -d '\r')" || rc=$?
    if [ "$rc" -ne 0 ]; then
        warn "The erasure journal was not copied to its mirror (see above)."
        _backup_log "$backup_dir" mirror - failed "erasure_mirror=failed"
        return 1
    fi
    while IFS=$'\t' read -r kind module count; do
        case "$kind" in
            COPIED) info "  erasure journal $module: $count entr(ies) copied to the mirror" ;;
            REMOVED) info "  erasure journal $module: $count old entr(ies) removed from the mirror" ;;
        esac
    done <<< "$out"
    case "$out" in
        NONE*) ;;
        *) _backup_log "$backup_dir" mirror - ok "erasure_mirror=ok" ;;
    esac
    return 0
}

# ─────────────────────────────────────────────────────────────────────────
# recover-snapshot
# ─────────────────────────────────────────────────────────────────────────
# papaia-ctl recover-snapshot [--insecure-images] [--config-dir=PATH]: after a VM or volume
# snapshot came back without `restore` (lib/recover_snapshot.py, BE-16a Nr. 4): the
# mirror's entries to the target, the rollback keys of the snapshot deleted, the core
# post-restore (realm-wide "not before") and every add-on's `erasure-replay` and
# `post-restore` before it comes up again, then doctor. No operator key.
_RECOVER_OPEN=0
_RECOVER_KEYS=0
_RECOVER_BACKUP_DIR=""
_RECOVER_ID=""
_RECOVER_STARTED=0

_recover_record() {
    local result="$1"
    py_cli recover-snapshot-record --result="$result" --rollback-keys="$_RECOVER_KEYS" \
        --mirror-added="$MIRROR_ADDED" --duration="$((SECONDS - _RECOVER_STARTED))" \
        | tr -d '\r'
}

# The EXIT trap while the stack restarts: a step that failed or stopped the command is
# recorded as such, and the way to finish it is named.
_recover_close_failed() {
    [ "$_RECOVER_OPEN" -eq 1 ] || return 0
    _RECOVER_OPEN=0
    _recover_record failed > /dev/null || true
    _backup_log "$_RECOVER_BACKUP_DIR" recover "$_RECOVER_ID" failed \
        "duration=$((SECONDS - _RECOVER_STARTED))s"
    error "recover-snapshot did not finish: an add-on whose erasure journal is not applied"
    error "stays down. Fix the reason above, then run 'papaia-ctl recover-snapshot' again."
}

cmd_recover_snapshot() {
    local config_dir="$DEFAULT_CONFIG_DIR" insecure_images=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --insecure-images) insecure_images=1 ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for recover-snapshot: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local mode
    mode="$(_topology_mode)" || exit 3
    if [ "$mode" = "distributed" ]; then
        error "recover-snapshot is not available in a distributed installation yet."
        exit 2
    fi
    if [ -z "${PAPAIA_CORRELATION_ID:-}" ]; then
        PAPAIA_CORRELATION_ID="$(py_cli new-correlation-id | tr -d '\r')" || exit 3
    fi
    export PAPAIA_CORRELATION_ID
    _RECOVER_STARTED=$SECONDS
    local since
    since="$(date +%s)"
    _RECOVER_ID="snapshot-$since"
    local backup_dir
    backup_dir="$(_resolve_backup_dir "")" || exit 3
    _RECOVER_BACKUP_DIR="$backup_dir"
    if [ ! -d "$backup_dir/erasure-journal" ] || [ -L "$backup_dir/erasure-journal" ]; then
        error "The erasure journal $backup_dir/erasure-journal is not reachable: mount the"
        error "backup target and run 'papaia-ctl recover-snapshot' again. Nothing was changed."
        exit 3
    fi
    info "recover-snapshot: applying the erasure journal after a returned snapshot"
    info "(correlation id $PAPAIA_CORRELATION_ID)."

    if ! _erasure_mirror_union "$backup_dir" 0; then
        error "The erasure journal mirror could not be merged into the backup target; nothing"
        error "else was changed. Mount the mirror (or remove it with 'papaia-ctl backup mirror"
        error "--erasure-mirror=none') and run again."
        exit 3
    fi

    local keys=""
    if ! keys="$(py_cli rollback-key purge --reason=recover-snapshot | tr -d '\r')"; then
        error "The rollback keys from the snapshot could not be deleted (see above)."
        exit 3
    fi
    _RECOVER_KEYS="${keys:-0}"
    if [ "$_RECOVER_KEYS" -gt 0 ]; then
        info "  $_RECOVER_KEYS rollback key(s) from the snapshot deleted; a way back now needs"
        info "  the operator key ('papaia-ctl rollback --identity=FILE|-')."
    fi

    _RECOVER_OPEN=1
    trap _recover_close_failed EXIT
    if ! _post_restore_mark "$since"; then
        error "Could not record the pending post-restore step in $CONFIG_DIR."
        exit 3
    fi
    local marked="" name actions
    if ! marked="$(py_cli module-actions-mark --trigger=recover-snapshot \
            --restore-point="$_RECOVER_ID")"; then
        error "Could not record the erasure journals due before the add-ons start."
        exit 3
    fi
    while IFS=$'\t' read -r name actions; do
        [ -n "$name" ] || continue
        info "  add-on $name: $actions due before it starts"
    done <<< "$marked"

    # No add-on serves on while its journal is still due: stopped first, started by `start`,
    # which runs the core step before the first add-on and each add-on's steps before it.
    info "Stopping the add-ons until their erasure journal is applied again..."
    _addon_compose_all stop
    local -a start_flags=(--addons --config-dir="$CONFIG_DIR")
    [ "$insecure_images" -eq 1 ] && start_flags+=(--insecure-images)
    cmd_start ${start_flags[@]+"${start_flags[@]}"}
    if [ -f "$CONFIG_DIR/post-restore.pending" ] \
        || [ "$(py_cli module-actions-state --marked | tr -d '\r')" != "ok" ]; then
        error "A step is still due after the start (see above)."
        exit 3
    fi
    _RECOVER_OPEN=0
    trap - EXIT

    local lines line
    lines="$(_recover_record ok)" || warn "The audit row of recover-snapshot was not written."
    while IFS= read -r line; do
        [ -n "$line" ] && info "  $line"
    done <<< "$lines"
    py_cli state-epoch-confirm --by=recover-snapshot > /dev/null \
        || warn "The generation of the erasure journal was not confirmed; doctor state_epoch warns."
    _backup_log "$backup_dir" recover "$_RECOVER_ID" ok \
        "duration=$((SECONDS - _RECOVER_STARTED))s rollback_keys=$_RECOVER_KEYS mirror=$MIRROR_ADDED"

    info "Running doctor..."
    local doctor_rc=0
    cmd_doctor --config-dir="$CONFIG_DIR" || doctor_rc=$?
    if [ "$doctor_rc" -ne 0 ]; then
        error "recover-snapshot ran, but doctor still reports a failure (see above)."
        exit "$doctor_rc"
    fi
    success "recover-snapshot complete: the erasure journal is applied in every add-on."
}

# The erasure probe after a restore (lib/host_restore.py). $1 backup dir, $2 restore point,
# $3 the selection of a scoped restore, $4 its add-ons. Returns 1 when it fails.
_restore_probe() {
    local backup_dir="$1" restore_id="$2" only="$3" addons="$4"
    local -a flags=(--backup-dir="$backup_dir" --restore-point="$restore_id")
    [ -n "$only" ] && flags+=(--addons="$addons")
    local out rc=0
    out="$(py_cli erasure-probe ${flags[@]+"${flags[@]}"} | tr -d '\r')" || rc=$?
    local kind module state count reason total=0
    while IFS=$'\t' read -r kind module state count reason; do
        [ "$kind" = PROBE ] || continue
        total=$((total + 1))
        info "erasure probe: $module $state ($count journaled since the point): $reason"
    done <<< "$out"
    case "$rc" in
        0)
            _backup_log "$backup_dir" probe "$restore_id" ok "modules=$total erasure_probe=pass"
            success "erasure probe passed: nothing deleted since $restore_id came back"
            return 0
            ;;
        1)
            _backup_log "$backup_dir" probe "$restore_id" failed "modules=$total erasure_probe=fail"
            error "erasure probe failed: data deleted since restore point $restore_id may be"
            error "back. The modules marked 'fail' above did not apply their erasure journal;"
            error "fix the reason, then run 'papaia-ctl restore' again."
            return 1
            ;;
        *)
            _backup_log "$backup_dir" probe "$restore_id" failed "erasure_probe=error"
            error "erasure probe could not run (see above); treat the restore as not verified."
            return 1
            ;;
    esac
}

# The open restore entry of backup.log: written by _restore_close, or by the EXIT trap
# (_restore_close_pending) when the command stops first.
_RESTORE_OPEN_ID=""
_RESTORE_OPEN=()
_RESTORE_MARKED=0
_RESTORE_ENCRYPTED=0
_RESTORE_IDENTITIES=""

# The audit row of the restore with its duration (the measured RTO). A failure to write
# it is reported; the restore itself is done by then.
# $1 op, $2 id, $3 result, $4 seconds, $5 post-restore, $6 module actions, $7 artifacts
_restore_record() {
    local -a flags=(--operation="$1" --restore-point="$2" --result="$3" --duration="$4"
        --post-restore="$5" --module-actions="$6" --artifacts="$7")
    [ "${_RESTORE_ENCRYPTED:-0}" -eq 1 ] && flags+=(--encrypted)
    py_cli restore-record ${flags[@]+"${flags[@]}"} \
        || warn "The audit row of restore $2 could not be written."
}

# $1 = backup dir, $2 = op, $3 = id, $4 = result, $5 = details, $6 = since, $7 = start
_restore_open() {
    _RESTORE_OPEN=("$@")
    _RESTORE_OPEN_ID="$3"
}

# $1 = the post-restore field. Logs the open entry once.
_restore_close() {
    [ -n "$_RESTORE_OPEN_ID" ] || return 0
    _RESTORE_OPEN_ID=""
    local -a marked=()
    [ "${_RESTORE_MARKED:-0}" -eq 1 ] && marked+=(--marked)
    local actions_state
    actions_state="$(py_cli module-actions-state ${marked[@]+"${marked[@]}"})" \
        || actions_state="pending"
    local seconds=$((SECONDS - ${_RESTORE_OPEN[6]}))
    _backup_log "${_RESTORE_OPEN[0]}" "${_RESTORE_OPEN[1]}" "${_RESTORE_OPEN[2]}" \
        "${_RESTORE_OPEN[3]}" \
        "${_RESTORE_OPEN[4]} duration=${seconds}s" \
        "post_restore=$1 module_actions=${actions_state:-pending}"
    _restore_record "${_RESTORE_OPEN[1]}" "${_RESTORE_OPEN[2]}" "${_RESTORE_OPEN[3]}" \
        "$seconds" "$1" "${actions_state:-pending}" "${_RESTORE_OPEN[4]#artifacts=}"
}

# The restart failed or exited: the step ran (ok), failed, or was never reached (pending).
_restore_close_pending() {
    [ -n "$_RESTORE_OPEN_ID" ] || return 0
    local state="pending" id="$_RESTORE_OPEN_ID"
    case "$POST_RESTORE_STATUS" in
        ok|failed) state="$POST_RESTORE_STATUS" ;;
    esac
    _restore_close "$state"
    if [ "$state" = "ok" ]; then
        error "Restore point $id was written and post-restore ran, but the stack did not"
        error "start again. Fix the cause and run 'papaia-ctl start'."
        return 0
    fi
    error "Restore point $id was written, but the command stopped before post-restore was"
    error "done (post-restore is $state)."
    _post_restore_hint "${_RESTORE_OPEN[5]}"
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
        # Through _addon_compose, as `addon stop --clean-up` does: the project
        # name, the root and add-on env files and the override files must match
        # what `up` used, or a network named after ${PAPAIA_PROJECT} resolves
        # to its fallback here and the real one stays behind.
        _addon_compose down "$addon_name" "$addon_path"
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

# Bring back only what the selection took down. $1 = profiles, $2 = addon names,
# $3 = 1 for --insecure-images (the image checks of this restore only).
#
# Add-ons come up before the core on purpose: cmd_start only includes an
# override from $CONFIG_DIR/overrides/ when its external network already
# exists, and otherwise drops it with a warning. A still-down add-on would
# therefore lose its core-side integration until the next full start.
# cmd_start --addons orders it the same way.
_restore_restart_scoped() {
    local profiles="$1" addons="$2" insecure_images="${3:-0}"
    local addon_name addon_path

    # Before the first add-on: Keycloak, then the pending post-restore step (BE-17).
    _post_restore_before_modules "$insecure_images" || return $?

    while IFS= read -r addon_name; do
        [ -z "$addon_name" ] && continue
        addon_path="$(_addon_path "$addon_name" 2>/dev/null || true)"
        if [ -z "$addon_path" ] || [ ! -f "$addon_path/docker-compose.yml" ]; then
            _restore_step restart "addon:$addon_name" missing
            continue
        fi
        _verify_addon_images restore "$insecure_images" "$addon_name" "$addon_path"
        info "Starting addon $addon_name from $addon_path"
        _addon_compose_up "$addon_name" "$addon_path"
        _restore_step restart "addon:$addon_name" ok
    done < <(_split_list "$addons")

    if [ -n "$profiles" ]; then
        info "Starting core profiles again: $profiles"
        _restore_step restart "$profiles" begin
        # No --addons: they were handled above, and starting the ones outside
        # the selection would turn a scoped restore into a stack-wide operation.
        local -a start_flags=(--profiles="$profiles" --config-dir="$CONFIG_DIR")
        [ "$insecure_images" -eq 1 ] && start_flags+=(--insecure-images)
        cmd_start ${start_flags[@]+"${start_flags[@]}"}
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
        _addon_compose_all down ${extra[@]+"${extra[@]}"}
    fi
    docker compose -f "$COMPOSE_FILE" --env-file "$env_file" down ${extra[@]+"${extra[@]}"}
}

# Empties /target, except the entry named by $KEEP, and unpacks $ARCHIVE into it without
# that entry; ARCHIVE=- reads the stream from standard input (an encrypted archive opened
# by papaia-ctl). Runs in $BACKUP_IMAGE (busybox sh and tar).
# shellcheck disable=SC2016  # expanded by the container's shell
_RESTORE_UNPACK='src="/backup/$ARCHIVE"; [ "$ARCHIVE" = - ] && src=-
for entry in /target/..?* /target/.[!.]* /target/*; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    [ -n "$KEEP" ] && [ "$entry" = "/target/$KEEP" ] && continue
    rm -rf "$entry"
done
if [ -n "$KEEP" ]; then
    tar xzf "$src" -C /target --exclude="./$KEEP" --exclude="./$KEEP/*"
else
    tar xzf "$src" -C /target
fi'
# The same for a named volume, which keeps nothing.
# shellcheck disable=SC2016  # expanded by the container's shell
_RESTORE_VOLUME='src="/backup/$ARCHIVE"; [ "$ARCHIVE" = - ] && src=-
rm -rf /volume/..?* /volume/.[!.]* /volume/* 2>/dev/null
tar xzf "$src" -C /volume'

# The plain tar.gz stream of an encrypted archive, for `docker run -i` to unpack: the key
# goes in on standard input, the archive never lies on disk in clear.
# $1 snapshot, $2 archive
_restore_open_archive() {
    printf '%s\n' "$_RESTORE_IDENTITIES" \
        | py_cli restore-open --snapshot="$1" --archive="$2" --identity=-
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
    # The archive arrives on standard input (ARCHIVE=-) when it is encrypted.
    local encrypted="${_RESTORE_ENCRYPTED:-0}"

    case "$kind" in
        volume)
            info "  volume $target ($owner)"
            docker volume inspect "$target" >/dev/null 2>&1 || docker volume create "$target" >/dev/null
            if [ "$encrypted" -eq 1 ]; then
                _restore_open_archive "$snapshot" "$archive" \
                    | _docker_run -i -e "ARCHIVE=-" -v "${target}:/volume" "$BACKUP_IMAGE" \
                        sh -c "$_RESTORE_VOLUME"
            else
                _docker_run \
                    -e "ARCHIVE=$archive" \
                    -v "${target}:/volume" \
                    -v "${snapshot_mount}:/backup" \
                    "$BACKUP_IMAGE" sh -c "$_RESTORE_VOLUME"
            fi
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
            # The config dir keeps its platform halt (state/): the restore point neither
            # lifts nor sets it, also when an archive holds one.
            local keep=""
            [ "$kind" = "configdir" ] && keep="state"
            if [ "$encrypted" -eq 1 ]; then
                _restore_open_archive "$snapshot" "$archive" \
                    | _docker_run -i -e "ARCHIVE=-" -e "KEEP=$keep" \
                        -v "$(_docker_hostpath "$target"):/target" \
                        "$BACKUP_IMAGE" sh -c "$_RESTORE_UNPACK"
            else
                _docker_run \
                    -e "ARCHIVE=$archive" \
                    -e "KEEP=$keep" \
                    -v "$(_docker_hostpath "$target"):/target" \
                    -v "${snapshot_mount}:/backup" \
                    "$BACKUP_IMAGE" sh -c "$_RESTORE_UNPACK"
            fi
            ;;
        *)
            warn "  unknown artifact kind '$kind', skipping"
            return 1
            ;;
    esac
}
