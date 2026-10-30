# shellcheck shell=bash
# papaia-ctl — `addon` command family: install / start / upgrade / rollback / list / stop / check /
# components / remove / uninstall.
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

_addon_path() {
    local addon_name="$1"
    py_cli addon-path --name="$addon_name"
}

cmd_addon_install() {
    local config_dir="$DEFAULT_CONFIG_DIR" addon_name="" addon_path="" addon_version="" force=0
    local node=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --node=*) node="${1#*=}" ;;
            --path=*) addon_path="${1#*=}" ;;
            --version=*) addon_version="${1#*=}" ;;
            --force) force=1 ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option: $1"; exit 2 ;;
            *) addon_name="$1" ;;
        esac
        shift
    done
    if [ -z "$addon_name" ]; then
        error "Usage: papaia-ctl addon install <name> --path=PATH [--version=VER] [--force]"
        exit 2
    fi
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local -a extra=()
    [ -n "$addon_path" ]    && extra+=(--path="$addon_path")
    [ -n "$addon_version" ] && extra+=(--version="$addon_version")
    [ "$force" -eq 1 ]      && extra+=(--force)
    [ -n "$node" ]          && extra+=(--node="$node")
    py_cli addon-install --name="$addon_name" "${extra[@]}"
    success "addon install complete: $addon_name"
}

# Run `docker compose <verb>` for one addon with the project name, compose files
# and env files that stay consistent between bring-up and teardown.
#
# Override files from $CONFIG_DIR/overrides/addons/ follow the naming pattern
# docker-compose.<addon_name>[-<suffix>].override.yml and are not picked up by
# the core compose loop (which globs overrides/ directly).  `py_cli
# addon-override-files` attributes each file to its owning addon by longest
# registered-name match, so `qdrant` does not pull in `qdrant-ingest`'s
# overrides -- a bare docker-compose.${addon_name}-* glob cannot tell them apart.
#
# The root .env is passed as --env-file so root vars (COMPOSE_PROJECT_NAME,
# DOCKER_NETWORK, PAPAIA_PROJECT, PAPAIA_HOST, …) are available for interpolation
# in the addon compose file even when papaia-ctl runs in a subprocess without
# the full host environment (e.g. the papaia-manager container), and --
# critically -- so a templated `networks.*.name`
# (${PAPAIA_PROJECT:-papaia}-<addon>-net) resolves to the same per-deployment
# bridge at `down` as it did at `up`.  Without it, teardown would resolve the
# bare fallback and leave the real network orphaned.  (PAPAIA_PROJECT rather
# than COMPOSE_PROJECT_NAME because the `-p <addon>` below pins the latter to
# the addon name in compose's interpolation env.)  --env-file disables compose's
# auto-discovery of the project .env, so the addon's own .env is passed second
# (higher precedence).
#
# Without the addon's docker-compose.yml (a deleted or half-written addon
# directory) compose cannot build the project, and `stop`/`down` fall back to
# project-name-only mode. There the COMPOSE_PROJECT_NAME of the root .env passed
# below wins over `-p`, so the call stops or removes the CORE stack instead of the
# addon. Such an addon is therefore handled by name alone (see
# _addon_compose_by_name), and anything that needs the file is refused.
#
# $1 verb, $2 addon_name, $3 addon_path, rest = extra `docker compose` args.
_addon_compose() {
    local verb="$1" addon_name="$2" addon_path="$3"; shift 3
    local -a extra=("$@")
    local mode
    mode="$(_topology_mode)" || return 3
    if [ "$mode" = "distributed" ]; then
        _addon_compose_distributed "$verb" "$addon_name" "${extra[@]}"
        return
    fi
    if [ ! -f "$addon_path/docker-compose.yml" ]; then
        _addon_compose_by_name "$verb" "$addon_name" "$addon_path" "${extra[@]}"
        return
    fi
    local -a compose_files=(-f "$addon_path/docker-compose.yml")
    if [ -d "$CONFIG_DIR/overrides/addons" ]; then
        local f
        while IFS= read -r f; do
            [ -n "$f" ] && [ -f "$f" ] && compose_files+=(-f "$f")
        done < <(py_cli addon-override-files --name="$addon_name" 2>/dev/null)
    fi
    local -a env_files=()
    local root_env="$REPO_ROOT/src/.env"
    [ -f "$root_env" ] && env_files+=(--env-file "$root_env")
    local addon_env="$addon_path/.env"
    [ -f "$addon_env" ] && env_files+=(--env-file "$addon_env")
    # Pin the compose project name to the addon directory basename. Without this,
    # the root .env passed above carries COMPOSE_PROJECT_NAME=<core>, which would
    # bring the addon up under the core stack's project instead of its own. That
    # breaks two things: papaia-manager's compute_status treats an addon as RUNNING
    # only when a project named after the addon dir appears in `docker ps`, and
    # `addon stop`/`addon uninstall` tear down using that same default project name
    # -- so a mismatched project would leave the addon invisible and un-removable.
    # This value matches docker compose's own default (basename of the compose
    # file's directory), so `up` and the later `down` operate on the same project.
    local project
    project="$(basename "$addon_path")"
    docker compose -p "$project" "${compose_files[@]}" "${env_files[@]}" "$verb" "${extra[@]}"
}

# `docker compose -p <project> stop|down` for an addon whose docker-compose.yml
# is missing. Neither -f nor --env-file is passed, so nothing but the project
# name tells compose what to act on, and the COMPOSE_* variables of the caller
# are dropped for the same reason. Compose then finds the containers (and, for
# `down`, the networks and, with -v, the volumes) carrying that project's label.
# Any other verb needs the file and is refused.
#
# $1 verb, $2 addon_name, $3 addon_path, rest = extra `docker compose` args.
_addon_compose_by_name() {
    local verb="$1" addon_name="$2" addon_path="$3"; shift 3
    local project
    project="$(basename "$addon_path")"
    case "$verb" in
        stop|down) ;;
        *)
            error "Cannot run 'docker compose $verb' for addon $addon_name: $addon_path/docker-compose.yml not found."
            return 1
            ;;
    esac
    case "$project" in
        ""|.|..|/)
            error "Cannot tell which containers belong to addon $addon_name: no usable directory name in '$addon_path'."
            return 1
            ;;
    esac
    warn "$addon_path/docker-compose.yml not found -- running 'docker compose $verb' for project '$project' by name only."
    (
        unset COMPOSE_PROJECT_NAME COMPOSE_FILE COMPOSE_PROFILES COMPOSE_ENV_FILES COMPOSE_PATH_SEPARATOR
        docker compose -p "$project" "$verb" "$@"
    )
}

_addon_compose_up() {
    _addon_compose up "$1" "$2" -d
}

# An add-on of a distributed installation runs on its node; the node's shim starts and
# stops it with the same project name, files and env files as here.
# $1 verb, $2 addon name, rest = the extra `docker compose` args of the caller
_addon_compose_distributed() {
    local verb="$1" addon_name="$2"; shift 2
    _cluster_require_unlocked
    case "$verb" in
        up|stop|down) : ;;
        *)
            error "'docker compose $verb' for add-on $addon_name runs on its node: use"
            error "'papaia-ctl node' there, or 'papaia-ctl status --addons'."
            return 2
            ;;
    esac
    local arg
    for arg in "$@"; do
        case "$arg" in
            -v|--volumes)
                warn "Add-on $addon_name: its volumes stay on its node; delete them there."
                ;;
        esac
    done
    py_cli cluster-addon --name="$addon_name" --verb="$verb"
}

cmd_addon_start() {
    local config_dir="$DEFAULT_CONFIG_DIR" addon_name="" force=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --force) force=1 ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option: $1"; exit 2 ;;
            *) addon_name="$1" ;;
        esac
        shift
    done
    if [ -z "$addon_name" ]; then
        error "Usage: papaia-ctl addon start <name> [--force]"
        exit 2
    fi
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local -a extra=()
    [ "$force" -eq 1 ] && extra+=(--force)
    # Materialize .env from the config bundle into the checkout, then
    # render. Gates on compatibility -- a non-zero exit (set -e) must
    # abort here, before _addon_compose_up brings containers up.
    py_cli addon-start --name="$addon_name" "${extra[@]}"
    local addon_path
    addon_path="$(_addon_path "$addon_name")"
    info "Starting addon $addon_name from $addon_path"
    _addon_compose_up "$addon_name" "$addon_path"
    success "addon start complete: $addon_name"
}

cmd_addon_stop() {
    local config_dir="$DEFAULT_CONFIG_DIR" addon_name="" clean_up=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --clean-up) clean_up=1 ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option: $1"; exit 2 ;;
            *) addon_name="$1" ;;
        esac
        shift
    done
    if [ -z "$addon_name" ]; then
        error "Usage: papaia-ctl addon stop <name> [--clean-up]"
        exit 2
    fi
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local addon_path
    addon_path="$(_addon_path "$addon_name")"
    if [ "$clean_up" -eq 1 ]; then
        info "Stopping and removing containers for addon $addon_name..."
        _addon_compose down "$addon_name" "$addon_path"
    else
        info "Stopping addon $addon_name..."
        _addon_compose stop "$addon_name" "$addon_path"
    fi
    success "addon stop complete: $addon_name"
}

cmd_addon_remove() {
    local config_dir="$DEFAULT_CONFIG_DIR" addon_name=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option: $1"; exit 2 ;;
            *) addon_name="$1" ;;
        esac
        shift
    done
    if [ -z "$addon_name" ]; then
        error "Usage: papaia-ctl addon remove <name>"
        exit 2
    fi
    CONFIG_DIR="$config_dir"
    _require_setup_done
    py_cli addon-remove --name="$addon_name"
    success "addon remove complete: $addon_name"
}

cmd_addon_check() {
    local config_dir="$DEFAULT_CONFIG_DIR"
    local -a extra=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --target-core=*) extra+=(--target-core="${1#*=}") ;;
            --target-version=*) extra+=(--target-version="${1#*=}") ;;
            --target-addon-api=*) extra+=(--target-addon-api="${1#*=}") ;;
            --target-min-addon-api=*) extra+=(--target-min-addon-api="${1#*=}") ;;
            --json) extra+=(--json) ;;
            --force) extra+=(--force) ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for addon check: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    py_cli addon-check "${extra[@]}"
}

cmd_addon_components() {
    local config_dir="$DEFAULT_CONFIG_DIR" addon_name=""
    local -a extra=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --json) extra+=(--json) ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option for addon components: $1"; exit 2 ;;
            *) addon_name="$1" ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    if [ -n "$addon_name" ]; then
        extra+=(--name="$addon_name")
    fi
    py_cli addon-components "${extra[@]}"
}

_ADDON_TMPFILES=()

# Restore point taken by the last _addon_backup call; empty when there was none.
ADDON_RESTORE_POINT=""

_addon_cleanup() {
    local f
    if [ ${#_ADDON_TMPFILES[@]} -gt 0 ]; then
        for f in "${_ADDON_TMPFILES[@]}"; do
            [ -f "$f" ] && rm -f "$f"
        done
        _ADDON_TMPFILES=()
    fi
    return 0
}

# Whether the add-on has running containers. $1 add-on name, $2 add-on path.
_addon_running() {
    local ids
    ids="$(_addon_compose ps "$1" "$2" -q 2>/dev/null || true)"
    [ -n "${ids//[$'\r\n']/}" ]
}

# Take a restore point that holds only this add-on's data and leave its id in
# ADDON_RESTORE_POINT. Returns 3 when taking it failed.
#
# cmd_backup ends in `exit`, so it runs in a subshell, and errexit is switched
# on again inside it: a subshell that is part of a `||` or `if` list ignores
# `set -e`, which would let a failed archive step go unnoticed. Status 2 is the
# planner saying the selector matched nothing -- an add-on without volumes or
# data directories -- which is not a reason to refuse the upgrade.
_addon_backup() {
    local addon_name="$1" id_file rc=0
    ADDON_RESTORE_POINT=""
    id_file="$(mktemp)"
    _ADDON_TMPFILES+=("$id_file")
    set +e
    (
        set -e
        cmd_backup --only="addon:$addon_name" --config-dir="$CONFIG_DIR"
        printf '%s' "$LAST_BACKUP_ID" > "$id_file"
    )
    rc=$?
    set -e
    case "$rc" in
        0) ADDON_RESTORE_POINT="$(cat "$id_file")" ;;
        2) warn "Addon $addon_name has no volumes or data directories to back up; no restore point was taken." ;;
        *) return 3 ;;
    esac
}

# Recreate an add-on's containers from the directory it is now registered at.
# --remove-orphans drops the services a newer version no longer has.
_addon_recreate() {
    local addon_name="$1" addon_path
    addon_path="$(_addon_path "$addon_name")"
    info "Recreating addon $addon_name from $addon_path..."
    _addon_compose up "$addon_name" "$addon_path" -d --remove-orphans
}

# Move an installed add-on to another version of itself (a directory of its
# own, see lib/addon_upgrade.py). Everything that can refuse -- the gate, the
# preconditions, a missing value -- happens in `addon-upgrade-plan`, before a
# restore point is taken or a file is written.
cmd_addon_upgrade() {
    local config_dir="$DEFAULT_CONFIG_DIR" addon_name="" new_path="" answers_file=""
    local dry_run=0 json=0 no_backup=0 no_restart=0 force=0 assume_yes=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --path=*) new_path="${1#*=}" ;;
            --answers-file=*) answers_file="${1#*=}" ;;
            --dry-run) dry_run=1 ;;
            --json) json=1 ;;
            --no-backup) no_backup=1 ;;
            --no-restart) no_restart=1 ;;
            --force) force=1 ;;
            -y) assume_yes=1 ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option: $1"; exit 2 ;;
            *) addon_name="$1" ;;
        esac
        shift
    done
    if [ -z "$addon_name" ] || [ -z "$new_path" ]; then
        error "Usage: papaia-ctl addon upgrade <name> --path=DIR [--dry-run [--json]] [--no-backup] [--no-restart] [--answers-file=FILE] [--force] [-y]"
        exit 2
    fi
    if [ "$json" -eq 1 ] && [ "$dry_run" -eq 0 ]; then
        error "--json only goes with --dry-run."
        exit 2
    fi
    CONFIG_DIR="$config_dir"
    _require_setup_done

    local -a target=(--name="$addon_name" --path="$new_path")
    [ "$force" -eq 1 ] && target+=(--force)

    if [ "$dry_run" -eq 1 ]; then
        local -a extra=()
        [ "$json" -eq 1 ] && extra+=(--json)
        py_cli addon-upgrade-plan "${target[@]}" "${extra[@]}"
        return 0
    fi

    # The values the new version asks for travel from the plan step to the apply
    # step in a private file, never on a command line.
    local answers_out
    answers_out="$(mktemp)"
    _ADDON_TMPFILES+=("$answers_out")
    trap _addon_cleanup EXIT INT TERM

    local -a plan_extra=(--answers-out="$answers_out")
    [ -n "$answers_file" ] && plan_extra+=(--answers-file="$answers_file")
    py_cli addon-upgrade-plan "${target[@]}" "${plan_extra[@]}"

    if [ "$assume_yes" -eq 0 ]; then
        if ! is_tty; then
            error "Refusing to upgrade without confirmation. Re-run with -y in non-interactive contexts."
            exit 2
        fi
        if ! confirm "Proceed with the upgrade of $addon_name?" "N"; then
            error "Aborted."
            exit 3
        fi
    fi

    local was_running=0 old_path
    old_path="$(_addon_path "$addon_name")"
    if [ "$no_restart" -eq 0 ] && _addon_running "$addon_name" "$old_path"; then
        was_running=1
    fi

    if [ "$no_backup" -eq 0 ]; then
        info "Creating a restore point of $addon_name..."
        _addon_backup "$addon_name" || {
            error "Could not take a restore point. Nothing was changed."
            exit 3
        }
    else
        warn "--no-backup: no restore point is created beforehand."
    fi

    local -a apply_extra=(--answers-file="$answers_out")
    [ -n "$ADDON_RESTORE_POINT" ] && apply_extra+=(--restore-point="$ADDON_RESTORE_POINT")
    py_cli addon-upgrade-apply "${target[@]}" "${apply_extra[@]}"

    if [ "$was_running" -eq 1 ]; then
        if ! _addon_recreate "$addon_name"; then
            error "The containers of $addon_name could not be recreated from the new version."
            error "Nothing was rolled back. To go back to the old version: papaia-ctl addon rollback $addon_name"
            exit 3
        fi
    elif [ "$no_restart" -eq 0 ]; then
        info "Addon $addon_name was not running; start it with 'papaia-ctl addon start $addon_name'."
    fi
    if [ -n "$ADDON_RESTORE_POINT" ]; then
        info "Restore point: $ADDON_RESTORE_POINT. 'papaia-ctl addon rollback $addon_name --restore-data' goes back to it, data included."
    fi
    success "addon upgrade complete: $addon_name"
}

# One step back: repoint the add-on at the version it had before the last
# upgrade. The data is only touched with --restore-data, which restores the
# restore point that the upgrade took (restore-scoped: it cannot replace the
# configuration directory).
cmd_addon_rollback() {
    local config_dir="$DEFAULT_CONFIG_DIR" addon_name=""
    local restore_data=0 no_restart=0 force=0 assume_yes=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --restore-data) restore_data=1 ;;
            --no-restart) no_restart=1 ;;
            --force) force=1 ;;
            -y) assume_yes=1 ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option: $1"; exit 2 ;;
            *) addon_name="$1" ;;
        esac
        shift
    done
    if [ -z "$addon_name" ]; then
        error "Usage: papaia-ctl addon rollback <name> [--restore-data] [--no-restart] [--force] [-y]"
        exit 2
    fi
    if [ "$restore_data" -eq 1 ] && [ "$no_restart" -eq 1 ]; then
        error "--restore-data replaces the add-on's volumes, which needs its containers down; it cannot be combined with --no-restart."
        exit 2
    fi
    CONFIG_DIR="$config_dir"
    _require_setup_done

    local -a target=(--name="$addon_name")
    [ "$force" -eq 1 ] && target+=(--force)

    local plan from="" to="" to_path="" restore_point="" key value
    plan="$(py_cli addon-rollback-plan "${target[@]}" | tr -d '\r')"
    while IFS=$'\t' read -r key value; do
        case "$key" in
            FROM) from="$value" ;;
            TO) to="$value" ;;
            PATH) to_path="$value" ;;
            RESTORE_POINT) restore_point="$value" ;;
        esac
    done <<< "$plan"

    if [ "$restore_data" -eq 1 ]; then
        if [ -z "$restore_point" ]; then
            error "No restore point was recorded for the last upgrade of $addon_name (it ran with --no-backup, or the add-on has no data)."
            error "Run without --restore-data to go back to the old version only."
            exit 2
        fi
        # Fails here, not after the add-on has been repointed, when the restore
        # point was pruned or deleted in the meantime.
        py_cli restore-resolve --restore-point="$restore_point" --only="addon:$addon_name" >/dev/null
    fi

    info "Rolling $addon_name back from ${from:-unknown} to ${to:-unknown} ($to_path)."
    if [ "$restore_data" -eq 1 ]; then
        warn "Its data is reset to restore point $restore_point: whatever the add-on wrote since is lost."
    else
        info "Its data is not touched; the volumes keep what the newer version wrote."
        [ -n "$restore_point" ] && info "Add --restore-data to reset them to restore point $restore_point."
    fi
    if [ "$assume_yes" -eq 0 ]; then
        if ! is_tty; then
            error "Refusing to roll back without confirmation. Re-run with -y in non-interactive contexts."
            exit 2
        fi
        if ! confirm "Proceed with the rollback of $addon_name?" "N"; then
            error "Aborted."
            exit 3
        fi
    fi

    local was_running=0 old_path
    old_path="$(_addon_path "$addon_name")"
    if [ "$no_restart" -eq 0 ] && _addon_running "$addon_name" "$old_path"; then
        was_running=1
    fi

    py_cli addon-rollback-apply "${target[@]}"

    if [ "$restore_data" -eq 1 ]; then
        # Brings the add-on down, restores its volumes and starts it again from
        # the directory it is registered at now.
        cmd_restore_scoped --only="addon:$addon_name" --restore-point="$restore_point" \
            --config-dir="$CONFIG_DIR" -y
    elif [ "$was_running" -eq 1 ]; then
        if ! _addon_recreate "$addon_name"; then
            error "The containers of $addon_name could not be recreated from the old version."
            exit 3
        fi
    fi
    success "addon rollback complete: $addon_name"
}

cmd_addon_list() {
    local config_dir="$DEFAULT_CONFIG_DIR"
    local -a extra=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --json) extra+=(--json) ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for addon list: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    py_cli addon-list "${extra[@]}"
}

cmd_addon_uninstall() {
    local config_dir="$DEFAULT_CONFIG_DIR" addon_name="" clean_up=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --clean-up) clean_up=1 ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option: $1"; exit 2 ;;
            *) addon_name="$1" ;;
        esac
        shift
    done
    if [ -z "$addon_name" ]; then
        error "Usage: papaia-ctl addon uninstall <name> [--clean-up]"
        exit 2
    fi
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local addon_path
    addon_path="$(_addon_path "$addon_name")"
    info "Removing containers for addon $addon_name..."
    if [ "$clean_up" -eq 1 ]; then
        _addon_compose down "$addon_name" "$addon_path" -v
    else
        _addon_compose down "$addon_name" "$addon_path"
    fi
    py_cli addon-uninstall --name="$addon_name"
    success "addon uninstall complete: $addon_name"
}
