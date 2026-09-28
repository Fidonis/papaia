# shellcheck shell=bash
# papaia-ctl — `addon` command family: install / start / stop / check / remove / uninstall.
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

_addon_path() {
    local addon_name="$1"
    py_cli addon-path --name="$addon_name"
}

cmd_addon_install() {
    local config_dir="$DEFAULT_CONFIG_DIR" addon_name="" addon_path="" addon_version="" force=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
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
# $1 verb, $2 addon_name, $3 addon_path, rest = extra `docker compose` args.
_addon_compose() {
    local verb="$1" addon_name="$2" addon_path="$3"; shift 3
    local -a extra=("$@")
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

_addon_compose_up() {
    _addon_compose up "$1" "$2" -d
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
