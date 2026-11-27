# shellcheck shell=bash
# papaia-ctl — LibreChat maintenance: librechat clear-history.
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

cmd_librechat() {
    local sub="${1:-}"
    shift || true
    case "$sub" in
        clear-history) cmd_librechat_clear_history "$@" ;;
        -h|--help|help|"") usage; exit 0 ;;
        *) error "Unknown librechat command: $sub (expected: clear-history)"; exit 2 ;;
    esac
}

# Removes one user's conversations, messages, files and shared links through the
# running LibreChat container (lib/librechat_history.py). The account, its agents
# and prompts stay. Without -y the counts are shown first and the deletion needs a
# "y"; without a terminal, -y is required.
cmd_librechat_clear_history() {
    local config_dir="$DEFAULT_CONFIG_DIR" email="" before="" before_given=false dry_run=false
    local assume_yes=false
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --before=*) before="${1#*=}"; before_given=true ;;
            --dry-run) dry_run=true ;;
            -y|--yes) assume_yes=true ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option for librechat clear-history: $1"; exit 2 ;;
            *)
                if [ -n "$email" ]; then
                    error "librechat clear-history takes one e-mail address, got '$email' and '$1'"
                    exit 2
                fi
                email="$1"
                ;;
        esac
        shift
    done
    if [ -z "$email" ]; then
        error "Usage: papaia-ctl librechat clear-history <email> [--before=YYYY-MM-DD] [--dry-run] [-y]"
        exit 2
    fi
    # shellcheck disable=SC2034  # read by py_cli
    CONFIG_DIR="$config_dir"
    if [ "$before_given" = true ] && [ -z "$before" ]; then
        # An unset variable in --before="$CUTOFF" must not turn into "everything".
        error "--before needs a date as YYYY-MM-DD; it was given empty."
        exit 2
    fi
    _require_setup_done

    local -a args=(--email="$email")
    [ -n "$before" ] && args+=(--before="$before")

    if [ "$dry_run" = true ]; then
        py_cli librechat-clear-history ${args[@]+"${args[@]}"} --dry-run
        return
    fi
    if [ "$assume_yes" != true ]; then
        if ! is_tty; then
            error "Not running in a terminal: pass -y to clear the history without a confirmation."
            exit 2
        fi
        # The dry run also refuses an unknown user before anything is asked.
        py_cli librechat-clear-history ${args[@]+"${args[@]}"} --dry-run
        if ! confirm "Delete this history? It can only be brought back by restoring a backup." "N"; then
            error "Aborted. Nothing was deleted."
            exit 3
        fi
    fi
    py_cli librechat-clear-history ${args[@]+"${args[@]}"}
}

# After `addon remove` or `addon uninstall` of an add-on that contributed LibreChat
# agents or prompts: run LibreChat's init scripts once, so their tombstones delete what
# the add-on no longer provides while LibreChat keeps running. Otherwise that happens
# only when LibreChat is next recreated.
#
# The scripts run in a one-off container of the librechat service (`compose run
# --no-deps`), not in the running one: the render has just replaced the add-on content
# directories, and only a new container mounts the new ones -- the running container
# still sees the old directory, which would read as "no add-on content at all" and
# delete the agents and prompts of every other add-on. The compose files and env file
# are those of `start`. Never fails the add-on command: anything that goes wrong ends in
# a hint to restart LibreChat. $1 add-on name
_librechat_sync_addon_content() {
    local addon_name="$1" mode
    local restart_hint="Its agents and prompts disappear from the chat when LibreChat is next restarted: run 'papaia-ctl start'."
    mode="$(_topology_mode 2>/dev/null)" || mode="unknown"
    if [ "$mode" != "single" ]; then
        info "Addon $addon_name contributed LibreChat agents or prompts. $restart_hint"
        return 0
    fi
    _core_compose_args 0
    local -a compose=(docker compose ${CORE_COMPOSE_ARGS[@]+"${CORE_COMPOSE_ARGS[@]}"})
    local running
    running="$(${compose[@]+"${compose[@]}"} ps -q --status running librechat 2>/dev/null)" || running=""
    if [ -z "${running//[$'\r\n']/}" ]; then
        info "LibreChat is not running; its next start removes the agents and prompts of addon $addon_name."
        return 0
    fi
    info "Removing the agents and prompts of addon $addon_name from LibreChat..."
    local rc=0
    ${compose[@]+"${compose[@]}"} run --rm --no-deps -T --entrypoint /bin/sh librechat -c \
        'cd /app && node /app/patches/agents-init.js && node /app/patches/prompts-init.js' \
        || rc=$?
    if [ "$rc" -ne 0 ]; then
        warn "Could not update the LibreChat agents and prompts (exit status $rc). $restart_hint"
    fi
    return 0
}
