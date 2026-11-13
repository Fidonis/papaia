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
    local config_dir="$DEFAULT_CONFIG_DIR" email="" before="" dry_run=false assume_yes=false
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --before=*) before="${1#*=}" ;;
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
