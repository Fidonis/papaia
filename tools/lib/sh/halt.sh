# shellcheck shell=bash
# papaia-ctl — platform halt: halt set | clear | status.
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

# Writes $CONFIG_DIR/state/halt.json (lib/halt.py). Touches neither Docker nor Keycloak,
# so it works while every service is down. `on` and `off` are the same as set and clear.
cmd_halt() {
    local config_dir="$DEFAULT_CONFIG_DIR" action="${1:-}" reason="" have_reason=0 json=0
    shift || true
    case "$action" in
        set|on)   action="set" ;;
        clear|off) action="clear" ;;
        status)   ;;
        -h|--help) usage; exit 0 ;;
        *) error "Unknown 'halt' subcommand: '${action:-<none>}'. Valid: set, clear, status."; exit 2 ;;
    esac
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --reason=*) reason="${1#*=}"; have_reason=1 ;;
            --reason)
                if [ $# -lt 2 ]; then
                    error "--reason needs a text."
                    exit 2
                fi
                reason="$2"; have_reason=1; shift
                ;;
            --json)
                if [ "$action" != "status" ]; then
                    error "--json is an option of 'halt status' only."
                    exit 2
                fi
                json=1
                ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for halt $action: $1"; exit 2 ;;
        esac
        shift
    done
    if [ "$action" = "status" ] && [ "$have_reason" -eq 1 ]; then
        error "--reason is an option of 'halt set' and 'halt clear' only."
        exit 2
    fi
    # shellcheck disable=SC2034  # read by py_cli and _require_setup_done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local mode
    mode="$(_topology_mode)" || exit 3
    if [ "$mode" = "distributed" ]; then
        error "halt is not available in a distributed installation yet."
        exit 2
    fi
    local -a args=(halt --action="$action")
    [ "$have_reason" -eq 1 ] && args+=(--reason="$reason")
    [ "$json" -eq 1 ] && args+=(--json)
    py_cli ${args[@]+"${args[@]}"}
}
