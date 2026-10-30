# shellcheck shell=bash
# papaia-ctl — `topology` command: show and check where the services of a distributed
# installation run. Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

cmd_topology() {
    local sub="${1:-show}"
    [ $# -gt 0 ] && shift
    local config_dir="$DEFAULT_CONFIG_DIR"
    local -a extra=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --json)
                [ "$sub" = "show" ] || { error "--json is an option of 'topology show'."; exit 2; }
                extra+=(--json) ;;
            --format=*)
                [ "$sub" = "firewall" ] || { error "--format is an option of 'topology firewall'."; exit 2; }
                extra+=(--format="${1#*=}") ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for topology $sub: $1"; exit 2 ;;
        esac
        shift
    done
    # shellcheck disable=SC2034  # read by py_cli and _require_setup_done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    case "$sub" in
        show)     py_cli topology-show "${extra[@]}" ;;
        validate) py_cli topology-validate ;;
        # The connections the installation opens between its nodes. papaia never applies
        # them; they are for whoever runs the firewalls.
        firewall) py_cli topology-firewall "${extra[@]}" ;;
        *) error "Unknown 'topology' subcommand: '$sub'. Valid: show, validate, firewall."; exit 2 ;;
    esac
}
