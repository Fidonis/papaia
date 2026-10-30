# shellcheck shell=bash
# papaia-ctl — `topology` command: show and check where the services of a distributed
# installation run. Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

# "single" or "distributed", without Python: a single-node installation has no
# `topology:` block in deployment.yaml, and every lifecycle command asks this first.
# A block that says anything but single is handed to Python, which validates it.
_topology_mode() {
    local manifest="$CONFIG_DIR/deployment.yaml"
    if [ ! -f "$manifest" ] || ! grep -q '^topology:' "$manifest"; then
        printf 'single'
        return 0
    fi
    local mode
    if ! mode="$(py_cli topology-mode)"; then
        return 3
    fi
    printf '%s' "${mode%$'\r'}"
}

cmd_topology() {
    local sub="${1:-show}"
    [ $# -gt 0 ] && shift
    local config_dir="$DEFAULT_CONFIG_DIR"
    local -a extra=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --json) extra+=(--json) ;;
            --format=*) extra+=(--format="${1#*=}") ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for topology $sub: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    case "$sub" in
        show)     py_cli topology-show "${extra[@]}" ;;
        validate) py_cli topology-validate ;;
        *) error "Unknown 'topology' subcommand: '$sub'. Valid: show, validate."; exit 2 ;;
    esac
}
