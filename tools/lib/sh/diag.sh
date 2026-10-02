# shellcheck shell=bash
# papaia-ctl — read-only diagnostics: status / doctor.
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint
#
# With --json nothing but the JSON document may reach stdout, so a caller can
# parse it as is. log.sh's info() and success() print to stdout and are
# therefore not used here; error() prints to stderr.

cmd_status() {
    local config_dir="$DEFAULT_CONFIG_DIR"
    local -a extra=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --profiles=*) extra+=(--profiles="${1#*=}") ;;
            --addons) extra+=(--addons) ;;
            --json) extra+=(--json) ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for status: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    py_cli status "${extra[@]}"
}

cmd_doctor() {
    local config_dir="$DEFAULT_CONFIG_DIR"
    local -a extra=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --skip=*) extra+=(--skip="${1#*=}") ;;
            --json) extra+=(--json) ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for doctor: $1"; exit 2 ;;
        esac
        shift
    done
    # shellcheck disable=SC2034  # read by py_cli
    CONFIG_DIR="$config_dir"
    # Deliberately no _require_setup_done: doctor is also the preflight to run
    # before 'setup' and 'upgrade'. Checks that need the installation's
    # configuration report 'skip' instead.
    py_cli doctor "${extra[@]}"
}
