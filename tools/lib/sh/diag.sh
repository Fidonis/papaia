# shellcheck shell=bash
# papaia-ctl — read-only diagnostics: status / doctor / hostnames.
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
    py_cli status ${extra[@]+"${extra[@]}"}
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
            # A check name (`doctor network`) runs that check only; Python validates it.
            [a-z]*) extra+=("$1") ;;
            *) error "Unknown option for doctor: $1"; exit 2 ;;
        esac
        shift
    done
    # shellcheck disable=SC2034  # read by py_cli
    CONFIG_DIR="$config_dir"
    # Deliberately no _require_setup_done: doctor is also the preflight to run
    # before 'setup' and 'upgrade'. Checks that need the installation's
    # configuration report 'skip' instead.
    py_cli doctor ${extra[@]+"${extra[@]}"}
}

cmd_logs() {
    local config_dir="$DEFAULT_CONFIG_DIR"
    local target=""
    local -a extra=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --since=*) extra+=(--since="${1#*=}") ;;
            --lines=*) extra+=(--lines="${1#*=}") ;;
            --follow|-f) extra+=(--follow) ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option for logs: $1"; exit 2 ;;
            *)
                if [ -n "$target" ]; then
                    error "logs takes one module or service, got '$target' and '$1'"; exit 2
                fi
                target="$1" ;;
        esac
        shift
    done
    if [ -z "$target" ]; then
        error "Usage: papaia-ctl logs <module|service> [--since=30m] [--lines=N] [--follow]"
        exit 2
    fi
    # shellcheck disable=SC2034  # read by py_cli
    CONFIG_DIR="$config_dir"
    _require_setup_done
    # `--` keeps a name from being read as an option; Python validates it.
    py_cli logs ${extra[@]+"${extra[@]}"} -- "$target"
}

cmd_support_bundle() {
    local config_dir="$DEFAULT_CONFIG_DIR"
    local -a extra=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --out=*) extra+=(--out="${1#*=}") ;;
            --lines=*) extra+=(--lines="${1#*=}") ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for support-bundle: $1"; exit 2 ;;
        esac
        shift
    done
    # shellcheck disable=SC2034  # read by py_cli
    CONFIG_DIR="$config_dir"
    _require_setup_done
    py_cli support-bundle ${extra[@]+"${extra[@]}"}
}

cmd_metrics() {
    local config_dir="$DEFAULT_CONFIG_DIR"
    local -a extra=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --out=*) extra+=(--out="${1#*=}") ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for metrics: $1"; exit 2 ;;
        esac
        shift
    done
    # shellcheck disable=SC2034  # read by py_cli
    CONFIG_DIR="$config_dir"
    _require_setup_done
    py_cli metrics ${extra[@]+"${extra[@]}"}
}

# The DNS names to create before the installation (BE-03, command 2): patterns before
# setup, the names themselves after it. Changes nothing; no switch to count.
cmd_hostnames() {
    local config_dir="$DEFAULT_CONFIG_DIR"
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for hostnames: $1"; exit 2 ;;
        esac
        shift
    done
    # shellcheck disable=SC2034  # read by py_cli
    CONFIG_DIR="$config_dir"
    py_cli hostnames
}
