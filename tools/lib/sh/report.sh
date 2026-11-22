# shellcheck shell=bash
# papaia-ctl — report: the permission report and its recertification; breakglass: the
# emergency account (lib/access_report.py, lib/breakglass.py, docs/permission-report.md).
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

# An option is named without its value in an error: a mistyped --token=... must not
# put the token into the terminal's scrollback or a log.
_report_unknown() {
    error "Unknown option for $1: ${2%%=*}"
    exit 2
}

# papaia-ctl report permissions --by=person|system [--format=json|csv] --token-file=PATH|-
# papaia-ctl report confirm --key=KEY --digest=SHA256 --token-file=PATH|-
cmd_report() {
    local sub="${1:-}" config_dir="$DEFAULT_CONFIG_DIR" by="" format="json" token_file=""
    local key="" digest=""
    shift || true
    case "$sub" in
        permissions|confirm) ;;
        -h|--help) usage; exit 0 ;;
        *) error "Unknown 'report' subcommand: '${sub:-<none>}'. Valid: permissions, confirm."; exit 2 ;;
    esac
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --token-file=*) token_file="${1#*=}" ;;
            --by=*) [ "$sub" = "permissions" ] || _report_unknown "report $sub" "$1"; by="${1#*=}" ;;
            --format=*) [ "$sub" = "permissions" ] || _report_unknown "report $sub" "$1"; format="${1#*=}" ;;
            --key=*) [ "$sub" = "confirm" ] || _report_unknown "report $sub" "$1"; key="${1#*=}" ;;
            --digest=*) [ "$sub" = "confirm" ] || _report_unknown "report $sub" "$1"; digest="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            *) _report_unknown "report $sub" "$1" ;;
        esac
        shift
    done
    if [ -z "$token_file" ]; then
        error "report $sub needs --token-file=PATH (or - for stdin): a person token for the audience papaia-audit."
        exit 2
    fi
    if [ "$sub" = "permissions" ]; then
        case "$by" in
            person|system) ;;
            *) error "--by must be person or system"; exit 2 ;;
        esac
        case "$format" in
            json|csv) ;;
            *) error "--format must be json or csv"; exit 2 ;;
        esac
    elif [ -z "$key" ] || [ -z "$digest" ]; then
        error "report confirm needs --key=person:<sub>|system:<audience> and --digest=sha256:<hex>"
        exit 2
    fi
    # shellcheck disable=SC2034  # read by py_cli and _require_setup_done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local mode
    mode="$(_topology_mode)" || exit 3
    if [ "$mode" = "distributed" ]; then
        error "'report' is not available in a distributed installation yet."
        exit 2
    fi
    py_cli join-stack-network || true
    if [ "$sub" = "permissions" ]; then
        py_cli report-permissions --by "$by" --format "$format" --token-file "$token_file"
    else
        py_cli report-confirm --key "$key" --digest "$digest" --token-file "$token_file"
    fi
}

# papaia-ctl breakglass create --address=EMAIL | rotate | status
cmd_breakglass() {
    local sub="${1:-}" config_dir="$DEFAULT_CONFIG_DIR" address=""
    shift || true
    case "$sub" in
        create|rotate|status) ;;
        -h|--help) usage; exit 0 ;;
        *) error "Unknown 'breakglass' subcommand: '${sub:-<none>}'. Valid: create, rotate, status."; exit 2 ;;
    esac
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --address=*) [ "$sub" = "create" ] || _report_unknown "breakglass $sub" "$1"; address="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            *) _report_unknown "breakglass $sub" "$1" ;;
        esac
        shift
    done
    if [ "$sub" = "create" ] && [ -z "$address" ]; then
        error "breakglass create needs --address=EMAIL: the operator address the account carries."
        exit 2
    fi
    # shellcheck disable=SC2034  # read by py_cli and _require_setup_done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local mode
    mode="$(_topology_mode)" || exit 3
    if [ "$mode" = "distributed" ]; then
        error "'breakglass' is not available in a distributed installation yet."
        exit 2
    fi
    py_cli join-stack-network || true
    local -a args=(breakglass --action "$sub")
    [ -n "$address" ] && args+=(--address "$address")
    py_cli ${args[@]+"${args[@]}"}
}
