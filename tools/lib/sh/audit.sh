# shellcheck shell=bash
# papaia-ctl — audit store: audit cert | verify | heads (docs/audit.md).
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

cmd_audit() {
    local sub="${1:-}"
    shift || true
    local config_dir="$DEFAULT_CONFIG_DIR" source="" against="" json=0
    local -a positional=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --source=*) source="${1#*=}" ;;
            --against=*) against="${1#*=}" ;;
            --json) json=1 ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option for audit $sub: $1"; exit 2 ;;
            *) positional+=("$1") ;;
        esac
        shift
    done
    # shellcheck disable=SC2034  # read by py_cli
    CONFIG_DIR="$config_dir"
    _require_setup_done

    case "$sub" in
        cert)
            if [ "${#positional[@]}" -ne 1 ]; then
                error "Usage: papaia-ctl audit cert <source>"
                exit 2
            fi
            py_cli audit-cert --source="${positional[0]}"
            ;;
        verify)
            [ "${#positional[@]}" -eq 0 ] || { error "audit verify takes no arguments, only options."; exit 2; }
            local -a args=()
            [ -n "$source" ] && args+=(--source="$source")
            [ -n "$against" ] && args+=(--against="$against")
            [ "$json" -eq 1 ] && args+=(--json)
            py_cli audit-verify ${args[@]+"${args[@]}"}
            ;;
        heads)
            [ "${#positional[@]}" -eq 0 ] || { error "audit heads takes no arguments."; exit 2; }
            py_cli audit-heads
            ;;
        *) error "Unknown 'audit' subcommand: '${sub:-<none>}'. Valid: cert, verify, heads."; exit 2 ;;
    esac
}
