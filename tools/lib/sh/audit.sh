# shellcheck shell=bash
# papaia-ctl — audit store: audit cert | verify | heads | token-keys | retention | siem |
# idmap (docs/audit.md).
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

cmd_audit() {
    local sub="${1:-}"
    shift || true
    local config_dir="$DEFAULT_CONFIG_DIR" source="" against="" json=0
    local until="" reason="" target="" ticket="" pseud="" tid="" oid=""
    local target_set=0 pseud_set=0 tid_set=0 oid_set=0
    local -a positional=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --source=*) source="${1#*=}" ;;
            --against=*) against="${1#*=}" ;;
            --json) json=1 ;;
            --until=*) until="${1#*=}" ;;
            --reason=*) reason="${1#*=}" ;;
            --target=*) target="${1#*=}"; target_set=1 ;;
            --ticket=*) ticket="${1#*=}" ;;
            --pseud=*) pseud="${1#*=}"; pseud_set=1 ;;
            --tid=*) tid="${1#*=}"; tid_set=1 ;;
            --oid=*) oid="${1#*=}"; oid_set=1 ;;
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
        token-keys)
            [ "${#positional[@]}" -eq 0 ] || { error "audit token-keys takes no arguments."; exit 2; }
            py_cli audit-token-keys
            ;;
        retention)
            [ "${#positional[@]}" -eq 0 ] || { error "audit retention takes no arguments."; exit 2; }
            py_cli audit-retention
            ;;
        siem)
            local action="${positional[0]:-}"
            case "$action" in
                status)
                    [ "${#positional[@]}" -eq 1 ] || { error "audit siem status takes no arguments."; exit 2; }
                    py_cli audit-siem-status
                    ;;
                skip)
                    [ "${#positional[@]}" -eq 1 ] || { error "audit siem skip takes only options."; exit 2; }
                    if [ -z "$source" ] || [ -z "$until" ]; then
                        error "Usage: papaia-ctl audit siem skip --source=NAME --until=SEQ --reason=TEXT [--target=TARGET]"
                        exit 2
                    fi
                    local -a skip_args=(--source="$source" --until="$until" --reason="$reason")
                    [ "$target_set" -eq 1 ] && skip_args+=(--target="$target")
                    py_cli audit-siem-skip ${skip_args[@]+"${skip_args[@]}"}
                    ;;
                *) error "Unknown 'audit siem' action: '${action:-<none>}'. Valid: status, skip."; exit 2 ;;
            esac
            ;;
        idmap)
            [ "${#positional[@]}" -eq 0 ] || { error "audit idmap takes only options."; exit 2; }
            if [ -z "$ticket" ]; then
                error "Usage: papaia-ctl audit idmap --ticket=ID (--pseud=P-XXXXXXXX | --tid=ID --oid=ID)"
                exit 2
            fi
            local -a map_args=(--ticket="$ticket")
            [ "$pseud_set" -eq 1 ] && map_args+=(--pseud="$pseud")
            [ "$tid_set" -eq 1 ] && map_args+=(--tid="$tid")
            [ "$oid_set" -eq 1 ] && map_args+=(--oid="$oid")
            py_cli audit-idmap ${map_args[@]+"${map_args[@]}"}
            ;;
        *) error "Unknown 'audit' subcommand: '${sub:-<none>}'. Valid: cert, verify, heads, token-keys, retention, siem, idmap."; exit 2 ;;
    esac
}
