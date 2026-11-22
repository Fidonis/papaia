# shellcheck shell=bash
# papaia-ctl — installation settings: settings show | set <key> <value> | unset <key>.
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

# Contact point, brand and the four-eyes rule (lib/settings.py). Each change is stored in
# the overlay, audited and rendered into the platform catalog at once. Exit 0 done or
# unchanged, 1 refused by the security profile, 2 invalid, 3 the catalog was not rendered.
cmd_settings() {
    local config_dir="$DEFAULT_CONFIG_DIR" action="${1:-}" json=0
    local -a positional=()
    shift || true
    case "$action" in
        show|set|unset) ;;
        -h|--help) usage; exit 0 ;;
        *) error "Unknown 'settings' subcommand: '${action:-<none>}'. Valid: show, set, unset."; exit 2 ;;
    esac
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --json)
                if [ "$action" != "show" ]; then
                    error "--json is an option of 'settings show' only."
                    exit 2
                fi
                json=1
                ;;
            -h|--help) usage; exit 0 ;;
            --*) error "Unknown option for settings $action: $1"; exit 2 ;;
            *) positional+=("$1") ;;
        esac
        shift
    done
    local want=0
    case "$action" in
        set) want=2 ;;
        unset) want=1 ;;
    esac
    if [ "${#positional[@]}" -ne "$want" ]; then
        case "$action" in
            show)  error "settings show takes no argument." ;;
            set)   error "settings set needs a key and a value: papaia-ctl settings set <key> <value>" ;;
            unset) error "settings unset needs a key: papaia-ctl settings unset <key>" ;;
        esac
        exit 2
    fi
    # shellcheck disable=SC2034  # read by py_cli and _require_setup_done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    case "$action" in
        show)
            if [ "$json" -eq 1 ]; then
                py_cli settings-show --json
            else
                py_cli settings-show
            fi
            ;;
        set)   py_cli settings-set --key="${positional[0]}" --value="${positional[1]}" ;;
        unset) py_cli settings-unset --key="${positional[0]}" ;;
    esac
}
