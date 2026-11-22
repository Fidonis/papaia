# shellcheck shell=bash
# papaia-ctl — delegations: the lifetime of delegations (offline sessions).
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

# papaia-ctl delegations lifetime [--idle-days=N] [--max-days=N] [--json]
# Without values it shows the lifetime in effect; with values it sets it in
# $CONFIG_DIR/settings/delegations.json (lib/delegation_lifetime.py, audited), then
# renders the platform catalog and runs the realm sync, which write the values where
# holders and Keycloak read them.
cmd_delegations() {
    local sub="${1:-}" config_dir="$DEFAULT_CONFIG_DIR" idle="" age="" json=0
    local have_idle=0 have_age=0
    shift || true
    case "$sub" in
        lifetime) ;;
        -h|--help) usage; exit 0 ;;
        *) error "Unknown 'delegations' subcommand: '${sub:-<none>}'. Valid: lifetime."; exit 2 ;;
    esac
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --idle-days=*) idle="${1#*=}"; have_idle=1 ;;
            --max-days=*) age="${1#*=}"; have_age=1 ;;
            --json) json=1 ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for delegations lifetime: $1"; exit 2 ;;
        esac
        shift
    done
    if [ "$json" -eq 1 ] && { [ "$have_idle" -eq 1 ] || [ "$have_age" -eq 1 ]; }; then
        error "--json only shows the values; leave out --idle-days and --max-days."
        exit 2
    fi
    # shellcheck disable=SC2034  # read by py_cli and _require_setup_done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local mode
    mode="$(_topology_mode)" || exit 3
    if [ "$mode" = "distributed" ]; then
        error "delegations lifetime is not available in a distributed installation yet."
        exit 2
    fi
    if [ "$have_idle" -eq 0 ] && [ "$have_age" -eq 0 ]; then
        local -a show=(delegation-lifetime --show)
        [ "$json" -eq 1 ] && show+=(--json)
        py_cli ${show[@]+"${show[@]}"}
        return
    fi
    local -a args=(delegation-lifetime)
    [ "$have_idle" -eq 1 ] && args+=(--idle-days="$idle")
    [ "$have_age" -eq 1 ] && args+=(--max-days="$age")
    py_cli ${args[@]+"${args[@]}"}
    local failed=0
    if ! py_cli catalog-render; then
        failed=1
    fi
    py_cli join-stack-network || true
    if ! py_cli realm-sync; then
        failed=1
    fi
    if [ "$failed" -ne 0 ]; then
        error "The delegation lifetime is saved, but not yet applied everywhere. Run"
        error "'papaia-ctl catalog render' and 'papaia-ctl realm sync' once the stack runs"
        error "('papaia-ctl start' does both)."
        exit 1
    fi
}
