# shellcheck shell=bash
# papaia-ctl — exchange-right pairings: pairing list | confirm | approve | revoke, and the
# confirmation step of `setup`.
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

# The last step of `setup`: shows the pairings of the signed bill of materials with the
# sha256 of the list and confirms them only on an explicit decision -- the question below,
# or --approve-pairings=<sha256>. `-y` never confirms. Without a decision setup still
# completes; nothing is assigned until the list is confirmed (lib/pairing_approval.py).
# With `setup --test-trust-anchor=FILE` (lib/sh/trust.sh, ADR 0030) every call here checks
# the bill of materials against that key; without it nothing differs.
# $1: 1 when setup runs with -y, $2: the value of --approve-pairings (may be empty).
_setup_pairings() {
    local non_interactive="$1" approved="$2" digest
    local -a anchored=()
    if [ -n "${TEST_TRUST_ANCHOR:-}" ]; then
        anchored+=(--test-trust-anchor="$TEST_TRUST_ANCHOR")
        [ -n "${IMAGES_CORRELATION_ID:-}" ] && anchored+=(--correlation-id="$IMAGES_CORRELATION_ID")
    fi
    if ! digest="$(py_cli pairing-list --digest ${anchored[@]+"${anchored[@]}"})"; then
        error "The pairings of the bill of materials cannot be shown (see above)."
        return 3
    fi
    if [ -z "$digest" ]; then
        if [ -n "$approved" ]; then
            warn "--approve-pairings is not used: no pairing of the bill of materials waits for a decision."
        fi
        return 0
    fi
    py_cli pairing-list ${anchored[@]+"${anchored[@]}"} || return 3
    if [ -n "$approved" ]; then
        py_cli pairing-confirm --approve-pairings="$approved" ${anchored[@]+"${anchored[@]}"} \
            || return 2
        return 0
    fi
    if [ "$non_interactive" -eq 0 ] && is_tty; then
        if confirm "Confirm the read pairings of this list ($digest)?" "N"; then
            py_cli pairing-confirm --approve-pairings="$digest" ${anchored[@]+"${anchored[@]}"} \
                || return 2
            return 0
        fi
        warn "Pairings not confirmed; nothing of the list is assigned."
    else
        warn "Pairings not confirmed: -y never confirms exchange rights; nothing of the list is assigned."
    fi
    warn "  Confirm this list later with 'papaia-ctl pairing confirm --approve-pairings=$digest'."
    return 0
}

cmd_pairing() {
    local config_dir="$DEFAULT_CONFIG_DIR" action="${1:-}" json=0 approved="" client="" audience="" effects=""
    shift || true
    case "$action" in
        list|confirm|approve|revoke) ;;
        -h|--help) usage; exit 0 ;;
        *) error "Unknown 'pairing' subcommand: '${action:-<none>}'. Valid: list, confirm, approve, revoke."; exit 2 ;;
    esac
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --json) json=1 ;;
            --approve-pairings=*) approved="${1#*=}" ;;
            --client=*) client="${1#*=}" ;;
            --audience=*) audience="${1#*=}" ;;
            --effects=*) effects="${1#*=}" ;;
            -y|--yes)
                error "pairing $action takes no -y: exchange rights are confirmed explicitly."
                exit 2
                ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for pairing $action: $1"; exit 2 ;;
        esac
        shift
    done
    if [ "$json" -eq 1 ] && [ "$action" != "list" ]; then
        error "--json is an option of 'pairing list' only."; exit 2
    fi
    if [ -n "$approved" ] && [ "$action" != "confirm" ]; then
        error "--approve-pairings is an option of 'pairing confirm' only."; exit 2
    fi
    if [ -n "$effects" ] && [ "$action" != "approve" ]; then
        error "--effects is an option of 'pairing approve' only."; exit 2
    fi
    # shellcheck disable=SC2034  # read by py_cli and _require_setup_done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    # --test-trust-anchor of this one command (lib/sh/trust.sh): list and confirm only.
    local -a anchored=()
    if [ -n "${TEST_TRUST_ANCHOR:-}" ]; then
        anchored+=(--test-trust-anchor="$TEST_TRUST_ANCHOR")
        [ -n "${IMAGES_CORRELATION_ID:-}" ] && anchored+=(--correlation-id="$IMAGES_CORRELATION_ID")
    fi
    case "$action" in
        list)
            if [ "$json" -eq 1 ]; then
                py_cli pairing-list --json ${anchored[@]+"${anchored[@]}"}
            else
                py_cli pairing-list ${anchored[@]+"${anchored[@]}"}
            fi
            ;;
        confirm)
            if [ -z "$approved" ]; then
                error "pairing confirm needs --approve-pairings=<sha256> as 'papaia-ctl pairing list' shows it."
                exit 2
            fi
            py_cli pairing-confirm --approve-pairings="$approved" ${anchored[@]+"${anchored[@]}"}
            ;;
        approve|revoke)
            if [ -z "$client" ] || [ -z "$audience" ]; then
                error "pairing $action needs --client=NAME and --audience=NAME."
                exit 2
            fi
            if [ "$action" = "approve" ] && [ -n "$effects" ]; then
                py_cli pairing-approve --client="$client" --audience="$audience" --effects="$effects"
            else
                py_cli "pairing-$action" --client="$client" --audience="$audience"
            fi
            ;;
    esac
}
