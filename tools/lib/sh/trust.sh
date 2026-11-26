# shellcheck shell=bash
# papaia-ctl — the test trust anchor of a pre-release core (lib/prerelease_anchor.py,
# docs/adr/0030-accept-a-test-trust-anchor-for-pre-release-cores.md).
#
# `--test-trust-anchor=FILE` lets one command (start, upgrade, pairing confirm, pairing list,
# suite verify, setup in its pairing step and module offer, and restore and restore-scoped
# in their image checks) accept a bill of materials of scope `test` signed with the public
# key in FILE. Only the command line sets it:
# TEST_TRUST_ANCHOR is reset whenever this file is sourced and never taken from the
# environment, a configuration file or stored state.

# shellcheck disable=SC2034  # read by the command libraries (lifecycle, upgrade, pairing)
TEST_TRUST_ANCHOR=""

# The name a command that takes the option goes by in banner and audit, or nothing.
# $1 command, $2 its first argument (the subcommand, where it has one).
_test_anchor_command() {
    case "$1" in
        start|upgrade|setup|restore|restore-scoped) echo "$1" ;;
        pairing)
            case "${2:-}" in
                confirm|list) echo "pairing-$2" ;;
            esac
            ;;
        suite)
            [ "${2:-}" = "verify" ] && echo "suite-verify"
            ;;
    esac
    return 0
}

# Run the dispatcher $1 for command $2 with the remaining arguments. Without
# --test-trust-anchor=FILE this is the dispatcher call itself. With it, the option is taken
# out, the core refuses it unless it is a pre-release (before anything else is read) and
# prints the opening banner; the command then runs in a subshell, so that whatever way it
# ends the closing banner follows, and its exit code is kept.
_dispatch_with_test_anchor() {
    local dispatch="$1" cmd="$2"
    shift 2
    local -a rest=()
    local file="" seen=0 arg
    for arg in "$@"; do
        case "$arg" in
            --test-trust-anchor=*) seen=$((seen + 1)); file="${arg#*=}" ;;
            --test-trust-anchor)
                error "--test-trust-anchor needs a file: --test-trust-anchor=FILE"
                exit 2
                ;;
            *) rest+=("$arg") ;;
        esac
    done
    if [ "$seen" -eq 0 ]; then
        "$dispatch" "$cmd" "$@"
        return
    fi
    local label
    label="$(_test_anchor_command "$cmd" "${rest[0]:-}")"
    if [ -z "$label" ]; then
        error "--test-trust-anchor is accepted by start, upgrade, pairing confirm, pairing list,"
        error "suite verify, setup (its pairing step and module offer), restore and"
        error "restore-scoped (their image checks) only."
        exit 2
    fi
    if [ "$seen" -ne 1 ] || [ -z "$file" ]; then
        error "--test-trust-anchor=FILE is given once, with a public key file."
        exit 2
    fi
    case "$file" in
        /*) ;;
        *) file="$PWD/$file" ;;
    esac
    local opened fingerprint correlation
    opened="$(CONFIG_DIR="$DEFAULT_CONFIG_DIR" py_cli test-anchor --phase=begin \
        --command="$label" --test-trust-anchor="$file" | tr -d '\r')" || exit 2
    IFS=$'\t' read -r fingerprint correlation <<< "$opened"
    # shellcheck disable=SC2034  # read by the command libraries
    TEST_TRUST_ANCHOR="$file"
    IMAGES_CORRELATION_ID="${IMAGES_CORRELATION_ID:-$correlation}"
    local rc=0
    set +e
    ( set -e; "$dispatch" "$cmd" ${rest[@]+"${rest[@]}"} )
    rc=$?
    set -e
    CONFIG_DIR="$DEFAULT_CONFIG_DIR" py_cli test-anchor --phase=end --command="$label" \
        --fingerprint="$fingerprint" --exit-code="$rc" --correlation-id="$correlation" || true
    exit "$rc"
}
