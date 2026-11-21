# shellcheck shell=bash
# papaia-ctl — stored secrets: secrets rotate <target>.
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

# Replaces one secret the core stores as a file and makes the running proxy use it
# (lib/paperless_gate.py). The only target is paperless-gate/proxy, the proxy's own
# secret for the Paperless gate; the gate reads it when the add-on starts again.
cmd_secrets_rotate() {
    local config_dir="$DEFAULT_CONFIG_DIR" target=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option for secrets rotate: $1"; exit 2 ;;
            *)
                if [ -n "$target" ]; then
                    error "secrets rotate takes one target, got '$target' and '$1'"
                    exit 2
                fi
                target="$1"
                ;;
        esac
        shift
    done
    if [ -z "$target" ]; then
        error "Usage: papaia-ctl secrets rotate paperless-gate/proxy [--config-dir=PATH]"
        exit 2
    fi
    # shellcheck disable=SC2034  # read by py_cli and _require_setup_done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    py_cli secrets-rotate --target="$target"
}
