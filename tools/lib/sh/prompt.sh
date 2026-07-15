# shellcheck shell=bash
# papaia-ctl — interactive prompt helpers.
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

prompt_with_default() {
    local message="$1" default="$2" answer
    read -rp "$message [${default:-none}]: " answer
    printf '%s' "${answer:-$default}"
}

# Show a titled section (bold-ish title + optional indented help line) and then
# read a value. Title/help go to stderr so this stays usable inside $( ) --
# only the resolved value (from prompt_with_default) reaches stdout.
prompt_field() {
    local title="$1" help="$2" label="$3" default="$4"
    printf '\n%s%s%s\n' "$CYAN" "$title" "$NC" >&2
    [ -n "$help" ] && printf '  %s\n' "$help" >&2
    prompt_with_default "  $label" "$default"
}

confirm() {
    local message="$1" default="${2:-N}" answer hint
    hint="y/N"; [ "$default" = "Y" ] && hint="Y/n"
    read -rp "$message [$hint]: " answer
    answer="${answer:-$default}"
    case "$answer" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

is_tty() { [ -t 0 ] && [ -t 1 ]; }
