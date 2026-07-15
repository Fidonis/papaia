# shellcheck shell=bash
# papaia-ctl — logging helpers (colors + info/success/warn/error).
# Sourced by tools/papaia-ctl; not executable on its own.

# --- logging helpers --------------------------------------------------------
if [ -t 1 ]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; CYAN=""; NC=""
fi
info()    { printf '%s[papaia-ctl]%s %s\n' "$CYAN" "$NC" "$*"; }
success() { printf '%s[ok]%s %s\n' "$GREEN" "$NC" "$*"; }
warn()    { printf '%s[!]%s %s\n' "$YELLOW" "$NC" "$*" >&2; }
error()   { printf '%s[error]%s %s\n' "$RED" "$NC" "$*" >&2; }
