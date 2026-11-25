# shellcheck shell=bash
# papaia-ctl — the runtime environment that runs lib.cli (tools/lib/ctl_runtime.py).
# Sourced by tools/papaia-ctl; not executable on its own.
#
# `setup`, `upgrade` and `rollback` (the way back of an upgrade) build the environment of
# tools/runtime.lock with the base interpreter, or reuse it, and point
# tools/.runtime/current at it. `hostnames`, `doctor` and `restore`, which run before setup
# on a fresh checkout or after the loss of the host, build it the same way when the
# checkout has none yet. Every other command only checks it and stops with one line when it
# is missing, stale or unsafe. lib.cli always runs as tools/.runtime/current/bin/python, by
# absolute path and with -P (the caller's working directory is not on its path): PATH and
# sudo's secure_path only matter while an environment is built.

CTL_RUNTIME_DIR="$REPO_ROOT/tools/.runtime"

# The numeric owner of a path (portable: GNU and BSD `ls -n` agree on the columns).
_ctl_runtime_uid() {
    local line uid
    line="$(ls -ldn "$1" 2>/dev/null)" || return 1
    read -r _ _ uid _ <<< "$line"
    [[ "$uid" =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "$uid"
}

# Prints why the directory tree $1 cannot be trusted to run as root: an entry writable by
# the group or by everyone, or owned by neither root nor the owner of tools/. $2 1 for the
# directory itself only, 2 for the tree without its site-packages and dist-packages (the
# standard library of the base). Checked before the environment's interpreter ever runs.
_ctl_runtime_unsafe() {
    local path="$1" mode="${2:-0}" owner found
    local -a depth=() skip=()
    [ "$mode" = "1" ] && depth=(-maxdepth 0)
    [ "$mode" = "2" ] && skip=(\( -name site-packages -o -name dist-packages \) -prune -o)
    owner="$(_ctl_runtime_uid "$REPO_ROOT/tools")" || { echo "$REPO_ROOT/tools cannot be read"; return 0; }
    found="$(find "$path" ${depth[@]+"${depth[@]}"} ${skip[@]+"${skip[@]}"} \
        \( ! -uid 0 ! -uid "$owner" \) -print -quit 2>/dev/null)"
    if [ -n "$found" ]; then
        echo "$found is owned by neither root nor the owner of $REPO_ROOT/tools"
        return 0
    fi
    found="$(find "$path" ${depth[@]+"${depth[@]}"} ${skip[@]+"${skip[@]}"} \
        \( ! -type l \( -perm -0020 -o -perm -0002 \) \) -print -quit 2>/dev/null)"
    [ -n "$found" ] && echo "$found is group- or world-writable"
    return 0
}

# Prints why the base of the environment $1 cannot be trusted: the interpreter its
# bin/python resolves to and the base's standard library, as the build recorded them in
# papaia-ctl-base (inside the environment, so checked with it), under the same rule.
_ctl_runtime_unsafe_base() {
    local record="$1/papaia-ctl-base" path problem count=0
    if [ ! -f "$record" ]; then
        echo "$record is missing"
        return 0
    fi
    while IFS= read -r path || [ -n "$path" ]; do
        case "$path" in /*) ;; *) continue ;; esac
        count=$((count + 1))
        if [ ! -e "$path" ]; then
            echo "$path (the base) is missing"
            return 0
        fi
        problem="$(_ctl_runtime_unsafe "$path" 2)"
        if [ -n "$problem" ]; then
            echo "$problem"
            return 0
        fi
    done < "$record"
    [ "$count" -gt 0 ] || echo "$record names no base"
    return 0
}

# Prints why the environment the link $1 names cannot run lib.cli for the tools/ directory
# $2; nothing when it can.
_ctl_runtime_problem() {
    local link="$1" tools="$2" target env problem rc=0
    if [ ! -L "$link" ]; then
        echo "missing ($link)"
        return 0
    fi
    target="$(readlink "$link")"
    if ! [[ "$target" =~ ^[0-9a-f]{64}$ ]] || [ ! -d "$CTL_RUNTIME_DIR/$target" ]; then
        echo "missing ($link points nowhere)"
        return 0
    fi
    env="$CTL_RUNTIME_DIR/$target"
    problem="$(_ctl_runtime_unsafe "$CTL_RUNTIME_DIR" 1)"
    [ -z "$problem" ] && problem="$(_ctl_runtime_unsafe "$link" 1)"
    [ -z "$problem" ] && problem="$(_ctl_runtime_unsafe "$env")"
    [ -z "$problem" ] && problem="$(_ctl_runtime_unsafe_base "$env")"
    if [ -n "$problem" ]; then
        echo "refused: $problem"
        return 0
    fi
    problem="$("$link/bin/python" -I "$REPO_ROOT/tools/lib/ctl_runtime.py" check \
        --tools="$tools" 2>/dev/null)" || rc=$?
    if [ "$rc" -eq 1 ] && [ -n "$problem" ]; then
        echo "$problem"
    elif [ "$rc" -ne 0 ]; then
        echo "unusable: its interpreter $link/bin/python does not run (exit $rc)"
    fi
    return 0
}

# Every command but setup, upgrade, rollback and (on a checkout without one) hostnames,
# doctor and restore: use the environment, never change it.
ctl_runtime_require() {
    local problem
    problem="$(_ctl_runtime_problem "$CTL_RUNTIME_DIR/current" "$REPO_ROOT/tools")"
    if [ -n "$problem" ]; then
        error "The runtime environment of papaia-ctl is $problem; run 'papaia-ctl setup' to build it."
        exit 2
    fi
    # shellcheck disable=SC2034  # consumed by tools/papaia-ctl and the libraries
    PYTHON_BIN="$CTL_RUNTIME_DIR/current/bin/python"
}

# Builds (hash-checked) or reuses the environment of the tools/ directory $1 under this
# checkout's tools/.runtime and prints its interpreter. $2 1 to leave `current` alone (the
# target tree of an upgrade). The base interpreter is PAPAIA_PYTHON or the first one on PATH.
_ctl_runtime_build() {
    local tools="$1" no_switch="${2:-0}" base
    local -a flags=(--tools="$tools" --runtime="$CTL_RUNTIME_DIR")
    [ "$no_switch" = "1" ] && flags+=(--no-switch)
    find_python || return 2
    if ! base="$(command -v "$PYTHON_BIN")"; then
        error "$PYTHON_BIN is not an executable interpreter."
        return 2
    fi
    "$base" -I "$REPO_ROOT/tools/lib/ctl_runtime.py" build ${flags[@]+"${flags[@]}"}
}

# setup, upgrade, rollback: build or reuse, switch `current`, then check it like every
# other command does.
ctl_runtime_ensure() {
    local line
    if ! line="$(_ctl_runtime_build "$REPO_ROOT/tools" 0)"; then
        error "The runtime environment of papaia-ctl could not be built (see above); nothing else was done."
        exit 2
    fi
    [ -n "$line" ] || exit 2
    ctl_runtime_require
}

# hostnames, doctor, restore: the commands the README runs before setup (the fresh
# installation) or without one (after the loss of the host). On a checkout that has no
# environment yet they build it exactly as setup does; once there is one they only use it.
ctl_runtime_bootstrap() {
    if [ ! -L "$CTL_RUNTIME_DIR/current" ]; then
        ctl_runtime_ensure
    else
        ctl_runtime_require
    fi
}

# The interpreter for lib.cli against another core tree (_py_cli_at), in
# CTL_RUNTIME_AT_PYTHON: that tree's own environment, built (hash-checked) before it is
# first used and kept for this run. A tree without runtime.lock predates the environment
# and gets this checkout's. Not in a subshell: the result is cached in the caller's shell.
_CTL_RUNTIME_AT_ROOT=""
# shellcheck disable=SC2034  # read by _py_cli_at in lib/sh/upgrade.sh
CTL_RUNTIME_AT_PYTHON=""
ctl_runtime_at() {
    local root="$1" python problem
    if [ "$root" = "$REPO_ROOT" ] || [ ! -f "$root/tools/runtime.lock" ]; then
        # shellcheck disable=SC2034  # read by _py_cli_at in lib/sh/upgrade.sh
        CTL_RUNTIME_AT_PYTHON="$PYTHON_BIN"
        return 0
    fi
    [ "$_CTL_RUNTIME_AT_ROOT" = "$root" ] && return 0
    if ! python="$(_ctl_runtime_build "$root/tools" 1)" || [ -z "$python" ]; then
        error "The runtime environment of the core tree $root could not be built (see above)."
        return 2
    fi
    problem="$(_ctl_runtime_unsafe "${python%/bin/python}")"
    [ -z "$problem" ] && problem="$(_ctl_runtime_unsafe_base "${python%/bin/python}")"
    if [ -n "$problem" ]; then
        error "The runtime environment of the core tree $root is refused: $problem."
        return 2
    fi
    _CTL_RUNTIME_AT_ROOT="$root"
    # shellcheck disable=SC2034  # read by _py_cli_at in lib/sh/upgrade.sh
    CTL_RUNTIME_AT_PYTHON="$python"
}

# Which commands build the environment and which only use it. Without a command papaia-ctl
# prints its usage and needs no environment; node-shell runs on a node, which has none
# (lib/node_shell.py needs PyYAML only).
ctl_runtime_preflight() {
    case "${1:-}" in
        ""|help|-h|--help) ;;
        setup|upgrade|rollback) ctl_runtime_ensure ;;
        hostnames|doctor|restore) ctl_runtime_bootstrap ;;
        node-shell)
            find_python || exit 2
            if ! "$PYTHON_BIN" -c 'import yaml' >/dev/null 2>&1; then
                error "Python module 'yaml' (PyYAML) not found for '$PYTHON_BIN' on this node:"
                error "  Debian/Ubuntu: sudo apt-get install -y python3-yaml"
                exit 2
            fi
            ;;
        *) ctl_runtime_require ;;
    esac
}
