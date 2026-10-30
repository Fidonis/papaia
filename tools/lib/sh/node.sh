# shellcheck shell=bash
# papaia-ctl — `node` command family (distributed installations) and the node-shell
# entry point. Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

# The forced command of a node's SSH key (and of the controller's own node). Hands over to
# lib/node_shell.py, which parses SSH_ORIGINAL_COMMAND itself. `exec`: nothing of this
# script runs after it, so a checkout replaced by `checkout-put` cannot be misread.
cmd_node_shell() {
    PYTHONPATH="$REPO_ROOT/tools${PYTHONPATH:+:$PYTHONPATH}" \
        exec "$PYTHON_BIN" -m lib.node_shell --repo-root "$REPO_ROOT" "$@"
}

cmd_node() {
    local sub="${1:-}"
    [ $# -gt 0 ] && shift
    case "$sub" in
        add)         _node_add "$@" ;;
        list)        _node_list "$@" ;;
        check)       _node_check "$@" ;;
        remove)      _node_remove "$@" ;;
        join-bundle) _node_join_bundle "$@" ;;
        renew-link)  _node_renew_link "$@" ;;
        sync)        _node_sync "$@" ;;
        *)
            error "Unknown 'node' subcommand: '${sub:-<none>}'. Valid: add, list, check, remove, join-bundle, renew-link, sync."
            exit 2
            ;;
    esac
}

# Every node command works on a distributed installation only.
_node_require_distributed() {
    _require_setup_done
    local mode
    mode="$(_topology_mode)" || exit 3
    if [ "$mode" != "distributed" ]; then
        error "This installation runs on one host. Nodes belong to a distributed installation,"
        error "which 'papaia-ctl setup --topology=distributed' creates for a new installation."
        exit 2
    fi
}

# Pin a node's SSH host key unless it is pinned already. $1 = node, $2 = fingerprint given
# with --host-key-fingerprint (may be empty), $3 = 1 for -y.
_node_pin_host_key() {
    local name="$1" wanted="$2" assume_yes="$3"
    if [ -f "$CONFIG_DIR/nodes/$name/ssh/known_hosts" ]; then
        return 0
    fi
    info "Asking $name for its SSH host key..."
    local scanned
    if ! scanned="$(py_cli node-keyscan --name="$name" | tr -d '\r')"; then
        error "Could not read the host key of $name. Is SSH reachable from here?"
        exit 3
    fi
    local marker kind fingerprint chosen="" first=""
    while IFS=$'\t' read -r marker kind fingerprint; do
        [ "$marker" = "HOSTKEY" ] || continue
        [ -z "$first" ] && first="$fingerprint"
        if [ -n "$wanted" ] && [ "$fingerprint" = "$wanted" ]; then
            chosen="$fingerprint"
        fi
        [ "$kind" = "ssh-ed25519" ] && [ -z "$wanted" ] && [ -z "$chosen" ] && chosen="$fingerprint"
    done <<< "$scanned"
    [ -z "$chosen" ] && [ -z "$wanted" ] && chosen="$first"

    if [ -n "$wanted" ]; then
        if [ "$chosen" != "$wanted" ]; then
            error "$name does not offer a host key with fingerprint $wanted. Nothing was pinned."
            exit 3
        fi
    else
        if [ "$assume_yes" -eq 1 ] || ! is_tty; then
            error "Refusing to trust the host key of $name unseen. Compare it with what the node's"
            error "install script printed and pass --host-key-fingerprint=SHA256:..."
            exit 2
        fi
        warn "Host keys offered by $name:"
        while IFS=$'\t' read -r marker kind fingerprint; do
            [ "$marker" = "HOSTKEY" ] && warn "  $kind  $fingerprint"
        done <<< "$scanned"
        if ! confirm "Trust $chosen for $name?" "N"; then
            error "Aborted. Nothing was pinned."
            exit 3
        fi
    fi
    py_cli node-pin --name="$name" --fingerprint="$chosen"
}

_node_add() {
    local config_dir="$DEFAULT_CONFIG_DIR" name="" address="" ssh_spec="" root="" gpu="" bind_ip=""
    local bootstrap="join" admin="" output="" fingerprint="" assume_yes=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --address=*) address="${1#*=}" ;;
            --ssh=*) ssh_spec="${1#*=}" ;;
            --root=*) root="${1#*=}" ;;
            --gpu=*) gpu="${1#*=}" ;;
            --bind-ip=*) bind_ip="${1#*=}" ;;
            --bootstrap=*) bootstrap="${1#*=}" ;;
            --admin=*) admin="${1#*=}" ;;
            --output=*) output="${1#*=}" ;;
            --host-key-fingerprint=*) fingerprint="${1#*=}" ;;
            -y|--yes) assume_yes=1 ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option for node add: $1"; exit 2 ;;
            *) name="$1" ;;
        esac
        shift
    done
    if [ -z "$name" ] || [ -z "$address" ]; then
        error "Usage: papaia-ctl node add <name> --address=ADDR [--ssh=USER@HOST[:PORT]] [--bootstrap=join|admin]"
        exit 2
    fi
    case "$bootstrap" in
        join|admin) : ;;
        *) error "--bootstrap must be 'join' or 'admin', got '$bootstrap'"; exit 2 ;;
    esac
    CONFIG_DIR="$config_dir"
    _node_require_distributed

    local -a register=(--name="$name" --address="$address")
    if [ -n "$ssh_spec" ]; then
        local ssh_user="${ssh_spec%%@*}" ssh_rest="${ssh_spec#*@}" ssh_port=""
        [ "$ssh_user" = "$ssh_spec" ] && ssh_user=""
        case "$ssh_rest" in
            *:*) ssh_port="${ssh_rest##*:}"; ssh_rest="${ssh_rest%:*}" ;;
        esac
        [ -n "$ssh_user" ] && register+=(--ssh-user="$ssh_user")
        [ -n "$ssh_rest" ] && register+=(--ssh-host="$ssh_rest")
        [ -n "$ssh_port" ] && register+=(--ssh-port="$ssh_port")
    fi
    [ -n "$root" ] && register+=(--root="$root")
    [ -n "$gpu" ] && register+=(--gpu="$gpu")
    [ -n "$bind_ip" ] && register+=(--bind-ip="$bind_ip")
    py_cli node-register "${register[@]}"

    if [ "$bootstrap" = "join" ]; then
        [ -z "$output" ] && output="$PWD/papaia-join-$name.tar.gz"
        py_cli node-join-bundle --name="$name" --output="$output"
        info "Copy $output to $name and run there, as root:"
        info "    tar -xzf $(basename "$output") && sudo ./papaia-join-$name/install.sh"
        info "Then confirm its host key and check the connection with:"
        info "    papaia-ctl node check $name"
        return 0
    fi

    # Admin session: the operator's own login on the node runs the install script. It goes
    # through the host key pinned for the node, so it is checked once, here.
    if [ -z "$admin" ]; then
        error "--bootstrap=admin needs --admin=USER@HOST[:PORT] (a login with sudo on the node)."
        exit 2
    fi
    _node_pin_host_key "$name" "$fingerprint" "$assume_yes"
    local admin_target="${admin%:*}" admin_port="22"
    case "$admin" in
        *:*) admin_port="${admin##*:}" ;;
    esac
    local archive
    archive="$(mktemp)"
    py_cli node-join-bundle --name="$name" --output="$archive"
    local remote="/tmp/papaia-join-$name-$$.tar.gz"
    local -a ssh_opts=(-o StrictHostKeyChecking=yes
        -o UserKnownHostsFile="$CONFIG_DIR/nodes/$name/ssh/known_hosts" -o GlobalKnownHostsFile=/dev/null)
    info "Copying the join archive to $admin_target..."
    if ! scp -q -P "$admin_port" "${ssh_opts[@]}" "$archive" "$admin_target:$remote"; then
        rm -f "$archive"
        error "Could not copy the join archive to $admin_target."
        exit 3
    fi
    rm -f "$archive"
    info "Running the install script on $name (sudo asks for the admin password if it needs one)..."
    # The remote command line is fixed text plus values papaia-ctl validated ($name is a node
    # name, $remote a path under /tmp it made up).
    if ! ssh -t -p "$admin_port" "${ssh_opts[@]}" "$admin_target" \
        "set -e; d=\$(mktemp -d); tar -xzf '$remote' -C \"\$d\"; rm -f '$remote'; sudo bash \"\$d/papaia-join-$name/install.sh\"; rm -rf \"\$d\""; then
        error "The install script did not finish on $name. Nothing was stored of the admin login."
        exit 3
    fi
    py_cli node-check --name="$name"
    success "node $name enrolled."
}

_node_list() {
    local config_dir="$DEFAULT_CONFIG_DIR"
    local -a extra=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --json) extra+=(--json) ;;
            --check) extra+=(--check) ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for node list: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _node_require_distributed
    py_cli node-list "${extra[@]}"
}

_node_check() {
    local config_dir="$DEFAULT_CONFIG_DIR" name="" fingerprint="" assume_yes=0
    local -a extra=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --host-key-fingerprint=*) fingerprint="${1#*=}" ;;
            --json) extra+=(--json) ;;
            -y|--yes) assume_yes=1 ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option for node check: $1"; exit 2 ;;
            *) name="$1" ;;
        esac
        shift
    done
    if [ -z "$name" ]; then
        error "Usage: papaia-ctl node check <name> [--host-key-fingerprint=SHA256:...] [--json]"
        exit 2
    fi
    CONFIG_DIR="$config_dir"
    _node_require_distributed
    local controller
    controller="$(py_cli topology-show --json | "$PYTHON_BIN" -c 'import json,sys; print(json.load(sys.stdin)["controller"])')"
    if [ "$name" != "${controller%$'\r'}" ]; then
        _node_pin_host_key "$name" "$fingerprint" "$assume_yes"
    fi
    py_cli node-check --name="$name" "${extra[@]}"
}

_node_remove() {
    local config_dir="$DEFAULT_CONFIG_DIR" name="" assume_yes=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            -y|--yes) assume_yes=1 ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option for node remove: $1"; exit 2 ;;
            *) name="$1" ;;
        esac
        shift
    done
    [ -z "$name" ] && { error "Usage: papaia-ctl node remove <name> [-y]"; exit 2; }
    CONFIG_DIR="$config_dir"
    _node_require_distributed
    if [ "$assume_yes" -eq 0 ]; then
        if ! is_tty; then
            error "Refusing to remove a node without confirmation. Re-run with -y."
            exit 2
        fi
        warn "Node $name leaves the topology, and its SSH key and link certificate are deleted."
        confirm "Remove node $name?" "N" || { error "Aborted."; exit 3; }
    fi
    py_cli node-unregister --name="$name"
}

_node_join_bundle() {
    local config_dir="$DEFAULT_CONFIG_DIR" name="" output=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --output=*) output="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option for node join-bundle: $1"; exit 2 ;;
            *) name="$1" ;;
        esac
        shift
    done
    [ -z "$name" ] && { error "Usage: papaia-ctl node join-bundle <name> [--output=FILE]"; exit 2; }
    CONFIG_DIR="$config_dir"
    _node_require_distributed
    [ -z "$output" ] && output="$PWD/papaia-join-$name.tar.gz"
    py_cli node-join-bundle --name="$name" --output="$output"
}

_node_renew_link() {
    local config_dir="$DEFAULT_CONFIG_DIR" name=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option for node renew-link: $1"; exit 2 ;;
            *) name="$1" ;;
        esac
        shift
    done
    [ -z "$name" ] && { error "Usage: papaia-ctl node renew-link <name>"; exit 2; }
    CONFIG_DIR="$config_dir"
    _node_require_distributed
    py_cli node-renew-link --name="$name"
    py_cli node-push --name="$name"
    info "Restarting the link gateway on $name..."
    py_cli node-exec --name="$name" compose-restart link-gateway
    success "link certificate of $name renewed."
}

_node_sync() {
    local config_dir="$DEFAULT_CONFIG_DIR" name="" checkout=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --all) name="all" ;;
            --checkout) checkout=1 ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option for node sync: $1"; exit 2 ;;
            *) name="$1" ;;
        esac
        shift
    done
    [ -z "$name" ] && { error "Usage: papaia-ctl node sync <name>|--all [--checkout]"; exit 2; }
    CONFIG_DIR="$config_dir"
    _node_require_distributed
    local -a extra=()
    [ "$checkout" -eq 1 ] && extra+=(--checkout)
    if [ "$name" = "all" ]; then extra+=(--all); else extra+=(--name="$name"); fi
    py_cli render
    py_cli node-push "${extra[@]}"
}
