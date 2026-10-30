# shellcheck shell=bash
# papaia-ctl — core lifecycle commands: start / stop / uninstall.
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

# "single" or "distributed", without Python: a single-node installation has no
# `topology:` block in deployment.yaml, and every lifecycle command asks this first.
# A block that says anything but single is handed to Python, which validates it.
_topology_mode() {
    local manifest="$CONFIG_DIR/deployment.yaml"
    if [ ! -f "$manifest" ] || ! grep -q '^topology:' "$manifest"; then
        printf 'single'
        return 0
    fi
    local mode
    if ! mode="$(py_cli topology-mode)"; then
        return 3
    fi
    printf '%s' "${mode%$'\r'}"
}

# Run docker compose start/stop/up/down on every active addon. Goes through
# _addon_compose (addon.sh) so teardown uses the same project name and env files
# as bring-up -- a templated `networks.*.name` otherwise resolves to its bare
# fallback here and leaves the per-deployment bridge orphaned.
# $1 = compose verb ("stop" or "down"), rest = extra docker compose flags
_addon_compose_all() {
    local verb="$1"; shift
    local -a extra=("$@")
    local addon_name addon_path
    while IFS= read -r addon_name; do
        [ -z "$addon_name" ] && continue
        addon_path="$(_addon_path "$addon_name")"
        info "  addon $addon_name: docker compose $verb"
        _addon_compose "$verb" "$addon_name" "$addon_path" "${extra[@]}"
    done < <(py_cli active-addons 2>/dev/null)
}

# Guard for every profile-restricted compose call.
#
# A profile subset that disables a hard `depends_on` target makes the project
# invalid. `docker compose stop`/`down` do not abort on that -- they fall back to
# project-name-only mode and derive their target set from the running containers
# of the project, so a scoped stop silently becomes a whole-stack stop. Resolve
# the selection up front and refuse rather than hand compose a project it will
# reinterpret.
#
# $1 = profile list, $2 = env file, rest = the `-f` args of the real call
_require_profiles_resolve() {
    local profiles="$1" env_file="$2"; shift 2
    local -a files=("$@")
    local services status=0
    services="$(COMPOSE_PROFILES="$profiles" docker compose "${files[@]}" \
        --env-file "$env_file" config --services 2>&1)" || status=$?

    if [ "$status" -ne 0 ]; then
        error "Profiles '$profiles' do not resolve to a valid compose project:"
        error "  $services"
        error "A service in these profiles depends on a service outside them. Add the"
        error "missing profile to --profiles, or mark that dependency 'required: false'."
        exit 2
    fi
    if [ -z "$services" ]; then
        error "Profiles '$profiles' match no service. Check the profile names against"
        error "COMPOSE_PROFILES in $env_file."
        exit 2
    fi
}

cmd_start() {
    local config_dir="$DEFAULT_CONFIG_DIR" addons=0 profiles="" force=0 node=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --addons) addons=1 ;;
            --profiles=*) profiles="${1#*=}" ;;
            --node=*) node="${1#*=}" ;;
            --force) force=1 ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for start: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done

    local mode
    mode="$(_topology_mode)" || exit 3
    if [ "$mode" = "distributed" ]; then
        _start_distributed "$node" "$profiles" "$addons" "$force"
        return
    fi
    _require_no_node "$node"

    # Compatibility gate for the upgrade case: the core may have moved since
    # the addons were installed. Refuse before anything is materialised or
    # started; --force degrades incompatibilities to warnings.
    local -a check_flags=()
    [ "$force" -eq 1 ] && check_flags+=(--force)
    if ! py_cli addon-check "${check_flags[@]}"; then
        error "Addon compatibility check failed. See 'papaia-ctl addon check', or re-run with --force to override."
        exit 2
    fi

    # Before materialising, so variables a newer checkout ships reach the
    # checkout copy in the same start. Silent unless something was added.
    py_cli sync-env

    info "Materialising configuration into checkout..."
    py_cli materialize-core

    info "Rendering current configuration..."
    py_cli render

    local env_file="$REPO_ROOT/src/.env"

    # Before the addons, so an unresolvable profile set aborts the whole command
    # instead of leaving the addons started and the core down. Checked against
    # the core compose file only; a broken override still fails `up` loudly.
    if [ -n "$profiles" ]; then
        _require_profiles_resolve "$profiles" "$env_file" -f "$COMPOSE_FILE"
    fi

    if [ "$addons" -eq 1 ]; then
        info "Starting active addons..."
        local addon_name addon_path
        while IFS= read -r addon_name; do
            [ -z "$addon_name" ] && continue
            addon_path="$(_addon_path "$addon_name")"
            info "  addon $addon_name: materialising env + starting"
            py_cli addon-start --name="$addon_name" "${check_flags[@]}"
            _addon_compose_up "$addon_name" "$addon_path"
        done < <(py_cli active-addons 2>/dev/null)
    fi

    # Build the override list, but skip any override whose external networks
    # don't exist yet.  Overrides declare addon networks as external:true —
    # if the addon hasn't been started yet the network doesn't exist and
    # docker compose up would fail.  Once `addon start <name>` (or
    # `start --addons`) runs, the network is Compose-owned and the override
    # is included automatically on the next start.
    local -a compose_overrides=()
    if [ -d "$CONFIG_DIR/overrides" ]; then
        for f in "$CONFIG_DIR"/overrides/docker-compose.*.override.yml; do
            [ -f "$f" ] || continue
            local nets_missing=0
            while IFS= read -r net_name; do
                [ -z "$net_name" ] && continue
                docker network inspect "$net_name" >/dev/null 2>&1 || { nets_missing=1; break; }
            done < <(py_cli override-external-nets --file="$f" 2>/dev/null)
            if [ "$nets_missing" -eq 0 ]; then
                compose_overrides+=(-f "$f")
            else
                warn "Addon not running — skipping override: $(basename "$f")"
            fi
        done
    fi

    if [ -n "$profiles" ]; then
        info "Starting core with profiles: $profiles"
        COMPOSE_PROFILES="$profiles" docker compose -f "$COMPOSE_FILE" "${compose_overrides[@]}" --env-file "$env_file" up -d
    else
        docker compose -f "$COMPOSE_FILE" "${compose_overrides[@]}" --env-file "$env_file" up -d
    fi

    if ! py_cli npm-provision; then
        warn "NPM proxy-host provisioning failed. Once the stack is healthy, run 'papaia-ctl npm-provision' to retry."
    fi

    if ! py_cli keycloak-role-sync; then
        warn "Keycloak role sync failed. Once Keycloak is healthy, run 'papaia-ctl keycloak-role-sync' to retry."
    fi

    success "start complete."
}

# The two provisioning steps `start` runs after `docker compose up`, as commands of their
# own so an operator can retry one when `start` reports it failed. `start` calls py_cli
# directly with the CONFIG_DIR it parsed; standalone, the command has to parse
# --config-dir itself like every other command, or py_cli expands an unset CONFIG_DIR.
cmd_npm_provision() { _provisioning_step npm-provision "$@"; }

cmd_keycloak_role_sync() { _provisioning_step keycloak-role-sync "$@"; }

# --node belongs to a distributed installation; on one host it is a mistake worth naming.
_require_no_node() {
    if [ -n "$1" ]; then
        error "--node is for a distributed installation; this one runs on one host."
        exit 2
    fi
}

# start in a distributed installation: the same gate and render as on one host, then the
# nodes in order (lib/cluster.py). $1 node, $2 profiles, $3 1 for --addons, $4 1 for --force
_start_distributed() {
    local node="$1" profiles="$2" addons="$3" force="$4"
    local -a check_flags=()
    [ "$force" -eq 1 ] && check_flags+=(--force)
    if ! py_cli addon-check "${check_flags[@]}"; then
        error "Addon compatibility check failed. See 'papaia-ctl addon check', or re-run with --force to override."
        exit 2
    fi
    py_cli sync-env
    info "Rendering the configuration and the node bundles..."
    py_cli render
    local -a extra=()
    [ -n "$node" ] && extra+=(--node="$node")
    [ -n "$profiles" ] && extra+=(--profiles="$profiles")
    py_cli cluster-start "${extra[@]}" || exit $?
    if [ "$addons" -eq 1 ]; then
        _addons_distributed start "$node"
    fi
    success "start complete."
}

# $1 node, $2 profiles, $3 1 for --addons, $4 1 for --clean-up
_stop_distributed() {
    local node="$1" profiles="$2" addons="$3" clean_up="$4"
    if [ "$addons" -eq 1 ]; then
        _addons_distributed "$([ "$clean_up" -eq 1 ] && echo down || echo stop)" "$node"
    fi
    local -a extra=()
    [ -n "$node" ] && extra+=(--node="$node")
    [ -n "$profiles" ] && extra+=(--profiles="$profiles")
    [ "$clean_up" -eq 1 ] && extra+=(--clean-up)
    py_cli cluster-stop "${extra[@]}" || exit $?
    success "stop complete."
}

_addons_distributed() {
    error "--addons is not available for a distributed installation yet."
    exit 2
}

_provisioning_step() {
    local step="$1"
    shift
    local config_dir="$DEFAULT_CONFIG_DIR"
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for $step: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local mode
    mode="$(_topology_mode)" || exit 3
    if [ "$mode" = "distributed" ]; then
        # The step runs where its service runs: the proxy's node, Keycloak's node.
        local service="nginx" owner
        [ "$step" = "keycloak-role-sync" ] && service="keycloak"
        owner="$(py_cli topology-node-of --service="$service")"
        py_cli node-exec --name="${owner%$'\r'}" hook "$step"
        return
    fi
    # The step's own exit status is the command's, so a retry that fails is visible.
    py_cli "$step"
}

# The profiles of the optional modules. `stop --volumes` deletes data, so it is limited to
# these: the always-on services (Keycloak, LibreChat, LiteLLM ...) and the manager keep theirs.
_VOLUME_DELETE_PROFILES="localai librechat-websearch rag smtp"

_require_deletable_profiles() {
    local profiles="$1" profile allowed
    local -a names
    IFS=',' read -r -a names <<< "$profiles"
    for profile in "${names[@]}"; do
        allowed=0
        for known in $_VOLUME_DELETE_PROFILES; do
            [ "$profile" = "$known" ] && allowed=1
        done
        if [ "$allowed" -eq 0 ]; then
            error "--volumes deletes data and is limited to the optional modules"
            error "  ($_VOLUME_DELETE_PROFILES); '$profile' is not one of them."
            exit 2
        fi
    done
}

cmd_stop() {
    local config_dir="$DEFAULT_CONFIG_DIR" clean_up=0 addons=0 profiles="" volumes=0 node=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --clean-up) clean_up=1 ;;
            --volumes) volumes=1 ;;
            --addons) addons=1 ;;
            --profiles=*) profiles="${1#*=}" ;;
            --node=*) node="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for stop: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    local env_file="$REPO_ROOT/src/.env"

    local mode
    mode="$(_topology_mode)" || exit 3
    if [ "$mode" = "distributed" ]; then
        if [ "$volumes" -eq 1 ]; then
            error "--volumes is not available for a distributed installation: run"
            error "'papaia-ctl stop --clean-up --profiles=LIST' and delete the volumes on the node."
            exit 2
        fi
        _stop_distributed "$node" "$profiles" "$addons" "$clean_up"
        return
    fi
    _require_no_node "$node"

    # Deleting volumes is only ever scoped: it needs the containers removed with them, and the
    # profiles that say whose.
    if [ "$volumes" -eq 1 ]; then
        if [ "$clean_up" -ne 1 ] || [ -z "$profiles" ]; then
            error "--volumes needs --clean-up and --profiles=LIST: it deletes the data of exactly"
            error "the named profiles."
            exit 2
        fi
        _require_deletable_profiles "$profiles"
    fi

    # Before the addons, so an unresolvable profile set aborts the whole command
    # instead of leaving the addons stopped and the core untouched.
    if [ -n "$profiles" ]; then
        _require_profiles_resolve "$profiles" "$env_file" -f "$COMPOSE_FILE"
    fi

    if [ "$addons" -eq 1 ]; then
        info "Stopping active addons..."
        if [ "$clean_up" -eq 1 ]; then
            _addon_compose_all down
        else
            _addon_compose_all stop
        fi
    fi

    if [ "$clean_up" -eq 1 ]; then
        if [ -n "$profiles" ] && [ "$volumes" -eq 1 ]; then
            # `down -v` with the profiles applied removes the volumes of the services of those
            # profiles only, anonymous ones included (a Redis or Postgres image declares one).
            # The profile set was resolved above: an unresolvable one would make compose
            # derive its targets from the project's running containers instead.
            COMPOSE_PROFILES="$profiles" docker compose -f "$COMPOSE_FILE" --env-file "$env_file" down --volumes
        elif [ -n "$profiles" ]; then
            COMPOSE_PROFILES="$profiles" docker compose -f "$COMPOSE_FILE" --env-file "$env_file" down
        else
            docker compose -f "$COMPOSE_FILE" --env-file "$env_file" down
        fi
    else
        if [ -n "$profiles" ]; then
            COMPOSE_PROFILES="$profiles" docker compose -f "$COMPOSE_FILE" --env-file "$env_file" stop
        else
            docker compose -f "$COMPOSE_FILE" --env-file "$env_file" stop
        fi
    fi
    success "stop complete."
}

# Commands a distributed installation does not offer: they would act on the controller
# alone and leave the other nodes behind. $1 = the command, rest = what to do instead.
_refuse_distributed() {
    local command="$1"; shift
    local mode
    mode="$(_topology_mode)" || exit 3
    [ "$mode" = "distributed" ] || return 0
    error "'papaia-ctl $command' is not available for a distributed installation."
    local line
    for line in "$@"; do
        error "$line"
    done
    exit 2
}

cmd_uninstall() {
    local config_dir="$DEFAULT_CONFIG_DIR" clean_up=0 addons=0 non_interactive=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --clean-up) clean_up=1 ;;
            --addons) addons=1 ;;
            -y|--yes) non_interactive=1 ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for uninstall: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _refuse_distributed uninstall \
        "Stop it with 'papaia-ctl stop --clean-up', remove the user and the directory on every" \
        "node, and delete $CONFIG_DIR by hand once nothing in it is needed any more."

    warn "This will stop and remove all core containers and permanently delete $CONFIG_DIR."
    if [ "$clean_up" -eq 1 ]; then
        warn "  --clean-up: all named volumes will also be removed."
    fi
    if [ "$addons" -eq 1 ]; then
        warn "  --addons: active addon containers will also be stopped and removed."
    fi

    if [ "$non_interactive" -eq 0 ] && is_tty; then
        if ! confirm "Proceed with uninstall?" "N"; then
            error "Aborted."
            exit 3
        fi
    fi

    local env_file="$REPO_ROOT/src/.env"

    if [ "$addons" -eq 1 ] && [ -f "$CONFIG_DIR/deployment.yaml" ]; then
        info "Stopping and removing active addon containers..."
        if [ "$clean_up" -eq 1 ]; then
            _addon_compose_all down -v
        else
            _addon_compose_all down
        fi
    fi

    if [ -f "$COMPOSE_FILE" ] && [ -f "$env_file" ]; then
        info "Stopping and removing core containers..."
        if [ "$clean_up" -eq 1 ]; then
            docker compose -f "$COMPOSE_FILE" --env-file "$env_file" down -v
        else
            docker compose -f "$COMPOSE_FILE" --env-file "$env_file" down
        fi
    fi

    if [ -d "$CONFIG_DIR" ]; then
        info "Deleting $CONFIG_DIR..."
        rm -rf "$CONFIG_DIR"
    fi
    success "uninstall complete."
}

_require_setup_done() {
    if [ ! -f "$CONFIG_DIR/.env" ] || [ ! -f "$CONFIG_DIR/deployment.yaml" ]; then
        error "No setup found at $CONFIG_DIR. Run 'papaia-ctl setup' first."
        exit 2
    fi
}
