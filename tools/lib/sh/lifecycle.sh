# shellcheck shell=bash
# papaia-ctl — core lifecycle commands: start / stop / uninstall.
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

# Run docker compose start/stop/up/down on every active addon.
# $1 = compose verb ("stop" or "down"), rest = extra docker compose flags
_addon_compose_all() {
    local verb="$1"; shift
    local -a extra=("$@")
    local addon_name addon_path
    while IFS= read -r addon_name; do
        [ -z "$addon_name" ] && continue
        addon_path="$(_addon_path "$addon_name")"
        info "  addon $addon_name: docker compose $verb"
        docker compose -f "$addon_path/docker-compose.yml" "$verb" "${extra[@]}"
    done < <(py_cli active-addons 2>/dev/null)
}

cmd_start() {
    local config_dir="$DEFAULT_CONFIG_DIR" addons=0 profiles="" force=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --addons) addons=1 ;;
            --profiles=*) profiles="${1#*=}" ;;
            --force) force=1 ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for start: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done

    # Compatibility gate for the upgrade case: the core may have moved since
    # the addons were installed. Refuse before anything is materialised or
    # started; --force degrades incompatibilities to warnings.
    local -a check_flags=()
    [ "$force" -eq 1 ] && check_flags+=(--force)
    if ! py_cli addon-check "${check_flags[@]}"; then
        error "Addon compatibility check failed. See 'papaia-ctl addon check', or re-run with --force to override."
        exit 2
    fi

    info "Materialising configuration into checkout..."
    py_cli materialize-core

    info "Rendering current configuration..."
    py_cli render

    local env_file="$REPO_ROOT/src/.env"

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
    success "start complete."
}

cmd_stop() {
    local config_dir="$DEFAULT_CONFIG_DIR" clean_up=0 addons=0 profiles=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --clean-up) clean_up=1 ;;
            --addons) addons=1 ;;
            --profiles=*) profiles="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for stop: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    local env_file="$REPO_ROOT/src/.env"

    if [ "$addons" -eq 1 ]; then
        info "Stopping active addons..."
        if [ "$clean_up" -eq 1 ]; then
            _addon_compose_all down
        else
            _addon_compose_all stop
        fi
    fi

    if [ "$clean_up" -eq 1 ]; then
        if [ -n "$profiles" ]; then
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
