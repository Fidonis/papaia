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

# A distributed installation is locked while an upgrade has not finished and while a node
# runs another release than this checkout: everything that changes it waits for `upgrade`.
# The upgrade itself sets UPGRADE_IN_PROGRESS for the commands it runs.
_cluster_require_unlocked() {
    [ "${UPGRADE_IN_PROGRESS:-0}" = "1" ] && return 0
    py_cli cluster-lock || exit 2
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
        _addon_compose "$verb" "$addon_name" "$addon_path" ${extra[@]+"${extra[@]}"}
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
    services="$(COMPOSE_PROFILES="$profiles" docker compose ${files[@]+"${files[@]}"} \
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

# Docker Desktop drops the bind-mount proxy paths of a stopped container, and `up` would
# start that container with its old mount source. Only a new container gets a valid one.
_stopped_containers_go_stale() {
    [ "$(docker info --format '{{.OperatingSystem}}' 2>/dev/null || true)" = "Docker Desktop" ]
}

# Without a terminal, Compose prints one line per progress event of every layer it pulls.
# papaia-manager reads a fixed tail of its runner logs, and a pull of new images would push
# the opening lines of a start, upgrade or restore out of it. A terminal keeps the progress
# bars; errors of a failed pull still reach stderr either way.
_pull_quietly() {
    [ ! -t 2 ]
}

# The core compose overrides `start` uses, in CORE_OVERRIDES as `-f <file>` pairs: every
# override whose external networks exist. Overrides declare add-on networks as
# external: true; until the add-on has started, its network does not exist and
# `docker compose up` would fail, so such an override is left out until the next start.
# $1 = "warn" to name each override left out, anything else to stay quiet.
CORE_OVERRIDES=()
_core_overrides() {
    local mode="${1:-quiet}" f net_name nets_missing
    CORE_OVERRIDES=()
    [ -d "$CONFIG_DIR/overrides" ] || return 0
    for f in "$CONFIG_DIR"/overrides/docker-compose.*.override.yml; do
        [ -f "$f" ] || continue
        nets_missing=0
        while IFS= read -r net_name; do
            [ -z "$net_name" ] && continue
            docker network inspect "$net_name" >/dev/null 2>&1 || { nets_missing=1; break; }
        done < <(py_cli override-external-nets --file="$f" 2>/dev/null)
        if [ "$nets_missing" -eq 0 ]; then
            CORE_OVERRIDES+=(-f "$f")
        elif [ "$mode" = "warn" ]; then
            warn "Addon not running — skipping override: $(basename "$f")"
        fi
    done
}

# Internal to one command, never stored: the release key fingerprint of the installed
# core while the target of an upgrade is checked, and the correlation id both phases
# of an upgrade write their audit rows under. Set by upgrade.sh.
IMAGES_ANCHOR="${IMAGES_ANCHOR:-}"
IMAGES_CORRELATION_ID="${IMAGES_CORRELATION_ID:-}"

# Refuse to go on unless every image to start is listed with its digest in the signed
# bill of materials of the core tree $2 and signed with its key (lib/images.py).
# $1 = command (start, upgrade, addon-start, ...), $2 = core tree,
# $3 = core image list file or empty, $4 = 1 to check every image the tree pins (all
# profiles and variants: the target of an upgrade, whose env files do not exist yet, and
# a distributed installation, whose services start on other nodes),
# $5 = 1 for --insecure-images (this command only, never stored), rest = extra flags,
# among them one --addon-images=NAME=FILE per add-on (see _addon_image_flags)
_verify_images() {
    local command="$1" root="$2" list="$3" whole_tree="$4" insecure="$5"
    shift 5
    local -a flags=(--command="$command" "$@")
    [ "$insecure" -eq 1 ] && flags+=(--insecure-images)
    [ -n "$list" ] && flags+=(--images-file="$list")
    [ "$whole_tree" -eq 1 ] && flags+=(--from-checkout)
    [ -n "$IMAGES_ANCHOR" ] && flags+=(--anchor-fingerprint="$IMAGES_ANCHOR")
    [ -n "$IMAGES_CORRELATION_ID" ] && flags+=(--correlation-id="$IMAGES_CORRELATION_ID")
    local rc=0
    info "Checking image digests and signatures against the bill of materials..."
    if [ "$root" = "$REPO_ROOT" ]; then
        py_cli image-verify ${flags[@]+"${flags[@]}"} || rc=$?
    else
        _py_cli_at "$root" image-verify ${flags[@]+"${flags[@]}"} || rc=$?
    fi
    if [ "$rc" -ne 0 ]; then
        error "Image check failed; no container was started."
        exit 2
    fi
}

# One image list per active add-on, for a check of everything `start --addons` (or an
# upgrade) runs: ADDON_IMAGE_FLAGS gets one --addon-images=NAME=FILE per add-on, so an
# image accepted outside the bill of materials counts for its own add-on only;
# ADDON_IMAGE_FILES the files, removed by _addon_image_files_remove. Uses the add-on
# helpers of addon.sh.
ADDON_IMAGE_FLAGS=()
ADDON_IMAGE_FILES=()
_addon_image_flags() {
    local addon_name addon_path list
    ADDON_IMAGE_FLAGS=()
    ADDON_IMAGE_FILES=()
    while IFS= read -r addon_name; do
        [ -z "$addon_name" ] && continue
        addon_path="$(_addon_path "$addon_name")"
        list="$(mktemp)"
        ADDON_IMAGE_FILES+=("$list")
        _addon_image_list "$addon_name" "$addon_path" "$list"
        ADDON_IMAGE_FLAGS+=(--addon-images="$addon_name=$list")
    done < <(py_cli active-addons 2>/dev/null)
}

_addon_image_files_remove() {
    local f
    for f in ${ADDON_IMAGE_FILES[@]+"${ADDON_IMAGE_FILES[@]}"}; do
        rm -f "$f"
    done
    ADDON_IMAGE_FILES=()
}

# Append the images compose starts for the core to the list file $1: the profiles
# ($2, or the env file's COMPOSE_PROFILES when empty) with the override files that
# follow, exactly as `up` gets them. $3 = env file, rest = -f args.
_core_image_list() {
    local out="$1" profiles="$2" env_file="$3"
    shift 3
    if ! (
        if [ -n "$profiles" ]; then export COMPOSE_PROFILES="$profiles"; fi
        docker compose -f "$COMPOSE_FILE" "$@" --env-file "$env_file" config --images
    ) >> "$out"; then
        error "Could not list the images to check. Nothing was started."
        exit 2
    fi
}

# Print the core override files `start` uses, one per line. An override that declares
# add-on networks as external is skipped while such a network does not exist yet;
# with $1 = 1 (--addons) the networks of the active add-ons count as present, because
# their start in the same command creates them. The image check and `up` use this
# one list, so the checked set is the started set.
_core_override_files() {
    local with_addons="$1" f net_name
    [ -d "$CONFIG_DIR/overrides" ] || return 0
    local -a coming=()
    if [ "$with_addons" -eq 1 ]; then
        while IFS= read -r net_name; do
            [ -n "$net_name" ] && coming+=("$net_name")
        done < <(py_cli addon-networks 2>/dev/null)
    fi
    for f in "$CONFIG_DIR"/overrides/docker-compose.*.override.yml; do
        [ -f "$f" ] || continue
        local nets_missing=0
        while IFS= read -r net_name; do
            [ -z "$net_name" ] && continue
            case " ${coming[*]+${coming[*]}} " in *" $net_name "*) continue ;; esac
            docker network inspect "$net_name" >/dev/null 2>&1 || { nets_missing=1; break; }
        done < <(py_cli override-external-nets --file="$f" 2>/dev/null)
        if [ "$nets_missing" -eq 0 ]; then
            printf '%s\n' "$f"
        else
            warn "Addon not running — skipping override: $(basename "$f")"
        fi
    done
}

# ── post-restore before the first module ────────────────────────────────
# The step is `papaia-ctl post-restore` (backup.sh, lib/post_restore.py). A restore that
# wrote something leaves $CONFIG_DIR/post-restore.pending with the second it began, until
# the step succeeded. While it exists, `start` brings up Keycloak alone, runs
# the step and starts no module before it succeeded; `addon start` refuses. Whatever stops
# a restore half-way, the restored delegations do not come back usable with the next start.

# $1 = the time the restore began (empty: now). Returns the step's status.
_post_restore() {
    local -a flags=()
    [ -n "${1:-}" ] && flags+=(--since="$1")
    py_cli join-stack-network || true
    py_cli post-restore ${flags[@]+"${flags[@]}"}
}

# shellcheck disable=SC2034  # read by restore (backup.sh)
POST_RESTORE_STATUS=""  # ok | failed, set by _post_restore_before_modules

_post_restore_marker() {
    printf '%s/post-restore.pending' "$CONFIG_DIR"
}

# $1 = the second the restore began.
_post_restore_mark() {
    local marker
    marker="$(_post_restore_marker)"
    { printf '%s\n' "$1" > "$marker.tmp" && mv -f "$marker.tmp" "$marker"; } 2>/dev/null
}

_post_restore_clear() {
    rm -f "$(_post_restore_marker)"
}

# Fails when nothing is pending; prints the recorded second, or nothing when the marker
# cannot be read as one. The step then starts from now, which revokes more, never less.
_post_restore_pending() {
    local marker value=""
    marker="$(_post_restore_marker)"
    [ -f "$marker" ] || return 1
    value="$(head -c 32 "$marker" 2>/dev/null | tr -d '[:space:]')" || value=""
    [[ "$value" =~ ^[1-9][0-9]{0,9}$ ]] || value=""
    printf '%s' "$value"
}

# $1 = the second the restore began (may be empty).
_post_restore_hint() {
    local since_flag=""
    [ -n "${1:-}" ] && since_flag=" --since=$1"
    error "Sessions and delegations from the restore point may still be usable."
    error "'papaia-ctl start' runs the step before any module starts; with Keycloak"
    error "running, finish it with:"
    error "  papaia-ctl post-restore$since_flag --config-dir=$CONFIG_DIR"
}

# The pending step before the first module (BE-17): the images of the keycloak profile
# checked, Keycloak and its database started alone, the step run against them. Returns 0
# when nothing is pending or the step succeeded; otherwise non-zero, and the caller starts
# nothing else. $1 = 1 for --insecure-images.
# shellcheck disable=SC2034  # POST_RESTORE_STATUS is read by restore (backup.sh)
_post_restore_before_modules() {
    local insecure="${1:-0}" since
    since="$(_post_restore_pending)" || return 0
    POST_RESTORE_STATUS="failed"
    local env_file="$REPO_ROOT/src/.env"
    info "A restore left post-restore pending; running it before any module starts..."
    # Without the keycloak profile (external_oidc) there is nothing to start: the step
    # reports that the delegations live at the external provider.
    # Captured first: under pipefail an early `grep -q` could fail the pipeline.
    local services=""
    services="$(docker compose -f "$COMPOSE_FILE" --env-file "$env_file" \
        config --services 2>/dev/null)" || services=""
    if grep -qx keycloak <<< "$services"; then
        local list verified=0 up_rc=0
        list="$(mktemp)"
        ( _core_image_list "$list" keycloak "$env_file" \
            && _verify_images restore "$REPO_ROOT" "$list" 0 "$insecure" ) || verified=$?
        rm -f "$list"
        if [ "$verified" -eq 0 ]; then
            info "Starting Keycloak alone..."
            docker compose -f "$COMPOSE_FILE" --env-file "$env_file" \
                up -d --no-recreate keycloak || up_rc=$?
        fi
        if [ "$verified" -ne 0 ] || [ "$up_rc" -ne 0 ]; then
            error "Keycloak could not be started on its own; no module was started."
            [ -z "${_RESTORE_OPEN_ID:-}" ] && _post_restore_hint "$since"
            return 3
        fi
    fi
    if ! _post_restore "$since"; then
        error "post-restore failed; no module was started."
        [ -z "${_RESTORE_OPEN_ID:-}" ] && _post_restore_hint "$since"
        return 3
    fi
    _post_restore_clear
    POST_RESTORE_STATUS="ok"
}

# For commands that start a module without `start`: refuse while the step is pending.
_require_no_pending_post_restore() {
    local since
    since="$(_post_restore_pending)" || return 0
    error "A restore left post-restore pending; no module may start before it ran."
    _post_restore_hint "$since"
    exit 2
}

cmd_start() {
    local config_dir="$DEFAULT_CONFIG_DIR" addons=0 profiles="" force=0 node="" unlock=0
    local insecure_images=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --insecure-images) insecure_images=1 ;;
            --addons) addons=1 ;;
            --profiles=*) profiles="${1#*=}" ;;
            --node=*) node="${1#*=}" ;;
            --unlock) unlock=1 ;;
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
        if [ "$unlock" -eq 1 ]; then
            # The operator's way out of an upgrade abandoned without a restore point: drop
            # the lock and let start put the checkout's release back on every node.
            warn "--unlock: releasing the upgrade lock; every node gets this checkout's release."
            py_cli cluster-lock --clear
            UPGRADE_IN_PROGRESS=1
        fi
        _start_distributed "$node" "$profiles" "$addons" "$force" "$insecure_images"
        return
    fi
    _require_no_node "$node"
    if [ "$unlock" -eq 1 ]; then
        error "--unlock is for a distributed installation; this one runs on one host."
        exit 2
    fi

    # Compatibility gate for the upgrade case: the core may have moved since
    # the addons were installed. Refuse before anything is materialised or
    # started; --force degrades incompatibilities to warnings.
    local -a check_flags=()
    [ "$force" -eq 1 ] && check_flags+=(--force)
    if ! py_cli addon-check ${check_flags[@]+"${check_flags[@]}"}; then
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

    # The native LocalAI of an Apple Silicon Mac (LOCALAI_RUNTIME=native): its binary and
    # start script, before `up` so a failed download is reported before the stack moves.
    LOCALAI_NATIVE="off"
    if _profiles_include_localai "$profiles"; then
        _localai_native_install
    fi

    local env_file="$REPO_ROOT/src/.env"

    # Before the addons, so an unresolvable profile set aborts the whole command
    # instead of leaving the addons started and the core down. Checked against
    # the core compose file only; a broken override still fails `up` loudly.
    if [ -n "$profiles" ]; then
        _require_profiles_resolve "$profiles" "$env_file" -f "$COMPOSE_FILE"
    fi

    # The add-ons' env files and overrides as `up` will use them, before the image check:
    # an add-on compose file picks its image through variables of the bundle .env that
    # addon-start copies over the checkout's, and the re-render may change the overrides.
    # --no-keycloak: Keycloak may not be up yet; the keycloak-role-sync step below
    # creates the add-on clients. Nothing is started here.
    local addon_name addon_path
    local -a active_addons=()
    if [ "$addons" -eq 1 ]; then
        while IFS= read -r addon_name; do
            [ -n "$addon_name" ] && active_addons+=("$addon_name")
        done < <(py_cli active-addons 2>/dev/null)
        for addon_name in ${active_addons[@]+"${active_addons[@]}"}; do
            info "  addon $addon_name: materialising env"
            py_cli addon-start --name="$addon_name" --no-keycloak ${check_flags[@]+"${check_flags[@]}"}
        done
    fi

    # Overrides that declare add-on networks as external are skipped while such a
    # network does not exist (see _core_override_files); built once, before the
    # check, so the images checked are the images `up` starts.
    local -a compose_overrides=()
    local override_file
    while IFS= read -r override_file; do
        [ -n "$override_file" ] && compose_overrides+=(-f "$override_file")
    done < <(_core_override_files "$addons")

    # Before the first container of the core or an add-on: every image this command
    # starts, core and active add-ons (each with its own list), in one check (digest
    # and signature). A refusal is returned, not an exit, so a caller such as the
    # second phase of an upgrade still reports it.
    local image_list
    image_list="$(mktemp)"
    _core_image_list "$image_list" "$profiles" "$env_file" \
        ${compose_overrides[@]+"${compose_overrides[@]}"}
    ADDON_IMAGE_FLAGS=() ADDON_IMAGE_FILES=()
    [ "$addons" -eq 1 ] && _addon_image_flags
    local verified=0
    ( _verify_images start "$REPO_ROOT" "$image_list" 0 "$insecure_images" \
        ${ADDON_IMAGE_FLAGS[@]+"${ADDON_IMAGE_FLAGS[@]}"} ) || verified=$?
    rm -f "$image_list"
    _addon_image_files_remove
    [ "$verified" -eq 0 ] || return 2

    # A restore left post-restore pending (see above): Keycloak alone, then the step, and
    # no add-on or core module before it succeeded (BE-17).
    _post_restore_before_modules "$insecure_images" || return 3

    if [ "$addons" -eq 1 ]; then
        info "Starting active addons..."
        for addon_name in ${active_addons[@]+"${active_addons[@]}"}; do
            addon_path="$(_addon_path "$addon_name")"
            info "  addon $addon_name: starting"
            _addon_compose_up "$addon_name" "$addon_path"
        done
    fi

    local up_flags=(-d)
    if _stopped_containers_go_stale; then
        up_flags+=(--force-recreate)
    fi
    if _pull_quietly; then
        up_flags+=(--quiet-pull)
        info "Starting the containers; missing images are pulled without progress output..."
    fi

    if [ -n "$profiles" ]; then
        info "Starting core with profiles: $profiles"
        COMPOSE_PROFILES="$profiles" docker compose -f "$COMPOSE_FILE" ${compose_overrides[@]+"${compose_overrides[@]}"} --env-file "$env_file" up ${up_flags[@]+"${up_flags[@]}"}
    else
        docker compose -f "$COMPOSE_FILE" ${compose_overrides[@]+"${compose_overrides[@]}"} --env-file "$env_file" up ${up_flags[@]+"${up_flags[@]}"}
    fi

    # After `up`, so LiteLLM is there when LocalAI answers. The init job need not have
    # finished: LocalAI reads a model's `<name>.yaml` on the first request for it.
    _localai_native_start

    # In a container (papaia-manager and its runners) the provisioning steps reach the stack
    # over its network, which `up` has just created; on the host this does nothing.
    py_cli join-stack-network || true

    if ! py_cli npm-provision; then
        warn "NPM proxy-host provisioning failed. Once the stack is healthy, run 'papaia-ctl npm-provision' to retry."
    fi

    if ! py_cli keycloak-role-sync; then
        warn "Keycloak role sync failed. Once Keycloak is healthy, run 'papaia-ctl keycloak-role-sync' to retry."
    fi

    success "start complete."
}

# What the native LocalAI step of `start` did (LOCALAI_NATIVE = off | skipped | installed |
# unchanged | failed), the pinned version, and whether a running job has to be
# restarted (a new binary, start script or key). Set by _localai_native_install.
LOCALAI_NATIVE="off"
LOCALAI_NATIVE_VERSION=""
LOCALAI_NATIVE_REPLACED=""
LOCALAI_NATIVE_RESTART="0"

# Whether a --profiles list covers LocalAI; no list means the whole stack.
_profiles_include_localai() {
    [ -z "$1" ] && return 0
    case ",$1," in
        *,localai,*) return 0 ;;
    esac
    return 1
}

# Installs the pinned LocalAI binary and writes the start script. Inside a container
# (papaia-manager) or on a host other than an Apple Silicon Mac with Docker Desktop it
# warns and skips; a failed download or checksum warns and the rest of the stack starts.
_localai_native_install() {
    local line out rc=0
    LOCALAI_NATIVE="off"
    LOCALAI_NATIVE_RESTART="0"
    out="$(py_cli localai-native-install)" || rc=$?
    if [ "$rc" -ne 0 ]; then
        LOCALAI_NATIVE="failed"
        warn "The native LocalAI was not installed (see above). Fix the cause and run 'papaia-ctl start' again."
        return 0
    fi
    while IFS= read -r line; do
        line="${line%$'\r'}"
        case "$line" in
            LOCALAI_NATIVE=*) LOCALAI_NATIVE="${line#*=}" ;;
            LOCALAI_NATIVE_VERSION=*) LOCALAI_NATIVE_VERSION="${line#*=}" ;;
            LOCALAI_NATIVE_REPLACED=*) LOCALAI_NATIVE_REPLACED="${line#*=}" ;;
            LOCALAI_NATIVE_RESTART=*) LOCALAI_NATIVE_RESTART="${line#*=}" ;;
        esac
    done <<< "$out"
}

# After `up`: load the launchd job (or restart it for a new binary) and wait for /readyz.
# Nothing when the install step was off, skipped or failed; a launchctl error warns and
# the rest of `start` goes on.
_localai_native_start() {
    case "$LOCALAI_NATIVE" in
        installed|unchanged) : ;;
        *) return 0 ;;
    esac
    if [ -n "$LOCALAI_NATIVE_REPLACED" ]; then
        info "LocalAI $LOCALAI_NATIVE_VERSION replaces $LOCALAI_NATIVE_REPLACED."
    fi
    local -a flags=()
    [ "$LOCALAI_NATIVE_RESTART" = "1" ] && flags+=(--restart)
    if ! py_cli localai-native-start ${flags[@]+"${flags[@]}"}; then
        warn "The native LocalAI did not start (see above). Fix the cause and run 'papaia-ctl start' again."
    fi
    return 0
}

# Before the Compose part of `stop`: unload and disable the launchd job, so LocalAI stays
# off after a login. $1 = profile list, $2 = 1 to delete the models and backends as well.
# Python decides whether there is a job; off a Mac and in a container it warns and skips.
_localai_native_stop() {
    local profiles="$1" purge="$2"
    _profiles_include_localai "$profiles" || return 0
    local -a flags=()
    [ "$purge" -eq 1 ] && flags+=(--purge-models)
    if ! py_cli localai-native-stop ${flags[@]+"${flags[@]}"}; then
        warn "The native LocalAI was not stopped (see above). Check it with 'papaia-ctl doctor'."
    fi
    return 0
}

# The two provisioning steps `start` runs after `docker compose up`, as commands of their
# own so an operator can retry one when `start` reports it failed. `start` calls py_cli
# directly with the CONFIG_DIR it parsed; standalone, the command has to parse
# --config-dir itself like every other command, or py_cli expands an unset CONFIG_DIR.
cmd_npm_provision() { _provisioning_step npm-provision "$@"; }

cmd_keycloak_role_sync() { _provisioning_step keycloak-role-sync "$@"; }

# `realm sync` also runs at the end of every keycloak-role-sync step; on its own it takes
# --check, which compares the realm with the declarations and changes nothing.
cmd_realm_sync() {
    local config_dir="$DEFAULT_CONFIG_DIR" check=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --check) check=1 ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for realm sync: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local mode
    mode="$(_topology_mode)" || exit 3
    if [ "$mode" = "distributed" ]; then
        error "In a distributed installation the realm sync runs on Keycloak's node: run 'papaia-ctl keycloak-role-sync'."
        exit 2
    fi
    py_cli join-stack-network || true
    local -a flags=()
    [ "$check" -eq 1 ] && flags+=(--check)
    py_cli realm-sync ${flags[@]+"${flags[@]}"}
}

# papaia-ctl service-account list [--json] | rotate <id> [--grace=SECONDS]
# The declared service accounts; created and kept by the realm sync, so this runs where
# the realm sync runs (Keycloak's node).
cmd_service_account() {
    local sub="${1:-}" config_dir="$DEFAULT_CONFIG_DIR" json=0 account="" grace=""
    shift || true
    case "$sub" in
        list|rotate) ;;
        *) error "Unknown 'service-account' subcommand: '${sub:-<none>}'. Valid: list, rotate."; exit 2 ;;
    esac
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            --json)
                if [ "$sub" != "list" ]; then
                    error "Unknown option for service-account $sub: $1"; exit 2
                fi
                json=1 ;;
            --grace=*)
                if [ "$sub" != "rotate" ]; then
                    error "Unknown option for service-account $sub: $1"; exit 2
                fi
                grace="${1#*=}"
                if ! [[ "$grace" =~ ^[0-9]{1,2}$ ]] || [ "$grace" -gt 60 ]; then
                    error "--grace must be 0 to 60 (seconds)"; exit 2
                fi ;;
            -*) error "Unknown option for service-account $sub: $1"; exit 2 ;;
            *)
                if [ "$sub" = "rotate" ] && [ -z "$account" ]; then
                    account="$1"
                else
                    error "Unknown argument for service-account $sub: $1"; exit 2
                fi ;;
        esac
        shift
    done
    if [ "$sub" = "rotate" ] && [ -z "$account" ]; then
        error "service-account rotate needs an account: papaia-ctl service-account rotate <id>"
        exit 2
    fi
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local mode
    mode="$(_topology_mode)" || exit 3
    if [ "$mode" = "distributed" ]; then
        error "'service-account' is not available in a distributed installation yet; the realm sync on Keycloak's node keeps the accounts."
        exit 2
    fi
    py_cli join-stack-network || true
    if [ "$sub" = "list" ]; then
        local -a flags=()
        [ "$json" -eq 1 ] && flags+=(--json)
        py_cli service-account-list ${flags[@]+"${flags[@]}"}
    else
        local -a flags=(--id "$account")
        [ -n "$grace" ] && flags+=(--grace "$grace")
        py_cli service-account-rotate ${flags[@]+"${flags[@]}"}
    fi
}

# --node belongs to a distributed installation; on one host it is a mistake worth naming.
_require_no_node() {
    if [ -n "$1" ]; then
        error "--node is for a distributed installation; this one runs on one host."
        exit 2
    fi
}

# start in a distributed installation: the same gate and render as on one host, then the
# nodes in order (lib/cluster.py). $1 node, $2 profiles, $3 1 for --addons, $4 1 for --force,
# $5 1 for --insecure-images
_start_distributed() {
    local node="$1" profiles="$2" addons="$3" force="$4" insecure_images="${5:-0}"
    _cluster_require_unlocked
    local -a check_flags=()
    [ "$force" -eq 1 ] && check_flags+=(--force)
    if ! py_cli addon-check ${check_flags[@]+"${check_flags[@]}"}; then
        error "Addon compatibility check failed. See 'papaia-ctl addon check', or re-run with --force to override."
        exit 2
    fi
    py_cli sync-env
    info "Rendering the configuration and the node bundles..."
    py_cli render
    # Every pin of the tree (the nodes start their own services) and the active add-ons,
    # each add-on with its own list.
    local verified=0
    ADDON_IMAGE_FLAGS=() ADDON_IMAGE_FILES=()
    [ "$addons" -eq 1 ] && _addon_image_flags
    ( _verify_images start "$REPO_ROOT" "" 1 "$insecure_images" \
        ${ADDON_IMAGE_FLAGS[@]+"${ADDON_IMAGE_FLAGS[@]}"} ) || verified=$?
    _addon_image_files_remove
    [ "$verified" -eq 0 ] || return 2
    local -a extra=()
    [ -n "$node" ] && extra+=(--node="$node")
    [ -n "$profiles" ] && extra+=(--profiles="$profiles")
    [ "$addons" -eq 1 ] && extra+=(--addons)
    py_cli cluster-start ${extra[@]+"${extra[@]}"} || exit $?
    success "start complete."
}

# $1 node, $2 profiles, $3 1 for --addons, $4 1 for --clean-up
_stop_distributed() {
    local node="$1" profiles="$2" addons="$3" clean_up="$4"
    local -a extra=()
    [ -n "$node" ] && extra+=(--node="$node")
    [ -n "$profiles" ] && extra+=(--profiles="$profiles")
    [ "$clean_up" -eq 1 ] && extra+=(--clean-up)
    [ "$addons" -eq 1 ] && extra+=(--addons)
    py_cli cluster-stop ${extra[@]+"${extra[@]}"} || exit $?
    success "stop complete."
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
    py_cli join-stack-network || true
    local mode
    mode="$(_topology_mode)" || exit 3
    if [ "$mode" = "distributed" ]; then
        # The step runs where its service runs: the proxy's node, Keycloak's node.
        local service="nginx" owner
        [ "$step" = "keycloak-role-sync" ] && service="keycloak"
        owner="$(py_cli topology-node-of --service="$service")"
        owner="${owner%$'\r'}"
        if [ -z "$owner" ]; then
            # As on one host: nothing to provision for a service the installation does not
            # run (an external proxy, an external identity provider).
            info "$step skipped: this installation does not run $service."
            return 0
        fi
        py_cli node-exec --name="$owner" hook "$step"
        return
    fi
    # The step's own exit status is the command's, so a retry that fails is visible.
    py_cli "$step"
}

# The profiles of the optional modules. `stop --volumes` deletes data, so it is limited to
# these: the always-on services (Keycloak, LibreChat, LiteLLM ...) and the manager keep theirs.
# The same set as the profiles of lib/modules.py's MODULES (tests/test_stop_volumes.py).
_VOLUME_DELETE_PROFILES="localai librechat-websearch rag smtp voice knowledge-map"

_require_deletable_profiles() {
    local profiles="$1" profile allowed
    local -a names
    IFS=',' read -r -a names <<< "$profiles"
    for profile in ${names[@]+"${names[@]}"}; do
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

    local purge_native=0
    [ "$clean_up" -eq 1 ] && [ "$volumes" -eq 1 ] && purge_native=1
    _localai_native_stop "$profiles" "$purge_native"

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
        warn "  --clean-up: all named volumes will also be removed, and the models of a"
        warn "  native LocalAI."
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

    # While $CONFIG_DIR still says where the native LocalAI lives.
    if [ -f "$CONFIG_DIR/.env" ]; then
        local -a native_flags=()
        [ "$clean_up" -eq 1 ] && native_flags+=(--purge)
        if ! py_cli localai-native-uninstall ${native_flags[@]+"${native_flags[@]}"}; then
            warn "The native LocalAI was not removed completely (see above)."
        fi
    fi

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
        if ! _remove_config_dir "$CONFIG_DIR"; then
            exit 1
        fi
    fi
    success "uninstall complete."
}

# Deletes the configuration directory. Containers write some of their bind-mounted data as
# root (Nginx Proxy Manager's `infra/nginx/nginx-data/`, for one), which a non-root
# operator cannot delete. What is left after the first attempt is deleted the way it was
# written: by a short-lived container that mounts the directory. If that is not possible
# either, the leftover path and the command that removes it are named.
_remove_config_dir() {
    local dir="$1" physical
    rm -rf "$dir" 2>/dev/null || true
    [ -e "$dir" ] || return 0

    physical="$(_physical_path "$dir")" || physical=""
    case "$physical" in
        "")
            error "Could not delete $dir completely; refusing to clean it up through a container."
            error "Remove it by hand: sudo rm -rf '$dir'"
            return 1
            ;;
        /)
            error "$dir is the root directory; refusing to delete what is left in it."
            return 1
            ;;
    esac
    if _contains_path "$physical" "${HOME:-}"; then
        error "$dir is or contains the home directory; refusing to delete what is left in it."
        return 1
    fi
    if _contains_path "$physical" "${REPO_ROOT:-}"; then
        error "$dir is or contains the papaia checkout; refusing to delete what is left in it."
        return 1
    fi

    info "Some files in $dir belong to root (written by containers); deleting them through a container..."
    if command -v docker >/dev/null 2>&1 \
        && _docker_run --network none -v "$(_docker_hostpath "$physical"):/target" \
            "$BACKUP_IMAGE" find /target -mindepth 1 -delete; then
        rm -rf "$dir" 2>/dev/null || true
    fi
    if [ -e "$dir" ]; then
        error "Could not delete $dir completely."
        error "Remove what is left with: sudo rm -rf '$dir'"
        return 1
    fi
    return 0
}

# True when the physical path of $2 is $1 (a path from _physical_path) or lies below it.
# An empty or unresolvable $2 contains nothing.
_contains_path() {
    local outer="$1" inner
    [ -n "$2" ] || return 1
    inner="$(_physical_path "$2")" || return 1
    [ "$inner" = "$outer" ] && return 0
    case "$inner" in "$outer"/*) return 0 ;; esac
    return 1
}

# Prints the physical path of directory $1. `pwd -P` keeps a leading `//` (POSIX leaves
# its meaning to the system), while Linux and Docker read it as `/`: without collapsing
# it, `//` or `//home` would slip past the guards above and still be mounted as `/` or
# `/home`.
_physical_path() {
    local path
    path="$(cd "$1" 2>/dev/null && pwd -P)" || return 1
    while [ "${path#//}" != "$path" ]; do
        path="${path#/}"
    done
    printf '%s' "$path"
}

_require_setup_done() {
    if [ ! -f "$CONFIG_DIR/.env" ] || [ ! -f "$CONFIG_DIR/deployment.yaml" ]; then
        error "No setup found at $CONFIG_DIR. Run 'papaia-ctl setup' first."
        exit 2
    fi
}
