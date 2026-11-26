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
# --test-trust-anchor=FILE of this one command (lib/sh/trust.sh sets it from the command
# line); never taken from the environment.
TEST_TRUST_ANCHOR=""

# Refuse to go on unless every image the installation is about to run is listed with its
# digest in the signed bill of materials of the core tree $2 and signed with its key
# (lib/images.py). The images it does not run (other profiles, the link gateway on one
# host) are not checked; a later command that runs them checks them then.
# $1 = command (start, upgrade, addon-start, ...), $2 = core tree,
# $3 = core image list file (what Compose lists for `up`) or empty,
# $4 = what else of the tree $2: 0 nothing, 1 every image the tree pins (all profiles and
# variants: a distributed installation, whose services start on other nodes), installed
# the images this installation runs from the tree (its profiles and variants: the target
# of an upgrade on one host, whose env files do not exist yet, so Compose cannot list them),
# $5 = 1 for --insecure-images (this command only, never stored), rest = extra flags,
# among them one --addon-images=NAME=FILE per add-on (see _addon_image_flags)
_verify_images() {
    local command="$1" root="$2" list="$3" tree="$4" insecure="$5"
    shift 5
    local -a flags=(--command="$command" "$@")
    [ "$insecure" -eq 1 ] && flags+=(--insecure-images)
    [ -n "$list" ] && flags+=(--images-file="$list")
    case "$tree" in
        1) flags+=(--from-checkout) ;;
        installed) flags+=(--as-installed) ;;
    esac
    [ -n "$IMAGES_ANCHOR" ] && flags+=(--anchor-fingerprint="$IMAGES_ANCHOR")
    [ -n "${TEST_TRUST_ANCHOR:-}" ] && flags+=(--test-trust-anchor="${TEST_TRUST_ANCHOR:-}")
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
# ($2, or the env file's COMPOSE_PROFILES when empty) of the core project the arguments
# that follow describe (CORE_COMPOSE_ARGS), exactly as `up` gets them.
_core_image_list() {
    local out="$1" profiles="$2"
    shift 2
    if ! (
        if [ -n "$profiles" ]; then export COMPOSE_PROFILES="$profiles"; fi
        docker compose "$@" config --images
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

# The arguments of a core Compose call as `start` passes them, in CORE_COMPOSE_ARGS: the
# compose file, the core overrides of _core_override_files and the env file, whose
# COMPOSE_PROFILES are the installation's profiles. A call that starts or lists a subset of
# the services of a running stack takes the same arguments: given fewer files, Compose sees
# another definition of a core network (with PAPAIA_SUBNET_POOL, the address block of the
# subnet-pool override is missing) and recreates it under the services still using it.
# $1 = 1 when the add-ons start in the same command, so their networks count as present.
CORE_COMPOSE_ARGS=()
_core_compose_args() {
    local with_addons="${1:-0}" override_file
    CORE_COMPOSE_ARGS=(-f "$COMPOSE_FILE")
    while IFS= read -r override_file; do
        [ -n "$override_file" ] && CORE_COMPOSE_ARGS+=(-f "$override_file")
    done < <(_core_override_files "$with_addons")
    CORE_COMPOSE_ARGS+=(--env-file "$REPO_ROOT/src/.env")
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
    info "A restore left post-restore pending; running it before any module starts..."
    # The core project as `start` describes it, so nothing that keeps running (a scoped
    # restore) is recreated. No add-on has started yet: an override that declares an add-on
    # network waits until that network exists, as in `start`.
    _core_compose_args 0
    local -a compose_args=(${CORE_COMPOSE_ARGS[@]+"${CORE_COMPOSE_ARGS[@]}"})
    # Without the keycloak profile (external_oidc) there is nothing to start: the step
    # reports that the delegations live at the external provider.
    # Captured first: under pipefail an early `grep -q` could fail the pipeline.
    local services=""
    services="$(docker compose ${compose_args[@]+"${compose_args[@]}"} \
        config --services 2>/dev/null)" || services=""
    if grep -qx keycloak <<< "$services"; then
        local list verified=0 up_rc=0
        list="$(mktemp)"
        ( _core_image_list "$list" keycloak ${compose_args[@]+"${compose_args[@]}"} \
            && _verify_images restore "$REPO_ROOT" "$list" 0 "$insecure" ) || verified=$?
        rm -f "$list"
        if [ "$verified" -eq 0 ]; then
            info "Starting Keycloak alone..."
            docker compose ${compose_args[@]+"${compose_args[@]}"} up -d --no-recreate keycloak || up_rc=$?
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
    local config_dir="$DEFAULT_CONFIG_DIR" addons="" profiles="" force=0 node="" unlock=0
    local insecure_images=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --insecure-images) insecure_images=1 ;;
            --addons) addons=1 ;;
            --no-addons) addons=0 ;;
            --profiles=*) profiles="${1#*=}" ;;
            --node=*) node="${1#*=}" ;;
            --unlock) unlock=1 ;;
            --force) force=1 ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for start: $1"; exit 2 ;;
        esac
        shift
    done
    # Without a switch `start` brings up the core and every module chosen with setup or
    # installed since (BE-03: no switch to count); a partial start of core profiles
    # (--profiles) leaves the add-ons alone unless --addons asks for them.
    if [ -z "$addons" ]; then
        addons=1
        [ -n "$profiles" ] && addons=0
    fi
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

    # With PAPAIA_SUBNET_POOL: no network of another stack in the pool and none of this
    # installation outside it, before the first container (docs/network.md).
    if ! py_cli subnet-pool-check; then
        error "The networks do not fit PAPAIA_SUBNET_POOL; nothing was started."
        exit 2
    fi

    # The certificates of the platform PKI, before anything starts: a service that needs
    # them must find them (docs/pki.md). Under the kritis profile this also refuses an
    # active add-on without a `pki:` request.
    if ! py_cli pki-issue; then
        error "The platform PKI could not issue the certificates; nothing was started."
        exit 2
    fi

    # The audit store (profile `audit`, always on) needs its certificates and passwords
    # before `up`; existing ones are kept.
    py_cli audit-prepare

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
    _core_compose_args "$addons"
    local -a compose_args=(${CORE_COMPOSE_ARGS[@]+"${CORE_COMPOSE_ARGS[@]}"})

    # Before the first container of the core or an add-on: every image this command
    # starts, core and active add-ons (each with its own list), in one check (digest
    # and signature). A refusal is returned, not an exit, so a caller such as the
    # second phase of an upgrade still reports it.
    local image_list
    image_list="$(mktemp)"
    _core_image_list "$image_list" "$profiles" ${compose_args[@]+"${compose_args[@]}"}
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
        COMPOSE_PROFILES="$profiles" docker compose ${compose_args[@]+"${compose_args[@]}"} up ${up_flags[@]+"${up_flags[@]}"}
    else
        docker compose ${compose_args[@]+"${compose_args[@]}"} up ${up_flags[@]+"${up_flags[@]}"}
    fi

    # After `up`, so LiteLLM is there when LocalAI answers. The init job need not have
    # finished: LocalAI reads a model's `<name>.yaml` on the first request for it.
    _localai_native_start

    # In a container (papaia-manager and its runners) the provisioning steps reach the stack
    # over its network, which `up` has just created; on the host this does nothing.
    py_cli join-stack-network || true

    # The steps after `up` (docs/adr/0033). One that creates clients, roles or rights fails
    # `start` when it fails: the stack stays up, every later step still runs, and the
    # command ends non-zero with the cause and the retry command instead of the success
    # line. The proxy hosts of npm-provision grant nothing; a failure there stays a warning.
    local -a failed_steps=()
    if ! py_cli npm-provision; then
        warn "NPM proxy-host provisioning failed. Once the stack is healthy, run 'papaia-ctl npm-provision' to retry."
    fi

    # The realm's clients, roles and rights; on the host without a published Keycloak
    # port it runs in the one-shot container whose image the check above covered.
    if ! py_cli keycloak-role-sync; then
        failed_steps+=("Keycloak role sync failed: the realm may lack the clients, roles and rights of the core and the modules. Once Keycloak is healthy, run 'papaia-ctl keycloak-role-sync' to retry.")
    fi

    # The database role papaia-replay reads the chat with.
    if ! py_cli replay-chat-sync; then
        failed_steps+=("The chat role of papaia-replay could not be set up. Once the chat database is healthy, run 'papaia-ctl start' again.")
    fi

    # The model keys of the modules, and the deletion of the revoked ones. Its outcome is
    # in the two variables below, not in errexit: it runs on the left of `||`.
    _model_keys_sync "$addons" || true
    if [ "$MODEL_KEYS_UNCHECKED" -ne 0 ]; then
        failed_steps+=("Not every module key of LiteLLM could be checked; a revoked key may still be valid. Once LiteLLM is healthy and the add-on manifests are fixed, run 'papaia-ctl start --addons' again.")
    fi
    if [ -n "$MODEL_KEYS_NOT_RESTARTED" ]; then
        failed_steps+=("Add-on(s) with a new model key not started again, still running with the old key:${MODEL_KEYS_NOT_RESTARTED}. Fix the cause above, then run 'papaia-ctl start --addons' again.")
    fi

    if [ "${#failed_steps[@]}" -gt 0 ]; then
        local step_error
        for step_error in ${failed_steps[@]+"${failed_steps[@]}"}; do
            error "$step_error"
        done
        error "start did not complete: the containers run, but the step(s) above failed."
        return 3
    fi
    success "start complete."
}

# The outcome of _model_keys_sync: 1 when not every key could be checked, and the add-ons
# with a new key that were not started again (each name after a space).
MODEL_KEYS_UNCHECKED=0
MODEL_KEYS_NOT_RESTARTED=""

# After `up`: every module that declares model needs holds its own LiteLLM key, and keys
# revoked while LiteLLM was down are deleted (docs/model-gateway.md). An add-on whose key
# changed is materialised and started again, so its containers see the key. The add-ons
# whose key did change are started again even when another key could not be checked, and
# one that fails does not stop the next. Every failure is checked explicitly and recorded
# in the two variables above, since a caller may run this where errexit is off; then the
# function returns 1 and `start` fails at its end (docs/adr/0033).
# $1 = 1 when the add-ons are part of this start
_model_keys_sync() {
    local addons="$1" out="" changed="" line addon_name addon_path
    MODEL_KEYS_UNCHECKED=0
    MODEL_KEYS_NOT_RESTARTED=""
    out="$(py_cli model-keys-sync)" || MODEL_KEYS_UNCHECKED=1
    while IFS= read -r line; do
        case "$line" in
            MODEL_KEY_CHANGED=*) changed+="${line#MODEL_KEY_CHANGED=}"$'\n' ;;
        esac
    done <<< "$out"
    if [ -n "$changed" ] && [ "$addons" -ne 1 ]; then
        warn "New model keys for: $(printf '%s' "$changed" | tr '\n' ' ')- run"
        warn "'papaia-ctl start --addons' so these add-ons see them."
    elif [ -n "$changed" ]; then
        while IFS= read -r addon_name; do
            [ -n "$addon_name" ] || continue
            info "  addon $addon_name: new model key, starting it again"
            if py_cli addon-start --name="$addon_name" --no-keycloak \
                    && addon_path="$(_addon_path "$addon_name")" \
                    && _addon_compose_up "$addon_name" "$addon_path"; then
                continue
            fi
            error "Add-on $addon_name was not started again with its new model key."
            MODEL_KEYS_NOT_RESTARTED+=" $addon_name"
        done <<< "$changed"
    fi
    [ "$MODEL_KEYS_UNCHECKED" -eq 0 ] && [ -z "$MODEL_KEYS_NOT_RESTARTED" ]
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

# papaia-ctl proxy list [--json]: host name -> internal target of every web interface of
# the core and the active add-ons (lib/ingress.py), the forwards an external proxy needs.
cmd_proxy() {
    local sub="${1:-}" config_dir="$DEFAULT_CONFIG_DIR" json=0
    shift || true
    case "$sub" in
        list) ;;
        *) error "Unknown 'proxy' subcommand: '${sub:-<none>}'. Valid: list."; exit 2 ;;
    esac
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --json) json=1 ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for proxy list: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local -a flags=()
    [ "$json" -eq 1 ] && flags+=(--json)
    py_cli proxy-list ${flags[@]+"${flags[@]}"}
}

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

# papaia-ctl realm keys apply <module>: register the public keys the module wrote to the
# files it declares in client_keys[], without a full realm sync (a key rotation).
cmd_realm_keys() {
    local sub="${1:-}" config_dir="$DEFAULT_CONFIG_DIR" module=""
    shift || true
    if [ "$sub" != "apply" ]; then
        error "Unknown 'realm keys' subcommand: '${sub:-<none>}'. Valid: apply."; exit 2
    fi
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            -*) error "Unknown option for realm keys apply: $1"; exit 2 ;;
            *)
                if [ -z "$module" ]; then
                    module="$1"
                else
                    error "Unknown argument for realm keys apply: $1"; exit 2
                fi ;;
        esac
        shift
    done
    if [ -z "$module" ]; then
        error "realm keys apply needs a module: papaia-ctl realm keys apply <module>"; exit 2
    fi
    if ! [[ "$module" =~ ^[a-z][a-z0-9-]{0,63}$ ]]; then
        error "'$module' is not a module name"; exit 2
    fi
    CONFIG_DIR="$config_dir"
    _require_setup_done
    local mode
    mode="$(_topology_mode)" || exit 3
    if [ "$mode" = "distributed" ]; then
        error "In a distributed installation the realm sync runs on Keycloak's node: run 'papaia-ctl keycloak-role-sync'."
        exit 2
    fi
    py_cli join-stack-network || true
    py_cli realm-keys-apply --module "$module"
}

# papaia-ctl catalog render: platform/services.json from the exposes declarations of the
# installed add-ons and the active core profiles. setup, start and every addon command
# render it as well; this renders it alone, without touching anything else.
cmd_catalog_render() {
    local config_dir="$DEFAULT_CONFIG_DIR"
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for catalog render: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    py_cli catalog-render
}

# papaia-ctl privacy-pack: the data protection package. Without --installation it writes
# (or with --check compares) docs/de/datenschutz/ of this checkout and needs no setup;
# with --installation it writes the package of the installation in --config-dir.
cmd_privacy_pack() {
    local config_dir="$DEFAULT_CONFIG_DIR" installation=0
    local -a flags=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            --installation) installation=1; flags+=("$1") ;;
            --check|--lang=*|--out=*|--format=*|--backup-retention=*|--offsite=*|--offsite-retention=*)
                flags+=("$1") ;;
            *) error "Unknown option for privacy-pack: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    [ "$installation" -eq 1 ] && _require_setup_done
    py_cli privacy-pack ${flags[@]+"${flags[@]}"}
}

# papaia-ctl person find|export|erase|status|run|handover|sweep: information and erasure
# for a person whose account is gone (lib/person_request.py, lib/person.py). export and
# erase only file a request; it runs (`person run`) once a second person confirmed it in
# the manager. Every module call is one audit row.
cmd_person() {
    local sub="${1:-}" config_dir="$DEFAULT_CONFIG_DIR"
    shift || true
    case "$sub" in
        find|export|erase|status|run|handover|sweep) ;;
        *)
            error "Unknown 'person' subcommand: '${sub:-<none>}'. Valid: find, export, erase, status, run, handover, sweep."
            exit 2 ;;
    esac
    local -a flags=() ids=()
    local now=0 requested=0 confirmed=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            -h|--help) usage; exit 0 ;;
            --name=*|--email=*)
                [ "$sub" = "find" ] || { error "Unknown option for person $sub: $1"; exit 2; }
                flags+=("$1") ;;
            --sub=*)
                case "$sub" in export|erase) ;; *) error "Unknown option for person $sub: $1"; exit 2 ;; esac
                flags+=("$1") ;;
            --requested-by=*|--confirmed-by=*)
                case "$sub" in export|erase) ;; *) error "Unknown option for person $sub: $1"; exit 2 ;; esac
                case "$1" in --requested-by=*) requested=1 ;; *) confirmed=1 ;; esac
                flags+=("$1") ;;
            --transfer-to=*)
                [ "$sub" = "erase" ] || { error "Unknown option for person $sub: $1"; exit 2; }
                flags+=("$1") ;;
            --now)
                [ "$sub" = "erase" ] || { error "Unknown option for person $sub: $1"; exit 2; }
                now=1 ;;
            -*) error "Unknown option for person $sub: $1"; exit 2 ;;
            *)
                case "$sub" in status|run|handover) ids+=("$1") ;;
                    *) error "Unknown argument for person $sub: $1"; exit 2 ;; esac ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"
    _require_setup_done
    case "$sub" in
        find) py_cli person-find ${flags[@]+"${flags[@]}"} ;;
        sweep) py_cli person-sweep ;;
        export|erase)
            if [ "$requested" -eq 0 ] || [ "$confirmed" -eq 0 ]; then
                error "person $sub needs --requested-by=SUB and --confirmed-by=SUB: a second person confirms the request in the manager."
                exit 2
            fi
            if [ "$sub" = "erase" ] && [ "$now" -eq 0 ]; then
                error "person erase deletes the person's data in every module; pass --now."
                exit 2
            fi
            py_cli person-request --operation="$sub" ${flags[@]+"${flags[@]}"} ;;
        status|run|handover)
            if [ "${#ids[@]}" -ne 1 ]; then
                error "person $sub needs the request id that person export|erase printed."
                exit 2
            fi
            case "$sub" in
                status) py_cli person-status --request="${ids[0]}" ;;
                handover) py_cli person-handover --request="${ids[0]}" ;;
                run) _person_run "${ids[0]}" ;;
            esac ;;
    esac
}

# The run of a confirmed request (lib/person.py): py_cli plans the module steps and
# checks every answer, this loop runs each step as `docker compose run --rm -T` of the
# declared service in the add-on's own project, standard input closed, its answer into the
# run folder. The run folder is private to this account (mktemp -d, mode 0700) and is
# removed when the command ends.
_person_run() {
    local request="$1"
    local work
    work="$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/papaia-person.XXXXXX")"
    # shellcheck disable=SC2064  # the folder is fixed now, on purpose
    trap "rm -rf '$work'" EXIT
    py_cli person-begin --work="$work" --request="$request" || exit 2
    local line rc=0 status addon_name addon_path
    local -a code=() parts=()
    while :; do
        line="$(py_cli person-next --work="$work" ${code[@]+"${code[@]}"})" || exit 2
        [ -n "$line" ] || break
        IFS=$'\t' read -r -a parts <<< "$line"
        addon_name="${parts[0]}"
        addon_path="$(_addon_path "$addon_name")" || exit 2
        info "  addon $addon_name: ${parts[$((${#parts[@]} - 1))]}"
        status=0
        (umask 077 && _addon_compose run "$addon_name" "$addon_path" --rm -T \
            "${parts[@]:1}" < /dev/null > "$work/step.out") || status=$?
        code=(--exit-code="$status")
    done
    py_cli person-finish --work="$work" || rc=$?
    exit "$rc"
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
    py_cli audit-prepare
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
_VOLUME_DELETE_PROFILES="localai librechat-websearch rag smtp voice knowledge-map connections"

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
        # The catalog keeps the add-ons, marked stopped; a catalog that cannot be
        # rendered does not undo the stop.
        py_cli addon-state --all --state=stopped || warn "The platform catalog was not updated."
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
