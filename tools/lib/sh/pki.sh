# shellcheck shell=bash
# papaia-ctl — the internal certificate authority of the `pki` profile (docs/pki.md).
# Sourced by tools/papaia-ctl; not executable on its own.
# The hooks in setup.sh, lifecycle.sh and addon.sh call into this file only when it is
# loaded (`declare -F`), so those files still work when sourced on their own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint
#
# Python (lib/pki.py) reads the requests and keeps the settings; the one-shot pki-issuer
# container (src/infra/pki/) holds the CA key and writes the certificates. Here the two
# are put together, and whatever the issuer changed is restarted.

# The answer of `setup --pki` / `--no-pki` or of the wizard; empty keeps the stored choice.
SETUP_PKI=""

PKI_COMPOSE_FILE="$REPO_ROOT/src/infra/pki/docker-compose.yml"

# Loads PKI_ENABLED, PKI_DIR, PKI_MODE, PKI_LEAF_DAYS, PKI_PROJECT, PKI_CA_NAME and
# PKI_INSIDE_CONFIG. Returns non-zero when the stored settings are unusable.
_pki_load_state() {
    local out
    out="$(py_cli pki-state)" || return 3
    local line
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [ -n "$line" ] && printf -v "${line%%=*}" '%s' "${line#*=}"
    done <<< "$out"
    return 0
}

# Runs the issuer: $1 its command, rest = extra `docker compose run` arguments.
# Its stdout (the `changed`/`service` lines) goes to stdout.
_pki_issuer() {
    local command="$1"; shift
    local host_dir
    host_dir="$(_docker_hostpath "$PKI_DIR")"
    COMPOSE_IGNORE_ORPHANS=1 MSYS_NO_PATHCONV=1 docker compose -p "$PKI_PROJECT" \
        -f "$PKI_COMPOSE_FILE" run --rm -T --quiet-pull \
        -v "$host_dir:/pki" \
        -e PKI_MODE="$PKI_MODE" -e PKI_LEAF_DAYS="$PKI_LEAF_DAYS" \
        -e PKI_CA_NAME="$PKI_CA_NAME" -e PKI_HOST_DIR="$PKI_DIR" \
        "$@" pki-issuer "$command" \
        2> >(grep -v -E '^ *(Container|Volume|Network) ' >&2)
}

# Restarts what the issuer output in file $1 names: running services of the core, running
# add-ons. A stopped one reads the new files when it starts.
_pki_restart_changed() {
    local output="$1" kind module service
    local -a core_services=()
    local -a addons=()
    while read -r kind module service; do
        case "$kind" in
            service)
                [ "$module" = core ] && core_services+=("$service")
                ;;
            changed)
                [ "$module" = core ] || addons+=("$module")
                ;;
        esac
    done < "$output"

    if [ "${#core_services[@]}" -gt 0 ]; then
        local env_file="$REPO_ROOT/src/.env" running name
        running="$(docker compose -f "$COMPOSE_FILE" --env-file "$env_file" ps --status running --services 2>/dev/null || true)"
        for name in ${core_services[@]+"${core_services[@]}"}; do
            if printf '%s\n' "$running" | grep -qx "$name"; then
                info "  restarting $name (new certificates)"
                docker compose -f "$COMPOSE_FILE" --env-file "$env_file" restart "$name" >/dev/null
            fi
        done
    fi

    if [ "${#addons[@]}" -gt 0 ]; then
        local active addon addon_path
        active="$(py_cli active-addons 2>/dev/null || true)"
        for addon in ${addons[@]+"${addons[@]}"}; do
            printf '%s\n' "$active" | tr -d '\r' | grep -qx "$addon" || continue
            addon_path="$(_addon_path "$addon")"
            if _addon_running "$addon" "$addon_path"; then
                info "  restarting add-on $addon (new certificates)"
                _addon_compose restart "$addon" "$addon_path" >/dev/null \
                    || warn "  could not restart add-on $addon"
            fi
        done
    fi
}

# Issues what is requested and missing, renews what is due, removes what is no longer
# requested, and restarts what changed. Does nothing while the profile is off.
# $1 = the issuer command (sync, stage-ca, promote-ca), rest = extra `docker compose run` args.
_pki_run() {
    local command="${1:-sync}"; shift || true
    local plan
    plan="$(py_cli pki-plan)" || return 3
    case "$plan" in
        *PKI_ENABLED=true*) : ;;
        *) return 0 ;;
    esac
    _pki_load_state || return 3
    if ! docker info >/dev/null 2>&1; then
        warn "Docker does not answer: the internal certificates are issued on the next 'papaia-ctl start'."
        return 0
    fi
    local output status=0
    output="$(mktemp)"
    _pki_issuer "$command" "$@" > "$output" || status=$?
    if [ "$status" -ne 0 ]; then
        rm -f "$output"
        error "The internal CA could not issue the certificates (see above)."
        return 3
    fi
    if grep -q '^changed ' "$output"; then
        info "Internal certificates changed for: $(sed -n 's/^changed //p' "$output" | paste -sd ' ' -)"
        _pki_restart_changed "$output"
    fi
    rm -f "$output"
    return 0
}

_pki_sync() { _pki_run sync; }

# Called by `setup` once its configuration is written: stores the choice and, with the
# profile on, issues the certificates right away when Docker answers.
_pki_setup() {
    local want="$SETUP_PKI"
    SETUP_PKI=""
    local -a flags=()
    [ -n "$want" ] && flags+=(--enable="$want")
    local out
    out="$(py_cli pki-configure ${flags[@]+"${flags[@]}"})" || return 3
    case "$out" in
        *PKI_ENABLED=true*)
            _pki_load_state || return 3
            info "Internal CA (pki) is on; certificates go to $PKI_DIR."
            _pki_sync || return 3
            ;;
        *)
            [ "$want" = "false" ] && info "Internal CA (pki) is off; 'papaia-ctl pki purge' deletes its files."
            ;;
    esac
    return 0
}

# The wizard question. Off for a fresh install; a previous opt-in stays the default.
_prompt_pki() {
    _pki_load_state >/dev/null 2>&1 || PKI_ENABLED="false"
    local default="2" choice yes_note="" no_note=" (default)"
    if [ "${PKI_ENABLED:-false}" = "true" ]; then
        default="1" yes_note=" (current)" no_note=""
    fi
    printf '\n%sInternal TLS between services%s\n' "$CYAN" "$NC" >&2
    printf '  1) Yes  — run an internal CA that issues certificates to the services and add-ons that ask for them%s\n' "$yes_note" >&2
    printf '  2) No   — services talk to each other as before%s\n' "$no_note" >&2
    choice="$(prompt_with_default "  Choose" "$default")"
    case "$choice" in
        1|yes) printf 'true' ;;
        2|no)  printf 'false' ;;
        *)
            warn "Unrecognized choice '$choice'; keeping the internal CA off."
            printf 'false'
            ;;
    esac
}

# One line for the summary of a bare `setup` re-run.
_pki_summary() {
    _pki_load_state >/dev/null 2>&1 || return 0
    if [ "${PKI_ENABLED:-false}" = "true" ]; then
        info "  Internal CA (pki) = enabled ($PKI_DIR)"
    fi
    return 0
}

# Before `uninstall` deletes the config dir: the service directories belong to other users
# and only the issuer can delete them. With --clean-up the CA volume goes as well.
_pki_uninstall() {
    local clean_up="$1"
    _pki_load_state >/dev/null 2>&1 || return 0
    docker info >/dev/null 2>&1 || return 0
    if [ "${PKI_INSIDE_CONFIG:-false}" = "true" ] && [ -d "$PKI_DIR" ]; then
        info "Deleting the internal certificates in $PKI_DIR..."
        _pki_issuer purge >/dev/null || warn "Could not delete $PKI_DIR through the issuer."
    fi
    if [ "$clean_up" -eq 1 ]; then
        docker volume rm "${PKI_PROJECT}_pki-ca" >/dev/null 2>&1 || true
    fi
    return 0
}

cmd_pki() {
    local sub="${1:-}"; shift || true
    local config_dir="$DEFAULT_CONFIG_DIR" json=0 force=0 ca=0 non_interactive=0
    local cert="" key="" chain=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --json) json=1 ;;
            --force) force=1 ;;
            --ca) ca=1 ;;
            --cert=*) cert="${1#*=}" ;;
            --key=*) key="${1#*=}" ;;
            --chain=*) chain="${1#*=}" ;;
            -y|--yes) non_interactive=1 ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for pki $sub: $1"; exit 2 ;;
        esac
        shift
    done
    # shellcheck disable=SC2034  # read by py_cli and _require_setup_done
    CONFIG_DIR="$config_dir"
    _require_setup_done

    case "$sub" in
        status)
            local -a extra=()
            [ "$json" -eq 1 ] && extra+=(--json)
            py_cli pki-status ${extra[@]+"${extra[@]}"}
            ;;
        renew)
            _pki_require_on
            local -a extra=()
            [ "$force" -eq 1 ] && extra+=(-e PKI_FORCE=1)
            _pki_run sync ${extra[@]+"${extra[@]}"} || exit 3
            success "pki renew complete."
            ;;
        rotate-ca)
            _pki_require_on
            _pki_rotate_ca "$cert" "$key" "$chain"
            ;;
        purge)
            _pki_purge "$ca" "$non_interactive"
            ;;
        *)
            error "Unknown 'pki' subcommand: '${sub:-<none>}'. Valid: status, renew, rotate-ca, purge."
            exit 2
            ;;
    esac
}

_pki_require_on() {
    _pki_load_state || exit 3
    if [ "${PKI_ENABLED:-false}" != "true" ]; then
        error "The internal CA is off. 'papaia-ctl setup --pki' switches it on."
        exit 2
    fi
}

# A new CA in two steps, each followed by the restart of what changed: first every bundle
# trusts the old and the new CA, then every certificate is issued by the new one. With
# --cert/--key (and --chain up to the root) the new CA is an intermediate of the company PKI.
_pki_rotate_ca() {
    local cert="$1" key="$2" chain="$3"
    local -a extra=()
    local import=""
    if [ -n "$cert" ] || [ -n "$key" ] || [ -n "$chain" ]; then
        if [ -z "$cert" ] || [ -z "$key" ]; then
            error "--cert and --key go together (and --chain for an intermediate)."
            exit 2
        fi
        local f
        for f in "$cert" "$key" ${chain:+"$chain"}; do
            [ -f "$f" ] || { error "Not a file: $f"; exit 2; }
        done
        import="$(mktemp -d)"
        cp "$cert" "$import/ca.crt"
        (umask 077 && cp "$key" "$import/ca.key")
        [ -n "$chain" ] && cp "$chain" "$import/chain.crt"
        extra+=(-v "$(_docker_hostpath "$import"):/import:ro")
    fi
    local status=0
    info "Step 1: the new CA joins every bundle..."
    _pki_run stage-ca ${extra[@]+"${extra[@]}"} || status=$?
    [ -n "$import" ] && rm -rf "$import"
    [ "$status" -eq 0 ] || exit 3
    # A first CA (nothing issued before) is active at once; the issuer then has nothing to
    # promote and says so.
    info "Step 2: every certificate is issued by the new CA..."
    _pki_run promote-ca || exit 3
    success "pki rotate-ca complete. 'papaia-ctl pki status' lists the CAs in the bundle."
}

_pki_purge() {
    local ca="$1" non_interactive="$2"
    _pki_load_state || exit 3
    if [ "${PKI_ENABLED:-false}" = "true" ]; then
        error "The internal CA is still on; 'papaia-ctl setup --no-pki' switches it off first."
        exit 2
    fi
    warn "This deletes every file in $PKI_DIR."
    [ "$ca" -eq 1 ] && warn "  --ca: the CA key in the volume ${PKI_PROJECT}_pki-ca is deleted as well."
    if [ "$non_interactive" -eq 0 ] && is_tty; then
        confirm "Delete the internal certificates?" "N" || { error "Aborted."; exit 3; }
    fi
    if [ -d "$PKI_DIR" ]; then
        _pki_issuer purge >/dev/null || exit 3
        rmdir "$PKI_DIR" 2>/dev/null || true
    fi
    if [ "$ca" -eq 1 ]; then
        docker volume rm "${PKI_PROJECT}_pki-ca" >/dev/null 2>&1 || true
    fi
    success "pki purge complete."
}
