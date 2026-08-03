# shellcheck shell=bash
# papaia-ctl — `setup` command: wizard, sticky defaults, py_cli handoff.
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

# Reads a py_cli subcommand's KEY=VALUE output into the current shell's
# variables.
_load_kv() {
    local line key value
    while IFS= read -r line; do
        # Strip a trailing CR: on Windows the Python interpreter emits CRLF
        # line endings, which would otherwise leave every value ending in \r
        # (e.g. AUTH_PROVIDER=internal_keycloak\r fails validation downstream).
        line="${line%$'\r'}"
        [ -z "$line" ] && continue
        key="${line%%=*}"
        value="${line#*=}"
        printf -v "$key" '%s' "$value"
    done < <(py_cli "$@")
}

# Sticky/derived prompt defaults (APP_HOST_STICKY, AUTH_HOST_STICKY,
# AUTH_HOST_DERIVED, ...).
load_defaults() { _load_kv defaults; }

# LocalAI accelerator detection (LOCALAI_VARIANT_NVIDIA, ..._LABEL, ..._WARN,
# LOCALAI_VARIANT_RECOMMENDED). Loaded lazily: it forks nvidia-smi and docker,
# so it must not run on every setup invocation the way load_defaults does.
load_localai_variants() { _load_kv localai-variants; }

cmd_setup() {
    local orig_argc=$#
    local config_dir="$DEFAULT_CONFIG_DIR" env_name="papaia"
    local host_ip="" app_host="" auth_host="" librechat_host="" litellm_host="" localai_host="" manager_host="" npm_admin_host=""
    local auth_provider="" oidc_issuer=""
    local reverse_proxy_provider="" external_reverse_proxy="" allow_direct_port_access=0
    local web_search="" local_ai="" localai_variant="" manager="" reranker_model="" backup_dir=""
    local force=0 non_interactive=0 env_only=0

    while [ $# -gt 0 ]; do
        case "$1" in
            --config-dir=*) config_dir="${1#*=}" ;;
            --env=*) env_name="${1#*=}" ;;
            --host-ip=*) host_ip="${1#*=}" ;;
            --app-host=*) app_host="${1#*=}" ;;
            --auth-host=*) auth_host="${1#*=}" ;;
            --npm-admin-host=*) npm_admin_host="${1#*=}" ;;
            --librechat-host=*) librechat_host="${1#*=}" ;;
            --auth-provider=*)
                auth_provider="${1#*=}"
                case "$auth_provider" in
                    internal_keycloak|external_oidc) : ;;
                    *)
                        error "Invalid --auth-provider value: '$auth_provider' (must be 'internal_keycloak' or 'external_oidc')"
                        exit 2
                        ;;
                esac
                ;;
            --oidc-issuer=*) oidc_issuer="${1#*=}" ;;
            --reverse-proxy-provider=*)
                reverse_proxy_provider="${1#*=}"
                case "$reverse_proxy_provider" in
                    internal_nginx|external_proxy|no_proxy) : ;;
                    *)
                        error "Invalid --reverse-proxy-provider value: '$reverse_proxy_provider' (must be 'internal_nginx', 'external_proxy', or 'no_proxy')"
                        exit 2
                        ;;
                esac
                ;;
            --external-reverse-proxy) external_reverse_proxy="true" ;;
            --no-external-reverse-proxy) external_reverse_proxy="false" ;;
            --web-search) web_search="true" ;;
            --no-web-search) web_search="false" ;;
            --local-ai) local_ai="true" ;;
            --no-local-ai) local_ai="false" ;;
            --localai-host=*) localai_host="${1#*=}" ;;
            --localai-variant=*)
                localai_variant="${1#*=}"
                case "$localai_variant" in
                    cpu|nvidia-cuda-12|nvidia-cuda-13|intel|hipblas|vulkan|auto) : ;;
                    *)
                        error "Invalid --localai-variant value: '$localai_variant' (must be 'cpu', 'nvidia-cuda-12', 'nvidia-cuda-13', 'intel', 'hipblas', 'vulkan', or 'auto')"
                        exit 2
                        ;;
                esac
                ;;
            --litellm-host=*) litellm_host="${1#*=}" ;;
            --manager) manager="true" ;;
            --no-manager) manager="false" ;;
            --manager-host=*) manager_host="${1#*=}" ;;
            --reranker-model=*) reranker_model="${1#*=}" ;;
            --backup-dir=*) backup_dir="${1#*=}" ;;
            --allow-direct-port-access) allow_direct_port_access=1 ;;
            --force) force=1 ;;
            -y|--non-interactive) non_interactive=1 ;;
            --env-only) env_only=1 ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option for setup: $1"; exit 2 ;;
        esac
        shift
    done
    CONFIG_DIR="$config_dir"

    load_defaults

    # Resolved here rather than in Python so the CLI contract downstream only
    # ever carries a concrete variant, and so the probe stays opt-in.
    if [ "$localai_variant" = "auto" ]; then
        info "Detecting available GPU accelerators, this can take a few seconds..."
        load_localai_variants
        localai_variant="${LOCALAI_VARIANT_RECOMMENDED:-cpu}"
        info "Detected LocalAI image variant: $localai_variant"
    fi

    if [ "$env_only" -eq 1 ]; then
        info "Reusing existing configuration; re-rendering env files only."
        # Checked rather than left to `set -e`: `upgrade` calls this in a
        # condition context, where set -e is suppressed and an unchecked
        # failure would report "setup complete" over a broken render.
        if ! _run_setup_py "$env_name" "" "" "" "" "$host_ip" 0 "" "" "" "" "" "" "" "" "" "" "" "" "$backup_dir" ""; then
            error "setup failed."
            return 3
        fi
        if [ "${AUTH_PROVIDER_STICKY:-internal_keycloak}" = "internal_keycloak" ]; then
            _ensure_keycloak_certs
        fi
        success "setup complete (re-render only)."
        return 0
    fi

    # Bare re-run: zero args, interactive TTY, already seeded -> offer to
    # reuse everything as-is (just refresh the render) instead of
    # re-prompting for values that were already resolved on a prior run.
    if [ "$orig_argc" -eq 0 ] && [ "$CONFIG_SEEDED" = "true" ] && is_tty && [ "$non_interactive" -eq 0 ]; then
        info "Existing setup detected in $CONFIG_DIR"
        info "  Server URL        = $APP_HOST_STICKY"
        if [ "${AUTH_PROVIDER_STICKY:-internal_keycloak}" = "external_oidc" ]; then
            info "  Identity provider = external OIDC"
        else
            info "  Keycloak URL      = $AUTH_HOST_STICKY"
        fi
        if [ -n "${REVERSE_PROXY_PROVIDER_STICKY:-}" ]; then
            local _rp_label="Nginx Proxy Manager (bundled)"
            [ "$REVERSE_PROXY_PROVIDER_STICKY" = "external_proxy" ] && _rp_label="external proxy"
            [ "$REVERSE_PROXY_PROVIDER_STICKY" = "no_proxy" ] && _rp_label="no proxy (direct port access)"
            info "  Reverse proxy     = $_rp_label"
            [ "$REVERSE_PROXY_PROVIDER_STICKY" = "internal_nginx" ] && [ -n "${NPM_ADMIN_HOST_STICKY:-}" ] && \
                info "  NPM admin URL     = $NPM_ADMIN_HOST_STICKY"
        fi
        [ -n "${LIBRECHAT_HOST_STICKY:-}" ] && info "  LibreChat URL     = $LIBRECHAT_HOST_STICKY"
        if [ -n "${WEB_SEARCH_STICKY:-}" ]; then
            local _ws_label="disabled"
            [ "$WEB_SEARCH_STICKY" = "true" ] && _ws_label="enabled"
            info "  Web Search        = $_ws_label"
            [ "$WEB_SEARCH_STICKY" = "true" ] && [ -n "${RERANKER_MODEL_STICKY:-}" ] && \
                info "  Reranker Model    = $RERANKER_MODEL_STICKY"
        fi
        if [ -n "${LOCAL_AI_STICKY:-}" ]; then
            local _lai_label="disabled"
            [ "$LOCAL_AI_STICKY" = "true" ] && _lai_label="enabled"
            info "  Local AI          = $_lai_label"
            [ "$LOCAL_AI_STICKY" = "true" ] && [ -n "${LOCALAI_HOST_STICKY:-}" ] && \
                info "  LocalAI URL       = $LOCALAI_HOST_STICKY"
            [ "$LOCAL_AI_STICKY" = "true" ] && [ -n "${LOCALAI_VARIANT_STICKY:-}" ] && \
                info "  LocalAI Image     = $LOCALAI_VARIANT_STICKY"
        fi
        if [ -n "${MANAGER_STICKY:-}" ]; then
            local _mgr_label="disabled"
            [ "$MANAGER_STICKY" = "true" ] && _mgr_label="enabled"
            info "  Extension Manager = $_mgr_label"
            [ "$MANAGER_STICKY" = "true" ] && [ -n "${MANAGER_HOST_STICKY:-}" ] && \
                info "  Manager URL       = $MANAGER_HOST_STICKY"
        fi
        if ! confirm "Reconfigure?" "N"; then
            info "Reusing existing configuration; re-rendering only."
            if ! _run_setup_py "$env_name" "" "" "" "" "$host_ip" 0 "" "" "" "" "" "" "" "" "" "" "" "" "$backup_dir" ""; then
                error "setup failed."
                return 3
            fi
            if [ "${AUTH_PROVIDER_STICKY:-internal_keycloak}" = "internal_keycloak" ]; then
                _ensure_keycloak_certs
            fi
            success "setup complete (re-render only)."
            return 0
        fi
    fi

    if [ "$non_interactive" -eq 0 ] && is_tty; then
        info "papAIa setup — press Enter to keep each [default]."
        if [ -z "$app_host" ]; then
            app_host="$(prompt_field "Public URL of this server" \
                "Where browsers reach papAIa (scheme + host, no path)." \
                "PAPAIA_HOST" "${APP_HOST_STICKY:-http://host.docker.internal}")"
        fi
        if [ -z "$auth_provider" ]; then
            local provider_default="1"
            [ "${AUTH_PROVIDER_STICKY:-}" = "external_oidc" ] && provider_default="2"
            printf '\n%sIdentity provider%s\n' "$CYAN" "$NC" >&2
            printf '  1) Bundled Keycloak  — papAIa runs its own login (default)\n' >&2
            printf '  2) External OIDC     — use your existing provider\n' >&2
            local provider_choice
            provider_choice="$(prompt_with_default "  Choose" "$provider_default")"
            case "$provider_choice" in
                1|internal|internal_keycloak) auth_provider="internal_keycloak" ;;
                2|external|external_oidc) auth_provider="external_oidc" ;;
                *)
                    warn "Unrecognized choice '$provider_choice'; defaulting to bundled Keycloak."
                    auth_provider="internal_keycloak"
                    ;;
            esac
        fi
        if [ "$auth_provider" = "external_oidc" ] && [ "${AUTH_PROVIDER_STICKY:-}" != "external_oidc" ]; then
            if [ -z "$oidc_issuer" ]; then
                oidc_issuer="$(prompt_field "External OIDC provider" \
                    "Issuer URL of your provider. See src/infra/keycloak/README.md 'Switching to an External OIDC Provider'." \
                    "OIDC_ISSUER" "")"
            fi
        fi
        if [ -z "$auth_host" ] && [ "$auth_provider" != "external_oidc" ]; then
            local auth_default="${AUTH_HOST_STICKY:-}"
            [ -z "$auth_default" ] && auth_default="$(_derive_auth_default "$app_host")"
            auth_host="$(prompt_field "Public Keycloak URL" \
                "Where browsers reach the bundled Keycloak." \
                "AUTH_HOST" "$auth_default")"
        fi
        if [ -z "$reverse_proxy_provider" ]; then
            local rp_default="1"
            [ "${REVERSE_PROXY_PROVIDER_STICKY:-}" = "external_proxy" ] && rp_default="2"
            [ "${REVERSE_PROXY_PROVIDER_STICKY:-}" = "no_proxy" ] && rp_default="3"
            printf '\n%sReverse Proxy%s\n' "$CYAN" "$NC" >&2
            printf '  1) Bundled Nginx Proxy Manager  — papAIa ships its own reverse proxy (default)\n' >&2
            printf '  2) External proxy               — use your existing Traefik, Caddy, load balancer, ...\n' >&2
            printf '  3) No proxy                     — direct port access (development / air-gapped setups)\n' >&2
            local rp_choice
            rp_choice="$(prompt_with_default "  Choose" "$rp_default")"
            case "$rp_choice" in
                1|internal|internal_nginx) reverse_proxy_provider="internal_nginx" ;;
                2|external|external_proxy) reverse_proxy_provider="external_proxy" ;;
                3|none|no_proxy) reverse_proxy_provider="no_proxy" ;;
                *)
                    warn "Unrecognized choice '$rp_choice'; defaulting to bundled Nginx Proxy Manager."
                    reverse_proxy_provider="internal_nginx"
                    ;;
            esac
        fi
        if [ "$reverse_proxy_provider" = "internal_nginx" ] && [ -z "$npm_admin_host" ]; then
            local npm_admin_default="${NPM_ADMIN_HOST_STICKY:-}"
            [ -z "$npm_admin_default" ] && npm_admin_default="${NPM_ADMIN_HOST_DERIVED:-}"
            npm_admin_host="$(prompt_field "Public URL of NPM admin UI" \
                "Where browsers reach the Nginx Proxy Manager admin interface." \
                "NPM_ADMIN_HOST" "$npm_admin_default")"
        fi
        # LibreChat is served for either auth provider, so ask in both cases.
        if [ -z "$librechat_host" ]; then
            local librechat_default="${LIBRECHAT_HOST_STICKY:-}"
            [ -z "$librechat_default" ] && librechat_default="$(_derive_librechat_default "$app_host")"
            librechat_host="$(prompt_field "Public URL of LibreChat" \
                "Where browsers reach the chat UI." \
                "DOMAIN_SERVER" "$librechat_default")"
        fi
        if [ -z "$litellm_host" ]; then
            local litellm_default="${LITELLM_HOST_STICKY:-}"
            [ -z "$litellm_default" ] && litellm_default="$(_derive_litellm_default "$app_host")"
            litellm_host="$(prompt_field "Public URL of LiteLLM Proxy" \
                "Where browsers and services reach the LiteLLM proxy." \
                "LITELLM_PUBLIC_URL" "$litellm_default")"
        fi
        if [ -z "$web_search" ]; then
            local web_search_default="1"
            [ "${WEB_SEARCH_STICKY:-}" = "false" ] && web_search_default="2"
            printf '\n%sEnable Web Search%s\n' "$CYAN" "$NC" >&2
            printf '  1) Yes  — activate SearXNG (meta-search) + Firecrawl (web crawler)\n' >&2
            printf '  2) No   — skip web search components\n' >&2
            local web_search_choice
            web_search_choice="$(prompt_with_default "  Choose" "$web_search_default")"
            case "$web_search_choice" in
                1|yes) web_search="true" ;;
                2|no)  web_search="false" ;;
                *)
                    warn "Unrecognized choice '$web_search_choice'; defaulting to enabled."
                    web_search="true"
                    ;;
            esac
        fi
        if [ "$web_search" = "true" ] && [ -z "$reranker_model" ]; then
            reranker_model="$(prompt_field "Reranker Model (optional)" \
                "LiteLLM model name for reranking (e.g. rerank/jina-reranker-v2-base-multilingual). Press Enter to skip — set RERANKER_MODEL manually later." \
                "RERANKER_MODEL" "${RERANKER_MODEL_STICKY:-}")"
        fi
        if [ -z "$local_ai" ]; then
            local local_ai_default="1"
            [ "${LOCAL_AI_STICKY:-}" = "false" ] && local_ai_default="2"
            printf '\n%sEnable Local AI%s\n' "$CYAN" "$NC" >&2
            printf '  1) Yes  — run local LLM inference via LocalAI (default)\n' >&2
            printf '  2) No   — skip LocalAI\n' >&2
            local local_ai_choice
            local_ai_choice="$(prompt_with_default "  Choose" "$local_ai_default")"
            case "$local_ai_choice" in
                1|yes) local_ai="true" ;;
                2|no)  local_ai="false" ;;
                *)
                    warn "Unrecognized choice '$local_ai_choice'; defaulting to disabled."
                    local_ai="false"
                    ;;
            esac
        fi
        if [ "$local_ai" = "true" ] && [ -z "$localai_host" ]; then
            local localai_default="${LOCALAI_HOST_STICKY:-}"
            [ -z "$localai_default" ] && localai_default="$(_derive_localai_default "$app_host")"
            localai_host="$(prompt_field "Public URL of LocalAI" \
                "Where browsers and LiteLLM reach LocalAI." \
                "LOCALAI_PUBLIC_URL" "$localai_default")"
        fi
        if [ "$local_ai" = "true" ] && [ -z "$localai_variant" ]; then
            localai_variant="$(_prompt_localai_variant)"
        fi
        if [ -z "$manager" ]; then
            local manager_default="1"
            [ "${MANAGER_STICKY:-}" = "false" ] && manager_default="2"
            printf '\n%sEnable Extension Manager%s\n' "$CYAN" "$NC" >&2
            printf '  1) Yes  — run papaia-manager, the web UI for installing and updating addons (default)\n' >&2
            printf '  2) No   — skip papaia-manager (the core runs without it)\n' >&2
            local manager_choice
            manager_choice="$(prompt_with_default "  Choose" "$manager_default")"
            case "$manager_choice" in
                1|yes) manager="true" ;;
                2|no)  manager="false" ;;
                *)
                    warn "Unrecognized choice '$manager_choice'; defaulting to disabled."
                    manager="false"
                    ;;
            esac
        fi
        if [ "$manager" = "true" ] && [ -z "$manager_host" ]; then
            local manager_default_url="${MANAGER_HOST_STICKY:-}"
            [ -z "$manager_default_url" ] && manager_default_url="$(_derive_manager_default "$app_host")"
            manager_host="$(prompt_field "Public URL of papaia-manager" \
                "Where browsers reach the extension management UI." \
                "MANAGER_PUBLIC_URL" "$manager_default_url")"
        fi
    else
        if [ -z "$app_host" ] && [ -z "$APP_HOST_STICKY" ]; then
            error "--app-host is required: no prior PAPAIA_HOST to reuse and not running interactively."
            exit 3
        fi
        if [ -z "$auth_provider" ]; then
            auth_provider="${AUTH_PROVIDER_STICKY:-internal_keycloak}"
        fi
        if [ "$auth_provider" = "external_oidc" ] && [ "${AUTH_PROVIDER_STICKY:-}" != "external_oidc" ] && [ -z "$oidc_issuer" ]; then
            error "--oidc-issuer is required: selecting --auth-provider=external_oidc for the first time with no interactive terminal to prompt in."
            exit 3
        fi
        # Sticky reuse for reverse proxy provider in non-interactive mode
        if [ -z "$reverse_proxy_provider" ] && [ -n "${REVERSE_PROXY_PROVIDER_STICKY:-}" ]; then
            reverse_proxy_provider="$REVERSE_PROXY_PROVIDER_STICKY"
        fi
        if [ -z "$npm_admin_host" ] && [ -n "${NPM_ADMIN_HOST_STICKY:-}" ]; then
            npm_admin_host="$NPM_ADMIN_HOST_STICKY"
        fi
        if [ -z "$manager_host" ] && [ -n "${MANAGER_HOST_STICKY:-}" ]; then
            manager_host="$MANAGER_HOST_STICKY"
        fi
        if [ -z "$litellm_host" ] && [ -n "${LITELLM_HOST_STICKY:-}" ]; then
            litellm_host="$LITELLM_HOST_STICKY"
        fi
    fi

    # --allow-direct-port-access is the explicit opt-in for "no proxy at
    # all" (nginx excluded, no external proxy declared). Bash owns
    # interactive confirmation, so ask here -- before invoking Python --
    # rather than after a failure, since the Python side never blocks on
    # its own once this flag is set (the flag IS the authorization).
    if [ "$allow_direct_port_access" -eq 1 ] && [ "$external_reverse_proxy" != "true" ]; then
        case "$app_host" in
            https://*) : ;;  # TLS already in place, nothing unsafe about it
            *)
                if [ "$non_interactive" -eq 0 ] && is_tty; then
                    warn "No reverse proxy and no TLS detected for this configuration."
                    if ! confirm "Continue with services reachable on plain HTTP ports directly?" "N"; then
                        error "Aborted."
                        exit 3
                    fi
                fi
                ;;
        esac
    fi

    if ! _run_setup_py "$env_name" "$app_host" "$auth_host" "$external_reverse_proxy" "$allow_direct_port_access" "$host_ip" "$force" "$auth_provider" "$oidc_issuer" "$librechat_host" "$web_search" "$localai_host" "$local_ai" "$reranker_model" "$reverse_proxy_provider" "$npm_admin_host" "$manager_host" "$manager" "$litellm_host" "$backup_dir" "$localai_variant"; then
        error "setup failed."
        return 3
    fi
    if [ "${auth_provider:-internal_keycloak}" = "internal_keycloak" ]; then
        _ensure_keycloak_certs
    fi
    success "setup complete. Run 'papaia-ctl start' to bring up the stack."
}

_derive_auth_default() {
    # Best-effort bash-side fallback if defaults() had no sticky value yet;
    # the authoritative derivation lives in resolve.derive_auth_host_default
    # and is what setup actually applies -- this is only used to pre-fill
    # the interactive prompt.
    case "$1" in
        *host.docker.internal*|*localhost*|*127.0.0.1*)
            printf 'https://host.docker.internal:%s' "${KEYCLOAK_EXT_PORT:-8110}" ;;
        *)
            printf '%s' "$1" | sed -E 's#^(https?://)([^:/]+).*#\1auth.\2#' ;;
    esac
}

_derive_litellm_default() {
    local host="$1" port="${LITELLM_EXT_PORT:-8200}" base
    base="$(printf '%s' "$host" | sed -E 's#^(https?://[^:/]+).*#\1#')"
    printf '%s:%s' "$base" "$port"
}

_derive_localai_default() {
    local host="$1" port="${LOCALAI_EXT_PORT:-8080}" base
    base="$(printf '%s' "$host" | sed -E 's#^(https?://[^:/]+).*#\1#')"
    printf '%s:%s' "$base" "$port"
}

# Menu position of a variant. The slots are fixed so the numbering stays the
# same no matter what was detected -- the operator's muscle memory and any
# copy-pasted instructions keep working on a host without a GPU.
_localai_variant_slot() {
    case "$1" in
        nvidia-cuda-12|nvidia-cuda-13) printf '1' ;;
        hipblas)                       printf '2' ;;
        intel)                         printf '3' ;;
        vulkan)                        printf '4' ;;
        *)                             printf '5' ;;
    esac
}

# One menu line: title, what detection found, and any unmet prerequisite.
_localai_variant_option() {
    local number="$1" title="$2" variant="$3" label="$4" warning="$5" marker=""
    [ -n "$variant" ] && [ "$variant" = "${LOCALAI_VARIANT_RECOMMENDED:-}" ] && marker="  (recommended)"
    printf '  %s) %-20s %s%s\n' "$number" "$title" "$label" "$marker" >&2
    [ -n "$warning" ] && printf '     %s%s%s\n' "$YELLOW" "$warning" "$NC" >&2
    return 0
}

# Picking a variant the host does not currently expose is allowed on purpose --
# an operator may run setup before installing the driver or container runtime --
# but it must not pass silently.
_localai_variant_unverified() {
    warn "$1 was not detected on this host. Install the driver and container runtime before starting the stack, or re-run setup and choose CPU."
}

# Asks which LocalAI accelerator image to install. Everything the operator sees
# goes to stderr; only the chosen variant id reaches stdout.
_prompt_localai_variant() {
    # Announced before the probe, not after: it shells out to nvidia-smi and
    # docker info, which takes long enough on a cold host to look like a hang.
    printf '\n%sLocalAI Image%s\n' "$CYAN" "$NC" >&2
    printf '  Detecting available GPU accelerators, this can take a few seconds ...\n' >&2
    load_localai_variants

    local default_slot
    if [ -n "${LOCALAI_VARIANT_STICKY:-}" ]; then
        default_slot="$(_localai_variant_slot "$LOCALAI_VARIANT_STICKY")"
    else
        default_slot="$(_localai_variant_slot "${LOCALAI_VARIANT_RECOMMENDED:-cpu}")"
    fi

    printf '\n  The GPU images need the matching host prerequisites to be in place already:\n' >&2
    printf '    NVIDIA  proprietary driver + NVIDIA Container Toolkit\n' >&2
    printf '    AMD     ROCm kernel driver (provides /dev/kfd)\n' >&2
    printf '    Intel   none - the backend ships its own driver\n' >&2
    printf '    Vulkan  a Vulkan-capable GPU driver on the host\n' >&2
    printf '  The stack does not install any of these. Detection below reports only what\n' >&2
    printf '  this host exposes right now.\n\n' >&2

    _localai_variant_option 1 "NVIDIA GPU (CUDA)" \
        "${LOCALAI_VARIANT_NVIDIA:-}" "${LOCALAI_VARIANT_NVIDIA_LABEL:-}" "${LOCALAI_VARIANT_NVIDIA_WARN:-}"
    _localai_variant_option 2 "AMD GPU (ROCm)" \
        "${LOCALAI_VARIANT_AMD:-}" "${LOCALAI_VARIANT_AMD_LABEL:-}" "${LOCALAI_VARIANT_AMD_WARN:-}"
    _localai_variant_option 3 "Intel GPU (SYCL)" \
        "${LOCALAI_VARIANT_INTEL:-}" "${LOCALAI_VARIANT_INTEL_LABEL:-}" "${LOCALAI_VARIANT_INTEL_WARN:-}"
    _localai_variant_option 4 "Vulkan (generic)" \
        "${LOCALAI_VARIANT_VULKAN:-}" "${LOCALAI_VARIANT_VULKAN_LABEL:-}" "${LOCALAI_VARIANT_VULKAN_WARN:-}"
    _localai_variant_option 5 "CPU only" \
        "${LOCALAI_VARIANT_CPU:-cpu}" "${LOCALAI_VARIANT_CPU_LABEL:-runs on any hardware}" ""

    local choice variant
    choice="$(prompt_with_default "  Choose" "$default_slot")"
    case "$choice" in
        1|nvidia)
            variant="${LOCALAI_VARIANT_NVIDIA:-}"
            # Unknown driver means an unknown CUDA major; the newest published
            # image is the better guess than refusing the choice outright.
            [ -z "$variant" ] && { variant="nvidia-cuda-13"; _localai_variant_unverified "An NVIDIA GPU"; }
            ;;
        2|amd|hipblas)
            variant="hipblas"
            [ -z "${LOCALAI_VARIANT_AMD:-}" ] && _localai_variant_unverified "An AMD GPU with ROCm"
            ;;
        3|intel)
            variant="intel"
            [ -z "${LOCALAI_VARIANT_INTEL:-}" ] && _localai_variant_unverified "An Intel GPU"
            ;;
        4|vulkan)
            variant="vulkan"
            [ -z "${LOCALAI_VARIANT_VULKAN:-}" ] && _localai_variant_unverified "A Vulkan-capable GPU"
            ;;
        5|cpu) variant="cpu" ;;
        *)
            warn "Unrecognized choice '$choice'; defaulting to the CPU image."
            variant="cpu"
            ;;
    esac
    printf '%s' "$variant"
}

_derive_manager_default() {
    # Best-effort bash-side prefill for the papaia-manager URL prompt; the
    # authoritative derivation lives in resolve.derive_manager_url_default.
    local host="$1" port="${MANAGER_EXT_PORT:-8120}" base
    base="$(printf '%s' "$host" | sed -E 's#^(https?://[^:/]+).*#\1#')"
    printf '%s:%s' "$base" "$port"
}

_derive_librechat_default() {
    # Best-effort bash-side prefill for the LibreChat URL prompt; the
    # authoritative derivation lives in resolve.derive_librechat_url_default.
    # host.docker.internal over plain HTTP -> localhost (Secure-cookie reason);
    # otherwise keep the app host, appending the LibreChat port.
    local host="$1" port="${LIBRECHAT_EXT_PORT:-8000}" base
    case "$host" in
        http://host.docker.internal*) printf 'http://localhost:%s' "$port" ;;
        *)
            base="$(printf '%s' "$host" | sed -E 's#^(https?://[^:/]+).*#\1#')"
            printf '%s:%s' "$base" "$port" ;;
    esac
}

_run_setup_py() {
    local env_name="$1" app_host="$2" auth_host="$3" external_rp="$4" allow_direct="$5" host_ip="$6" force="$7"
    local auth_provider="$8" oidc_issuer="$9" librechat_host="${10}" web_search="${11}"
    local localai_host="${12}" local_ai="${13}" reranker_model="${14}" reverse_proxy_provider="${15:-}" npm_admin_host="${16:-}" manager_host="${17:-}" manager="${18:-}" litellm_host="${19:-}" backup_dir="${20:-}" localai_variant="${21:-}"
    local -a extra=()
    [ -n "$app_host" ] && extra+=(--app-host="$app_host")
    [ -n "$auth_host" ] && extra+=(--auth-host="$auth_host")
    [ -n "$librechat_host" ] && extra+=(--librechat-host="$librechat_host")
    [ -n "$litellm_host" ] && extra+=(--litellm-host="$litellm_host")
    [ -n "$localai_host" ] && extra+=(--localai-host="$localai_host")
    [ -n "$manager_host" ] && extra+=(--manager-host="$manager_host")
    [ -n "$npm_admin_host" ] && extra+=(--npm-admin-host="$npm_admin_host")
    [ -n "$auth_provider" ] && extra+=(--auth-provider="$auth_provider")
    [ -n "$oidc_issuer" ] && extra+=(--oidc-issuer="$oidc_issuer")
    [ -n "$reverse_proxy_provider" ] && extra+=(--reverse-proxy-provider="$reverse_proxy_provider")
    [ -n "$external_rp" ] && extra+=(--external-reverse-proxy="$external_rp")
    [ -n "$web_search" ] && extra+=(--enable-web-search="$web_search")
    [ -n "$local_ai" ] && extra+=(--enable-local-ai="$local_ai")
    [ -n "$localai_variant" ] && extra+=(--localai-variant="$localai_variant")
    [ -n "$manager" ] && extra+=(--enable-manager="$manager")
    [ -n "$reranker_model" ] && extra+=(--reranker-model="$reranker_model")
    [ -n "$backup_dir" ] && extra+=(--backup-dir="$backup_dir")
    [ -n "$host_ip" ] && extra+=(--host-ip="$host_ip")
    [ "$allow_direct" = "1" ] && extra+=(--allow-direct-port-access)
    [ "$force" = "1" ] && extra+=(--force)
    py_cli setup --env="$env_name" "${extra[@]}"
}
