# shellcheck shell=bash
# papaia-ctl — local CA + Keycloak TLS certificate generation.
# Sourced by tools/papaia-ctl; not executable on its own.
# shellcheck disable=SC2154  # globals (colors, CONFIG_DIR, ...) come from the entrypoint

_is_local_auth_host() {
    # Returns 0 when the URL's hostname is a local/non-FQDN host for which a
    # locally-generated CA certificate is appropriate: localhost,
    # host.docker.internal, 127.0.0.1, or any bare IPv4 address.
    # A real domain (e.g. auth.example.com) returns 1 -- the operator handles
    # TLS there via their own reverse proxy with a proper certificate.
    local url="$1"
    local host
    host="${url#*://}"   # strip scheme
    host="${host%%:*}"   # strip port
    host="${host%%/*}"   # strip path
    [ -z "$host" ] && return 0
    case "$host" in
        localhost|host.docker.internal|127.0.0.1) return 0 ;;
        [0-9]*.[0-9]*.[0-9]*.[0-9]*) return 0 ;;
    esac
    return 1
}

# Server certificates live at most 825 days and carry serverAuth: macOS, and the browsers
# that use its verifier, reject a TLS certificate without them even under a trusted CA.
_KEYCLOAK_CERT_DAYS=825
# A server certificate this close to its end (in seconds) is issued again.
_KEYCLOAK_CERT_RENEW_BEFORE=$((30 * 24 * 3600))
# The names Keycloak's certificate serves. A new local CA is limited to them (name
# constraints), so its key cannot issue a certificate for any other domain that a browser
# trusting the CA would accept. A CA made before keeps working without the limit.
_LOCAL_CA_DNS_NAMES="keycloak localhost host.docker.internal"

# Runs `openssl "$@"` for the step named in $1. Its output is kept back unless it fails:
# then the step and openssl's own message are printed and papaia-ctl exits.
_openssl_step() {
    local step="$1"; shift
    local output
    if ! output="$(openssl "$@" 2>&1)"; then
        error "Certificate generation failed: $step."
        if [ -n "$output" ]; then
            printf '%s\n' "$output" | sed 's/^/    openssl: /' >&2
        fi
        error "openssl: $(openssl version 2>/dev/null || echo unknown)"
        exit 2
    fi
}

# Returns 0 when the Keycloak certificate in $1 has to be issued again: it predates
# serverAuth, or it ends within _KEYCLOAK_CERT_RENEW_BEFORE.
_keycloak_cert_outdated() {
    local crt="$1"
    openssl x509 -in "$crt" -noout -text 2>/dev/null \
        | grep -q "TLS Web Server Authentication" || return 0
    openssl x509 -in "$crt" -noout -checkend "$_KEYCLOAK_CERT_RENEW_BEFORE" >/dev/null 2>&1 \
        || return 0
    return 1
}

# Issues the Keycloak server certificate for the key in $certs_dir, signed by the local CA.
_issue_keycloak_cert() {
    local certs_dir="$1"
    local ca_key="$certs_dir/local-ca.key" ca_crt="$certs_dir/local-ca.crt"
    local kc_key="$certs_dir/keycloak.key" kc_crt="$certs_dir/keycloak.crt"
    local csr="$certs_dir/keycloak.csr" ext="$certs_dir/keycloak-san.ext"

    _openssl_step "Keycloak certificate request" req -new -key "$kc_key" -out "$csr" \
        -subj "/CN=keycloak/O=papAIa"

    # SAN covers all names the certificate must serve
    local san="" name
    for name in $_LOCAL_CA_DNS_NAMES; do san="${san:+$san,}DNS:$name"; done
    printf '%s\n' \
        "subjectAltName=$san" \
        "basicConstraints=critical,CA:FALSE" \
        "keyUsage=critical,digitalSignature,keyEncipherment" \
        "extendedKeyUsage=serverAuth" \
        > "$ext"

    # Written next to the old certificate first: a failed run leaves the old one in place.
    _openssl_step "Keycloak certificate signing" x509 -req -in "$csr" \
        -CA "$ca_crt" -CAkey "$ca_key" -CAcreateserial \
        -out "$kc_crt.new" -days "$_KEYCLOAK_CERT_DAYS" \
        -extfile "$ext"
    mv -f "$kc_crt.new" "$kc_crt"

    # Readable by the Keycloak container user (UID 1000 inside the image)
    chmod 644 "$kc_key" "$kc_crt"

    # Remove ephemeral intermediates
    rm -f "$csr" "$ext" "$certs_dir/local-ca.srl"
}

_ensure_keycloak_certs() {
    local certs_dir="$CONFIG_DIR/certs"
    local ca_key="$certs_dir/local-ca.key"
    local ca_crt="$certs_dir/local-ca.crt"
    local kc_key="$certs_dir/keycloak.key"
    local kc_crt="$certs_dir/keycloak.crt"

    command -v openssl >/dev/null 2>&1 || {
        error "openssl not found. Required for Keycloak TLS certificate generation."
        exit 2
    }

    # The CA key is read by papaia-ctl only; no container mounts it. A key from an older
    # setup was world-readable. Not fatal: a file someone else owns keeps its mode.
    [ -f "$ca_key" ] && { chmod 600 "$ca_key" 2>/dev/null || true; }

    if [ -f "$ca_key" ] && [ -f "$ca_crt" ] && [ -f "$kc_key" ] && [ -f "$kc_crt" ]; then
        if ! _keycloak_cert_outdated "$kc_crt"; then
            info "Keycloak TLS certificates already present — skipping generation."
            return 0
        fi
        # Same CA and key: a browser or keychain that trusts the CA keeps trusting it.
        info "Renewing the Keycloak TLS certificate (signed by the existing local CA)..."
        _issue_keycloak_cert "$certs_dir"
        success "Keycloak TLS certificate renewed in $certs_dir."
        warn "A running Keycloak keeps the old certificate until it restarts:" \
            "run 'papaia-ctl stop' and 'papaia-ctl start'."
        return 0
    fi

    info "Generating local CA and Keycloak TLS certificates..."
    mkdir -p "$certs_dir"

    # Local CA key + self-signed certificate, limited to Keycloak's names
    local constraints="" name
    for name in $_LOCAL_CA_DNS_NAMES; do
        constraints="${constraints:+$constraints,}permitted;DNS:$name"
    done
    _openssl_step "local CA key" genrsa -out "$ca_key" 4096
    chmod 600 "$ca_key"
    _openssl_step "local CA certificate" req -new -x509 -key "$ca_key" -out "$ca_crt" \
        -days 3650 \
        -subj "/CN=papaia-local-ca/O=papAIa" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "nameConstraints=critical,$constraints"

    # Keycloak server key + certificate
    _openssl_step "Keycloak key" genrsa -out "$kc_key" 4096
    _issue_keycloak_cert "$certs_dir"

    # The certificate is read by the containers that trust Keycloak; the key stays private.
    chmod 644 "$ca_crt"

    success "Keycloak TLS certificates generated in $certs_dir."
}

# macOS only, for a local auth host: browsers there check Keycloak's certificate against
# the user's keychain, and they reach Keycloak under the auth host's name from the Mac
# itself, where host.docker.internal resolves only with an /etc/hosts entry. Offers to
# trust the local CA for TLS server certificates only (no admin rights needed) and names
# what is still missing. Reads AUTH_HOST from the rendered $CONFIG_DIR/.env, so a derived
# default counts too.
_macos_local_tls_steps() {
    local non_interactive="$1"
    [ "$(uname -s)" = "Darwin" ] || return 0
    local auth_host=""
    [ -f "$CONFIG_DIR/.env" ] && auth_host="$(sed -n 's/^AUTH_HOST=//p' "$CONFIG_DIR/.env" | tail -n 1)"
    [ -n "$auth_host" ] || return 0
    _is_local_auth_host "$auth_host" || return 0
    local ca_crt="$CONFIG_DIR/certs/local-ca.crt"
    local kc_crt="$CONFIG_DIR/certs/keycloak.crt"
    local keychain="$HOME/Library/Keychains/login.keychain-db"
    [ -f "$ca_crt" ] || return 0

    # Asked the way a browser asks: Keycloak's certificate under the TLS server policy. A
    # trust limited to that policy (-p ssl) does not show when the CA alone is checked.
    if ! security verify-cert -c "$kc_crt" -c "$ca_crt" -p ssl -L >/dev/null 2>&1; then
        if [ "$non_interactive" -eq 0 ] && is_tty \
            && confirm "Trust the local CA in your login keychain, so browsers on this Mac accept Keycloak?" "Y" \
            && security add-trusted-cert -r trustRoot -p ssl -k "$keychain" "$ca_crt"; then
            success "Local CA trusted for TLS in $keychain."
        else
            warn "Browsers on this Mac reject Keycloak until the local CA is trusted. Run:"
            printf '  security add-trusted-cert -r trustRoot -p ssl -k %s %s\n' "$keychain" "$ca_crt" >&2
        fi
    fi

    local host="${auth_host#*://}"
    host="${host%%:*}"
    host="${host%%/*}"
    if [ "$host" = "host.docker.internal" ] \
        && ! dscacheutil -q host -a name "$host" 2>/dev/null | grep '^ip_address:' >/dev/null; then
        warn "$host does not resolve on this Mac, so browsers cannot reach Keycloak. Run:"
        printf '  echo "127.0.0.1 %s" | sudo tee -a /etc/hosts\n' "$host" >&2
    fi
}
