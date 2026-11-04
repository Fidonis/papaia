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
    printf '%s\n' \
        "subjectAltName=DNS:keycloak,DNS:localhost,DNS:host.docker.internal" \
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

    # Local CA key + self-signed certificate
    _openssl_step "local CA key" genrsa -out "$ca_key" 4096
    _openssl_step "local CA certificate" req -new -x509 -key "$ca_key" -out "$ca_crt" \
        -days 3650 \
        -subj "/CN=papaia-local-ca/O=papAIa" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"

    # Keycloak server key + certificate
    _openssl_step "Keycloak key" genrsa -out "$kc_key" 4096
    _issue_keycloak_cert "$certs_dir"

    # Readable by the Keycloak container user (UID 1000 inside the image)
    chmod 644 "$ca_key" "$ca_crt"

    success "Keycloak TLS certificates generated in $certs_dir."
}
