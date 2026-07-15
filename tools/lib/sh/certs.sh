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

_ensure_keycloak_certs() {
    local certs_dir="$CONFIG_DIR/certs"
    local ca_key="$certs_dir/local-ca.key"
    local ca_crt="$certs_dir/local-ca.crt"
    local kc_key="$certs_dir/keycloak.key"
    local kc_crt="$certs_dir/keycloak.crt"

    if [ -f "$ca_key" ] && [ -f "$ca_crt" ] && [ -f "$kc_key" ] && [ -f "$kc_crt" ]; then
        info "Keycloak TLS certificates already present — skipping generation."
        return 0
    fi

    command -v openssl >/dev/null 2>&1 || {
        error "openssl not found. Required for Keycloak TLS certificate generation."
        exit 2
    }

    info "Generating local CA and Keycloak TLS certificates..."
    mkdir -p "$certs_dir"

    # Local CA key + self-signed certificate
    openssl genrsa -out "$ca_key" 4096 2>/dev/null
    openssl req -new -x509 -key "$ca_key" -out "$ca_crt" -days 3650 \
        -subj "/CN=papaia-local-ca/O=papAIa" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

    # Keycloak server key + CSR
    openssl genrsa -out "$kc_key" 4096 2>/dev/null
    openssl req -new -key "$kc_key" -out "$certs_dir/keycloak.csr" \
        -subj "/CN=keycloak/O=papAIa" 2>/dev/null

    # SAN extension (covers all names the certificate must serve)
    printf 'subjectAltName=DNS:keycloak,DNS:localhost,DNS:host.docker.internal\n' \
        > "$certs_dir/keycloak-san.ext"

    # Sign the server certificate with the local CA
    openssl x509 -req -in "$certs_dir/keycloak.csr" \
        -CA "$ca_crt" -CAkey "$ca_key" -CAcreateserial \
        -out "$kc_crt" -days 3650 \
        -extfile "$certs_dir/keycloak-san.ext" 2>/dev/null

    # Readable by the Keycloak container user (UID 1000 inside the image)
    chmod 644 "$ca_key" "$ca_crt" "$kc_key" "$kc_crt"

    # Remove ephemeral intermediates
    rm -f "$certs_dir/keycloak.csr" "$certs_dir/keycloak-san.ext" \
        "$certs_dir/local-ca.srl"

    success "Keycloak TLS certificates generated in $certs_dir."
}
