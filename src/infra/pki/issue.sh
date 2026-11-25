#!/bin/sh
# papAIa internal CA: issues, renews and installs the certificates of the `pki` profile.
#
# Runs inside the pki-issuer container (src/infra/pki/docker-compose.yml), never on the
# host: the CA key is in the volume mounted at /ca and nowhere else. papaia-ctl mounts
# PAPAIA_PKI_DIR at /pki and writes the requests to /pki/requests.tsv first, one line per
# service, the fields separated by a tab:
#
#   <module> <service> <uid> <dns,dns,...|- for no server certificate> <1|0 client certificate>
#
# Commands:
#   sync        issue what is requested and missing, renew what is past two thirds of its
#               lifetime, remove what is no longer requested, write inventory.json
#   stage-ca    put a new CA next to the active one (generated, or the one in /import),
#               then sync: every bundle then trusts both
#   promote-ca  make the staged CA the active one, keep the old one in the bundle until its
#               last certificate has expired, then sync: every leaf is issued again
#   purge       delete what the CA wrote under /pki (its files, the module directories it
#               issued into) and the bookkeeping in /ca/state; other files stay
#
# Settings (environment): PKI_MODE issue|external, PKI_LEAF_DAYS (1-90), PKI_CA_DAYS,
# PKI_CA_NAME, PKI_FORCE=1 (issue every leaf again), PKI_HOST_DIR (the host path of /pki,
# for messages only), PKI_NOW (the current time as a Unix epoch, for tests of the renewal).
#
# Output: on stdout one line `changed <module>` per module whose files changed and one
# line `service <module> <service>` per changed service; everything else goes to stderr.
# Exit 3 when a request or a provided file cannot be used; nothing is half written then.
set -eu
umask 077

CA=/ca
PKI=/pki
REQUESTS="$PKI/requests.tsv"
MODE="${PKI_MODE:-issue}"
LEAF_DAYS="${PKI_LEAF_DAYS:-90}"
CA_DAYS="${PKI_CA_DAYS:-3650}"
CA_NAME="${PKI_CA_NAME:-papaia internal CA}"
FORCE="${PKI_FORCE:-0}"
HOST_DIR="${PKI_HOST_DIR:-$PKI}"
NOW="${PKI_NOW:-$(date -u +%s)}"
TAB="$(printf '\t')"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
: > "$TMP/changed"
: > "$TMP/errors"

log() { printf '%s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 3; }
# A problem with one service; reported together at the end, so one run names all of them.
problem() { printf '%s\n' "$*" >> "$TMP/errors"; }
host_path() { printf '%s' "$HOST_DIR${1#"$PKI"}"; }

case "$LEAF_DAYS" in
    ''|*[!0-9]*) die "PKI_LEAF_DAYS must be a number of days, not '$LEAF_DAYS'" ;;
esac
if [ "$LEAF_DAYS" -lt 1 ] || [ "$LEAF_DAYS" -gt 90 ]; then
    die "PKI_LEAF_DAYS must be between 1 and 90, not $LEAF_DAYS"
fi
case "$MODE" in
    issue|external) : ;;
    *) die "PKI_MODE must be 'issue' or 'external', not '$MODE'" ;;
esac

# ─────────────────────────────────────────────────────────────────────────
# certificate helpers
# ─────────────────────────────────────────────────────────────────────────

ossl() {
    # openssl with its chatter kept back unless it fails.
    if ! out="$(openssl "$@" 2>&1)"; then
        log "$out"
        return 1
    fi
}

# Epoch of the start or end of a certificate's validity. $1 file, $2 start|end
cert_epoch() {
    ce_stamp="$(openssl x509 -in "$1" -noout -"$2"date -dateopt iso_8601 2>/dev/null)" || return 1
    ce_stamp="${ce_stamp#*=}"
    date -u -d "${ce_stamp%Z}" +%s 2>/dev/null
}

iso_of() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }

fingerprint() {
    openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null \
        | sed 's/^.*=//; s/://g' | tr 'A-F' 'a-f'
}

self_signed() {
    [ "$(openssl x509 -in "$1" -noout -subject_hash 2>/dev/null)" = \
      "$(openssl x509 -in "$1" -noout -issuer_hash 2>/dev/null)" ]
}

same_key() {
    # $1 certificate, $2 private key
    sk_a="$(openssl x509 -in "$1" -noout -pubkey 2>/dev/null)" || return 1
    sk_b="$(openssl pkey -in "$2" -pubout 2>/dev/null)" || return 1
    [ -n "$sk_a" ] && [ "$sk_a" = "$sk_b" ]
}

# Whether a leaf has to be issued again: unreadable, or two thirds of its lifetime gone.
due() {
    du_start="$(cert_epoch "$1" start)" || return 0
    du_end="$(cert_epoch "$1" end)" || return 0
    [ "$du_end" -gt "$du_start" ] || return 0
    [ $((NOW - du_start)) -ge $(((du_end - du_start) * 2 / 3)) ]
}

# Splits the PEM certificates of $1 into $2.1.pem, $2.2.pem, ...; prints how many.
split_pem() {
    awk -v prefix="$2" '
        /-----BEGIN CERTIFICATE-----/ { n++; file = prefix "." n ".pem" }
        file { print > file }
        /-----END CERTIFICATE-----/ { close(file); file = "" }
        END { print n + 0 }
    ' "$1"
}

json_str() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }

subject_of() { openssl x509 -in "$1" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//'; }

# The subject CN of a certificate (RFC 2253 order: the CN is wherever it is).
cn_of() {
    subject_of "$1" | tr ',' '\n' | sed -n 's/^CN=//p' | head -n 1
}

# Owner $2:$2 and mode $3 (octal, as `stat -c %a` prints it) for $1, set only where they
# differ: a run with nothing to do changes nothing, not even a file's ctime.
own() {
    ow_now="$(stat -c '%u:%g %a' "$1" 2>/dev/null)" || ow_now=""
    [ "$ow_now" = "$2:$2 $3" ] && return 0
    chown "$2:$2" "$1"
    chmod "$3" "$1"
}

# Mode $2 for $1 (owner unchanged), set only where it differs.
mode() {
    [ "$(stat -c '%a' "$1" 2>/dev/null)" = "$2" ] || chmod "$2" "$1"
}

# Writes $1 to $2 by rename in the target directory, owner $3 and mode $4.
install_file() {
    if_tmp="$(dirname "$2")/.$(basename "$2").new"
    cp "$1" "$if_tmp"
    chown "$3:$3" "$if_tmp"
    chmod "$4" "$if_tmp"
    mv -f "$if_tmp" "$2"
}

# ─────────────────────────────────────────────────────────────────────────
# the CA
# ─────────────────────────────────────────────────────────────────────────

# A new self-signed issuing CA in directory $1: ECDSA P-256, dedicated to this installation.
new_ca() {
    mkdir -p "$1"
    id="$(openssl rand -hex 4)"
    ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1/ca.key" \
        || die "could not create the CA key"
    ossl req -new -x509 -key "$1/ca.key" -out "$1/ca.crt" -days "$CA_DAYS" \
        -subj "/O=papAIa/CN=$CA_NAME $id" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" \
        || die "could not create the CA certificate"
    : > "$1/chain.crt"
    echo pki > "$1/source"
    chmod 0400 "$1/ca.key"
    log "Created the internal CA '$CA_NAME $id' (valid $CA_DAYS days)."
}

# An issuing CA from /import (an intermediate of the company PKI) into directory $1.
import_ca() {
    src=/import
    [ -s "$src/ca.crt" ] && [ -s "$src/ca.key" ] || die "the CA certificate or its key is missing"
    openssl x509 -in "$src/ca.crt" -noout -ext basicConstraints 2>/dev/null | grep -q "CA:TRUE" \
        || die "the certificate given with --cert is not a CA certificate (basicConstraints CA:TRUE)"
    if openssl x509 -in "$src/ca.crt" -noout -ext keyUsage 2>/dev/null | grep -q "Usage"; then
        openssl x509 -in "$src/ca.crt" -noout -ext keyUsage 2>/dev/null | grep -q "Certificate Sign" \
            || die "the CA certificate may not sign certificates (keyUsage keyCertSign)"
    fi
    same_key "$src/ca.crt" "$src/ca.key" || die "the key given with --key does not belong to the CA certificate"
    bits="$(openssl pkey -in "$src/ca.key" -noout -text_pub 2>/dev/null | sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p' | head -n 1)"
    if openssl pkey -in "$src/ca.key" -noout -text_pub 2>/dev/null | grep -q "Modulus"; then
        [ "${bits:-0}" -ge 3072 ] || die "an RSA CA key needs at least 3072 bits, this one has ${bits:-?}"
    fi
    openssl x509 -in "$src/ca.crt" -noout -checkend $((LEAF_DAYS * 86400)) >/dev/null 2>&1 \
        || die "the CA certificate expires within $LEAF_DAYS days, before the certificates it would sign"
    chain="$TMP/import-chain.crt"
    : > "$chain"
    [ -s "$src/chain.crt" ] && cat "$src/chain.crt" > "$chain"
    if ! self_signed "$src/ca.crt"; then
        [ -s "$chain" ] || die "the CA is an intermediate: --chain must hold its issuers up to the root"
        ossl verify -CAfile "$chain" "$src/ca.crt" \
            || die "the CA certificate does not verify against the chain given with --chain"
    fi
    mkdir -p "$1"
    cp "$src/ca.crt" "$1/ca.crt"
    cp "$src/ca.key" "$1/ca.key"
    cp "$chain" "$1/chain.crt"
    echo enterprise > "$1/source"
    chmod 0400 "$1/ca.key"
    log "Imported the issuing CA '$(subject_of "$1/ca.crt")'."
}

# Adds the certificates of file $1 to the bundle under construction, once each.
bundle_add() {
    [ -s "$1" ] || return 0
    ba_count="$(split_pem "$1" "$TMP/part")"
    ba_i=1
    while [ "$ba_i" -le "$ba_count" ]; do
        ba_part="$TMP/part.$ba_i.pem"
        ba_fp="$(fingerprint "$ba_part")"
        if [ -n "$ba_fp" ] && ! grep -qx "$ba_fp" "$TMP/bundle.fps" 2>/dev/null; then
            echo "$ba_fp" >> "$TMP/bundle.fps"
            cat "$ba_part" >> "$TMP/bundle.crt"
        fi
        rm -f "$ba_part"
        ba_i=$((ba_i + 1))
    done
}

# Every CA a consumer must trust: the active CA and its chain, a staged CA, and retired CAs
# until their last certificate has expired.
build_bundle() {
    : > "$TMP/bundle.crt"
    : > "$TMP/bundle.fps"
    if [ "$MODE" = external ]; then
        [ -s "$PKI/ca-bundle.crt" ] \
            || die "PKI_MODE=external, but $(host_path "$PKI/ca-bundle.crt") is missing: put the CA certificates every service must trust there"
        bundle_add "$PKI/ca-bundle.crt"
        return 0
    fi
    bundle_add "$CA/active/ca.crt"
    bundle_add "$CA/active/chain.crt"
    if [ -d "$CA/next" ]; then
        bundle_add "$CA/next/ca.crt"
        bundle_add "$CA/next/chain.crt"
    fi
    if [ -d "$CA/retired" ]; then
        for bb_crt in "$CA"/retired/*.crt; do
            [ -f "$bb_crt" ] || continue
            bb_until="$(cat "${bb_crt%.crt}.until" 2>/dev/null || echo 0)"
            if [ "$bb_until" -le "$NOW" ]; then
                log "Removing the retired CA '$(subject_of "$bb_crt")' from the bundle: its last certificate has expired."
                rm -f "$bb_crt" "${bb_crt%.crt}.until" "${bb_crt%.crt}.chain" "${bb_crt%.crt}.source"
                continue
            fi
            bundle_add "$bb_crt"
            # An imported CA's issuers up to its root: without them a verifier that needs a
            # self-signed anchor rejects the leaves it signed.
            bundle_add "${bb_crt%.crt}.chain"
        done
    fi
}

# The intermediates a leaf carries after itself: the issuing CA unless it is a root, then
# every certificate of its chain that is not a root.
build_intermediates() {
    : > "$TMP/intermediates.crt"
    self_signed "$CA/active/ca.crt" || cat "$CA/active/ca.crt" >> "$TMP/intermediates.crt"
    if [ -s "$CA/active/chain.crt" ]; then
        bi_count="$(split_pem "$CA/active/chain.crt" "$TMP/chain")"
        bi_i=1
        while [ "$bi_i" -le "$bi_count" ]; do
            self_signed "$TMP/chain.$bi_i.pem" || cat "$TMP/chain.$bi_i.pem" >> "$TMP/intermediates.crt"
            rm -f "$TMP/chain.$bi_i.pem"
            bi_i=$((bi_i + 1))
        done
    fi
}

# ─────────────────────────────────────────────────────────────────────────
# leaves
# ─────────────────────────────────────────────────────────────────────────

# Signs a new leaf. $1 server|client, $2 service, $3 comma-separated DNS names, $4 output
# prefix ($4.key, $4.crt with the intermediates after the leaf).
sign_leaf() {
    sl_kind="$1" sl_service="$2" sl_dns="$3" sl_out="$4"
    # A leaf never outlives the CA that signs it: shortened to the CA's end, and refused
    # once less than a day is left.
    sl_days="$LEAF_DAYS"
    sl_ca_end="$(cert_epoch "$CA/active/ca.crt" end)" || die "cannot read the end date of the issuing CA"
    sl_left=$(( (sl_ca_end - $(date -u +%s)) / 86400 ))
    [ "$sl_left" -ge 1 ] || die "the issuing CA ends within a day; replace it with 'papaia-ctl pki rotate-ca'"
    if [ "$sl_left" -lt "$sl_days" ]; then
        log "The issuing CA ends in $sl_left days: the $sl_kind certificate of $sl_service ends with it."
        sl_days="$sl_left"
    fi
    ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$sl_out.key" \
        || die "could not create a key for $sl_service"
    ossl req -new -key "$sl_out.key" -subj "/CN=$sl_service" -out "$TMP/leaf.csr" \
        || die "could not create a request for $sl_service"
    {
        echo "basicConstraints=critical,CA:FALSE"
        echo "keyUsage=critical,digitalSignature"
        echo "subjectKeyIdentifier=hash"
        echo "authorityKeyIdentifier=keyid"
        if [ "$sl_kind" = server ]; then
            echo "extendedKeyUsage=serverAuth"
            sl_names=""
            sl_ifs="$IFS"; IFS=,
            for sl_name in $sl_dns localhost; do
                case ",$sl_names," in *",DNS:$sl_name,"*) continue ;; esac
                sl_names="${sl_names:+$sl_names,}DNS:$sl_name"
            done
            IFS="$sl_ifs"
            echo "subjectAltName=$sl_names,IP:127.0.0.1"
        else
            echo "extendedKeyUsage=clientAuth"
        fi
    } > "$TMP/leaf.ext"
    ossl x509 -req -in "$TMP/leaf.csr" -CA "$CA/active/ca.crt" -CAkey "$CA/active/ca.key" \
        -set_serial "0x$(openssl rand -hex 16)" -days "$sl_days" -extfile "$TMP/leaf.ext" \
        -out "$TMP/leaf.crt" \
        || die "could not sign the $sl_kind certificate of $sl_service"
    cat "$TMP/leaf.crt" "$TMP/intermediates.crt" > "$sl_out.crt"
    sl_purpose=sslserver
    [ "$sl_kind" = client ] && sl_purpose=sslclient
    ossl verify -CAfile "$TMP/bundle.crt" -untrusted "$sl_out.crt" -purpose "$sl_purpose" "$sl_out.crt" \
        || die "the new $sl_kind certificate of $sl_service does not verify against the bundle"
}

# Checks a provided leaf. $1 certificate, $2 key, $3 server|client, $4 service, $5 DNS names.
check_leaf() {
    cl_crt="$1" cl_key="$2" cl_kind="$3" cl_service="$4" cl_dns="$5"
    if [ ! -s "$cl_crt" ] || [ ! -s "$cl_key" ]; then
        problem "$(host_path "$cl_crt") or $(host_path "$cl_key") is missing"
        return 0
    fi
    cl_purpose=sslserver
    [ "$cl_kind" = client ] && cl_purpose=sslclient
    if ! openssl verify -CAfile "$TMP/bundle.crt" -untrusted "$cl_crt" -purpose "$cl_purpose" "$cl_crt" >/dev/null 2>&1; then
        problem "$(host_path "$cl_crt") does not verify against ca-bundle.crt for $cl_purpose (another CA, no extendedKeyUsage for it, or expired)"
        return 0
    fi
    same_key "$cl_crt" "$cl_key" || problem "$(host_path "$cl_key") does not belong to $(host_path "$cl_crt")"
    if [ "$cl_kind" = server ]; then
        cl_ifs="$IFS"; IFS=,
        for cl_name in $cl_dns; do
            openssl x509 -in "$cl_crt" -noout -checkhost "$cl_name" 2>/dev/null | grep -q "does match" \
                || problem "$(host_path "$cl_crt") has no subjectAltName DNS:$cl_name"
        done
        IFS="$cl_ifs"
    else
        [ "$(cn_of "$cl_crt")" = "$cl_service" ] \
            || problem "$(host_path "$cl_crt") must have the subject CN=$cl_service, not '$(cn_of "$cl_crt")'"
    fi
}

# Brings one service's directory to what is requested. $1 module, $2 service, $3 uid,
# $4 DNS names, $5 1 for a client certificate.
sync_service() {
    module="$1" service="$2" uid="$3" dns="$4" client="$5"
    dir="$PKI/$module/$service"
    state="$CA/state/$module/$service"
    mkdir -p "$PKI/$module" "$state" "$dir"
    mode "$PKI/$module" 755
    staged="$TMP/staged"
    rm -rf "$staged"
    mkdir -p "$staged"
    changed=0

    old_request="$(cat "$state/request" 2>/dev/null || true)"
    old_uid="$(printf '%s' "$old_request" | cut -f1)"
    old_dns="$(printf '%s' "$old_request" | cut -f2)"
    old_client="$(printf '%s' "$old_request" | cut -f3)"

    if [ "$MODE" = external ]; then
        # Checked for every service before anything is written (cmd_sync); here only what
        # changed since the last run.
        sum="$(cat "$dir/tls.crt" "$dir/tls.key" "$dir/client.crt" "$dir/client.key" \
            "$TMP/bundle.crt" 2>/dev/null | sha256sum | cut -d' ' -f1)"
        if [ "$sum" != "$(cat "$state/sum" 2>/dev/null || true)" ]; then
            changed=1
        fi
        printf '%s\n' "$sum" > "$state/sum"
    else
        again=0
        if [ "$FORCE" = 1 ] || [ "$(cat "$state/issuer" 2>/dev/null || true)" != "$ISSUER" ]; then
            again=1
        fi
        if [ -n "$dns" ]; then
            if [ "$again" = 1 ] || [ "$dns" != "$old_dns" ] || [ ! -s "$dir/tls.crt" ] \
                || [ ! -s "$dir/tls.key" ] || due "$dir/tls.crt"; then
                sign_leaf server "$service" "$dns" "$staged/tls"
            fi
        elif [ -e "$dir/tls.crt" ] || [ -e "$dir/tls.key" ]; then
            rm -f "$dir/tls.crt" "$dir/tls.key"
            changed=1
        fi
        if [ "$client" = 1 ]; then
            if [ "$again" = 1 ] || [ "$old_client" != 1 ] || [ ! -s "$dir/client.crt" ] \
                || [ ! -s "$dir/client.key" ] || due "$dir/client.crt"; then
                sign_leaf client "$service" "" "$staged/client"
            fi
        elif [ -e "$dir/client.crt" ] || [ -e "$dir/client.key" ]; then
            rm -f "$dir/client.crt" "$dir/client.key"
            changed=1
        fi
    fi

    # Keys before certificates, the CA bundle after them, the generation last: a reader
    # never sees a partly written file, and a changed generation means the rest is done.
    for name in tls.key client.key; do
        if [ -f "$staged/$name" ]; then
            install_file "$staged/$name" "$dir/$name" "$uid" 0400
            changed=1
        fi
    done
    for name in tls.crt client.crt; do
        if [ -f "$staged/$name" ]; then
            install_file "$staged/$name" "$dir/$name" "$uid" 0444
            changed=1
        fi
    done
    if ! cmp -s "$TMP/bundle.crt" "$dir/ca.crt"; then
        install_file "$TMP/bundle.crt" "$dir/ca.crt" "$uid" 0444
        changed=1
    fi
    if [ "$old_uid" != "$uid" ]; then
        changed=1
    fi

    # Owner and modes of what is there, also of files someone else put there.
    for name in tls.key client.key; do
        if [ -f "$dir/$name" ]; then
            own "$dir/$name" "$uid" 400
        fi
    done
    for name in tls.crt client.crt ca.crt; do
        if [ -f "$dir/$name" ]; then
            own "$dir/$name" "$uid" 444
        fi
    done

    generation="$(cat "$dir/generation" 2>/dev/null || echo 0)"
    case "$generation" in ''|*[!0-9]*) generation=0 ;; esac
    if [ "$changed" = 1 ] || [ ! -f "$dir/generation" ]; then
        generation=$((generation + 1))
        printf '%s\n' "$generation" > "$TMP/generation"
        install_file "$TMP/generation" "$dir/generation" "$uid" 0444
        echo "$module" >> "$TMP/changed"
        echo "service $module $service" >> "$TMP/services"
    fi
    own "$dir" "$uid" 500

    printf '%s\n' "$uid$TAB$dns$TAB$client" > "$state/request"
    if [ "$MODE" = issue ]; then
        printf '%s\n' "$ISSUER" > "$state/issuer"
    fi

    # One inventory entry per service, joined into inventory.json at the end.
    {
        printf '    {"module": %s, "name": %s, "uid": %s, "generation": %s' \
            "$(json_str "$module")" "$(json_str "$service")" "$uid" "$generation"
        if [ -n "$dns" ] && [ -s "$dir/tls.crt" ]; then
            printf ', "server": {"dns": ['
            first=1
            old_ifs="$IFS"; IFS=,
            for name in $dns; do
                [ "$first" = 1 ] || printf ', '
                json_str "$name"
                first=0
            done
            IFS="$old_ifs"
            printf '], "not_after": "%s"}' "$(iso_of "$(cert_epoch "$dir/tls.crt" end)")"
        fi
        if [ "$client" = 1 ] && [ -s "$dir/client.crt" ]; then
            printf ', "client": {"cn": %s, "not_after": "%s"}' "$(json_str "$service")" \
                "$(iso_of "$(cert_epoch "$dir/client.crt" end)")"
        fi
        printf '}'
    } > "$TMP/inv.$module.$service"
    echo "$TMP/inv.$module.$service" >> "$TMP/inventory.parts"
}

# Removes what was issued for a service that is no longer requested.
prune() {
    [ -d "$CA/state" ] || return 0
    for state in "$CA"/state/*/*; do
        [ -d "$state" ] || continue
        service="$(basename "$state")"
        module="$(basename "$(dirname "$state")")"
        grep -qx "$module/$service" "$TMP/wanted" 2>/dev/null && continue
        if [ "$MODE" = issue ]; then
            log "Removing the certificates of $module/$service: no longer requested."
            rm -rf "${PKI:?}/$module/$service"
            rmdir "$PKI/$module" 2>/dev/null || true
        fi
        rm -rf "$state"
        rmdir "$(dirname "$state")" 2>/dev/null || true
        echo "$module" >> "$TMP/changed"
    done
}

ca_entry() {
    # $1 certificate, $2 role (active, next, retired, trusted), $3 source (pki, enterprise,
    # external)
    printf '    {"subject": %s, "sha256": "%s", "not_after": "%s", "source": "%s", "role": "%s"}' \
        "$(json_str "$(subject_of "$1")")" "$(fingerprint "$1")" \
        "$(iso_of "$(cert_epoch "$1" end)")" "$3" "$2"
}

write_inventory() {
    {
        printf '{\n  "format": "papaia.platform-pki/1",\n'
        printf '  "generated_at": "%s",\n' "$(iso_of "$NOW")"
        printf '  "mode": "%s",\n' "$MODE"
        printf '  "ca": [\n'
        wi_first=1
        if [ "$MODE" = external ]; then
            wi_count="$(split_pem "$TMP/bundle.crt" "$TMP/inv-ca")"
            wi_i=1
            while [ "$wi_i" -le "$wi_count" ]; do
                [ "$wi_first" = 1 ] || printf ',\n'
                ca_entry "$TMP/inv-ca.$wi_i.pem" trusted external
                wi_first=0
                wi_i=$((wi_i + 1))
            done
        else
            ca_entry "$CA/active/ca.crt" active "$(cat "$CA/active/source" 2>/dev/null || echo pki)"
            if [ -d "$CA/next" ]; then
                printf ',\n'
                ca_entry "$CA/next/ca.crt" next "$(cat "$CA/next/source" 2>/dev/null || echo pki)"
            fi
            for wi_crt in "$CA"/retired/*.crt; do
                [ -f "$wi_crt" ] || continue
                printf ',\n'
                ca_entry "$wi_crt" retired "$(cat "${wi_crt%.crt}.source" 2>/dev/null || echo pki)"
            done
        fi
        printf '\n  ],\n  "services": [\n'
        wi_first=1
        if [ -s "$TMP/inventory.parts" ]; then
            while IFS= read -r wi_part; do
                [ "$wi_first" = 1 ] || printf ',\n'
                cat "$wi_part"
                wi_first=0
            done < "$TMP/inventory.parts"
        fi
        printf '\n  ]\n}\n'
    } > "$TMP/inventory.json"
    # `generated_at` differs on every run; the file is replaced only when anything else did.
    if [ -f "$PKI/inventory.json" ] && [ "$(grep -v '"generated_at"' "$TMP/inventory.json")" = \
        "$(grep -v '"generated_at"' "$PKI/inventory.json")" ]; then
        return 0
    fi
    if ! cmp -s "$TMP/inventory.json" "$PKI/inventory.json"; then
        cp "$TMP/inventory.json" "$PKI/.inventory.json.new"
        chmod 0444 "$PKI/.inventory.json.new"
        mv -f "$PKI/.inventory.json.new" "$PKI/inventory.json"
    fi
}

# ─────────────────────────────────────────────────────────────────────────
# commands
# ─────────────────────────────────────────────────────────────────────────

cmd_sync() {
    [ -d "$PKI" ] || die "the PKI directory is not mounted at $PKI"
    if [ "$MODE" = issue ] && [ ! -s "$CA/active/ca.key" ]; then
        new_ca "$CA/active.new"
        mv "$CA/active.new" "$CA/active"
    fi
    build_bundle
    if [ "$MODE" = issue ]; then
        ISSUER="$(fingerprint "$CA/active/ca.crt")"
        build_intermediates
    fi
    if ! cmp -s "$TMP/bundle.crt" "$PKI/ca-bundle.crt"; then
        cp "$TMP/bundle.crt" "$PKI/.ca-bundle.crt.new"
        chmod 0444 "$PKI/.ca-bundle.crt.new"
        mv -f "$PKI/.ca-bundle.crt.new" "$PKI/ca-bundle.crt"
    fi
    mode "$PKI" 755

    : > "$TMP/wanted"
    : > "$TMP/inventory.parts"
    : > "$TMP/services"
    : > "$TMP/requests"
    if [ -f "$REQUESTS" ]; then
        while IFS="$TAB" read -r module service uid dns client; do
            [ -n "$module" ] || continue
            case "$module" in \#*) continue ;; esac
            # A tab is a whitespace separator to `read`, so an empty field would vanish.
            [ "$dns" = - ] && dns=""
            case "$module/$service" in
                */*/*|*[!a-z0-9._/-]*|.*|*/.*|*/) die "invalid request line: '$module $service'" ;;
            esac
            case "$uid" in ''|*[!0-9]*) die "invalid uid '$uid' for $module/$service" ;; esac
            case "$dns" in *[!a-z0-9.,-]*) die "invalid DNS names '$dns' for $module/$service" ;; esac
            case "${client:-0}" in 0|1) : ;; *) die "invalid client flag for $module/$service" ;; esac
            echo "$module/$service" >> "$TMP/wanted"
            printf '%s\t%s\t%s\t%s\t%s\n' "$module" "$service" "$uid" "${dns:--}" "${client:-0}" >> "$TMP/requests"
        done < "$REQUESTS"
    fi

    # Provided certificates are checked all at once and before anything is written: one
    # run names every problem, and a set with a problem changes nothing.
    if [ "$MODE" = external ]; then
        while IFS="$TAB" read -r module service uid dns client; do
            [ "$dns" = - ] && dns=""
            dir="$PKI/$module/$service"
            if [ -n "$dns" ]; then
                check_leaf "$dir/tls.crt" "$dir/tls.key" server "$service" "$dns"
            fi
            if [ "$client" = 1 ]; then
                check_leaf "$dir/client.crt" "$dir/client.key" client "$service" ""
            fi
        done < "$TMP/requests"
        if [ -s "$TMP/errors" ]; then
            log "These provided certificates cannot be used:"
            sed 's/^/  - /' "$TMP/errors" >&2
            exit 3
        fi
    fi

    while IFS="$TAB" read -r module service uid dns client; do
        [ "$dns" = - ] && dns=""
        sync_service "$module" "$service" "$uid" "$dns" "$client"
    done < "$TMP/requests"
    prune
    write_inventory
    sort -u "$TMP/changed" | sed 's/^/changed /'
    sort -u "$TMP/services"
}

cmd_stage_ca() {
    [ "$MODE" = issue ] || die "rotating the CA needs PKI_MODE=issue; with PKI_MODE=external the bundle is yours"
    rm -rf "$CA/next.new"
    if [ -d /import ]; then
        import_ca "$CA/next.new"
    else
        new_ca "$CA/next.new"
    fi
    if [ ! -s "$CA/active/ca.key" ]; then
        # Nothing issued yet: the new CA is the first one.
        mv "$CA/next.new" "$CA/active"
    else
        rm -rf "$CA/next"
        mv "$CA/next.new" "$CA/next"
        log "Staged the new CA; it is in every bundle from now on."
    fi
    cmd_sync
}

cmd_promote_ca() {
    [ "$MODE" = issue ] || die "rotating the CA needs PKI_MODE=issue"
    if [ ! -s "$CA/next/ca.key" ]; then
        # The first CA of an installation is active at once; there is nothing to replace.
        log "No CA is staged; nothing to promote."
        cmd_sync
        return 0
    fi
    mkdir -p "$CA/retired"
    old_fp="$(fingerprint "$CA/active/ca.crt")"
    cp "$CA/active/ca.crt" "$CA/retired/$old_fp.crt"
    # An imported CA keeps its issuers and its source: the bundle still leads its leaves to
    # their root, and the inventory still names it `enterprise`.
    if [ -s "$CA/active/chain.crt" ]; then
        cp "$CA/active/chain.crt" "$CA/retired/$old_fp.chain"
    fi
    cat "$CA/active/source" 2>/dev/null > "$CA/retired/$old_fp.source" || echo pki > "$CA/retired/$old_fp.source"
    # Its leaves live LEAF_DAYS at most; a day of margin for clocks and slow restarts.
    echo $((NOW + (LEAF_DAYS + 1) * 86400)) > "$CA/retired/$old_fp.until"
    rm -rf "$CA/active.old"
    mv "$CA/active" "$CA/active.old"
    mv "$CA/next" "$CA/active"
    rm -rf "$CA/active.old"
    log "The new CA is active; every certificate is issued again."
    cmd_sync
}

cmd_purge() {
    # Only what the PKI wrote: its files at the top and the module directories it issued
    # into, as its bookkeeping, the request list and the inventory name them. Anything else
    # in the directory stays.
    : > "$TMP/modules"
    for pg_state in "$CA"/state/*; do
        if [ -d "$pg_state" ]; then basename "$pg_state" >> "$TMP/modules"; fi
    done
    if [ -f "$REQUESTS" ]; then cut -f1 "$REQUESTS" >> "$TMP/modules"; fi
    if [ -f "$PKI/inventory.json" ]; then
        sed -n 's/^ *{"module": "\([^"]*\)".*/\1/p' "$PKI/inventory.json" >> "$TMP/modules"
    fi
    sort -u "$TMP/modules" > "$TMP/modules.sorted"
    while IFS= read -r pg_module; do
        case "$pg_module" in ''|.*|*/*|*[!a-z0-9._-]*) continue ;; esac
        if [ -d "$PKI/$pg_module" ]; then rm -rf "${PKI:?}/$pg_module"; fi
    done < "$TMP/modules.sorted"
    rm -f "$PKI/ca-bundle.crt" "$PKI/inventory.json" "$REQUESTS" \
        "$PKI/.ca-bundle.crt.new" "$PKI/.inventory.json.new"
    rm -rf "$CA/state"
    log "Removed the certificates in $(host_path "$PKI")."
    pg_left="$(ls -A "$PKI" 2>/dev/null | tr '\n' ' ')"
    if [ -n "$pg_left" ]; then
        log "Left in place, not written by the internal CA: $pg_left"
    fi
}

mkdir -p "$CA"
exec 9>"$CA/.lock"
flock 9

case "${1:-sync}" in
    sync) cmd_sync ;;
    stage-ca) cmd_stage_ca ;;
    promote-ca) cmd_promote_ca ;;
    purge) cmd_purge ;;
    *) die "unknown command '${1:-}' (sync, stage-ca, promote-ca, purge)" ;;
esac
