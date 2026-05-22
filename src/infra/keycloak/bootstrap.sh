#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# papAIa — Keycloak Bootstrap
# by Fidonis GmbH · https://fidonis.de
# ═══════════════════════════════════════════════════════════════════════════
# Idempotent Keycloak bootstrap — communicates with the running container
# via docker exec (no compose env files required).
# Safe to run on every start: only creates what is missing, never overwrites.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REALM_JSON="$SCRIPT_DIR/realm-import/papaia-realm.json"

# Read admin password from local .env; fall back to env var or default
KC_ADMIN_PASS=$(grep "^KC_ADMIN_PASSWORD=" "$SCRIPT_DIR/.env" 2>/dev/null | cut -d'=' -f2- || true)
KC_ADMIN_PASS="${KC_ADMIN_PASS:-${KC_ADMIN_PASSWORD:-password}}"

KC_CFG=/tmp/kc-bootstrap-cfg

# ---------------------------------------------------------------------------
# Find the Keycloak container by compose labels — no hardcoded names needed
KC_CONTAINER=$(docker ps \
    --filter "label=com.docker.compose.service=keycloak" \
    --filter "label=com.docker.compose.project=papaia" \
    --format "{{.ID}}" | head -1)

if [[ -z "$KC_CONTAINER" ]]; then
    echo "[keycloak-bootstrap] ERROR: No running Keycloak container found." >&2
    echo "[keycloak-bootstrap] Make sure the stack is up: docker compose -f src/docker-compose.yml up -d" >&2
    exit 1
fi

KCADM="docker exec -i $KC_CONTAINER /opt/keycloak/bin/kcadm.sh"

# ---------------------------------------------------------------------------
# Wait for Keycloak to be healthy (relies on the container's own healthcheck)
echo "[keycloak-bootstrap] Waiting for Keycloak to become healthy..."
until [ "$(docker inspect --format='{{.State.Health.Status}}' "$KC_CONTAINER")" == "healthy" ]; do
    sleep 5
done
echo "[keycloak-bootstrap] Keycloak healthy."

# ---------------------------------------------------------------------------
# Authenticate kcadm against the internal HTTP endpoint
echo "[keycloak-bootstrap] Authenticating as admin..."
$KCADM config credentials \
    --server http://localhost:8080 \
    --realm master \
    --user admin \
    --password "$KC_ADMIN_PASS" \
    --config "$KC_CFG"

# ---------------------------------------------------------------------------
# Disable SSL requirement on master realm
$KCADM update realms/master -s sslRequired=NONE --config "$KC_CFG"
echo "[keycloak-bootstrap] master realm: sslRequired=NONE"

# ---------------------------------------------------------------------------
# Import or sync realm
if $KCADM get realms/papaia --config "$KC_CFG" --fields realm > /dev/null 2>&1; then
    echo "[keycloak-bootstrap] Realm 'papaia' exists — syncing clients..."

    EXISTING_CLIENTS=$($KCADM get clients -r papaia --config "$KC_CFG" --fields clientId 2>/dev/null || echo "[]")

    python3 - "$REALM_JSON" "$EXISTING_CLIENTS" "$KC_CONTAINER" << 'PYEOF'
import json, sys, subprocess

realm_json_path = sys.argv[1]
existing_json_str = sys.argv[2]
container_id = sys.argv[3]

BUILTIN = {"account", "account-console", "admin-cli", "broker",
           "realm-management", "security-admin-console"}

with open(realm_json_path) as f:
    realm_def = json.load(f)

try:
    existing_ids = {c["clientId"] for c in json.loads(existing_json_str)}
except Exception:
    existing_ids = set()

ok = True
for client in realm_def.get("clients", []):
    cid = client["clientId"]
    if cid in BUILTIN:
        continue
    if cid in existing_ids:
        print(f"[keycloak-bootstrap]   {cid}: already exists — skipped")
        continue
    result = subprocess.run(
        ["docker", "exec", "-i", container_id,
         "/opt/keycloak/bin/kcadm.sh", "create", "clients",
         "-r", "papaia", "-f", "-", "--config", "/tmp/kc-bootstrap-cfg"],
        input=json.dumps(client), capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"[keycloak-bootstrap]   {cid}: created")
    else:
        print(f"[keycloak-bootstrap]   {cid}: ERROR — {result.stderr.strip()}", file=sys.stderr)
        ok = False

sys.exit(0 if ok else 1)
PYEOF

else
    echo "[keycloak-bootstrap] Realm 'papaia' not found — importing from JSON..."
    docker cp "$REALM_JSON" "$KC_CONTAINER:/tmp/papaia-realm.json"
    $KCADM create realms -f /tmp/papaia-realm.json --config "$KC_CFG"
    echo "[keycloak-bootstrap] Realm 'papaia' created."
fi

echo "[keycloak-bootstrap] Done."
