#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# papAIa — sync-config.sh
#
# Populates the externalised configuration directory (PAPAIA_CONFIG_DIR)
# with the shipped defaults from src/. Idempotent and non-destructive:
# existing files in the target are left untouched so customer edits survive
# repeated runs and repo upgrades.
#
# Usage:
#   src/sync-config.sh                  # target = $PAPAIA_CONFIG_DIR from src/.env
#   src/sync-config.sh /custom/path     # target = explicit path
#   src/sync-config.sh --force          # overwrite existing files (DESTRUCTIVE
#                                       # — discards customer edits)
#
# Files that are mirrored (mirrors the bind-mount list in the per-service
# docker-compose.yml files):
#
#   ai/librechat/librechat.yaml
#   ai/litellm/{config.yaml,prometheus.yml}
#   ai/localai/models.txt
#   ai/n8n/nginx.conf
#   infra/keycloak/keycloak.conf
#   infra/keycloak/realm-import/         (entire directory)
#   services/homepage/config/            (entire directory)
#   services/searxng/settings.yml
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

FORCE=0
TARGET_ARG=""
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        -h|--help)
            sed -n '2,33p' "$0"
            exit 0
            ;;
        -*)
            echo "Unknown option: $arg" >&2
            exit 2
            ;;
        *)
            if [ -n "$TARGET_ARG" ]; then
                echo "Too many positional arguments." >&2
                exit 2
            fi
            TARGET_ARG="$arg"
            ;;
    esac
done

# Resolve target directory: explicit arg > PAPAIA_CONFIG_DIR from src/.env
if [ -n "$TARGET_ARG" ]; then
    TARGET="$TARGET_ARG"
elif [ -f "$SCRIPT_DIR/.env" ]; then
    TARGET="$(grep -E '^[[:space:]]*PAPAIA_CONFIG_DIR=' "$SCRIPT_DIR/.env" \
                | tail -n1 | cut -d= -f2- | tr -d '"' | tr -d "'")"
fi

if [ -z "${TARGET:-}" ]; then
    echo "ERROR: target directory not given and PAPAIA_CONFIG_DIR not set in" \
         "src/.env." >&2
    echo "Usage: $0 [/absolute/path] [--force]" >&2
    exit 1
fi

case "$TARGET" in
    /*|[A-Za-z]:/*|[A-Za-z]:\\*) ;;   # absolute (POSIX or Windows-style)
    *)
        echo "ERROR: PAPAIA_CONFIG_DIR must be an absolute path." \
             "Got: $TARGET" >&2
        exit 1
        ;;
esac

echo "Source: $SCRIPT_DIR"
echo "Target: $TARGET"
if [ "$FORCE" -eq 1 ]; then
    echo "Mode:   --force (existing target files will be OVERWRITTEN)"
else
    echo "Mode:   non-destructive (existing target files are kept)"
fi
echo

mkdir -p "$TARGET"

# Files (and a few directories) to mirror — relative to src/.
FILES=(
    "ai/librechat/librechat.yaml"
    "ai/litellm/config.yaml"
    "ai/litellm/prometheus.yml"
    "ai/localai/models.txt"
    "ai/n8n/nginx.conf"
    "infra/keycloak/keycloak.conf"
    "services/searxng/settings.yml"
)

# Whole-directory trees to mirror (recursive).
DIRS=(
    "infra/keycloak/realm-import"
    "services/homepage/config"
    "ai/localai/models"
)

copied=0
skipped=0
missing_src=0

copy_one() {
    local rel="$1"
    local src="$SCRIPT_DIR/$rel"
    local dst="$TARGET/$rel"

    if [ ! -e "$src" ]; then
        echo "  [missing-source]  $rel"
        missing_src=$((missing_src + 1))
        return
    fi

    mkdir -p "$(dirname "$dst")"

    if [ -e "$dst" ] && [ "$FORCE" -ne 1 ]; then
        echo "  [keep-existing]   $rel"
        skipped=$((skipped + 1))
        return
    fi

    if [ -d "$src" ]; then
        cp -R "$src/." "$dst/"
    else
        cp "$src" "$dst"
    fi
    echo "  [copied]          $rel"
    copied=$((copied + 1))
}

for f in "${FILES[@]}";  do copy_one "$f"; done
for d in "${DIRS[@]}";   do copy_one "$d"; done

echo
echo "Done. copied=$copied  kept=$skipped  missing-source=$missing_src"
echo
echo "Restart the affected services to pick up changes, e.g.:"
echo "    docker compose -f $SCRIPT_DIR/docker-compose.yml --env-file $SCRIPT_DIR/.env up -d --force-recreate <service>"
