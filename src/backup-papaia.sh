#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# papAIa — backup-papaia.sh
#
# Backs up every named Docker volume to gzipped tarballs. Also includes the
# externalised configuration directory (PAPAIA_CONFIG_DIR) if it is set in
# src/.env — customer-specific service config is otherwise outside the
# repo and would not be captured by a normal volume backup.
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="/var/backups/papAIa"
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
TARGET="$BACKUP_DIR/$DATE"

echo "=== Docker Volume Backup started: $DATE ==="

# Create backup directory
mkdir -p "$TARGET"

# Backup all volumes
for VOLUME in $(docker volume ls -q); do
    echo "Backup volume: $VOLUME"

    docker run --rm \
        -v ${VOLUME}:/volume:ro \
        -v ${TARGET}:/backup \
        alpine \
        tar czf /backup/${VOLUME}.tar.gz -C /volume .
done

# Also archive the externalised config directory if it exists.
if [ -f "$SCRIPT_DIR/.env" ]; then
    CONFIG_DIR="$(grep -E '^[[:space:]]*PAPAIA_CONFIG_DIR=' "$SCRIPT_DIR/.env" \
                    | tail -n1 | cut -d= -f2- | tr -d '"' | tr -d "'")"
    if [ -n "${CONFIG_DIR:-}" ] && [ -d "$CONFIG_DIR" ]; then
        echo "Backup config dir: $CONFIG_DIR"
        tar czf "$TARGET/papaia-config.tar.gz" -C "$CONFIG_DIR" .
    else
        echo "Skip config dir: PAPAIA_CONFIG_DIR unset or directory missing."
    fi
fi

echo "Backup completed: $TARGET"

# Delete old backups (older than 14 days)
echo "Deleting old backups (older than 14 days)..."
find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -mtime +14 -exec rm -rf {} \;
echo "Cleanup completed."

echo "=== Finished ==="
