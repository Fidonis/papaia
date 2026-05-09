#!/bin/bash

BACKUP_DIR="/var/backups/home-server"
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

echo "Backup completed: $TARGET"

# Delete old backups (older than 14 days)
echo "Deleting old backups (older than 14 days)..."
find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -mtime +14 -exec rm -rf {} \;
echo "Cleanup completed."

echo "=== Finished ==="
