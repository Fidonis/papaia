#!/bin/bash

# Usage:
# ./restore_docker_volume.sh <volume_name> <backup_file.tar.gz>

VOLUME_NAME="$1"
BACKUP_FILE="$2"

if [ -z "$VOLUME_NAME" ] || [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <volume_name> <backup_file.tar.gz>"
    exit 1
fi

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file does not exist: $BACKUP_FILE"
    exit 1
fi

echo "=== Restore gestartet ==="
echo "Volume: $VOLUME_NAME"
echo "Backup: $BACKUP_FILE"

# Create volume if it doesn't exist, otherwise warn that it will be overwritten
if ! docker volume inspect "$VOLUME_NAME" >/dev/null 2>&1; then
    echo "Volume will be created: $VOLUME_NAME"
    docker volume create "$VOLUME_NAME"
else
    echo "Volume exists - content will be overwritten."
fi

# Restore durchführen
docker run --rm \
  -v "${VOLUME_NAME}:/volume" \
  -v "$(dirname "$BACKUP_FILE"):/backup" \
  alpine \
  sh -c "rm -rf /volume/* && tar xzf /backup/$(basename "$BACKUP_FILE") -C /volume"

echo "=== Restore completed ==="
