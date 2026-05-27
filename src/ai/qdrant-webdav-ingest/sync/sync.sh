#!/bin/sh
# -----------------------------------------------------------------------------
# qdrant-webdav-ingest / sync.sh
#
# Role:    Document source integration — WebDAV (multi-source).
# Purpose: One-way sync from one or more WebDAV servers into the shared
#          /data/docs/ volume. Each source lands in its own subdirectory,
#          which the ingester traverses to derive per-folder Qdrant
#          collections.
#
# Source configuration (N = 1, 2, 3, ...):
#   WEBDAV_N_NAME    Target subdirectory under /data/docs/, e.g. "nextcloud"
#   WEBDAV_N_URL     Full WebDAV base URL
#   WEBDAV_N_USER    Username
#   WEBDAV_N_PASS    Plaintext password or Nextcloud app password
#   WEBDAV_N_VENDOR  rclone vendor hint (default: "webdav"; use "nextcloud" for NC)
#
# Global:
#   SYNC_INTERVAL    Seconds between syncs per source (default: 60)
#
# Behavior:
#   - Pull-only: remote state is mirrored locally, including deletions
#   - Each source runs in a separate background loop
#   - Local changes are never synced back
#   - A failed sync is logged and retried on the next interval (non-fatal)
#
# Author: Fidonis GmbH
# -----------------------------------------------------------------------------
set -eu

INTERVAL="${SYNC_INTERVAL:-60}"
count=0
i=1

while true; do
    # Stop when no more WEBDAV_N_URL is set
    eval "URL=\${WEBDAV_${i}_URL:-}"
    [ -z "$URL" ] && break

    eval "NAME=\${WEBDAV_${i}_NAME:-}"
    eval "USER=\${WEBDAV_${i}_USER:-}"
    eval "PASS=\${WEBDAV_${i}_PASS:-}"
    eval "VENDOR=\${WEBDAV_${i}_VENDOR:-webdav}"

    [ -z "$NAME" ] && { echo "[sync] ERROR: WEBDAV_${i}_NAME is required."; exit 1; }
    [ -z "$USER" ] && { echo "[sync] ERROR: WEBDAV_${i}_USER is required."; exit 1; }
    [ -z "$PASS" ] && { echo "[sync] ERROR: WEBDAV_${i}_PASS is required."; exit 1; }

    # Each source runs in its own background subshell
    (
        OBSCURED=$(rclone obscure "$PASS")

        trap 'echo "[sync:'"$NAME"'] received TERM/INT, stopping."; exit 0' TERM INT

        while true; do
            echo "[sync:$NAME] syncing from $URL ..."
            if rclone sync ":webdav:/" "/data/docs/$NAME" \
                --webdav-url    "$URL" \
                --webdav-user   "$USER" \
                --webdav-pass   "$OBSCURED" \
                --webdav-vendor "$VENDOR" \
                --log-level     INFO \
                --transfers     4 \
                --checkers      4 \
                --exclude ".DS_Store" \
                --exclude "*.tmp" \
                --exclude "*.part"; then
                echo "[sync:$NAME] sync complete."
            else
                echo "[sync:$NAME] ERROR: sync failed — will retry in ${INTERVAL}s."
            fi
            sleep "$INTERVAL"
        done
    ) &

    count=$((count + 1))
    i=$((i + 1))
done

if [ "$count" -eq 0 ]; then
    echo "[sync] ERROR: No WebDAV sources configured."
    echo "[sync]   At minimum, set: WEBDAV_1_NAME, WEBDAV_1_URL, WEBDAV_1_USER, WEBDAV_1_PASS"
    exit 1
fi

echo "[sync] $count source(s) started. Interval: ${INTERVAL}s. Waiting..."
wait
