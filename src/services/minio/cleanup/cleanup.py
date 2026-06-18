#!/usr/bin/env python3
"""
MinIO Cleanup Service
=====================
Periodically deletes objects from a configured MinIO bucket/prefix
that exceed the configured retention period.

Configuration is done entirely via environment variables (see README).
"""

import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone

import boto3
from botocore.client import Config
from botocore.exceptions import BotoCoreError, ClientError

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-5s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("minio-cleanup")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def get_env(name: str, default: str | None = None, required: bool = False) -> str | None:
    value = os.environ.get(name, default)
    if required and not value:
        log.error("Required environment variable '%s' is not set.", name)
        sys.exit(1)
    return value


def load_config() -> dict:
    return {
        "endpoint":          get_env("MINIO_ENDPOINT",            "http://minio:9000"),
        "access_key":        get_env("MINIO_ACCESS_KEY",          required=True),
        "secret_key":        get_env("MINIO_SECRET_KEY",          required=True),
        "bucket":            get_env("CLEANUP_BUCKET",            required=True),
        "prefix":            get_env("CLEANUP_PREFIX",            ""),
        "retention_hours":   float(get_env("CLEANUP_RETENTION_HOURS",   "24")),
        "interval_seconds":  int(get_env("CLEANUP_INTERVAL_SECONDS",    "3600")),
        "dry_run":           get_env("CLEANUP_DRY_RUN",           "false").lower() == "true",
    }

# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------

_shutdown = False

def _handle_signal(signum, frame):
    global _shutdown
    log.info("Shutdown signal received (%s). Finishing current run …", signum)
    _shutdown = True

signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT,  _handle_signal)

# ---------------------------------------------------------------------------
# S3 client
# ---------------------------------------------------------------------------

def build_client(cfg: dict):
    """Build a boto3 S3 client configured for MinIO."""
    return boto3.client(
        "s3",
        endpoint_url=cfg["endpoint"],
        aws_access_key_id=cfg["access_key"],
        aws_secret_access_key=cfg["secret_key"],
        config=Config(
            signature_version="s3v4",
            connect_timeout=10,
            read_timeout=30,
            retries={"max_attempts": 3, "mode": "standard"},
        ),
    )

# ---------------------------------------------------------------------------
# Cleanup logic
# ---------------------------------------------------------------------------

def run_cleanup(client, cfg: dict) -> tuple[int, int, int]:
    """
    Perform one cleanup run.

    Returns:
        (scanned, deleted, errors)
    """
    bucket          = cfg["bucket"]
    prefix          = cfg["prefix"]
    retention_hours = cfg["retention_hours"]
    dry_run         = cfg["dry_run"]

    retention_seconds = retention_hours * 3600
    now               = datetime.now(tz=timezone.utc)
    scanned = deleted = errors = 0

    log.info(
        "=== Cleanup run started  bucket=%s  prefix=%r  retention=%.1fh  dry_run=%s ===",
        bucket, prefix, retention_hours, dry_run,
    )

    paginator = client.get_paginator("list_objects_v2")
    pages = paginator.paginate(Bucket=bucket, Prefix=prefix)

    for page in pages:
        for obj in page.get("Contents", []):
            scanned += 1
            key          = obj["Key"]
            last_modified = obj["LastModified"]  # already timezone-aware (UTC)
            age_seconds   = (now - last_modified).total_seconds()
            age_hours     = age_seconds / 3600

            if age_seconds >= retention_seconds:
                if dry_run:
                    log.info("[DRY-RUN] Would delete: %s  (age: %.1fh)", key, age_hours)
                    deleted += 1
                else:
                    try:
                        client.delete_object(Bucket=bucket, Key=key)
                        log.info("Deleted: %s  (age: %.1fh)", key, age_hours)
                        deleted += 1
                    except (BotoCoreError, ClientError) as exc:
                        log.error("Failed to delete %s: %s", key, exc)
                        errors += 1

    log.info(
        "=== Run complete: scanned=%d  deleted=%d  errors=%d ===",
        scanned, deleted, errors,
    )
    return scanned, deleted, errors


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    cfg = load_config()

    log.info(
        "MinIO Cleanup Service starting  endpoint=%s  bucket=%s  prefix=%r  "
        "retention=%.1fh  interval=%ds  dry_run=%s",
        cfg["endpoint"], cfg["bucket"], cfg["prefix"],
        cfg["retention_hours"], cfg["interval_seconds"], cfg["dry_run"],
    )

    if cfg["dry_run"]:
        log.warning("DRY-RUN mode is active — no objects will be deleted.")

    while not _shutdown:
        try:
            client = build_client(cfg)
            run_cleanup(client, cfg)
        except (BotoCoreError, ClientError) as exc:
            log.error("Cleanup run failed with S3 error: %s", exc)
        except Exception as exc:  # pylint: disable=broad-except
            log.error("Cleanup run failed with unexpected error: %s", exc, exc_info=True)

        if _shutdown:
            break

        log.info("Next run in %ds …", cfg["interval_seconds"])
        # Sleep in small increments so we can react to SIGTERM quickly
        for _ in range(cfg["interval_seconds"]):
            if _shutdown:
                break
            time.sleep(1)

    log.info("MinIO Cleanup Service stopped.")


if __name__ == "__main__":
    main()
