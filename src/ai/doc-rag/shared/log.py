"""
Shared structured JSON logging for all doc-rag services.

Usage:
    from shared.log import configure
    configure("ingester")          # call once at module top-level
    log = logging.getLogger(__name__)
"""

import json
import logging


class _JsonFormatter(logging.Formatter):
    def __init__(self, service: str) -> None:
        super().__init__()
        self._service = service

    def format(self, record: logging.LogRecord) -> str:
        obj: dict = {
            "ts":      self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level":   record.levelname,
            "service": self._service,
            "msg":     record.getMessage(),
        }
        if record.exc_info:
            obj["exc"] = self.formatException(record.exc_info)
        return json.dumps(obj, ensure_ascii=False)


def configure(service: str) -> None:
    """Configure JSON structured logging globally for the given service name."""
    handler = logging.StreamHandler()
    handler.setFormatter(_JsonFormatter(service))
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
