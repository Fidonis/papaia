"""The communication matrix: every connection the installation makes or accepts.

`security/comm-matrix.yaml` is the one source (docs/network.md). This module validates
it strictly (unknown fields, a missing `via` on a row that leaves the stack and a
direct route other than K-12, K-14 and K-15 are errors) and turns its outbound and host
rows into the routes of this installation for `papaia-ctl topology firewall`: the
addresses of the SQL source (K-14), the mail server (K-10), the corporate proxy (K-18)
and a model server outside the stack (K-20) where they are configured.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from . import egress, hosted_model, smtp, sql_uplink

MATRIX_FILE = Path("security") / "comm-matrix.yaml"
VERSION = 1
DIRECTIONS = ("inbound", "internal", "outbound", "host")
VIAS = ("egress", "direct")
PROTOCOLS = ("tcp", "udp", "file")
# The file system targets and the SQL source; everything else that leaves the stack
# goes through papaia-egress.
DIRECT_ROWS = ("K-12", "K-14", "K-15")
_REQUIRED = {
    "id",
    "direction",
    "from",
    "from_network",
    "to",
    "ports",
    "protocol",
    "purpose",
    "when",
    "required",
}
_OPTIONAL = {"via", "pending"}
_ID = re.compile(r"^K-\d{2}$")
_MAX_TEXT = 1000
_MAX_ROWS = 200

# Rows whose target this installation names in its configuration; listed only where set.
_CONFIGURED = ("K-10", "K-14", "K-18", "K-20")


class MatrixError(ValueError):
    """A matrix that cannot be used."""


def _text(row: dict, key: str) -> str:
    value = row[key]
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
        raise MatrixError(f"{row.get('id', '?')}: {key} must be a text of 1 to {_MAX_TEXT} chars")
    return value


def validate(doc: object) -> list[dict]:
    """The rows of a parsed matrix; raises MatrixError on anything unexpected."""
    if not isinstance(doc, dict) or set(doc) != {"version", "rows"}:
        raise MatrixError("the matrix must have exactly the fields version and rows")
    if doc["version"] != VERSION:
        raise MatrixError(f"unknown version {doc['version']!r}")
    rows = doc["rows"]
    if not isinstance(rows, list) or not rows or len(rows) > _MAX_ROWS:
        raise MatrixError(f"rows must be a list of 1 to {_MAX_ROWS} rows")
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise MatrixError("a row must be a mapping")
        unknown = sorted(set(row) - _REQUIRED - _OPTIONAL)
        missing = sorted(_REQUIRED - set(row))
        if unknown or missing:
            raise MatrixError(
                f"{row.get('id', '?')}: unknown field(s) {unknown}, missing field(s) {missing}"
            )
        row_id = row["id"]
        if not isinstance(row_id, str) or not _ID.match(row_id) or row_id in seen:
            raise MatrixError(f"bad or repeated id {row_id!r}")
        seen.add(row_id)
        for key in ("from", "from_network", "to", "purpose", "when"):
            _text(row, key)
        if row["direction"] not in DIRECTIONS:
            raise MatrixError(f"{row_id}: direction must be one of {', '.join(DIRECTIONS)}")
        if row["protocol"] not in PROTOCOLS:
            raise MatrixError(f"{row_id}: protocol must be one of {', '.join(PROTOCOLS)}")
        if not isinstance(row["required"], bool):
            raise MatrixError(f"{row_id}: required must be true or false")
        ports = row["ports"]
        if not isinstance(ports, list) or len(ports) > 16 or any(
            isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535 for p in ports
        ):
            raise MatrixError(f"{row_id}: ports must be a list of port numbers")
        if "pending" in row:
            _text(row, "pending")
        if row["direction"] == "outbound":
            if row.get("via") not in VIAS:
                raise MatrixError(f"{row_id}: a row that leaves the stack needs via: egress|direct")
            if row["via"] == "direct" and row_id not in DIRECT_ROWS:
                raise MatrixError(
                    f"{row_id}: only {', '.join(DIRECT_ROWS)} may leave the stack directly"
                )
        elif "via" in row:
            raise MatrixError(f"{row_id}: via belongs to rows that leave the stack only")
    return rows


def load(repo_root: Path) -> list[dict]:
    path = repo_root / MATRIX_FILE
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise MatrixError(f"{path}: {exc}") from exc
    try:
        return validate(doc)
    except MatrixError as exc:
        raise MatrixError(f"{path}: {exc}") from exc


def _route(row: dict, to: str, address: str, ports: list[int], network: str) -> dict:
    return {
        "id": row["id"],
        "from": row["from"],
        "from_network": network,
        "to": to,
        "to_address": address,
        "ports": ports,
        "protocol": row["protocol"],
        "via": row.get("via", "host"),
        "purpose": " ".join(row["purpose"].split()),
        "pending": " ".join(row.get("pending", "").split()),
    }


def _configured(row: dict, config_dir: Path, repo_root: Path) -> list[dict]:
    env = sql_uplink.root_env(config_dir)
    if row["id"] == "K-14":
        return [
            _route(
                row,
                f"{t['name']} ({t['catalog_entry']})",
                str(net),
                t["ports"],
                sql_uplink.NETWORK,
            )
            for t in sql_uplink.targets(config_dir)
            for net in t["networks"]
        ]
    if row["id"] == "K-10":
        relay = smtp.Settings.load(config_dir)
        if not relay.active:
            return []
        port = relay.port or smtp.DEFAULT_PORTS[relay.security]
        return [_route(row, row["to"], relay.host, [port], row["from_network"])]
    if row["id"] == "K-18":
        upstream = egress.upstream_proxy(env, config_dir)
        if upstream is None:
            return []
        return [
            _route(row, row["to"], upstream["host"], [upstream["port"]], row["from_network"])
        ]
    # K-20: a model route outside the stack.
    found = hosted_model.route(config_dir, hosted_model.rendered_stack_names(config_dir, repo_root))
    if found is None:
        return []
    host, port = found
    return [_route(row, row["to"], host, [port], hosted_model.network(env))]


def routes(config_dir: Path, repo_root: Path) -> list[dict]:
    """The outbound and host rows of this installation: the configured targets of K-10,
    K-14, K-18 and K-20 where they are set, the rows that always apply, and none of the
    rows still pending in this release."""
    found: list[dict] = []
    for row in load(repo_root):
        if row["direction"] not in ("outbound", "host"):
            continue
        if row["id"] in _CONFIGURED:
            found.extend(_configured(row, config_dir, repo_root))
        elif "pending" not in row:
            found.append(_route(row, row["to"], "", list(row["ports"]), row["from_network"]))
    return found


def format_routes(found: list[dict], host_rules: list[str], rules_file: Path, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(
            {
                "routes": found,
                "host_rules": host_rules,
                "rules_file": str(rules_file) if host_rules else "",
            },
            indent=2,
        )
    ports = [",".join(str(p) for p in r["ports"]) or "-" for r in found]
    if fmt == "csv":

        def cell(value: str) -> str:
            return '"' + value.replace('"', "'") + '"'

        lines = ["id,from,from_network,to,to_address,ports,protocol,via,pending"]
        lines += [
            ",".join(
                [
                    r["id"],
                    cell(r["from"]),
                    cell(r["from_network"]),
                    cell(r["to"]),
                    r["to_address"],
                    cell(p),
                    r["protocol"],
                    r["via"],
                    cell(r["pending"]),
                ]
            )
            for r, p in zip(found, ports, strict=True)
        ]
        return "\n".join(lines)
    header = ("ID", "FROM", "NETWORK", "TO", "ADDRESS", "PORTS", "VIA")
    rows = [
        (r["id"], r["from"], r["from_network"], r["to"], r["to_address"] or "-", p, r["via"])
        for r, p in zip(found, ports, strict=True)
    ]
    widths = [max([len(header[i])] + [len(row[i]) for row in rows]) for i in range(len(header))]
    out = ["  ".join(header[i].ljust(widths[i]) for i in range(len(header))).rstrip()]
    out += ["  ".join(row[i].ljust(widths[i]) for i in range(len(header))).rstrip() for row in rows]
    out.append("")
    if host_rules:
        out.append(
            f"Host rules ({sql_uplink.DOCKER_USER}), load as root with: sudo sh {rules_file}"
        )
        out += [f"  {rule}" for rule in host_rules]
    else:
        out.append("No host rules: there is no SQL source, so nothing leaves the stack directly.")
    return "\n".join(out)
