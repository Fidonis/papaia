"""What `doctor` learns about the modules of the platform catalog (PLT-42, BE-26, RE-56).

Three reads, nothing written:

  * the catalog `$PAPAIA_CONFIG_DIR/platform/services.json` (lib/catalog.py): which
    module offers which entry, in which version and state, at which internal address;
  * `GET /healthz` and `GET /metrics` of every running entry with an address, asked from
    inside the network the module lives on. The core reaches no module network itself, so
    one short-lived probe container per network does it: the pinned papaia-manager image
    (it carries Python), read-only file system, no capabilities, no volume, no published
    port, never pulled, removed when it exits. It runs `PROBE`, which sends two GET
    requests per address without a token, follows no redirect, uses no proxy and prints
    only the status codes, the `/healthz` body (at most 4 KiB) and the values of the gauge
    `revocations_age_seconds`;
  * the membership of every attached core service in the add-on's app network
    (`docker network inspect`), which is the network path `networks.attach` promises.

`/healthz` answers in the kit form `healthz.v1`: `{"status": "ok" | "degraded" | "down"}`
and nothing else; `/metrics` carries `revocations_age_seconds` (kit contract, section
Health). Everything the probe prints is validated here before a check looks at it.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import catalog, common, deployment, gen_override, keycloak_admin_path

HEALTH_STATES = ("ok", "degraded", "down")
HEALTHZ_LIMIT = 4096
METRICS_LIMIT = 1024 * 1024
GAUGE_VALUES_LIMIT = 16
REQUEST_TIMEOUT_SECONDS = 5
# Per probe container: start, two requests per address, exit.
PROBE_TIMEOUT_SECONDS = 60.0
MAX_ENTRIES = 512
MAX_ORIGINS_PER_PROBE = 64
PROBE_LABEL_ROLE = "doctor-probe"
CORE_PROVIDER_PREFIX = "core:"

# BE-26 `revocations_age`: older than 60 s is `warn`, older than 300 s `fail`.
REVOCATIONS_WARN_SECONDS = 60
REVOCATIONS_FAIL_SECONDS = 300

_HOST = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")
_NAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9:._-]{0,127}\Z")
_ERROR = re.compile(r"\A[A-Za-z][A-Za-z0-9_]{0,63}\Z")
_NUMBER = re.compile(r"\A[0-9.eE+-]{1,32}\Z")
_NETWORK = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
# The catalog names a module by its compose service or container name (catalog._address):
# one DNS label with at least one letter and not a hex number, so it can be neither a
# dotted name outside the stack nor an address in any of the forms inet_aton accepts.
_SERVICE_HOST = re.compile(
    r"\A(?!0[xX][0-9A-Fa-f]*\Z)(?=[A-Za-z0-9-]*[A-Za-z])"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)

# Runs inside the probe container with `python3 -I -c`; argv[1] is the JSON list of origins.
PROBE = rf"""
import json, re, sys, urllib.error, urllib.request
GAUGE = re.compile(
    r"^revocations_age_seconds(?:\{{[^}}]{{0,512}}\}})?"
    r"[ \t]+([0-9.eE+-]{{1,32}})(?:[ \t]+-?[0-9]{{1,20}})?$"
)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
opener = urllib.request.build_opener(urllib.request.ProxyHandler({{}}), NoRedirect())
def get(url, limit):
    try:
        with opener.open(url, timeout={REQUEST_TIMEOUT_SECONDS}) as answer:
            return answer.status, answer.read(limit + 1), None
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, exc.read(limit + 1), None
        except Exception:
            return exc.code, b"", None
    except Exception as exc:
        reason = getattr(exc, "reason", None)
        cause = reason if isinstance(reason, BaseException) else exc
        return None, b"", type(cause).__name__[:64]
out = []
for origin in json.loads(sys.argv[1]):
    code, body, error = get(origin + "/healthz", {HEALTHZ_LIMIT})
    healthz = {{"code": code, "error": error, "body": None}}
    if len(body) <= {HEALTHZ_LIMIT}:
        healthz["body"] = body.decode("utf-8", "replace")
    code, body, error = get(origin + "/metrics", {METRICS_LIMIT})
    values = []
    if code == 200 and len(body) <= {METRICS_LIMIT}:
        for line in body.decode("utf-8", "replace").splitlines():
            found = GAUGE.match(line)
            if found and len(values) < {GAUGE_VALUES_LIMIT}:
                values.append(found.group(1))
    out.append({{"origin": origin, "healthz": healthz,
                "metrics": {{"code": code, "error": error, "values": values}}}})
print(json.dumps(out))
"""


class ModuleHealthError(Exception):
    """A catalog or a probe answer this module does not accept."""


@dataclass(frozen=True)
class Entry:
    id: str
    provider: str
    version: str
    state: str
    origin: str | None  # scheme://host:port of the internal address, or None


@dataclass
class Probe:
    """What one origin answered."""

    origin: str
    health: str | None = None  # ok | degraded | down, when the body is in the kit form
    healthz_code: int | None = None
    healthz_error: str | None = None
    healthz_form: bool = False
    metrics_code: int | None = None
    metrics_error: str | None = None
    revocations: list[float] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────
# catalog
# ─────────────────────────────────────────────────────────────────────────


def _origin(address: object, where: str) -> str:
    if not isinstance(address, str) or len(address) > 2048:
        raise ModuleHealthError(f"{where}: address is not a string")
    try:
        parts = urlsplit(address)
        port = parts.port
    except ValueError as exc:
        raise ModuleHealthError(f"{where}: address {address!r}: {exc}") from None
    host = parts.hostname or ""
    if (
        parts.scheme not in ("http", "https")
        or not _HOST.match(host)
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
    ):
        raise ModuleHealthError(f"{where}: address {address!r} is not http(s)://host[:port]/path")
    return f"{parts.scheme}://{host}" + (f":{port}" if port is not None else "")


def load_entries(config_dir: Path) -> list[Entry] | None:
    """The entries of `services.json`, or None while there is no catalog. Raises
    ModuleHealthError for a file that is not a catalog of the expected form."""
    path = catalog.platform_dir(config_dir, create=False) / catalog.SERVICES_FILE
    try:
        if not path.is_file():
            return None
        if path.stat().st_size > catalog.MAX_BYTES:
            raise ModuleHealthError(f"{path} is larger than {catalog.MAX_BYTES} bytes")
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ModuleHealthError(f"{path} cannot be read: {exc}") from None
    if not isinstance(doc, dict) or doc.get("format") != catalog.SERVICES_FORMAT:
        raise ModuleHealthError(f"{path} is not a {catalog.SERVICES_FORMAT} document")
    raw = doc.get("services")
    if not isinstance(raw, list) or len(raw) > MAX_ENTRIES:
        raise ModuleHealthError(f"{path}: services is not a list of at most {MAX_ENTRIES}")
    entries = []
    for index, item in enumerate(raw):
        where = f"{path.name}: services/{index}"
        if not isinstance(item, dict):
            raise ModuleHealthError(f"{where} is not an object")
        values = [item.get(key) for key in ("id", "provider", "version", "state")]
        if not all(isinstance(v, str) and _NAME.match(v) for v in values[:2]) or not (
            isinstance(values[2], str) and 0 < len(values[2]) <= 64
        ):
            raise ModuleHealthError(f"{where}: id, provider or version is not usable")
        if values[3] not in catalog.STATES:
            raise ModuleHealthError(f"{where}: state is not one of {', '.join(catalog.STATES)}")
        origin = _origin(item["address"], where) if "address" in item else None
        entries.append(Entry(values[0], values[1], values[2], values[3], origin))
    return entries


# ─────────────────────────────────────────────────────────────────────────
# networks
# ─────────────────────────────────────────────────────────────────────────


def core_network(config_dir: Path) -> str:
    env = common.parse_env_file(config_dir / ".env")
    return (env.get("DOCKER_NETWORK") or keycloak_admin_path.DEFAULT_NETWORK).strip()


@dataclass(frozen=True)
class Addon:
    name: str
    project: str  # the compose project: the directory name of the add-on
    manifest: dict
    network: str | None  # resolved networks.app_network
    attach: tuple[str, ...]


def active_addons(config_dir: Path, repo_root: Path) -> list[Addon]:
    """The active add-ons with their app network and attached core services. An add-on
    whose manifest cannot be read is left out here; `addon_compat` reports it."""
    found = []
    for entry in deployment.active_addons(deployment.load(config_dir) or {}):
        if not entry.get("name") or not entry.get("path"):
            continue
        path = deployment.resolve_addon_path(entry, repo_root)
        manifest, _ = deployment.load_addon_manifest(path)
        if manifest is None:
            continue
        networks = manifest.get("networks") or {}
        raw = networks.get("app_network") if isinstance(networks, dict) else None
        attach = networks.get("attach") if isinstance(networks, dict) else None
        network = (
            gen_override.resolve_app_network(raw, config_dir) if isinstance(raw, str) else None
        )
        found.append(
            Addon(
                str(entry["name"]),
                path.name,
                manifest,
                network if network and _NETWORK.match(network) else None,
                tuple(s for s in attach if isinstance(s, str)) if isinstance(attach, list) else (),
            )
        )
    return found


def parse_network_members(text: str) -> set[str]:
    """Container names from `docker network inspect --format '{{json .Containers}}'`."""
    doc = json.loads(text.strip() or "null")
    if doc is None:
        return set()
    if not isinstance(doc, dict):
        raise ValueError("not an object")
    names = set()
    for member in doc.values():
        name = member.get("Name") if isinstance(member, dict) else None
        if not isinstance(name, str):
            raise ValueError("member without a name")
        names.add(name)
    return names


# ─────────────────────────────────────────────────────────────────────────
# probe
# ─────────────────────────────────────────────────────────────────────────


def outside_the_stack(origin: str) -> str | None:
    """Why *origin* is not probed, or None for a compose service or container name.

    The catalog is rendered from add-on manifests; the probe runs on an internal network
    and only asks the modules of this stack, never a host a manifest names outside it."""
    host = urlsplit(origin).hostname or ""
    if _SERVICE_HOST.match(host):
        return None
    return f"{origin} not probed: {host} is not a compose service name"


def probe_argv(repo_root: Path, network: str, origins: list[str]) -> list[str]:
    """The `docker run` command line of one probe container on *network*."""
    if not _NETWORK.match(network):
        raise ModuleHealthError(f"{network!r} is not a network name")
    if not origins or len(origins) > MAX_ORIGINS_PER_PROBE:
        raise ModuleHealthError(f"between 1 and {MAX_ORIGINS_PER_PROBE} addresses per probe")
    for origin in origins:
        if _origin(origin, "probe") != origin:
            raise ModuleHealthError(f"{origin!r} is not an origin")
        refused = outside_the_stack(origin)
        if refused is not None:
            raise ModuleHealthError(refused)
    try:
        image = keycloak_admin_path.runner_image(repo_root)
    except keycloak_admin_path.AdminPathError as exc:
        raise ModuleHealthError(str(exc)) from None
    return [
        "docker", "run", "--rm", "--pull", "never",
        "--network", network,
        "--user", "65534:65534",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--memory", "64m",
        "--pids-limit", "32",
        "--label", "de.fidonis.module=papaia-ctl",
        "--label", f"de.fidonis.role={PROBE_LABEL_ROLE}",
        "--entrypoint", "python3",
        image,
        "-I", "-c", PROBE,
        json.dumps(origins),
    ]


def _code(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 599:
        raise ValueError("status code")
    return value


def _error(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _ERROR.match(value):
        raise ValueError("error name")
    return value


def health_state(body: object) -> str | None:
    """The state of a `/healthz` body in the kit form `healthz.v1`, else None."""
    if not isinstance(body, str):
        return None
    try:
        doc = json.loads(body)
    except ValueError:
        return None
    if isinstance(doc, dict) and set(doc) == {"status"} and doc["status"] in HEALTH_STATES:
        return doc["status"]
    return None


def parse_probe(text: str, origins: list[str]) -> dict[str, Probe]:
    """The probe's answer per origin. ValueError for anything not in the expected form."""
    doc = json.loads(text.strip().splitlines()[-1] if text.strip() else "")
    if not isinstance(doc, list) or [i.get("origin") if isinstance(i, dict) else None
                                     for i in doc] != origins:
        raise ValueError("not one answer per address")
    found = {}
    for item in doc:
        if set(item) != {"origin", "healthz", "metrics"}:
            raise ValueError("fields")
        healthz, metrics = item["healthz"], item["metrics"]
        if not isinstance(healthz, dict) or set(healthz) != {"code", "error", "body"}:
            raise ValueError("healthz")
        if not isinstance(metrics, dict) or set(metrics) != {"code", "error", "values"}:
            raise ValueError("metrics")
        body = healthz["body"]
        if body is not None and (not isinstance(body, str) or len(body) > HEALTHZ_LIMIT):
            raise ValueError("healthz body")
        values = metrics["values"]
        if not isinstance(values, list) or len(values) > GAUGE_VALUES_LIMIT:
            raise ValueError("gauge values")
        ages = []
        for value in values:
            if not isinstance(value, str) or not _NUMBER.match(value):
                raise ValueError("gauge value")
            number = float(value)
            if not math.isfinite(number) or number < 0:
                raise ValueError("gauge value")
            ages.append(number)
        state = health_state(body)
        found[item["origin"]] = Probe(
            origin=item["origin"],
            health=state,
            healthz_code=_code(healthz["code"]),
            healthz_error=_error(healthz["error"]),
            healthz_form=state is not None,
            metrics_code=_code(metrics["code"]),
            metrics_error=_error(metrics["error"]),
            revocations=ages,
        )
    return found


# ─────────────────────────────────────────────────────────────────────────
# verdicts
# ─────────────────────────────────────────────────────────────────────────


def health_verdict(probe: Probe, network: str) -> tuple[str, str]:
    """(pass | warn | fail, text) for the `/healthz` answer of one origin."""
    origin = probe.origin
    if probe.healthz_code is None:
        return "fail", (
            f"{origin} does not answer from network {network} "
            f"({probe.healthz_error or 'no answer'})"
            "; the network path is missing or the service is down"
        )
    if probe.health == "ok":
        return "pass", f"{origin} ok"
    if probe.health == "degraded":
        return "warn", f"{origin} reports degraded"
    if probe.health == "down":
        return "fail", f"{origin} reports down"
    if probe.healthz_code == 404:
        return "warn", f"{origin} serves no /healthz"
    if probe.healthz_code in (401, 403):
        return "warn", f"{origin} asks for sign-in on /healthz (HTTP {probe.healthz_code})"
    if probe.healthz_code >= 500:
        return "fail", f"{origin} answers /healthz with HTTP {probe.healthz_code}"
    return "warn", f"{origin} answers /healthz outside the kit form (HTTP {probe.healthz_code})"


def revocations_verdict(probe: Probe) -> tuple[str, str, float | None]:
    """(pass | warn | fail | skip, text, age) for `revocations_age_seconds` of one origin."""
    origin = probe.origin
    if probe.metrics_code is None:
        reason = probe.metrics_error or "no answer"
        return "warn", f"{origin}: /metrics cannot be read ({reason})", None
    if probe.metrics_code in (401, 403):
        return "skip", f"{origin}: /metrics needs the operations token", None
    if probe.metrics_code != 200:
        return "warn", f"{origin}: /metrics answers HTTP {probe.metrics_code}", None
    if not probe.revocations:
        return "warn", f"{origin} does not report revocations_age_seconds", None
    age = max(probe.revocations)
    shown = f"{age:.0f} s"
    if age > REVOCATIONS_FAIL_SECONDS:
        return "fail", (
            f"{origin}: revocation list {shown} old (more than {REVOCATIONS_FAIL_SECONDS} s); "
            "locked accounts may still be accepted"
        ), age
    if age > REVOCATIONS_WARN_SECONDS:
        return "warn", f"{origin}: revocation list {shown} old", age
    return "pass", f"{origin}: revocation list {shown} old", age
