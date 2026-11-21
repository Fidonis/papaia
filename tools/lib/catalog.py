"""The platform catalog: `$PAPAIA_CONFIG_DIR/platform/services.json` and `groups.json`.

`papaia-ctl catalog render` (and every `setup`, `start` and `addon` operation, which
render the configuration) writes the catalog from the `exposes:` declarations of the
installed add-ons and of the active core profiles (`exposes.yaml` next to the profile's
compose file). Format and rules come from papaia-kit, whose schemas are vendored under
tools/schemas/kit:

- `services.json` (`papaia.platform-services/1`): one entry per declared surface with
  `provider`, `version`, `state` (`running`/`stopped`, set by `addon start|stop`),
  `trust`, the resolved internal `address`, the public address of each interface and a
  `content_hash` (SHA-256 over the RFC 8785 form of the entry). Installed add-ons stay in
  the catalog while stopped; add-ons that are not installed are absent. Fields that
  serve the core alone (`service_accounts`, `storage`, `requires`, ...) stay out: the
  catalog is mounted into every consuming module. On top: `identity`, `branding`,
  `platform_notices` and the model aliases.
- `groups.json` (`papaia.platform-groups/1`): the realm's groups with `id`, `path`,
  `display_name` and `technical` only, written by `realm sync` from the identity
  provider; no member lists, no personal data.

Both files are written atomically (temporary file, rename), mode 0644 in a 0755
directory, because modules mount `platform/` read-only and read it under their own uid.
The catalog is the only writer's view and is checked against the schema before it is
written; a declaration or a result that does not pass leaves the files unchanged. A
file is rewritten only when its content changed, and every write leaves one
`papaia.audit/1` row. The catalog is an offer, not a permission.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import yaml

from . import common, compat, deployment, exposes, hosted_model, schema_check, semver, suite

logger = logging.getLogger(__name__)

CATALOG_DIR = "platform"
SERVICES_FILE = "services.json"
GROUPS_FILE = "groups.json"
LOGO_FILE = "brand-logo"
SERVICES_FORMAT = "papaia.platform-services/1"
GROUPS_FORMAT = "papaia.platform-groups/1"
MAX_BYTES = 1024 * 1024

# Core profiles that declare catalog entries: profile -> directory holding its
# exposes.yaml and the docker-compose.yml its `address.service` names.
CORE_PROFILES: dict[str, str] = {
    "rag": "src/ai/rag",
}

BRANDING_OVERLAY = "overlay/platform/branding.yaml"
LOGO_OVERLAY = "overlay/platform/brand-logo"
DEFAULT_BRAND_NAME = "papAIa"

RUNNING = "running"
STOPPED = "stopped"
STATES = (RUNNING, STOPPED)

TEST_MODE_NOTICE = {
    "id": "test-mode",
    "level": "warning",
    "text": {
        "de": "Testbetrieb mit externem Modell.",
        "en": "Test mode with an external model.",
    },
}

SECURITY_PROFILES = ("standard", "kritis")
TEXT_LIMIT = 200  # characters per language of a catalog text
WRITER = "papaia-ctl/catalog"
GROUP_PAGE = 100


class CatalogError(Exception):
    """The catalog cannot be rendered; the files stay as they were."""


# ─────────────────────────────────────────────────────────────────────────
# canonical form (RFC 8785) and content hash
# ─────────────────────────────────────────────────────────────────────────

_EXACT_INT = 2**53


def canonical_json(value: object) -> bytes:
    """The RFC 8785 (JSON Canonicalization Scheme) form of `value` as UTF-8."""
    out: list[str] = []
    _canonical(value, out)
    try:
        return "".join(out).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("a string with a lone surrogate has no canonical form") from exc


def content_hash(entry: dict) -> str:
    """`sha256:<hex>` over the canonical form of `entry` without `content_hash`."""
    body = {key: value for key, value in entry.items() if key != "content_hash"}
    return "sha256:" + hashlib.sha256(canonical_json(body)).hexdigest()


def _canonical(value: object, out: list[str]) -> None:
    if value is None or isinstance(value, bool):
        out.append({None: "null", True: "true", False: "false"}[value])
    elif isinstance(value, int):
        if abs(value) > _EXACT_INT and int(float(value)) != value:
            raise ValueError("an integer outside the exact range of a double")
        out.append(str(value) if abs(value) <= _EXACT_INT else _double(float(value)))
    elif isinstance(value, float):
        out.append(_double(value))
    elif isinstance(value, str):
        # json.dumps escapes exactly what RFC 8785 escapes: quote, backslash and the
        # control characters (\b \t \n \f \r short, the others as lower-case \u00xx).
        out.append(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        out.append("{")
        for index, key in enumerate(keys):
            if not isinstance(key, str):
                raise ValueError("object keys must be strings")
            out.append(("," if index else "") + json.dumps(key, ensure_ascii=False) + ":")
            _canonical(value[key], out)
        out.append("}")
    elif isinstance(value, list):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _canonical(item, out)
        out.append("]")
    else:
        raise ValueError(f"{type(value).__name__} has no JSON form")


def _double(value: float) -> str:
    """ECMAScript Number::toString (ECMA-262 7.1.12.1), as RFC 8785 prescribes."""
    if not math.isfinite(value):
        raise ValueError("NaN and infinities have no JSON form")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    # repr is the shortest digit string that round-trips, the digits ECMAScript uses.
    _, digit_tuple, exponent = Decimal(repr(abs(value))).as_tuple()
    assert isinstance(exponent, int)
    raw = "".join(str(d) for d in digit_tuple)
    digits = raw.rstrip("0")
    exponent += len(raw) - len(digits)
    k, n = len(digits), exponent + len(digits)
    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        text = "0." + "0" * -n + digits
    else:
        e = n - 1
        mantissa = digits[0] + ("." + digits[1:] if k > 1 else "")
        text = f"{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + text


# ─────────────────────────────────────────────────────────────────────────
# sources: core profiles and installed add-ons
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Source:
    """One `exposes:` section and what the core adds to its entries."""

    provider: str  # add-on name or core:<profile>
    version: str
    trust: str
    state: str
    section: list
    compose: Path
    host_env: dict  # where `<HOST_KEY>_HOST` is looked up, most specific first


def _profiles(env: dict[str, str]) -> set[str]:
    return {p.strip() for p in env.get("COMPOSE_PROFILES", "").split(",") if p.strip()}


def _core_sources(repo_root: Path, env: dict[str, str], version: str) -> list[Source]:
    sources = []
    active = _profiles(env)
    for profile, directory in CORE_PROFILES.items():
        path = repo_root / directory / "exposes.yaml"
        if profile not in active or not path.is_file():
            continue
        where = f"core:{profile}"
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise CatalogError(f"{where}: {path} is not valid YAML: {exc}") from None
        if not isinstance(doc, dict) or set(doc) != {"exposes"}:
            raise CatalogError(f"{where}: {path} must hold exactly the key exposes")
        sources.append(
            Source(where, version, "platform", RUNNING, doc["exposes"],
                   repo_root / directory / "docker-compose.yml", env)
        )
    return sources


def _trust(name: str, version: str, matrix: dict | None, core_version: str | None) -> str:
    """`platform` only for a module of the suite: named in the compatibility matrix of
    this core with a version in the cell of its suite (or the one before); every other
    add-on is `addon`. Never declared by the add-on itself."""
    if matrix is None or core_version is None or name not in matrix["components"]:
        return "addon"
    row, before = suite.matrix_rows(matrix, core_version)
    for candidate in (row, before):
        cell = (candidate or {}).get("versions", {}).get(name)
        try:
            if cell and semver.satisfies(version, cell):
                return "platform"
        except ValueError:
            return "addon"
    return "addon"


def _addon_sources(
    config_dir: Path,
    repo_root: Path,
    env: dict[str, str],
    core_version: str | None,
    deployed: dict | None,
) -> list[Source]:
    try:
        matrix = suite.load_matrix(repo_root)
    except suite.SuiteError as exc:
        raise CatalogError(str(exc)) from None
    sources = []
    if deployed is None:
        deployed = deployment.load(config_dir)
    for entry in deployment.active_addons(deployed):
        name = entry.get("name")
        addon_path = deployment.resolve_addon_path(entry, repo_root)
        manifest, error = deployment.load_addon_manifest(addon_path)
        if manifest is None:
            raise CatalogError(f"{name}: {error}")
        if manifest.get("exposes") is None:
            continue
        version = str(manifest.get("version") or entry.get("version") or "unversioned")
        bundle = common.parse_env_file(config_dir / "addons" / str(name) / ".env")
        sources.append(
            Source(
                str(name),
                version,
                _trust(str(name), version, matrix, core_version),
                RUNNING if entry.get("state") == RUNNING else STOPPED,
                manifest["exposes"],
                addon_path / "docker-compose.yml",
                {**env, **bundle},
            )
        )
    return sources


# ─────────────────────────────────────────────────────────────────────────
# entries
# ─────────────────────────────────────────────────────────────────────────


def _text(value: dict) -> dict:
    """Both languages: a missing one falls back to the other (exposes.v1, plain text);
    a text longer than the catalog allows is shortened with an ellipsis."""

    def fit(text: str) -> str:
        return text if len(text) <= TEXT_LIMIT else text[: TEXT_LIMIT - 1] + "…"

    de, en = value.get("de", value.get("en")), value.get("en", value.get("de"))
    return {"de": fit(de), "en": fit(en)}


def _compose_services(path: Path, where: str) -> dict:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CatalogError(f"{where}: {path} not found") from None
    except yaml.YAMLError as exc:
        raise CatalogError(f"{where}: {path} is not valid YAML: {exc}") from None
    services = (doc or {}).get("services") if isinstance(doc, dict) else None
    return services if isinstance(services, dict) else {}


def _address(declared: dict, services: dict, where: str) -> str:
    service = declared["service"]
    if service not in services:
        raise CatalogError(
            f"{where}/address/service: no service '{service}' in the module's docker-compose.yml"
        )
    container = (services[service] or {}).get("container_name")
    # The container name is the stable DNS name; a templated one is not known here, the
    # service name resolves on every network the service joins.
    host = container if isinstance(container, str) and "$" not in container else service
    path = declared.get("path", "/")
    return f"{declared.get('scheme', 'http')}://{host}:{declared['port']}{path}"


def _public_url(host_key: str, path: str, host_env: dict, where: str) -> str:
    variable = host_key.upper().replace("-", "_") + "_HOST"
    base = host_env.get(variable, "")
    parts = urllib.parse.urlsplit(base)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
    ):
        raise CatalogError(
            f"{where}/host_key: no public https address for host key '{host_key}' "
            f"(set {variable} in the root .env or the add-on's .env)"
        )
    return f"https://{parts.netloc}{parts.path.rstrip('/')}{path}"


def _operation(operation: dict) -> dict:
    result = {k: v for k, v in operation.items() if k != "description"}
    result["title"] = _text(operation["title"])
    return result


def _ui(item: dict, host_env: dict, where: str) -> dict:
    result: dict = {"id": item["id"], "title": _text(item["title"])}
    for key in ("summary", "example"):
        if key in item:
            result[key] = _text(item[key])
    for key in ("icon", "order", "host_key", "path"):
        result[key] = item[key]
    result["public_url"] = _public_url(item["host_key"], item["path"], host_env, where)
    result["visible_for_roles"] = list(item["visible_for_roles"])
    for key in ("targets", "admin_url"):
        if key in item:
            result[key] = item[key]
    result["opens_in"] = item.get("opens_in", "same_tab")
    return result


def _entry(source: Source, index: int, declared: dict, services: dict) -> dict:
    where = f"{source.provider}: exposes/{index}"
    entry: dict = {
        "id": declared["id"],
        "provider": source.provider,
        "version": source.version,
        "kind": declared["kind"],
        "state": source.state,
        "trust": source.trust,
        "title": _text(declared["title"]),
    }
    if "description" in declared:
        entry["description"] = _text(declared["description"])
    if "address" in declared:
        entry["address"] = _address(declared["address"], services, where)
    for key in ("audience", "identity"):
        if key in declared:
            entry[key] = declared[key]
    if "operations" in declared:
        entry["operations"] = [_operation(op) for op in declared["operations"]]
    if "events" in declared:
        entry["events"] = [dict(ev, title=_text(ev["title"])) for ev in declared["events"]]
    if "ui" in declared:
        entry["ui"] = [
            _ui(item, source.host_env, f"{where}/ui/{number}")
            for number, item in enumerate(declared["ui"])
        ]
    for key in ("downstream", "standard_operations"):
        if key in declared:
            entry[key] = declared[key]
    if "roles" in declared:
        entry["roles"] = [
            {"name": r["name"], "title": _text(r["title"])}
            | ({"description": _text(r["description"])} if "description" in r else {})
            for r in declared["roles"]
        ]
    entry["content_hash"] = content_hash(entry)
    return entry


# ─────────────────────────────────────────────────────────────────────────
# the document
# ─────────────────────────────────────────────────────────────────────────


def _stamp(now: datetime | None) -> str:
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _branding(config_dir: Path) -> tuple[dict, bytes | None]:
    """The brand from the operator overlay (`overlay/platform/branding.yaml`, fields
    `name`, `suffix`, `contact`) and the logo file next to it; the core sets
    `logo_sha256`. Without an overlay the product name."""
    path = config_dir / BRANDING_OVERLAY
    branding: dict = {"name": DEFAULT_BRAND_NAME}
    if path.is_file():
        try:
            branding = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise CatalogError(f"{BRANDING_OVERLAY} is not valid YAML: {exc}") from None
        if not isinstance(branding, dict) or "logo_sha256" in branding:
            raise CatalogError(
                f"{BRANDING_OVERLAY}: must be a mapping of name, suffix and contact "
                "(the core sets logo_sha256 from the logo file)"
            )
        try:
            schema_check.validate(
                branding, exposes.load_schema(exposes.SERVICES_SCHEMA), "#/$defs/Branding"
            )
        except schema_check.SchemaError as exc:
            raise CatalogError(f"{BRANDING_OVERLAY}: {exc}") from None
    logo_path = config_dir / LOGO_OVERLAY
    logo = None
    if logo_path.is_file():
        if logo_path.stat().st_size > MAX_BYTES:
            raise CatalogError(f"{LOGO_OVERLAY} is larger than {MAX_BYTES} bytes")
        logo = logo_path.read_bytes()
        branding = {**branding, "logo_sha256": hashlib.sha256(logo).hexdigest()}
    return branding, logo


def skip_reason(config_dir: Path, repo_root: Path) -> str | None:
    """Why this installation has no catalog, or None when it has one: the core serves
    no contract generation with `exposes:` (7), or no identity provider with a public
    https issuer is configured yet (OIDC_ISSUER in the root .env); without one no
    catalog is valid."""
    window = compat.resolve_addon_api_window(repo_root)
    if window is None or window[1] < compat.GENERATION_FEATURES["exposes"]:
        return "the core serves no contract generation with exposes (7)"
    issuer = common.parse_env_file(config_dir / ".env").get("OIDC_ISSUER", "")
    if not issuer:
        return "OIDC_ISSUER is not set in the root .env"
    if not issuer.startswith("https://"):
        # Modules check `iss` against the catalog, and the contract allows only an
        # https issuer; an installation signing in over plain http gets no catalog.
        return "OIDC_ISSUER is not an https address"
    return None


def build(
    config_dir: Path,
    repo_root: Path,
    now: datetime | None = None,
    *,
    deployed: dict | None = None,
) -> dict | None:
    """The catalog document, or None when the installation has none (skip_reason).
    `deployed` stands in for deployment.yaml: the registration an add-on verb is about
    to save, checked before it is saved (check)."""
    if skip_reason(config_dir, repo_root) is not None:
        return None
    env = common.parse_env_file(config_dir / ".env")
    for key in ("OIDC_TOKEN_URL", "OIDC_JWKS_URL"):
        if not env.get(key):
            raise CatalogError(f"{key} is not set in the root .env")
    core = compat.resolve_core_target(repo_root)
    version = core.platform_version or "unversioned"
    sources = _core_sources(repo_root, env, version) + _addon_sources(
        config_dir, repo_root, env, core.platform_version, deployed
    )

    entries: dict[str, dict] = {}
    for source in sources:
        try:
            exposes.check(source.section, source.provider)
        except exposes.ExposesError as exc:
            raise CatalogError(str(exc)) from None
        services = _compose_services(source.compose, source.provider)
        for index, declared in enumerate(source.section):
            if declared["id"] in entries:
                raise CatalogError(
                    f"catalog id '{declared['id']}' is declared by "
                    f"{entries[declared['id']]['provider']} and {source.provider}"
                )
            entries[declared["id"]] = _entry(source, index, declared, services)

    assert core.addon_api is not None  # skip_reason
    profile = env.get("PAPAIA_SECURITY_PROFILE", "standard")
    branding, _ = _branding(config_dir)
    return {
        "format": SERVICES_FORMAT,
        "generated_at": _stamp(now),
        "addon_api": core.addon_api[1],
        "security_profile": profile if profile in SECURITY_PROFILES else "standard",
        "identity": {
            "issuer": env["OIDC_ISSUER"],
            "token_endpoint_internal": env["OIDC_TOKEN_URL"],
            "jwks_uri_internal": env["OIDC_JWKS_URL"],
        },
        "services": [entries[key] for key in sorted(entries)],
        "models": [],
        "branding": branding,
        "platform_notices": [TEST_MODE_NOTICE] if hosted_model.enabled(env) else [],
    }


def _check_document(doc: dict) -> None:
    try:
        schema_check.validate(doc, exposes.load_schema(exposes.SERVICES_SCHEMA))
    except schema_check.SchemaError as exc:
        parts = exc.path.split("/")
        if len(parts) > 2 and parts[1] == "services":
            entry = doc["services"][int(parts[2])]
            where = "/".join(parts[3:])
            raise CatalogError(
                f"{entry['provider']}: entry '{entry['id']}' cannot be rendered: "
                f"{where or '/'}: {exc.reason}"
            ) from None
        raise CatalogError(f"{SERVICES_FILE}: {exc}") from None


# ─────────────────────────────────────────────────────────────────────────
# files
# ─────────────────────────────────────────────────────────────────────────


def platform_dir(config_dir: Path, *, create: bool = True) -> Path:
    path = config_dir / CATALOG_DIR
    if create:
        common.ensure_dir(path)
        os.chmod(path, 0o755)  # modules read it under their own uid
    return path


def _write(path: Path, data: bytes) -> None:
    """Write beside the file and rename it into place, so a module reads the old or the
    new file, never a part; modules mount the directory, so the new inode is seen."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), 0o644)
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _serialize(doc: dict) -> bytes:
    data = (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if len(data) > MAX_BYTES:
        raise CatalogError(f"{SERVICES_FILE} would be larger than {MAX_BYTES} bytes")
    return data


def _without_stamp(doc: object) -> object:
    if isinstance(doc, dict):
        return {k: v for k, v in doc.items() if k != "generated_at"}
    return doc


def _change(name: str, action: str, operation: str, effect: str = "write"):
    from . import realm_sync as rs  # it imports the render path

    return rs.Change("file", f"{CATALOG_DIR}/{name}", action, operation, effect=effect)


def _audit_log(config_dir: Path):
    """An open audit log, before anything is written: an outbox that cannot be appended
    to stops the render (realm_sync.AuditLog)."""
    from . import realm_sync as rs  # it imports the render path

    try:
        return rs.AuditLog(rs.audit_path(config_dir), rs.new_correlation_id(), writer=WRITER)
    except (rs.RealmSyncError, OSError) as exc:
        raise CatalogError(f"the audit outbox cannot be written: {exc}") from None


def check(config_dir: Path, repo_root: Path, deployed: dict) -> None:
    """Raise CatalogError if the installation `deployed` describes would have no valid
    catalog; write nothing. Some declarations are only wrong next to the others (an id
    another module declares, a UI surface whose public host is not set, an address
    service missing from compose), so an add-on verb checks the whole prospective
    installation before it saves deployment.yaml: once saved, every render would fail."""
    doc = build(config_dir, repo_root, deployed=deployed)
    if doc is not None:
        _check_document(doc)
        _serialize(doc)


def render(config_dir: Path, repo_root: Path, now: datetime | None = None) -> bool:
    """Render `platform/services.json` (and an empty `groups.json` until `realm sync`
    writes the groups). Returns True when services.json was written. Raises
    CatalogError, leaving every file unchanged, for a declaration or result that does
    not pass the checks."""
    doc = build(config_dir, repo_root, now)
    if doc is None:
        logger.warning("platform catalog not rendered: %s", skip_reason(config_dir, repo_root))
        return False
    _check_document(doc)
    data = _serialize(doc)
    _, logo = _branding(config_dir)

    platform = platform_dir(config_dir)
    # Every file written here is one audit row, made on the host without a token.
    writes: list[tuple[object, Callable[[], object]]] = []
    logo_path = platform / LOGO_FILE
    if logo is None:
        if logo_path.exists() or logo_path.is_symlink():
            writes.append((
                _change(LOGO_FILE, "brand logo removed", "brand_logo_delete", "delete"),
                lambda: logo_path.unlink(missing_ok=True),
            ))
    elif not logo_path.is_file() or logo_path.read_bytes() != logo:
        writes.append((
            _change(LOGO_FILE, "brand logo written", "brand_logo_write"),
            lambda: _write(logo_path, logo),
        ))
    if not (platform / GROUPS_FILE).is_file():
        # Modules mount the file before the first realm sync writes the groups.
        writes.append((
            _change(GROUPS_FILE, "empty group list written", "platform_groups.write"),
            lambda: write_groups(config_dir, [], now=now),
        ))
    path = platform / SERVICES_FILE
    services_changed = _without_stamp(_read_json(path)) != _without_stamp(doc)
    if services_changed:
        writes.append((
            _change(
                SERVICES_FILE,
                f"platform catalog written ({len(doc['services'])} entries)",
                "services_write",
            ),
            lambda: _write(path, data),
        ))
    if not writes:
        return False
    with _audit_log(config_dir) as audit:
        for change, write in writes:
            try:
                write()
            except OSError:
                audit.write(change, "error", "io", host=True)
                raise
            audit.write(change, "allowed", host=True)
    return services_changed


# ─────────────────────────────────────────────────────────────────────────
# groups.json
# ─────────────────────────────────────────────────────────────────────────


def _attribute(group: dict, name: str) -> str | None:
    values = (group.get("attributes") or {}).get(name)
    if isinstance(values, list) and values and isinstance(values[0], str) and values[0]:
        return values[0]
    return None


def _group_row(group: dict) -> dict:
    name = group.get("name") if isinstance(group.get("name"), str) else ""
    de = _attribute(group, "papaia.display_name.de") or name
    en = _attribute(group, "papaia.display_name.en") or name
    return {
        "id": group.get("id"),
        "path": group.get("path"),
        "display_name": _text({"de": de, "en": en}),
        "technical": _attribute(group, "papaia.technical") == "true",
    }


def groups_from_realm(call, page: int = GROUP_PAGE) -> list[dict]:
    """The realm's groups as rows of groups.json, sorted by path. `call` is the Admin
    API of the realm (read with the rights papaia-ctl has on the host). Only `id`,
    `path`, the display name and the `papaia.technical` attribute are taken; members,
    other attributes and role mappings are never read into the rows. A group whose id
    or path the format cannot carry is left out and noted."""
    schema = exposes.load_schema(exposes.GROUPS_SCHEMA)
    rows: list[dict] = []

    def level(parent: str | None) -> None:
        first = 0
        while True:
            query = f"briefRepresentation=false&first={first}&max={page}"
            path = (
                f"/groups?{query}"
                if parent is None
                else f"/groups/{urllib.parse.quote(parent, safe='')}/children?{query}"
            )
            batch = call("GET", path) or []
            for group in batch:
                if not isinstance(group, dict):
                    continue
                row = _group_row(group)
                try:
                    schema_check.validate(row, schema, "#/$defs/Group")
                except schema_check.SchemaError as exc:
                    print(f"  note: a group ({exc}) is not in the group list", flush=True)
                    continue
                rows.append(row)
                if len(rows) > 5000:
                    raise CatalogError("the realm has more than 5000 groups")
                if group.get("subGroupCount", 1):
                    level(row["id"])
            if len(batch) < page:
                return
            first += page

    level(None)
    rows.sort(key=lambda r: r["path"])
    ids = [r["id"] for r in rows]
    if len(ids) != len(set(ids)):
        raise CatalogError("the realm reports a group id twice")
    return rows


def current_groups(config_dir: Path) -> list | None:
    doc = _read_json(platform_dir(config_dir, create=False) / GROUPS_FILE)
    return doc.get("groups") if isinstance(doc, dict) else None


def write_groups(config_dir: Path, groups: list[dict], now: datetime | None = None) -> bool:
    """Write groups.json when the groups differ from the file; returns True if written."""
    if current_groups(config_dir) == groups:
        return False
    doc = {"format": GROUPS_FORMAT, "generated_at": _stamp(now), "groups": groups}
    try:
        schema_check.validate(doc, exposes.load_schema(exposes.GROUPS_SCHEMA))
    except schema_check.SchemaError as exc:
        raise CatalogError(f"{GROUPS_FILE}: {exc}") from None
    _write(platform_dir(config_dir) / GROUPS_FILE, _serialize(doc))
    return True
