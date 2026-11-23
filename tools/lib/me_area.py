"""What the core writes for Mein Bereich (core profile `me`, ADR 0020) besides its compose file.

While the profile is on:

- `$PAPAIA_CONFIG_DIR/personal-settings/registry.yaml`, the module list of the area: the
  `personal_settings:` section of every active add-on, as JSON (`{"registry": 1,
  "modules": [...]}`, sorted by module). The core checks only what makes an entry the
  module's own: a mapping with a positive integer `api` whose `module` is the add-on's
  name. Everything else is checked again by `me-web` before it builds a form, against the
  kit's schema of the contract (the area keeps no copy, nor does the core). An entry that
  fails here is left out and named in a warning; an inactive add-on has no entry.
- `personal-settings/module-ca/<module>.pem`: for a module whose endpoint is `https`, the
  public CA certificate the platform PKI issued its endpoint service with
  (`pki/<module>/<service>/ca.crt`). `me-web` trusts it for that module alone. A file that
  holds anything but certificates is never copied.
- `security/azp/azp-allowlist.json`, the `azp` allow-list of `prefs` (kit format
  `{"version": 1, "audiences": {"papaia-prefs": {"<azp>": [effects]}}}`): the clients of
  the confirmed pairings with `papaia-prefs` that the realm sync assigned, nothing else.
  A write pairing is confirmed only after the second person's approval, so it is listed
  only then. The render prepares an empty list before the start (Compose must not create
  the folder as root); the realm sync writes the list after the realm is in line and
  removes it when the profile is off. `prefs` re-reads it when it is replaced and refuses
  every token while it is missing or unreadable.

Every file is written beside its target and renamed into place (a reader sees the old or
the new file, never a part), owned by the user running papaia-ctl, mode 0644 in 0755
folders: `me-web` and `prefs` read them under their own uid, and only they mount these
folders (read-only). None of them holds a secret. Every write and every removal is one
`papaia.audit/1` row without content.

The realm sync pairs `papaia-me` with `papaia-audit` itself (effect x, the person's own
read tickets at `GET /v1/me/reads`) while the profiles `me` and `audit` are both on, like
the manager's pairing (lib/audit_report_account.py): `pairings.yaml` cannot name the
audit service.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import stat
from pathlib import Path

from . import common, deployment
from . import realm_sync as rs

logger = logging.getLogger(__name__)

PROFILE = "me"
CLIENT = "papaia-me"
PREFS_AUDIENCE = "papaia-prefs"
AUDIT_AUDIENCE = "papaia-audit"
AUDIT_EFFECTS = ("x",)
WRITER = "papaia-ctl/me-area"

REGISTRY_DIR = "personal-settings"
REGISTRY_FILE = "registry.yaml"
MODULE_CA_DIR = "module-ca"
REGISTRY_FORMAT = 1
ALLOWLIST_DIR = "security/azp"
ALLOWLIST_FILE = "azp-allowlist.json"
ALLOWLIST_REF = f"{ALLOWLIST_DIR}/{ALLOWLIST_FILE}"
ALLOWLIST_VERSION = 1
# The effect letters of a pairing as the kit's allow-list names them (security 1.4:
# r read, w write, d delete, x a call of the module interface, checked by the server).
EFFECT_NAMES = {"r": "read", "w": "write", "d": "delete", "x": "check"}

MAX_REGISTRY_BYTES = 1 << 20
MAX_CA_BYTES = 64 * 1024
_MODULE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_SERVICE_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+?-----END CERTIFICATE-----\r?\n?"
)


def enabled(root_env: dict[str, str]) -> bool:
    """The profile is on for the installation (cluster-wide, like the realm)."""
    return PROFILE in common.cluster_profiles(root_env)


# ─────────────────────────────────────────────────────────────────────────
# the exchange right with the audit service
# ─────────────────────────────────────────────────────────────────────────


def platform_pairings(tree: dict) -> list[rs.Pairing]:
    """`papaia-me` -> `papaia-audit` (effect x) while `me` and `audit` are both on."""
    profiles = common.cluster_profiles(tree.get("", {}))
    if PROFILE not in profiles or "audit" not in profiles:
        return []
    return [
        rs.Pairing(
            CLIENT,
            AUDIT_AUDIENCE,
            AUDIT_EFFECTS,
            True,
            rs.PLATFORM_PERSON,
            rs.PLATFORM_PERSON,
        )
    ]


# ─────────────────────────────────────────────────────────────────────────
# files: one writer, rename into place
# ─────────────────────────────────────────────────────────────────────────


def _folder(path: Path, *, create: bool) -> int | None:
    """A descriptor of `path` (created 0755 with `create`), None when it does not exist.
    A symbolic link, or a folder someone else could change, is refused."""
    if create:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.mkdir(path, 0o755)
        except FileExistsError:
            pass
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise rs.RealmSyncError(
            f"{path} cannot be opened safely (a symbolic link is refused): {exc.strerror}"
        ) from None
    try:
        st = os.fstat(fd)
        if st.st_uid not in (os.geteuid(), 0) or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise rs.RealmSyncError(
                f"{path} must belong to the user running papaia-ctl and not be writable "
                "by group or others"
            )
        if create:
            os.fchmod(fd, 0o755)  # me-web and prefs read it under their own uid
    except BaseException:
        os.close(fd)
        raise
    return fd


def _read(dfd: int | None, name: str) -> bytes | None:
    """The current file; None when there is none, b"" when it is no regular file."""
    if dfd is None:
        return None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
    except FileNotFoundError:
        return None
    except OSError:
        return b""  # a symbolic link or worse: replaced, never followed
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            return b""
        return fh.read()


def _replace(dfd: int, name: str, content: bytes) -> None:
    tmp = f".{name}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=dfd)
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), 0o644)
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp, dir_fd=dfd)
        raise
    os.fsync(dfd)


def _apply(dfd: int, name: str, content: bytes | None, change: rs.Change, audit) -> None:
    """Write (or with None remove) one file; one audit row whatever the outcome."""
    try:
        if content is None:
            os.unlink(name, dir_fd=dfd)
        else:
            _replace(dfd, name, content)
    except OSError:
        if audit is not None:
            audit.write(change, "error", "io", host=True)
        raise
    if audit is not None:
        audit.write(change, "allowed", host=True)


def _json(doc: object) -> bytes:
    return (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


# ─────────────────────────────────────────────────────────────────────────
# the azp allow-list of prefs
# ─────────────────────────────────────────────────────────────────────────


def allowlist(plan: rs.Plan, pairings: list[rs.Pairing]) -> dict:
    """The allow-list of `prefs`: per client of a confirmed pairing with `papaia-prefs`
    that the plan assigns (both sides installed), its effects."""
    scope = rs.exchange_scope(PREFS_AUDIENCE)
    released: dict[str, list[str]] = {}
    for pairing in pairings:
        if pairing.audience != PREFS_AUDIENCE or not pairing.confirmed:
            continue
        spec = plan.clients.get(pairing.client)
        if spec is None or scope not in spec.optional_scopes:
            continue
        released[pairing.client] = [
            EFFECT_NAMES[e] for e in rs.EFFECTS if e in pairing.effects
        ]
    return {
        "version": ALLOWLIST_VERSION,
        "audiences": {PREFS_AUDIENCE: dict(sorted(released.items()))},
    }


def _empty_allowlist() -> dict:
    return {"version": ALLOWLIST_VERSION, "audiences": {PREFS_AUDIENCE: {}}}


def ensure_allowlist(config_dir: Path, audit=None) -> bool:
    """The folder `prefs` mounts and, when there is none yet, an empty list (prefs then
    releases nobody until the realm sync writes the confirmed pairings). True if written."""
    dfd = _folder(config_dir / ALLOWLIST_DIR, create=True)
    assert dfd is not None
    try:
        if _read(dfd, ALLOWLIST_FILE) is not None:
            return False
        change = rs.Change(
            "file", ALLOWLIST_REF, "prefs azp allow-list prepared (empty)",
            "prefs_azp_allowlist.write",
        )
        _apply(dfd, ALLOWLIST_FILE, _json(_empty_allowlist()), change, audit)
        return True
    finally:
        os.close(dfd)


def sync_allowlist(
    plan: rs.Plan,
    pairings: list[rs.Pairing],
    config_dir: Path,
    *,
    enabled: bool,
    apply: bool,
    audit=None,
) -> list[rs.Change]:
    """Compare the allow-list with the plan; with `apply`, rewrite it (or remove it when
    the profile is off). Returns the deviation, if any."""
    target = _json(allowlist(plan, pairings)) if enabled else None
    dfd = _folder(config_dir / ALLOWLIST_DIR, create=apply and target is not None)
    try:
        current = _read(dfd, ALLOWLIST_FILE)
        if current == target:
            return []
        if target is None:
            change = rs.Change(
                "file", ALLOWLIST_REF, "prefs azp allow-list removed (profile me is off)",
                "prefs_azp_allowlist.delete", effect="delete",
            )
        else:
            count = len(allowlist(plan, pairings)["audiences"][PREFS_AUDIENCE])
            change = rs.Change(
                "file", ALLOWLIST_REF, f"prefs azp allow-list written ({count} client(s))",
                "prefs_azp_allowlist.write",
            )
        print(f"{'  ' if apply else 'fail: '}{change.kind} {change.name}: {change.action}",
              flush=True)
        if not apply:
            return [change]
        assert dfd is not None  # created above, or the list to remove exists
        _apply(dfd, ALLOWLIST_FILE, target, change, audit)
        return [change]
    finally:
        if dfd is not None:
            os.close(dfd)


# ─────────────────────────────────────────────────────────────────────────
# the module list of the area
# ─────────────────────────────────────────────────────────────────────────


def _declaration(name: str, section: object) -> tuple[dict | None, str | None]:
    """The section as the module's own entry, or (None, reason)."""
    if not isinstance(section, dict):
        return None, "personal_settings must be a mapping"
    api = section.get("api")
    if type(api) is not int or api < 1:
        return None, "api must be a positive integer"
    if section.get("module") != name:
        return None, f"module must be the add-on's own name {name!r}"
    try:
        json.dumps(section, allow_nan=False)
    except (TypeError, ValueError):
        return None, "not representable as JSON"
    return section, None


def _https_service(section: dict) -> str | None:
    """The endpoint service of a contract-1 declaration served over https."""
    endpoint = section.get("endpoint")
    if not isinstance(endpoint, dict) or endpoint.get("scheme") != "https":
        return None
    service = endpoint.get("service")
    return service if isinstance(service, str) and _SERVICE_RE.match(service) else None


def _module_ca(config_dir: Path, module: str, service: str) -> bytes | None:
    """The public CA certificate the platform PKI issued `service` of `module` with;
    None when there is none or the file holds anything but certificates."""
    path = config_dir / "pki" / module / service / "ca.crt"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            return None
        raw = fh.read(MAX_CA_BYTES + 1)
    if len(raw) > MAX_CA_BYTES:
        logger.warning("module CA of %s: %s is too large; not trusted", module, path)
        return None
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    blocks = _PEM_BLOCK_RE.findall(text)
    if not blocks or _PEM_BLOCK_RE.sub("", text).strip():
        logger.warning("module CA of %s: %s holds more than certificates; not trusted",
                       module, path)
        return None
    return "".join(b if b.endswith("\n") else b + "\n" for b in blocks).encode("ascii")


def registry(config_dir: Path, repo_root: Path) -> tuple[dict, dict[str, bytes]]:
    """The module list and the CA files of `module-ca/` (file name -> content)."""
    modules: list[dict] = []
    cas: dict[str, bytes] = {}
    for addon in deployment.active_addons(deployment.load(config_dir) or {}):
        name = addon.get("name")
        if not isinstance(name, str) or not _MODULE_RE.match(name):
            continue
        manifest, reason = deployment.load_addon_manifest(
            deployment.resolve_addon_path(addon, repo_root)
        )
        if manifest is None:
            logger.warning("personal settings of %s left out: %s", name, reason)
            continue
        if manifest.get("personal_settings") is None:
            continue
        section, reason = _declaration(name, manifest["personal_settings"])
        if section is None:
            logger.warning("personal settings of %s left out: %s", name, reason)
            continue
        modules.append(section)
        service = _https_service(section)
        ca = _module_ca(config_dir, name, service) if service else None
        if ca is not None:
            cas[f"{name}.pem"] = ca
    modules.sort(key=lambda m: m["module"])
    return {"registry": REGISTRY_FORMAT, "modules": modules}, cas


def render(config_dir: Path, repo_root: Path) -> bool:
    """With the profile on: write the module list, `module-ca/` and, if missing, the
    empty allow-list of `prefs`. Returns True when a file was written or removed. Without
    the profile nothing is written."""
    if not enabled(common.parse_env_file(config_dir / ".env")):
        return False
    doc, cas = registry(config_dir, repo_root)
    data = _json(doc)
    if len(data) > MAX_REGISTRY_BYTES:
        raise rs.RealmSyncError(
            f"{REGISTRY_DIR}/{REGISTRY_FILE} would be larger than {MAX_REGISTRY_BYTES} bytes"
        )
    root = config_dir / REGISTRY_DIR
    written = False
    with rs.AuditLog(rs.audit_path(config_dir), rs.new_correlation_id(), writer=WRITER) as audit:
        rfd = _folder(root, create=True)
        assert rfd is not None
        try:
            if _read(rfd, REGISTRY_FILE) != data:
                change = rs.Change(
                    "file", f"{REGISTRY_DIR}/{REGISTRY_FILE}",
                    f"module list of Mein Bereich written ({len(doc['modules'])} module(s))",
                    "registry.write",
                )
                _apply(rfd, REGISTRY_FILE, data, change, audit)
                written = True
        finally:
            os.close(rfd)
        cfd = _folder(root / MODULE_CA_DIR, create=True)
        assert cfd is not None
        try:
            present = {n for n in os.listdir(cfd) if n.endswith(".pem")}
            for name in sorted(present | set(cas)):
                content = cas.get(name)
                if _read(cfd, name) == content:
                    continue
                ref = f"{REGISTRY_DIR}/{MODULE_CA_DIR}/{name}"
                if content is None:
                    change = rs.Change("file", ref, "module CA removed", "module_ca.delete",
                                       effect="delete")
                else:
                    change = rs.Change("file", ref, "module CA written", "module_ca.write")
                _apply(cfd, name, content, change, audit)
                written = True
        finally:
            os.close(cfd)
        written = ensure_allowlist(config_dir, audit) or written
    return written
