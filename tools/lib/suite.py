"""Suite bill of materials and the core x manager x module compatibility matrix.

The bill of materials (`suite-<version>.yaml`, schema `papaia.suite-bom/1`)
names every repo of one suite with tag and commit and, where the repo vendors
the kit, its kit version and whether it renders kit UI (`kit:`, checked by the
kit's `pk-check bom`), every image with digest,
the container and image counts, the kit snapshot checksum, the public key
the suite is signed with and, optionally, the exchange-right pairings the suite
ships with (confirmed at installation by `pairing_approval`). It is signed like
`cosign sign-blob` with a key pair: ECDSA P-256 over SHA-256, the signature
file holding base64 DER. The signature is checked against a key the operator
trusts, never against the key inside the file alone: the release key pinned
in the core checkout (`compat/release-key.pub`), or one given with `--key` or
`--fingerprint`.
No byte of the file is parsed as YAML before the signature holds; with a
fingerprint, the embedded key is located by a bounded pattern over the raw
bytes and must hash to that fingerprint. A verified file is then bound to the
suite and scope the caller expects (default: delivery scope), so an older or a
test-scope file signed with the same key is refused.

The matrix (`compat/suite.yaml`, schema `papaia.compat-matrix/1`) lists one
row per suite: the core range, the add-on contract window and the version
range of each component. `addon check` applies it: core N accepts the add-on
versions of suite N and N-1.

Every input is validated with explicit type checks and unknown fields are
refused; tools/schemas/*.schema.json describe the same shape for other tools.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path

import yaml

from . import compat, semver

BOM_SCHEMA = "papaia.suite-bom/1"
MATRIX_SCHEMA = "papaia.compat-matrix/1"
MATRIX_PATH = Path("compat") / "suite.yaml"
RELEASE_KEY_PATH = Path("compat") / "release-key.pub"
MATRIX_AXIS = "matrix"
MAX_BOM_BYTES = 1024 * 1024
MAX_SIGNATURE_BYTES = 4096

ROLES = ("core", "manager", "module", "addon", "mcp", "kit", "registry")
SINGLE_ROLES = ("core", "manager", "kit")
# PLT-37-A2: a delivery names its modules, the add-ons (Paperless among them)
# and both MCP servers. Which ones exactly is the generator's business.
DELIVERY_MIN_ROLES = {"module": 1, "addon": 1, "mcp": 2}
SCOPES = ("delivery", "test")
LICENSE_CLASSES = ("P", "W", "S", "N", "Q", "X")
DELIVERY = ("shipped", "customer-pulled", "test-only")
SUITE_STATUS = ("released", "candidate")

# DER prefix of a SubjectPublicKeyInfo for an uncompressed P-256 key: the only
# key type `cosign generate-key-pair` produces.
_P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
_PEM_RE = re.compile(
    r"\A-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=\n]+)-----END PUBLIC KEY-----\n?\Z"
)
# The embedded key in the raw, unauthenticated bytes: one PEM block whose body is
# base64 and whitespace (any YAML block or folded style), bounded in length.
_RAW_PEM_MARK = b"-----BEGIN PUBLIC KEY-----"
_RAW_PEM_RE = re.compile(
    rb"-----BEGIN PUBLIC KEY-----([A-Za-z0-9+/=\s]{1,400}?)-----END PUBLIC KEY-----"
)
_VERSION_RE = re.compile(r"\A\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?\Z")
_COMMIT_RE = re.compile(r"\A[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_NAME_RE = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,63}\Z")
_IMAGE_RE = re.compile(r"\A[a-z0-9][a-z0-9._:/-]{0,254}\Z")
_TAG_RE = re.compile(r"\A[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
_SPDX_RE = re.compile(r"\A[A-Za-z0-9.+() -]{1,128}\Z")
_TIME_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
# A client or audience name of the naming register.
_CLIENT_RE = re.compile(r"\A[a-z][a-z0-9]*(-[a-z0-9]+)*\Z")
PAIRING_EFFECTS = ("r", "w", "d", "x")
MAX_PAIRINGS = 256


class SuiteError(ValueError):
    """A bill of materials or matrix that must not be trusted or used."""


# ── field checks ─────────────────────────────────────────────────────────────


def _mapping(value: object, where: str, required: set[str], optional: set[str] = frozenset()):
    if not isinstance(value, dict):
        raise SuiteError(f"{where}: must be a mapping")
    unknown = sorted(str(k) for k in value if k not in required | optional)
    if unknown:
        raise SuiteError(f"{where}: unknown field(s) {', '.join(unknown)}")
    missing = sorted(required - set(value))
    if missing:
        raise SuiteError(f"{where}: missing field(s) {', '.join(missing)}")
    return value


def _text(value: object, where: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        raise SuiteError(f"{where}: invalid value {value!r}"[:200])
    return value


def _count(value: object, where: str) -> int:
    # bool is an int subclass; `containers: true` is not a count.
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10000:
        raise SuiteError(f"{where}: must be an integer between 0 and 10000")
    return value


def _choice(value: object, where: str, allowed: tuple[str, ...]) -> str:
    if value not in allowed:
        raise SuiteError(f"{where}: must be one of {', '.join(allowed)}")
    return value


def _window(value: object, where: str) -> tuple[int, int]:
    _mapping(value, where, {"min", "current"})
    low, high = _count(value["min"], f"{where}.min"), _count(value["current"], f"{where}.current")
    if low > high:
        raise SuiteError(f"{where}: min {low} > current {high}")
    return low, high


def _range(value: object, where: str) -> str:
    if not isinstance(value, str) or len(value) > 128:
        raise SuiteError(f"{where}: must be a version range")
    try:
        semver.parse_constraint(value)
    except ValueError as exc:
        raise SuiteError(f"{where}: {exc}") from exc
    return value


# ── keys and signatures ──────────────────────────────────────────────────────


def _der_from_body(body: str) -> bytes:
    try:
        der = base64.b64decode("".join(body.split()), validate=True)
    except binascii.Error as exc:
        raise SuiteError("public key: invalid base64") from exc
    if len(der) != 91 or not der.startswith(_P256_SPKI_PREFIX):
        raise SuiteError("public key: algorithm must be ECDSA P-256")
    return der


def _key_der(pem: str) -> bytes:
    match = _PEM_RE.match(pem) if isinstance(pem, str) else None
    if not match:
        raise SuiteError("public key: not a PEM 'PUBLIC KEY' block")
    return _der_from_body(match.group(1))


def _pem(der: bytes) -> str:
    body = base64.b64encode(der).decode("ascii")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


def _embedded_key(data: bytes) -> bytes:
    """DER of the one public key in the raw bytes, found without parsing them."""
    if data.count(_RAW_PEM_MARK) != 1:
        raise SuiteError("bill of materials: exactly one embedded public key is required")
    match = _RAW_PEM_RE.search(data)
    if not match:
        raise SuiteError("bill of materials: embedded public key is not a PEM block")
    return _der_from_body(match.group(1).decode("ascii"))


def key_fingerprint(pem: str) -> str:
    """`sha256:<hex>` over the DER SubjectPublicKeyInfo, as `openssl pkey -pubin
    -outform DER | sha256sum` prints it."""
    return "sha256:" + hashlib.sha256(_key_der(pem)).hexdigest()


def _signature_valid(data: bytes, signature: bytes, pem: str) -> bool:
    """ECDSA P-256/SHA-256 check by openssl, which `setup` already requires."""
    with tempfile.TemporaryDirectory(prefix="papaia-suite-") as tmp:
        key, sig, blob = Path(tmp, "key.pem"), Path(tmp, "blob.sig"), Path(tmp, "blob")
        key.write_text(pem, encoding="ascii")
        sig.write_bytes(signature)
        blob.write_bytes(data)
        try:
            done = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(key), "-signature", str(sig),
                 str(blob)],
                capture_output=True, text=True, timeout=30, check=False,
            )
        except FileNotFoundError as exc:
            raise SuiteError("openssl not found; it is needed to verify the signature") from exc
    return done.returncode == 0 and "Verified OK" in done.stdout


def _read_limited(path: Path, limit: int, what: str) -> bytes:
    """At most `limit` bytes of a regular file. O_NONBLOCK keeps a FIFO from
    blocking the open; fstat on the opened descriptor leaves no window to swap
    the file; reading limit + 1 bytes catches a file that grew since."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        raise SuiteError(f"{what} not readable: {path}") from exc
    chunks: list[bytes] = []
    size = 0
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SuiteError(f"{what} is not a regular file: {path}")
        if info.st_size > limit:
            raise SuiteError(f"{what} too large: {info.st_size} bytes (limit {limit})")
        while size <= limit:
            chunk = os.read(fd, limit + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    except OSError as exc:
        raise SuiteError(f"{what} not readable: {path}") from exc
    finally:
        os.close(fd)
    if size > limit:
        raise SuiteError(f"{what} too large: more than {limit} bytes")
    return b"".join(chunks)


def _parse_yaml(data: bytes, what: str) -> object:
    """safe_load that turns every parser failure (deep nesting, bad encoding)
    into SuiteError instead of a traceback."""
    try:
        return yaml.safe_load(data)
    except (yaml.YAMLError, RecursionError, ValueError, MemoryError) as exc:
        raise SuiteError(f"{what}: not YAML ({type(exc).__name__})") from exc


# ── bill of materials ────────────────────────────────────────────────────────

_REPO_REQUIRED = {"name", "role", "version", "tag", "commit", "containers", "images"}
_REPO_OPTIONAL = {"addon_api", "min_core", "schema_version", "snapshot_sha256", "kit"}
# The kit release a repo vendors (`kit:`), in the shape the kit defines for its suite
# check `pk-check bom` (papaia-kit contract/suite-bom-kit.schema.json, `$defs/module_kit`):
# a release version without prerelease, and whether the repo renders kit UI.
_KIT_VERSION_RE = re.compile(r"\A(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\Z")
_IMAGE_REQUIRED = {"name", "tag", "digest", "license", "license_class", "sbom_digest", "delivery"}


# Components that mean something to the core, with the one place a bill of materials may
# name them: the repo role and the delivery class. `paperless-gate` is the gate the
# Paperless add-on ships in front of Paperless (lib/module_offer.py); it counts only on a
# shipped image of the add-on repo. Other component names are free labels.
COMPONENT_HOMES = {"paperless-gate": ("addon", "shipped")}


def _validate_image(image: object, where: str, scope: str, role: str) -> None:
    _mapping(image, where, _IMAGE_REQUIRED, {"source_archive", "component"})
    _text(image["name"], f"{where}.name", _IMAGE_RE)
    _text(image["tag"], f"{where}.tag", _TAG_RE)
    _text(image["digest"], f"{where}.digest", _DIGEST_RE)
    _text(image["license"], f"{where}.license", _SPDX_RE)
    _choice(image["license_class"], f"{where}.license_class", LICENSE_CLASSES)
    _text(image["sbom_digest"], f"{where}.sbom_digest", _DIGEST_RE)
    _choice(image["delivery"], f"{where}.delivery", DELIVERY)
    if "source_archive" in image:
        _text(image["source_archive"], f"{where}.source_archive", _IMAGE_RE)
    if "component" in image:
        component = _text(image["component"], f"{where}.component", _NAME_RE)
        home = COMPONENT_HOMES.get(component)
        if home is not None and (role, image["delivery"]) != home:
            raise SuiteError(
                f"{where}.component: '{component}' belongs on a {home[1]} image of the"
                f" {home[0]} repo"
            )
    if scope == "delivery" and image["delivery"] == "test-only":
        raise SuiteError(f"{where}: test-only image in a delivery bill of materials")


def validate_module_kit(value: object, where: str) -> None:
    """The kit a repo of the suite vendors: `version` and optionally `renders_ui`."""
    kit = _mapping(value, where, {"version"}, {"renders_ui"})
    _text(kit["version"], f"{where}.version", _KIT_VERSION_RE)
    if "renders_ui" in kit and not isinstance(kit["renders_ui"], bool):
        raise SuiteError(f"{where}.renders_ui: must be true or false")


def _validate_repo(repo: object, where: str, scope: str) -> None:
    _mapping(repo, where, _REPO_REQUIRED, _REPO_OPTIONAL)
    _text(repo["name"], f"{where}.name", _NAME_RE)
    role = _choice(repo["role"], f"{where}.role", ROLES)
    version = _text(repo["version"], f"{where}.version", _VERSION_RE)
    if repo["tag"] != f"v{version}":
        raise SuiteError(f"{where}.tag: must be 'v{version}'")
    _text(repo["commit"], f"{where}.commit", _COMMIT_RE)
    _count(repo["containers"], f"{where}.containers")
    if "addon_api" in repo:
        _count(repo["addon_api"], f"{where}.addon_api")
    if "min_core" in repo:
        _text(repo["min_core"], f"{where}.min_core", _VERSION_RE)
    if "schema_version" in repo:
        _text(repo["schema_version"], f"{where}.schema_version", _TAG_RE)
    if (role == "kit") != ("snapshot_sha256" in repo):
        raise SuiteError(f"{where}: snapshot_sha256 is required for the kit and only there")
    if role == "kit":
        _text(repo["snapshot_sha256"], f"{where}.snapshot_sha256", _SHA256_RE)
        if "kit" in repo:
            raise SuiteError(f"{where}.kit: the kit carries no kit version of its own")
    elif "kit" in repo:
        validate_module_kit(repo["kit"], f"{where}.kit")
    if not isinstance(repo["images"], list) or len(repo["images"]) > 256:
        raise SuiteError(f"{where}.images: must be a list of at most 256 entries")
    for index, image in enumerate(repo["images"]):
        _validate_image(image, f"{where}.images[{index}]", scope, role)


def _validate_pairings(value: object) -> None:
    """The exchange-right pairings the suite ships with (security 1.4): client, audience
    and effects. Only their shape is checked here; `pairing_approval` checks them against
    the naming register before anything is offered for confirmation."""
    if not isinstance(value, list) or len(value) > MAX_PAIRINGS:
        raise SuiteError(f"pairings: must be a list of at most {MAX_PAIRINGS} entries")
    seen: set[tuple[str, str]] = set()
    for index, pairing in enumerate(value):
        where = f"pairings[{index}]"
        _mapping(pairing, where, {"client", "audience", "effects"})
        client = _text(pairing["client"], f"{where}.client", _CLIENT_RE)
        audience = _text(pairing["audience"], f"{where}.audience", _CLIENT_RE)
        effects = pairing["effects"]
        if (
            not isinstance(effects, list)
            or not effects
            or len(set(map(str, effects))) != len(effects)
            or not all(isinstance(e, str) and e in PAIRING_EFFECTS for e in effects)
        ):
            raise SuiteError(
                f"{where}.effects: distinct letters out of {', '.join(PAIRING_EFFECTS)}"
            )
        if (client, audience) in seen:
            raise SuiteError(f"{where}: {client} -> {audience} is listed twice")
        seen.add((client, audience))


def validate_bom(doc: object) -> None:
    """Raise SuiteError unless `doc` is a complete, consistent bill of materials."""
    _mapping(
        doc, "bill of materials",
        {"schema", "suite", "scope", "created", "contract_generation", "signing_key", "repos",
         "totals"},
        {"pairings"},
    )
    if "pairings" in doc:
        _validate_pairings(doc["pairings"])
    if doc["schema"] != BOM_SCHEMA:
        raise SuiteError(f"schema: must be '{BOM_SCHEMA}'")
    _text(doc["suite"], "suite", _VERSION_RE)
    scope = _choice(doc["scope"], "scope", SCOPES)
    _text(doc["created"], "created", _TIME_RE)
    _window(doc["contract_generation"], "contract_generation")
    key = _mapping(doc["signing_key"], "signing_key", {"algorithm", "fingerprint", "public_key"})
    if key["algorithm"] != "ecdsa-p256-sha256":
        raise SuiteError("signing_key.algorithm: must be 'ecdsa-p256-sha256'")
    if key["fingerprint"] != key_fingerprint(key["public_key"]):
        raise SuiteError("signing_key.fingerprint: does not match public_key")

    repos = doc["repos"]
    if not isinstance(repos, list) or not 1 <= len(repos) <= 64:
        raise SuiteError("repos: must be a list of 1 to 64 entries")
    for index, repo in enumerate(repos):
        _validate_repo(repo, f"repos[{index}]", scope)
    names = [repo["name"] for repo in repos]
    if len(set(names)) != len(names):
        raise SuiteError("repos: duplicate repo name")
    for role in SINGLE_ROLES:
        if sum(1 for repo in repos if repo["role"] == role) != 1:
            raise SuiteError(f"repos: exactly one entry with role {role} is required")
    if scope == "delivery":
        for role, least in DELIVERY_MIN_ROLES.items():
            if sum(1 for repo in repos if repo["role"] == role) < least:
                raise SuiteError(
                    f"repos: a delivery bill of materials needs at least {least} "
                    f"entr{'y' if least == 1 else 'ies'} with role {role}"
                )

    totals = _mapping(doc["totals"], "totals", {"containers", "images"})
    containers = sum(repo["containers"] for repo in repos)
    if _count(totals["containers"], "totals.containers") != containers:
        raise SuiteError(f"totals.containers: {totals['containers']} != {containers} listed")
    images = len({image["digest"] for repo in repos for image in repo["images"]})
    if _count(totals["images"], "totals.images") != images:
        raise SuiteError(f"totals.images: {totals['images']} != {images} distinct digests")


def components(doc: dict) -> set[str]:
    """The components a validated bill of materials names on its images (`component`):
    the role an image plays where its name alone does not say it, such as the gate in
    front of Paperless, which runs a generic proxy image."""
    return {
        image["component"]
        for repo in doc["repos"]
        for image in repo["images"]
        if "component" in image
    }


def image_refs(doc: dict) -> list[str]:
    """Every image of a validated bill of materials as `name:tag@digest`."""
    return [
        f"{image['name']}:{image['tag']}@{image['digest']}"
        for repo in doc["repos"]
        for image in repo["images"]
    ]


def verify_bom(
    bom_path: Path,
    signature_path: Path,
    *,
    key_path: Path | None = None,
    fingerprint: str | None = None,
    require_scope: str = "delivery",
    expected_suite: str | None = None,
) -> dict:
    """The content of a verified bill of materials (see verify_bom_with_digest)."""
    return verify_bom_with_digest(
        bom_path, signature_path, key_path=key_path, fingerprint=fingerprint,
        require_scope=require_scope, expected_suite=expected_suite,
    )[0]


def verify_bom_with_digest(
    bom_path: Path,
    signature_path: Path,
    *,
    key_path: Path | None = None,
    fingerprint: str | None = None,
    require_scope: str = "delivery",
    expected_suite: str | None = None,
) -> tuple[dict, str]:
    """Check signature, structure, signing key, scope and suite of a bill of
    materials and return its content.

    The trust anchor is either a release public key file (`key_path`, normally
    the pinned RELEASE_KEY_PATH) or its fingerprint. With a fingerprint the one
    PEM block in the raw bytes is located by a bounded pattern, without parsing
    the file, and must hash to that fingerprint. Only after the signature holds
    is the file parsed as YAML. The embedded key must be the trusted one,
    because image checks later rely on it. The file must have scope
    `require_scope` and, when given, suite `expected_suite`; otherwise an older
    or a test-scope file signed with the same key would pass.

    Returns the content and `sha256:<hex>` of exactly the bytes that were verified."""
    if (key_path is None) == (fingerprint is None):
        raise SuiteError("pass exactly one of a public key file or a key fingerprint")
    if require_scope not in SCOPES:
        raise SuiteError(f"require_scope: must be one of {', '.join(SCOPES)}")
    if expected_suite is not None:
        _text(expected_suite, "expected suite", _VERSION_RE)
    data = _read_limited(Path(bom_path), MAX_BOM_BYTES, "bill of materials")
    raw_signature = _read_limited(Path(signature_path), MAX_SIGNATURE_BYTES, "signature")
    try:
        signature = base64.b64decode(raw_signature.strip(), validate=True)
    except binascii.Error as exc:
        raise SuiteError("signature: not base64 (cosign sign-blob output expected)") from exc
    if not signature:
        raise SuiteError("signature: empty")

    if key_path is not None:
        raw_key = _read_limited(Path(key_path), 4096, "public key")
        # A key file copied on Windows has CRLF line endings; it is the same key.
        trusted_pem = raw_key.decode("ascii", "replace").replace("\r\n", "\n")
        trusted = key_fingerprint(trusted_pem)
    else:
        if not isinstance(fingerprint, str) or not _DIGEST_RE.match(fingerprint):
            raise SuiteError("fingerprint: must be sha256:<64 hex digits>")
        der = _embedded_key(data)
        if "sha256:" + hashlib.sha256(der).hexdigest() != fingerprint:
            raise SuiteError("signing_key: fingerprint differs from the trusted fingerprint")
        trusted, trusted_pem = fingerprint, _pem(der)

    if not _signature_valid(data, signature, trusted_pem):
        raise SuiteError("signature: verification failed; the file is altered or not signed "
                         "with the trusted key")
    doc = _parse_yaml(data, "bill of materials")
    validate_bom(doc)
    if doc["signing_key"]["fingerprint"] != trusted:
        raise SuiteError("signing_key: the file names another key than the trusted one")
    if doc["scope"] != require_scope:
        raise SuiteError(f"scope: '{doc['scope']}' where '{require_scope}' is required")
    if expected_suite is not None and doc["suite"] != expected_suite:
        raise SuiteError(f"suite: the file is suite {doc['suite']}, expected {expected_suite}")
    return doc, "sha256:" + hashlib.sha256(data).hexdigest()


# ── compatibility matrix ─────────────────────────────────────────────────────


def validate_matrix(doc: object) -> None:
    """Raise SuiteError unless `doc` is a well-formed compatibility matrix."""
    _mapping(doc, "matrix", {"schema", "components", "suites"})
    if doc["schema"] != MATRIX_SCHEMA:
        raise SuiteError(f"schema: must be '{MATRIX_SCHEMA}'")
    components = doc["components"]
    if not isinstance(components, list) or not components:
        raise SuiteError("components: must be a non-empty list of distinct names")
    for index, name in enumerate(components):
        _text(name, f"components[{index}]", _NAME_RE)
    if len(set(components)) != len(components):
        raise SuiteError("components: must be a non-empty list of distinct names")
    suites = doc["suites"]
    if not isinstance(suites, list) or not suites:
        raise SuiteError("suites: must be a non-empty list")
    previous: str | None = None
    for index, row in enumerate(suites):
        where = f"suites[{index}]"
        _mapping(row, where, {"suite", "status", "core", "addon_api", "versions"})
        version = _text(row["suite"], f"{where}.suite", _VERSION_RE)
        if previous is not None and semver.compare(version, previous) <= 0:
            raise SuiteError(f"{where}.suite: rows must be in ascending suite order, no repeats")
        previous = version
        _choice(row["status"], f"{where}.status", SUITE_STATUS)
        _range(row["core"], f"{where}.core")
        if not semver.satisfies(version, row["core"]):
            raise SuiteError(f"{where}.core: does not contain the suite version {version}")
        _window(row["addon_api"], f"{where}.addon_api")
        versions = row["versions"]
        if not isinstance(versions, dict) or not versions:
            raise SuiteError(f"{where}.versions: must be a non-empty mapping")
        for name, cell in versions.items():
            if name not in components:
                raise SuiteError(f"{where}.versions: '{name}' is not a component")
            _range(cell, f"{where}.versions.{name}")


def load_matrix(repo_root: Path) -> dict | None:
    """The validated matrix of a core checkout, or None for a core without one."""
    path = Path(repo_root) / MATRIX_PATH
    if not path.is_file():
        return None
    doc = _parse_yaml(_read_limited(path, MAX_BOM_BYTES, str(MATRIX_PATH)), str(MATRIX_PATH))
    try:
        validate_matrix(doc)
    except SuiteError as exc:
        raise SuiteError(f"{MATRIX_PATH}: {exc}") from exc
    return doc


def matrix_rows(matrix: dict, core_version: str) -> tuple[dict | None, dict | None]:
    """The row whose core range holds `core_version` and the row before it.

    A prerelease core (1.10.0-rc.1) is judged by the row of its release
    (1.10.0): semver sorts it below `>=1.10.0`, but it is that suite's candidate."""
    try:
        parsed = semver.parse_version(core_version)
    except ValueError:
        return None, None
    release = semver.Version(parsed.major, parsed.minor, parsed.patch)
    suites = matrix["suites"]
    for index, row in enumerate(suites):
        if semver.satisfies(release, row["core"]):
            return row, suites[index - 1] if index > 0 else None
    return None, None


def evaluate_matrix(
    result: compat.CompatResult, version: str | None, matrix: dict, core_version: str | None
) -> compat.CompatResult:
    """Fold the matrix verdict for one add-on into its `addon check` result.

    Only add-ons the matrix names are judged, and only a verdict that is still
    OK or UNKNOWN can be lowered. The add-on version must lie in the cell of the
    core's suite or of the suite before it (core N accepts suites N and N-1)."""
    name = result.name
    if name not in matrix["components"] or result.status not in (
        compat.STATUS_OK, compat.STATUS_UNKNOWN
    ):
        return result
    if core_version is None:
        # Only --target-addon-api was given: that axis alone is judged.
        note = "core version unknown; suite matrix not checked"
        return compat.CompatResult(
            name, result.status, result.axis, result.requirement, result.core_value,
            result.reason, (*result.warnings, note),
        )
    row, before = matrix_rows(matrix, core_version)
    if row is None:
        # Fail closed: a matrix that does not cover the judged core vouches for nothing.
        return compat.CompatResult(
            name, compat.STATUS_INCOMPATIBLE, axis=MATRIX_AXIS, requirement=version,
            core_value=core_version,
            reason=f"suite matrix has no row for core {core_version}; check against the "
                   f"candidate checkout with --target-core",
            warnings=result.warnings,
        )
    cells = [(r["suite"], r["versions"][name]) for r in (row, before)
             if r is not None and name in r["versions"]]
    if not cells:
        note = f"suite matrix lists no version of '{name}' for core {core_version}"
        return compat.CompatResult(
            name, result.status, result.axis, result.requirement, result.core_value,
            result.reason, (*result.warnings, note),
        )
    if version is None:
        note = f"add-on '{name}' states no version; suite matrix not checked"
        return compat.CompatResult(
            name, result.status, result.axis, result.requirement, result.core_value,
            result.reason, (*result.warnings, note),
        )
    try:
        fits = any(semver.satisfies(version, cell) for _, cell in cells)
    except ValueError:
        fits = False
    if fits:
        return result
    allowed = " or ".join(f"{cell} (suite {suite_version})" for suite_version, cell in cells)
    return compat.CompatResult(
        name, compat.STATUS_INCOMPATIBLE, axis=MATRIX_AXIS, requirement=version,
        core_value=core_version,
        reason=f"'{name}' {version} is not in the suite matrix for core {core_version}: "
               f"allowed {allowed}",
        warnings=result.warnings,
    )


_TITLES = {
    "manager": "Manager", "papaia-me": "Me", "papaia-studio": "Studio", "papaia-data": "Data",
    "papaia-flow": "Flow", "papaia-assist": "Assistant", "paperless": "Paperless",
    "papaia-connections": "Connections",
}


def table_header(matrix: dict) -> str:
    titles = [_TITLES.get(name, name) for name in matrix["components"]]
    return "| " + " | ".join(["Suite", "Status", "Core", "Add-on API", *titles]) + " |"


def table_row(matrix: dict, row: dict) -> str:
    """One row of the public table in docs/compatibility.md."""
    window = f"{row['addon_api']['min']}..{row['addon_api']['current']}"
    cells = [f"`{row['versions'][n]}`" if n in row["versions"] else "–"
             for n in matrix["components"]]
    return "| " + " | ".join(
        [row["suite"], row["status"], f"`{row['core']}`", window, *cells]
    ) + " |"
