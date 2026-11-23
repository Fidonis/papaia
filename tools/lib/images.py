"""Pinned images and their signatures, checked before `start` and `upgrade`.

Every compose file names its images as `name:tag@sha256:<digest>`; a tag alone
can be moved, a digest cannot. Before containers are started, each image that
compose is about to run must

1. be listed in the signed suite bill of materials of this core (lib/suite.py),
   with the same name, tag and digest, and
2. carry a valid cosign signature by the key of that bill of materials.

The bill of materials is only trusted through the release key pinned in the core
checkout (`compat/release-key.pub`), never through the key inside it alone, and
it must be the `delivery` file of exactly this core version. Without the pinned
key the check refuses instead of checking without an anchor.

cosign (2.x, `cosign sign --key`) stores a signature as an OCI manifest tagged
`sha256-<hex>.sig` in the image's repository: one layer of media type
`application/vnd.dev.cosign.simplesigning.v1+json` whose blob names the signed
manifest digest and whose annotation `dev.cosignproject.cosign/signature` holds
the base64 ECDSA P-256/SHA-256 signature over that blob. It is read from the
registry over the plain /v2 API and checked by openssl, the same way the bill
of materials is; no cosign binary is needed on the host.

An upgrade checks the target's bill of materials against the release key of the
installed core (its fingerprint, `anchor`), never against the key the target brings:
a new key is accepted only through `compat/release-key-rotation.yaml`, a signature
by the installed key over the new key file.

Signatures live in one repository named by the release in
`compat/image-signatures.yaml` (cosign's `COSIGN_REPOSITORY`): the project cannot
write into the repositories of third-party images. Without that file a signature is
looked up next to its image.

`PAPAIA_IMAGE_MIRROR` (a registry prefix such as `registry.example.com/papaia/`)
is placed in front of every core image by a generated override
(gen_override.generate_image_mirror_override); the mirror serves the images and
the signature repository under the same prefix, and digests do not change.
`PAPAIA_IMAGE_SIGNATURES` overrides the signature repository for a mirror that
keeps signatures elsewhere.

The registry is read with the host's Docker credentials when there are any (a
logged-in Docker Hub account has far higher pull limits); a verified signature is
remembered per key and digest in the configuration directory, so a repeated start
asks the registry nothing. Rate limits and server errors are "not reachable": start
refuses, doctor warns.

`--insecure-images` skips the check for one command: a banner on stderr and one
`papaia.audit/1` row in the configuration directory; the flag is never stored.
Add-on images from a repository the bill of materials does not list can be
accepted at `addon install` with `--accept-unlisted-images`: by exact digest, for
that add-on only, recorded and audited once the add-on is registered.
"""

from __future__ import annotations

import base64
import binascii
import getpass
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

import yaml

from . import suite

EXCEPTIONS_PATH = Path("compat") / "image-exceptions.yaml"
EXCEPTIONS_SCHEMA = "papaia.image-exceptions/1"
MAX_EXCEPTION_DAYS = 90
MIRROR_VAR = "PAPAIA_IMAGE_MIRROR"
SIGNATURES_VAR = "PAPAIA_IMAGE_SIGNATURES"
AUDIT_LOG = Path("audit") / "papaia-ctl.jsonl"
ROTATION_PATH = Path("compat") / "release-key-rotation.yaml"
ROTATION_SCHEMA = "papaia.release-key-rotation/1"
SIGNATURES_PATH = Path("compat") / "image-signatures.yaml"
SIGNATURES_SCHEMA = "papaia.image-signatures/1"
CACHE_PATH = Path("cache") / "image-signatures.json"
CACHE_SCHEMA = "papaia.image-signature-cache/1"
MAX_CACHE_ENTRIES = 4096
ACCEPTED_PATH = Path("trust") / "accepted-images.json"
ACCEPTED_SCHEMA = "papaia.accepted-images/1"

SIMPLESIGNING_MEDIA_TYPE = "application/vnd.dev.cosign.simplesigning.v1+json"
SIGNATURE_ANNOTATION = "dev.cosignproject.cosign/signature"
SIGNATURE_TYPE = "cosign container image signature"

MAX_IMAGES = 256
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_SIGNATURE_LAYERS = 16
HTTP_TIMEOUT_SECONDS = 20

# A tag naming a moving target: `latest`, a branch or a development build.
_FLOATING_SEGMENTS = {"latest", "dev", "develop", "development", "nightly", "snapshot"}
_BRANCH_TAGS = {"main", "master", "trunk", "head", "edge", "stable", "unstable", "beta", "alpha"}

_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_HOST = r"(?:[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*|\[[0-9a-fA-F:]+\])(?::[0-9]{1,5})?"
_NAME_RE = re.compile(rf"\A(?:(?P<host>{_HOST})/)?(?P<path>{_COMPONENT}(?:/{_COMPONENT})*)\Z")
_TAG_RE = re.compile(r"\A[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_MIRROR_RE = re.compile(rf"\A{_HOST}(?:/{_COMPONENT})*/\Z")
_LOOPBACK = ("localhost", "127.0.0.1", "[::1]")

_MANIFEST_ACCEPT = ", ".join((
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))
# A pinned image is usually a multi-platform index; its digest is the index's.
_RESOLVE_ACCEPT = ", ".join((
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))


class ImageError(ValueError):
    """An image or a setting that must not be used; the message says why."""


class NotFound(ImageError):
    """The registry answered 404 for a manifest or blob."""


class Unreachable(ImageError):
    """The registry did not answer usefully for now: no connection, a rate limit (429)
    or a server error (5xx). Nothing is known about the signature."""


@dataclass(frozen=True)
class Ref:
    registry: str
    repository: str
    tag: str | None
    digest: str | None


@dataclass(frozen=True)
class Problem:
    ref: str
    reason: str
    # True when the registry could not be asked (Unreachable): doctor warns instead of
    # failing; start and upgrade still refuse.
    transient: bool = False
    # True when the bill of materials does not list the image's repository at all (an
    # add-on from elsewhere); only such an image can be accepted at `addon install`.
    # Another tag or digest of a listed repository is never "unlisted".
    unlisted: bool = False


# ── references ───────────────────────────────────────────────────────────────


def _split(text: str) -> tuple[str, str | None, str | None]:
    """(name, tag, digest) of `name[:tag][@digest]`; the tag's colon is the one
    after the last slash, a registry port is not a tag."""
    name, _, digest = text.partition("@")
    slash = name.rfind("/")
    colon = name.rfind(":")
    tag = None
    if colon > slash:
        name, tag = name[:colon], name[colon + 1:]
    return name, tag, (digest if "@" in text else None)


def parse_ref(text: str) -> Ref:
    """Normalise a reference like Docker: a first component without `.`, `:` or
    `localhost` is a Docker Hub path, a single one lives under `library/`."""
    if not isinstance(text, str) or len(text) > 512:
        raise ImageError("invalid image reference")
    name, tag, digest = _split(text)
    match = _NAME_RE.match(name)
    if not match:
        raise ImageError(f"invalid image reference {text[:120]!r}")
    host, path = match.group("host"), match.group("path")
    if host is not None and not ("." in host or ":" in host or host == "localhost"
                                 or host.startswith("[")):
        host, path = None, f"{host}/{path}"
    if host is None or host in ("index.docker.io", "registry-1.docker.io"):
        host = "docker.io"
        if "/" not in path:
            path = f"library/{path}"
    if tag is not None and not _TAG_RE.match(tag):
        raise ImageError(f"invalid tag in {text[:120]!r}")
    if digest is not None and not _DIGEST_RE.match(digest):
        raise ImageError(f"invalid digest in {text[:120]!r}")
    return Ref(host, path, tag, digest)


def load_exceptions(repo_root: Path, today: date | None = None) -> set[tuple[str, str, str]]:
    """(registry, repository, digest) of the images that may stay without a tag: an
    upstream that keeps no tag for the pinned build. Each entry names its reason and
    expires after at most 90 days; an expired entry is an error, not a silent pass."""
    path = Path(repo_root) / EXCEPTIONS_PATH
    if not path.is_file():
        return set()
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or set(doc) != {"schema", "exceptions"} or (
        doc["schema"] != EXCEPTIONS_SCHEMA or not isinstance(doc["exceptions"], list)
    ):
        raise ImageError(f"{EXCEPTIONS_PATH}: expected schema {EXCEPTIONS_SCHEMA} and a list")
    today = today or date.today()
    allowed: set[tuple[str, str, str]] = set()
    for index, entry in enumerate(doc["exceptions"]):
        where = f"{EXCEPTIONS_PATH}: exceptions[{index}]"
        if not isinstance(entry, dict) or set(entry) != {
            "image", "digest", "rule", "reason", "expires"
        }:
            raise ImageError(f"{where}: needs exactly image, digest, rule, reason, expires")
        if entry["rule"] != "tag":
            raise ImageError(f"{where}: only the rule 'tag' can be excepted")
        if not isinstance(entry["reason"], str) or len(entry["reason"].strip()) < 20:
            raise ImageError(f"{where}: reason must say why (at least 20 characters)")
        expires = entry["expires"]
        if isinstance(expires, str):
            try:
                expires = date.fromisoformat(expires)
            except ValueError:
                expires = None
        if not isinstance(expires, date):
            raise ImageError(f"{where}: expires must be a date YYYY-MM-DD")
        if expires < today:
            raise ImageError(f"{where}: expired on {expires.isoformat()}")
        if expires > today + timedelta(days=MAX_EXCEPTION_DAYS):
            raise ImageError(f"{where}: expires more than {MAX_EXCEPTION_DAYS} days ahead")
        ref = parse_ref(f"{entry['image']}@{entry['digest']}")
        if ref.tag is not None or ref.digest is None:
            raise ImageError(f"{where}: image without tag and a sha256 digest expected")
        allowed.add((ref.registry, ref.repository, ref.digest))
    return allowed


def pin_problem(text: str, exceptions: set[tuple[str, str, str]] = frozenset()) -> str | None:
    """Why a compose image reference is not pinned, or None. `exceptions`
    (load_exceptions) may release an exactly named digest from the tag rule,
    never from the digest rule."""
    if not isinstance(text, str):
        return "not a string"
    ref = text
    if "$" in ref:
        return "contains a variable; an image is pinned literally"
    _, tag, digest = _split(ref)
    if digest is not None and not _DIGEST_RE.match(digest):
        return "invalid digest (sha256:<64 hex> expected)"
    try:
        parsed = parse_ref(ref)
    except ImageError as exc:
        return str(exc)
    if parsed.digest is None:
        return "no digest: name:tag@sha256:<digest> expected"
    if parsed.tag is None:
        if (parsed.registry, parsed.repository, parsed.digest) in exceptions:
            return None
        return "no tag: name:tag@sha256:<digest> expected"
    tag = parsed.tag.lower()
    segments = set(re.split(r"[-._]", tag))
    if "latest" in segments:
        return "floating tag 'latest'"
    if tag in _BRANCH_TAGS or tag in _FLOATING_SEGMENTS:
        return f"branch tag '{parsed.tag}'"
    if segments & _FLOATING_SEGMENTS:
        return f"development tag '{parsed.tag}'"
    return None


def compose_services(repo_root: Path) -> dict[str, str]:
    """{service: image} of every service of the core's compose files."""
    found: dict[str, str] = {}
    for path in sorted((Path(repo_root) / "src").rglob("docker-compose*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for service, body in (doc.get("services") or {}).items():
            if isinstance(body, dict) and isinstance(body.get("image"), str):
                found[service] = body["image"]
    return found


def compose_image_refs(repo_root: Path) -> list[tuple[str, str]]:
    """(location, reference) of every image in the core's compose files: each
    `services.*.image` and each value of an `x-papaia-*-images` variant map."""
    found: list[tuple[str, str]] = []
    src = Path(repo_root) / "src"
    for path in sorted(src.rglob("docker-compose*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        rel = path.relative_to(repo_root).as_posix()
        for service, body in sorted((doc.get("services") or {}).items()):
            if isinstance(body, dict) and "image" in body:
                found.append((f"{rel}: services.{service}.image", body["image"]))
        for key, value in sorted(doc.items()):
            if isinstance(key, str) and key.startswith("x-papaia-") and key.endswith("-images"):
                for variant, ref in sorted((value or {}).items()):
                    found.append((f"{rel}: {key}.{variant}", ref))
    return found


def validate_mirror(value: str) -> str:
    """`host[:port][/path]/` or empty; put in front of every core image."""
    if value == "":
        return value
    if not isinstance(value, str) or len(value) > 200 or not _MIRROR_RE.match(value):
        raise ImageError(
            f"{MIRROR_VAR} must be a registry prefix ending in '/', such as "
            "'registry.example.com/papaia/'"
        )
    return value


def _signature_repository(value: str, where: str = SIGNATURES_VAR) -> Ref | None:
    if value == "":
        return None
    try:
        ref = parse_ref(value)
    except ImageError:
        ref = None
    if ref is None or ref.tag is not None or ref.digest is not None:
        raise ImageError(f"{where} must name a repository, such as "
                         "'ghcr.io/example/signatures'")
    return ref


# ── registry ─────────────────────────────────────────────────────────────────


def _is_loopback(host: str | None) -> bool:
    return (host or "").strip("[]") in ("localhost", "127.0.0.1", "::1")


_HELPER_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_DOCKER_HUB_KEYS = ("https://index.docker.io/v1/", "index.docker.io", "docker.io",
                    "registry-1.docker.io", "https://registry-1.docker.io")


class DockerCredentials:
    """Read-only lookup of the host's registry credentials, as `docker login` stored
    them: `$DOCKER_CONFIG/config.json` (default `~/.docker/config.json`), its
    `credHelpers`, `credsStore` and `auths`. Identity tokens are not used. Nothing is
    written, printed or kept beyond this process."""

    def __init__(self, config_dir: Path | None = None):
        if config_dir is None:
            env = os.environ.get("DOCKER_CONFIG", "")
            config_dir = Path(env) if env else Path.home() / ".docker"
        self._path = Path(config_dir) / "config.json"
        self._doc: dict | None = None
        self._found: dict[str, tuple[str, str] | None] = {}

    def _config(self) -> dict:
        if self._doc is None:
            try:
                doc = json.loads(suite._read_limited(self._path, 1024 * 1024, "docker config"))
            except (suite.SuiteError, ValueError):
                doc = {}
            self._doc = doc if isinstance(doc, dict) else {}
        return self._doc

    @staticmethod
    def _keys(host: str) -> tuple[str, ...]:
        if host == "docker.io":
            return _DOCKER_HUB_KEYS
        return (host, f"https://{host}", f"https://{host}/v1/", f"http://{host}")

    def _helper(self, name: object, server: str) -> tuple[str, str] | None:
        if not isinstance(name, str) or not _HELPER_RE.match(name):
            return None
        program = shutil.which(f"docker-credential-{name}")
        if program is None:
            return None
        try:
            done = subprocess.run([program, "get"], input=server, capture_output=True,
                                  text=True, timeout=10, check=False)
            doc = json.loads(done.stdout) if done.returncode == 0 else None
        except (OSError, subprocess.SubprocessError, ValueError):
            return None
        if not isinstance(doc, dict):
            return None
        user, secret = doc.get("Username"), doc.get("Secret")
        if not isinstance(user, str) or not isinstance(secret, str) or not secret:
            return None
        return None if user == "<token>" else (user, secret)

    def _lookup(self, host: str) -> tuple[str, str] | None:
        config = self._config()
        keys = self._keys(host)
        helpers = config.get("credHelpers")
        if isinstance(helpers, dict):
            for key in keys:
                if key in helpers:
                    return self._helper(helpers[key], key)
        auths = config.get("auths") if isinstance(config.get("auths"), dict) else {}
        stored = next((key for key in keys if key in auths), None)
        if config.get("credsStore"):
            found = self._helper(config["credsStore"], stored or keys[0])
            if found is not None:
                return found
        entry = auths.get(stored) if stored else None
        if isinstance(entry, dict) and isinstance(entry.get("auth"), str):
            try:
                user, sep, secret = base64.b64decode(entry["auth"], validate=True).decode(
                    "utf-8").partition(":")
            except (binascii.Error, UnicodeDecodeError):
                return None
            if sep and secret:
                return user, secret
        return None

    def lookup(self, host: str) -> tuple[str, str] | None:
        """(user, secret) for the registry `host`, or None for anonymous access."""
        if host not in self._found:
            self._found[host] = self._lookup(host)
        return self._found[host]


class _RedirectRefused(urllib.error.URLError):
    """A redirect that would leave HTTPS (outside loopback)."""


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Follows a registry's redirect (blobs are often served from storage on another
    host) without the registry's token, and never from HTTPS down to plain HTTP;
    plain HTTP is only followed to a loopback host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(urllib.parse.urljoin(req.full_url, newurl))
        if new.scheme != "https" and not (
            new.scheme == "http" and old.scheme == "http" and _is_loopback(new.hostname)
        ):
            raise _RedirectRefused(f"redirect from {old.scheme} to {new.scheme} refused")
        request = super().redirect_request(req, fp, code, msg, headers, new.geturl())
        if request is not None and (old.hostname, old.port) != (new.hostname, new.port):
            request.remove_header("Authorization")
        return request


class Registry:
    """Read-only client of the registry /v2 API: manifests and blobs, bearer tokens
    with the host's credentials or anonymous. HTTPS except for loopback registries,
    as Docker does."""

    def __init__(self, timeout: float = HTTP_TIMEOUT_SECONDS, credentials=None):
        self.timeout = timeout
        self.credentials = credentials if credentials is not None else DockerCredentials()
        self._tokens: dict[tuple[str, str], str] = {}
        self._opener = urllib.request.build_opener(_SafeRedirect())

    @staticmethod
    def _base(host: str) -> str:
        endpoint = "registry-1.docker.io" if host == "docker.io" else host
        plain = endpoint.rsplit(":", 1)[0] if not endpoint.startswith("[") else (
            endpoint.split("]")[0] + "]")
        scheme = "http" if plain in _LOOPBACK else "https"
        return f"{scheme}://{endpoint}"

    def _basic(self, host: str) -> str | None:
        found = self.credentials.lookup(host)
        if not found:
            return None
        return "Basic " + base64.b64encode(f"{found[0]}:{found[1]}".encode()).decode("ascii")

    def _token(self, challenge: str, host: str, repository: str) -> str | None:
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = params.get("realm", "")
        if not challenge.lower().startswith("bearer ") or not realm.startswith("https://"):
            return None
        query = {"scope": params.get("scope") or f"repository:{repository}:pull"}
        if params.get("service"):
            query["service"] = params["service"]
        url = f"{realm}?{urllib.parse.urlencode(query)}"
        headers: dict[str, str] = {}
        basic = self._basic(host)
        if basic:
            headers["Authorization"] = basic
        body = self._fetch(url, headers, 64 * 1024)
        try:
            doc = json.loads(body)
        except ValueError as exc:
            raise ImageError("registry token answer is not JSON") from exc
        token = doc.get("token") or doc.get("access_token") if isinstance(doc, dict) else None
        return token if isinstance(token, str) and token else None

    def _fetch(self, url: str, headers: dict[str, str], limit: int) -> bytes:
        return self._open(url, headers, limit)[0]

    def _open(self, url: str, headers: dict[str, str], limit: int,
              method: str = "GET") -> tuple[bytes, dict[str, str]]:
        request = urllib.request.Request(url, headers=headers, method=method)
        with self._opener.open(request, timeout=self.timeout) as answer:
            data = answer.read(limit + 1) if method == "GET" else b""
            found = {key.lower(): value for key, value in answer.headers.items()}
        if len(data) > limit:
            raise ImageError(f"registry answer larger than {limit} bytes")
        return data, found

    def _get(self, host: str, repository: str, path: str, accept: str, limit: int) -> bytes:
        return self._request(host, repository, path, accept, limit)[0]

    def _request(self, host: str, repository: str, path: str, accept: str, limit: int,
                 method: str = "GET") -> tuple[bytes, dict[str, str]]:
        url = f"{self._base(host)}/v2/{repository}/{path}"
        headers = {"Accept": accept}
        token = self._tokens.get((host, repository))
        if token:
            headers["Authorization"] = f"Bearer {token}"
        for attempt in (0, 1):
            try:
                if method == "GET":
                    return self._fetch(url, headers, limit), {}
                return self._open(url, headers, limit, method)
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    raise NotFound(f"{host}/{repository}: {path} not found") from None
                if exc.code == 429:
                    raise Unreachable(f"{host}: HTTP 429 (rate limited)") from None
                if exc.code >= 500:
                    raise Unreachable(f"{host}: HTTP {exc.code} (server error)") from None
                challenge = exc.headers.get("WWW-Authenticate", "") if exc.headers else ""
                if exc.code == 401 and attempt == 0 and challenge:
                    if challenge.lower().startswith("basic"):
                        basic = self._basic(host)
                        if basic:
                            headers["Authorization"] = basic
                            continue
                    else:
                        token = self._token(challenge, host, repository)
                        if token:
                            self._tokens[(host, repository)] = token
                            headers["Authorization"] = f"Bearer {token}"
                            continue
                raise ImageError(f"{host}: HTTP {exc.code}") from None
            except _RedirectRefused as exc:
                raise ImageError(f"{host}: {exc.reason}") from None
            except (urllib.error.URLError, OSError) as exc:
                reason = getattr(exc, "reason", exc)
                raise Unreachable(f"{host}: not reachable ({reason})") from None
        raise ImageError(f"{host}: access refused")

    def manifest(self, host: str, repository: str, reference: str) -> bytes:
        return self._get(host, repository, f"manifests/{reference}", _MANIFEST_ACCEPT,
                         MAX_MANIFEST_BYTES)

    def blob(self, host: str, repository: str, digest: str, limit: int) -> bytes:
        return self._get(host, repository, f"blobs/{digest}", "*/*", limit)

    def resolve(self, host: str, repository: str, reference: str) -> str:
        """The digest the registry serves for a tag or digest, without the body where
        it can: a HEAD request (Docker Hub does not count it against the pull limit)
        whose `Docker-Content-Digest` names it; otherwise the sha256 of the manifest
        or index fetched with GET. Raises NotFound for an unknown tag or digest."""
        _, headers = self._request(host, repository, f"manifests/{reference}",
                                   _RESOLVE_ACCEPT, MAX_MANIFEST_BYTES, method="HEAD")
        digest = headers.get("docker-content-digest", "")
        if _DIGEST_RE.match(digest):
            return digest
        body, _ = self._request(host, repository, f"manifests/{reference}",
                                _RESOLVE_ACCEPT, MAX_MANIFEST_BYTES)
        return "sha256:" + hashlib.sha256(body).hexdigest()


class SignatureCache:
    """Signatures already verified on this host: (key fingerprint, image digest). A
    cosign key signature does not expire, so a digest verified once with a key holds
    for that key. Only the signature lookup is skipped; the bill of materials is
    checked every time. A damaged file is ignored and rewritten."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._entries: list[str] = []
        self._dirty = False
        try:
            doc = json.loads(suite._read_limited(self.path, 1024 * 1024, "signature cache"))
        except (suite.SuiteError, ValueError):
            return
        if isinstance(doc, dict) and doc.get("schema") == CACHE_SCHEMA and isinstance(
            doc.get("verified"), list
        ):
            self._entries = [e for e in doc["verified"] if isinstance(e, str)
                             and re.fullmatch(r"sha256:[0-9a-f]{64} sha256:[0-9a-f]{64}", e)]

    @staticmethod
    def _key(fingerprint: str, digest: str) -> str:
        return f"{fingerprint} {digest}"

    def known(self, fingerprint: str, digest: str) -> bool:
        return self._key(fingerprint, digest) in self._entries

    def remember(self, fingerprint: str, digest: str) -> None:
        key = self._key(fingerprint, digest)
        if key not in self._entries:
            self._entries.append(key)
            self._entries = self._entries[-MAX_CACHE_ENTRIES:]
            self._dirty = True

    def save(self) -> None:
        if not self._dirty:
            return
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps({"schema": CACHE_SCHEMA, "verified": self._entries},
                                    indent=0).encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, self.path)
        self._dirty = False


# ── signatures ───────────────────────────────────────────────────────────────


def _layer_valid(registry, where: Ref, layer: object, digest: str, pem: str) -> bool:
    if not isinstance(layer, dict) or layer.get("mediaType") != SIMPLESIGNING_MEDIA_TYPE:
        return False
    blob_digest = layer.get("digest")
    annotations = layer.get("annotations")
    if not isinstance(blob_digest, str) or not _DIGEST_RE.match(blob_digest):
        return False
    if not isinstance(annotations, dict) or not isinstance(
        annotations.get(SIGNATURE_ANNOTATION), str
    ):
        return False
    try:
        signature = base64.b64decode(annotations[SIGNATURE_ANNOTATION], validate=True)
    except binascii.Error:
        return False
    payload = registry.blob(where.registry, where.repository, blob_digest, MAX_PAYLOAD_BYTES)
    if "sha256:" + hashlib.sha256(payload).hexdigest() != blob_digest:
        return False
    # The signature first: the payload is only parsed once it is authentic.
    if not signature or not suite._signature_valid(payload, signature, pem):
        return False
    try:
        critical = json.loads(payload)["critical"]
        return (
            critical["type"] == SIGNATURE_TYPE
            and critical["image"]["docker-manifest-digest"] == digest
        )
    except (ValueError, KeyError, TypeError):
        return False


UNREACHABLE = "signature not readable: registry not reachable"


def signature_problem(registry, ref: Ref, pem: str, signatures: Ref | None = None) -> str | None:
    """Why `ref` has no valid cosign signature by `pem`, or None when it has one. A
    reason starting with UNREACHABLE means the registry could not be asked."""
    if ref.digest is None:
        return "no digest to check a signature against"
    where = signatures or ref
    tag = ref.digest.replace(":", "-") + ".sig"
    try:
        raw = registry.manifest(where.registry, where.repository, tag)
    except NotFound:
        return f"no signature ({where.registry}/{where.repository}:{tag} not found)"
    except Unreachable as exc:
        return f"{UNREACHABLE}: {exc}"
    except ImageError as exc:
        return f"signature not readable: {exc}"
    try:
        layers = json.loads(raw)["layers"]
    except (ValueError, KeyError, TypeError):
        return "signature manifest is not an OCI manifest"
    if not isinstance(layers, list) or not 0 < len(layers) <= MAX_SIGNATURE_LAYERS:
        return "signature manifest has no usable layer"
    unreachable = None
    for layer in layers:
        try:
            if _layer_valid(registry, where, layer, ref.digest, pem):
                return None
        except Unreachable as exc:
            unreachable = exc
        except ImageError:
            continue
    if unreachable is not None:
        return f"{UNREACHABLE}: {unreachable}"
    return "no valid signature by the key of the bill of materials"


def _bom_index(bom: dict) -> dict[tuple[str, str], dict[str, str]]:
    """{(registry, repository): {tag: digest}} of a verified bill of materials."""
    index: dict[tuple[str, str], dict[str, str]] = {}
    for repo in bom["repos"]:
        for image in repo["images"]:
            ref = parse_ref(f"{image['name']}:{image['tag']}")
            index.setdefault((ref.registry, ref.repository), {})[image["tag"]] = image["digest"]
    return index


_NOT_LISTED = "not in the bill of materials"


def _listed_problem(index: dict[tuple[str, str], dict[str, str]], ref: Ref) -> str | None:
    """Why the bill of materials does not cover `ref`, or None. Exactly
    `_NOT_LISTED` when it does not list the repository at all; any other answer is
    about a repository of the delivery and can never be accepted."""
    tags = index.get((ref.registry, ref.repository))
    if tags is None:
        return _NOT_LISTED
    if ref.tag is None:
        # An excepted untagged pin: the digest itself must be listed.
        if ref.digest in tags.values():
            return None
        return ("the bill of materials lists this repository, but not this digest; "
                "it cannot be accepted")
    expected = tags.get(ref.tag)
    if expected is None:
        return (f"the bill of materials lists this repository, but not tag {ref.tag}; "
                "it cannot be accepted")
    if expected != ref.digest:
        return f"digest differs from the bill of materials, which lists {expected}"
    return None


def repository_listed(bom: dict, text: str) -> bool:
    """Whether the bill of materials lists the repository of `text` (under any tag)."""
    ref = parse_ref(text)
    return (ref.registry, ref.repository) in _bom_index(bom)


def verify_images(
    refs: list[str],
    bom: dict,
    *,
    registry,
    mirror: str = "",
    signatures: str = "",
    cache: SignatureCache | None = None,
    accepted: set[tuple[str, str, str]] = frozenset(),
) -> list[Problem]:
    """One Problem per image that may not be started; empty when all may.

    The bill of materials is consulted before the registry: an image it does not
    list, or lists with another digest, is refused without a network call. An image
    whose repository it does not list at all passes only when the operator accepted
    exactly that digest for the add-on being checked (`accepted`, see
    load_accepted; empty for the core); an image of a listed repository never passes
    with another tag, another digest or without its signature. `cache` skips the
    signature lookup of a digest already verified with this key."""
    pem = bom["signing_key"]["public_key"]
    fingerprint = bom["signing_key"]["fingerprint"]
    index = _bom_index(bom)
    signature_repo = _signature_repository(signatures)
    problems: list[Problem] = []
    for served in refs:
        try:
            ref = parse_ref(served)
            listed = parse_ref(served.removeprefix(mirror) if mirror else served)
        except ImageError as exc:
            problems.append(Problem(served, str(exc)))
            continue
        if ref.digest is None:
            problems.append(Problem(served, "not pinned: name:tag@sha256:<digest> expected"))
            continue
        listed_problem = _listed_problem(index, listed)
        if listed_problem is not None:
            if listed_problem == _NOT_LISTED:
                if (listed.registry, listed.repository, listed.digest) in accepted:
                    continue
                problems.append(Problem(served, listed_problem, unlisted=True))
            else:
                problems.append(Problem(served, listed_problem))
            continue
        if cache is not None and cache.known(fingerprint, ref.digest):
            continue
        why = signature_problem(registry, ref, pem, signature_repo)
        if why is None:
            if cache is not None:
                cache.remember(fingerprint, ref.digest)
            continue
        problems.append(Problem(served, why, transient=why.startswith(UNREACHABLE)))
    return problems


# ── trust anchor ─────────────────────────────────────────────────────────────


def core_version(repo_root: Path) -> str:
    path = Path(repo_root) / "VERSION"
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ImageError(f"{path} not readable") from exc


def suite_version(version: str) -> str:
    """The suite a core version belongs to: the version itself, or for a pre-release
    (1.10.0-rc.1) the release it is a candidate of (1.10.0). A candidate core is checked
    against the bill of materials of the suite it will ship in, never an older one."""
    match = re.fullmatch(r"(\d+\.\d+\.\d+)(?:-[0-9A-Za-z.-]+)?", version)
    if not match:
        raise ImageError(f"VERSION {version[:40]!r} is not a version X.Y.Z[-pre-release]")
    return match.group(1)


def is_candidate(version: str) -> bool:
    """Whether the core version is a pre-release (a candidate of its suite)."""
    return suite_version(version) != version


def bom_path(repo_root: Path, version: str) -> Path:
    return Path(repo_root) / "compat" / f"suite-{suite_version(version)}.yaml"


def _read_key(path: Path) -> str:
    try:
        raw = suite._read_limited(path, 4096, "public key")
    except suite.SuiteError as exc:
        raise ImageError(str(exc)) from exc
    # A key file copied on Windows has CRLF line endings; it is the same key.
    return raw.decode("ascii", "replace").replace("\r\n", "\n")


def anchor_fingerprint(repo_root: Path) -> str:
    """Fingerprint of the release key pinned in this checkout: the anchor an upgrade
    carries into the target's check."""
    path = Path(repo_root) / suite.RELEASE_KEY_PATH
    if not path.is_file():
        raise ImageError(
            f"no trust anchor: {suite.RELEASE_KEY_PATH} is not in this checkout, so image "
            "signatures cannot be checked"
        )
    try:
        return suite.key_fingerprint(_read_key(path))
    except suite.SuiteError as exc:
        raise ImageError(f"{suite.RELEASE_KEY_PATH}: {exc}") from exc


def _exact_mapping(value: object, keys: set[str], where: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ImageError(f"{where}: needs exactly {', '.join(sorted(keys))}")
    return value


def _rotation_proven(root: Path, new_pem: str, anchor: str) -> None:
    """Raise unless the target's rotation file holds a signature by the installed key
    (fingerprint `anchor`) over the target's release key file."""
    path = root / ROTATION_PATH
    if not path.is_file():
        raise ImageError(
            f"the target's release key differs from the installed one ({anchor}) and it "
            f"brings no rotation signed by the installed key ({ROTATION_PATH})"
        )
    try:
        doc = suite._parse_yaml(suite._read_limited(path, 256 * 1024, "key rotation"),
                                str(ROTATION_PATH))
    except suite.SuiteError as exc:
        raise ImageError(str(exc)) from exc
    doc = _exact_mapping(doc, {"schema", "rotations"}, str(ROTATION_PATH))
    if doc["schema"] != ROTATION_SCHEMA or not isinstance(doc["rotations"], list) or not (
        0 < len(doc["rotations"]) <= 16
    ):
        raise ImageError(f"{ROTATION_PATH}: expected schema {ROTATION_SCHEMA} and 1 to 16 "
                         "rotations")
    for index, entry in enumerate(doc["rotations"]):
        entry = _exact_mapping(entry, {"previous_key", "signature"},
                               f"{ROTATION_PATH}: rotations[{index}]")
        try:
            if suite.key_fingerprint(entry["previous_key"]) != anchor:
                continue
            signature = base64.b64decode(str(entry["signature"]).strip(), validate=True)
        except (suite.SuiteError, binascii.Error) as exc:
            raise ImageError(f"{ROTATION_PATH}: rotations[{index}]: {exc}") from exc
        if signature and suite._signature_valid(new_pem.encode("ascii"), signature,
                                                entry["previous_key"]):
            return
        raise ImageError(f"{ROTATION_PATH}: the rotation from the installed key is not "
                         "signed by it")
    raise ImageError(f"{ROTATION_PATH}: no rotation starts at the installed release key "
                     f"{anchor}")


_FINGERPRINT_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")


def load_trusted_bom(repo_root: Path, anchor: str | None = None) -> dict:
    """The delivery bill of materials of this core version, verified against the
    pinned release key. Refuses without the key rather than check without anchor.

    `anchor` is the fingerprint of the release key of the installed core when
    `repo_root` is the target of an upgrade: the target's key must be that key or
    be introduced by a rotation the installed key signed. A target never vouches for
    itself."""
    root = Path(repo_root)
    key_path = root / suite.RELEASE_KEY_PATH
    if anchor is not None:
        if not isinstance(anchor, str) or not _FINGERPRINT_RE.match(anchor):
            raise ImageError("trust anchor: sha256:<64 hex digits> expected")
        if anchor_fingerprint(root) != anchor:
            _rotation_proven(root, _read_key(key_path), anchor)
    elif not key_path.is_file():
        anchor_fingerprint(root)  # raises with the missing-anchor message
    version = core_version(root)
    path = bom_path(root, version)
    if not path.is_file():
        raise ImageError(f"no bill of materials for {version}: {path.relative_to(root)} is missing")
    try:
        return suite.verify_bom(
            path, Path(f"{path}.sig"), key_path=key_path, require_scope="delivery",
            expected_suite=suite_version(version),
        )
    except suite.SuiteError as exc:
        raise ImageError(f"bill of materials {path.relative_to(root)}: {exc}") from exc


def mirrored(refs: list[str], mirror: str) -> list[str]:
    """The references as they are pulled: with a mirror, every image comes from it.
    A reference the mirror override already rewrote stays as it is."""
    if not mirror:
        return list(refs)
    return [ref if ref.startswith(mirror) else mirror + ref for ref in refs]


def release_signature_repository(repo_root: Path) -> str:
    """The repository the release keeps every image signature in
    (`compat/image-signatures.yaml`), or '' when the release names none."""
    path = Path(repo_root) / SIGNATURES_PATH
    if not path.is_file():
        return ""
    try:
        doc = suite._parse_yaml(suite._read_limited(path, 16 * 1024, "signature setting"),
                                str(SIGNATURES_PATH))
    except suite.SuiteError as exc:
        raise ImageError(str(exc)) from exc
    doc = _exact_mapping(doc, {"schema", "repository"}, str(SIGNATURES_PATH))
    if doc["schema"] != SIGNATURES_SCHEMA or not isinstance(doc["repository"], str):
        raise ImageError(f"{SIGNATURES_PATH}: expected schema {SIGNATURES_SCHEMA} and a "
                         "repository")
    _signature_repository(doc["repository"], str(SIGNATURES_PATH))
    return doc["repository"]


def settings(env: dict[str, str], repo_root: Path | None = None) -> tuple[str, str]:
    """(mirror, signature repository): the mirror from the core `.env`; the signature
    repository of the release, behind the mirror when there is one, unless the
    operator names another in the `.env`. Validated."""
    mirror = validate_mirror(env.get(MIRROR_VAR, "").strip())
    override = env.get(SIGNATURES_VAR, "").strip()
    if override:
        _signature_repository(override)
        return mirror, override
    release = release_signature_repository(repo_root) if repo_root is not None else ""
    return mirror, (mirror + release if mirror and release else release)


# ── add-on images outside the bill of materials ──────────────────────────────


def _accepted_doc(config_dir: Path) -> dict:
    path = Path(config_dir) / ACCEPTED_PATH
    if not path.is_file():
        return {"schema": ACCEPTED_SCHEMA, "images": {}}
    try:
        doc = json.loads(suite._read_limited(path, 1024 * 1024, "accepted images"))
    except (suite.SuiteError, ValueError) as exc:
        raise ImageError(f"{ACCEPTED_PATH}: not readable ({exc})") from exc
    doc = _exact_mapping(doc, {"schema", "images"}, str(ACCEPTED_PATH))
    if doc["schema"] != ACCEPTED_SCHEMA or not isinstance(doc["images"], dict):
        raise ImageError(f"{ACCEPTED_PATH}: expected schema {ACCEPTED_SCHEMA}")
    for addon, refs in doc["images"].items():
        if not isinstance(addon, str) or not ADDON_NAME_RE.match(addon):
            raise ImageError(f"{ACCEPTED_PATH}: invalid add-on name")
        if not isinstance(refs, list) or len(refs) > MAX_IMAGES:
            raise ImageError(f"{ACCEPTED_PATH}: {addon}: a list of images expected")
        for ref in refs:
            parsed = parse_ref(ref) if isinstance(ref, str) else None
            if parsed is None or parsed.digest is None:
                raise ImageError(f"{ACCEPTED_PATH}: {addon}: pinned image expected")
    return doc


ADDON_NAME_RE = re.compile(r"\A[a-z0-9][a-z0-9_-]{0,63}\Z")


def load_accepted(config_dir: Path, addon: str) -> set[tuple[str, str, str]]:
    """(registry, repository, digest) of the images the operator accepted outside the
    bill of materials for the add-on `addon`, and for no other: an acceptance is a
    decision about one add-on, not a digest every add-on or the core may use."""
    found: set[tuple[str, str, str]] = set()
    for ref in _accepted_doc(config_dir)["images"].get(addon, []):
        parsed = parse_ref(ref)
        found.add((parsed.registry, parsed.repository, parsed.digest))
    return found


def _write_accepted(config_dir: Path, doc: dict) -> Path:
    path = Path(config_dir) / ACCEPTED_PATH
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(tmp, path)
    return path


def accept_images(config_dir: Path, addon: str, refs: list[str], bom: dict) -> Path:
    """Record that the operator accepted these exact digests for `addon` (file 0600,
    directory 0700). They replace what was accepted for that add-on before. Each must
    be pinned and from a repository the verified bill of materials `bom` does not
    list; anything else raises and nothing is written."""
    if not ADDON_NAME_RE.match(addon):
        raise ImageError("invalid add-on name")
    if not refs or len(refs) > MAX_IMAGES:
        raise ImageError(f"1 to {MAX_IMAGES} images expected")
    for ref in refs:
        if parse_ref(ref).digest is None:
            raise ImageError(f"{ref}: only a pinned image can be accepted")
        if repository_listed(bom, ref):
            raise ImageError(f"{ref}: the bill of materials lists this repository; an "
                             "image of it cannot be accepted")
    doc = _accepted_doc(config_dir)
    doc["images"][addon] = sorted(set(refs))
    return _write_accepted(config_dir, doc)


def forget_accepted(config_dir: Path, addon: str) -> list[str]:
    """Drop what was accepted for `addon`; return the references dropped (empty when
    there were none, and then nothing is written)."""
    if not ADDON_NAME_RE.match(addon):
        raise ImageError("invalid add-on name")
    doc = _accepted_doc(config_dir)
    dropped = doc["images"].pop(addon, [])
    if dropped:
        _write_accepted(config_dir, doc)
    return list(dropped)


def _text(value: object, limit: int = 120) -> str:
    return str(value)[:limit] if isinstance(value, str | int) else "-"


def addon_disclosure(name: str, path: Path, manifest: dict, refs: list[str]) -> list[str]:
    """What an add-on outside the bill of materials would bring: origin, the images
    with their digests, the operations it declares with their effect, and the
    networks it asks for. Read from its manifest; nothing is executed."""
    lines = [f"Add-on {name} {_text(manifest.get('version'))} from "
             f"{_text(manifest.get('addon_repo'))} ({path})",
             "  Images outside the bill of materials:"]
    for ref in refs:
        parsed = parse_ref(ref)
        lines.append(f"    {parsed.registry}/{parsed.repository}:{parsed.tag or '-'}  "
                     f"digest {parsed.digest}")
    lines.append("  Declared operations (effect):")
    operations = []
    exposes = manifest.get("exposes")
    for entry in exposes if isinstance(exposes, list) else []:
        if not isinstance(entry, dict):
            continue
        for operation in entry.get("operations") or []:
            if isinstance(operation, dict):
                operations.append(f"    {_text(entry.get('id'))}: "
                                  f"{_text(operation.get('name'))} "
                                  f"({_text(operation.get('effect'))})")
    lines.extend(operations or ["    none declared"])
    networks = manifest.get("networks") if isinstance(manifest.get("networks"), dict) else {}

    def names(value: object) -> str:
        items = value if isinstance(value, list) else []
        return ", ".join(_text(item) for item in items[:32]) or "none"

    lines.append(f"  Networks: own {_text(networks.get('app_network'))}; attaches to "
                 f"{names(networks.get('attach'))}; joins add-ons "
                 f"{names(networks.get('join_addons'))}")
    return lines


# ── audit ────────────────────────────────────────────────────────────────────

_CORRELATION_RE = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def correlation_id(value: str | None) -> str:
    """The given correlation id (a lowercase UUID), or a new one."""
    if value is None:
        return str(uuid.uuid4())
    if not isinstance(value, str) or not _CORRELATION_RE.match(value):
        raise ImageError("correlation id: a lowercase UUID expected")
    return value


def _row(command: str, event: str, detail: dict, correlation: str | None) -> dict:
    now = time.time()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + f".{int(now % 1 * 1000):03d}Z"
    return {
        "format": "papaia.audit/1",
        "time": stamp,
        "correlation_id": correlation_id(correlation),
        "writer": "papaia-ctl",
        "role": "operator",
        "sub": None,
        "identity_kind": "host",
        "azp": None,
        "catalog_id": None,
        "operation": command,
        "effect": "configure",
        "result": "allowed",
        "error_code": None,
        "event": event,
        "detail": detail,
    }


def audit_row(command: str, images: int, correlation: str | None = None) -> dict:
    """The `papaia.audit/1` row of a skipped check. No image names or content."""
    return _row(command, "image_verification_skipped",
                {"command": command, "images": images, "flag": "--insecure-images"},
                correlation)


_LOGIN_RE = re.compile(r"\A[A-Za-z0-9._][A-Za-z0-9._@-]{0,63}\Z")


def confirming_user() -> str:
    """The host login that confirmed the decision: the user behind `sudo` when there
    is one, otherwise the user running papaia-ctl. Running papaia-ctl on the host is
    the papaia-admin role of the installation, so this names the papaia-admin who
    confirmed. A name that is not a plain login is not written as it is."""
    name = os.environ.get("SUDO_USER", "").strip()
    if not name:
        try:
            name = getpass.getuser()
        except (KeyError, OSError):
            name = ""
    return name if _LOGIN_RE.match(name) else "unknown"


def acceptance_row(addon: str, refs: list[str], correlation: str | None = None) -> dict:
    """The `papaia.audit/1` row of add-on images accepted outside the bill of
    materials: the exact references and who confirmed them, so the decision can be
    traced."""
    return _row("addon-install", "addon_images_accepted",
                {"addon": addon, "images": sorted(set(refs)),
                 "flag": "--accept-unlisted-images", "role": "papaia-admin",
                 "confirmed_by": confirming_user()}, correlation)


def forget_row(addon: str, refs: list[str], correlation: str | None = None) -> dict:
    """The `papaia.audit/1` row of an acceptance dropped at `addon uninstall`."""
    return _row("addon-uninstall", "addon_images_forgotten",
                {"addon": addon, "images": sorted(set(refs))}, correlation)


def append_audit(config_dir: Path, row: dict) -> Path:
    """Append one row to the host's audit journal (directory 0700, file 0600)."""
    path = Path(config_dir) / AUDIT_LOG
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(row, separators=(",", ":")) + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    return path
