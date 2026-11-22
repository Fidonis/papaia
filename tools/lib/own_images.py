"""Own images of the core: built from this repository, signed, pinned and listed.

A core service that runs code of this repository runs it from an image built here,
never from a stock image with the code mounted in, and never from a compose `build:`.
`compat/own-images.yaml` lists each such image with its Dockerfile, the files the build
may read (`inputs`), the compose services that run it and its license.

The path of an image, the same for a release and for a local test environment:

1. `build`   build linux/amd64 and linux/arm64 from a context holding only the inputs
             (and LICENSE), push to `<prefix><name>:<VERSION>`, record the digest of
             the index. Timestamps are fixed (SOURCE_DATE_EPOCH=0) and no attestation
             is added, so the same inputs give the same digest on any host and from
             any later commit. Inputs with uncommitted changes are refused.
2. `sign`    cosign signs each digest with the release key into the signature
             repository of the release (compat/image-signatures.yaml; behind the
             prefix, as the start check looks it up through PAPAIA_IMAGE_MIRROR).
3. `pin`     the compose services of the image name `<name>:<VERSION>@<digest>`.
4. `bom-entries` the image entries of the core in the suite bill of materials
             (papaia.suite-bom/1), from the pins in compose.

In CI (.github/workflows/images.yml) a version tag adds `verify` (the rebuilt digests
are the scanned and pinned ones) and `sign-keyless` (signature and CycloneDX SBOM
attestations by the workflow identity, next to the image); lib/image_scan.py gates
the build on its vulnerability findings.

`prefix` is empty for the release registry and a registry prefix such as
`127.0.0.1:5000/unpublished/` for a local one; the digest does not depend on it. The
start check (lib/images.py) knows no own images: they must be listed with their digest
and signed like every other image.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

from . import images, suite

SCHEMA = "papaia.own-images/1"
DECLARATION_PATH = Path("compat") / "own-images.yaml"
BUILDS_SCHEMA = "papaia.own-image-builds/1"
PLATFORMS = ("linux/amd64", "linux/arm64")
# Read by every build besides the declared inputs: the notice and the version label.
ALWAYS_INPUTS = ("LICENSE", "VERSION")
MAX_IMAGES = 32
MAX_INPUTS = 64
# cosign v2.4.1 (amd64 and arm64), used when no cosign binary is given.
COSIGN_IMAGE = (
    "ghcr.io/sigstore/cosign/cosign:v2.4.1"
    "@sha256:b03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31"
)
BUILD_TIMEOUT_SECONDS = 1800

_IMAGE_KEYS = {"name", "dockerfile", "inputs", "services", "license", "license_class"}
_BUILD_KEYS = {"name", "tag", "digest", "revision"}
_SERVICE_RE = re.compile(r"\A[a-z0-9][a-z0-9_-]{0,62}\Z")
_PATH_RE = re.compile(r"\A[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)*\Z")
_REVISION_RE = re.compile(r"\A[0-9a-f]{40}\Z")
_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_NUMERIC_USER_RE = re.compile(r"\A(\d+)(?::(\d+))?\Z")
_CODE_SUFFIXES = (".py", ".sh", ".js", ".mjs", ".ts", ".rb", ".pl")


class OwnImageError(ValueError):
    """A declaration, a build or a setting that must not be used; the message says why."""


@dataclass(frozen=True)
class OwnImage:
    name: str
    dockerfile: str
    inputs: tuple[str, ...]
    services: tuple[str, ...]
    license: str
    license_class: str

    @property
    def short(self) -> str:
        """The last path component: the folder of its notice files in the image."""
        return self.name.rsplit("/", 1)[1]


Runner = Callable[..., subprocess.CompletedProcess]


def _run(cmd: list[str], env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, env=env, capture_output=True, text=True,
                          timeout=BUILD_TIMEOUT_SECONDS, check=False)


# ── declaration ──────────────────────────────────────────────────────────────


def _input_path(root: Path, rel: object, where: str) -> str:
    if not isinstance(rel, str) or len(rel) > 200 or not _PATH_RE.match(rel) or ".." in rel:
        raise OwnImageError(f"{where}: {rel!r} is not a relative path inside the checkout")
    path = root / rel
    if path.is_symlink() or not path.is_file():
        raise OwnImageError(f"{where}: {rel} must be a regular file of the checkout")
    return rel


def _image(root: Path, entry: object, where: str) -> OwnImage:
    if not isinstance(entry, dict) or set(entry) != _IMAGE_KEYS:
        unknown = sorted(set(entry) - _IMAGE_KEYS) if isinstance(entry, dict) else []
        raise OwnImageError(f"{where}: needs exactly {', '.join(sorted(_IMAGE_KEYS))}"
                            + (f" (unknown: {', '.join(map(str, unknown))})" if unknown else ""))
    name = entry["name"]
    try:
        ref = images.parse_ref(name) if isinstance(name, str) else None
    except images.ImageError:
        ref = None
    if ref is None or ref.tag is not None or ref.digest is not None:
        raise OwnImageError(f"{where}.name: a repository without tag or digest expected")
    if not name.startswith(f"{ref.registry}/") or ref.registry == "docker.io":
        raise OwnImageError(f"{where}.name: must name its registry, such as "
                            "ghcr.io/<owner>/<image>")
    inputs = entry["inputs"]
    if not isinstance(inputs, list) or not 0 < len(inputs) <= MAX_INPUTS:
        raise OwnImageError(f"{where}.inputs: 1 to {MAX_INPUTS} paths expected")
    inputs = tuple(_input_path(root, rel, f"{where}.inputs") for rel in inputs)
    dockerfile = entry["dockerfile"]
    if dockerfile not in inputs:
        raise OwnImageError(f"{where}.dockerfile: must be one of the inputs")
    services = entry["services"]
    if not isinstance(services, list) or not services or not all(
        isinstance(s, str) and _SERVICE_RE.match(s) for s in services
    ):
        raise OwnImageError(f"{where}.services: a list of compose service names expected")
    if not isinstance(entry["license"], str) or not suite._SPDX_RE.match(entry["license"]):
        raise OwnImageError(f"{where}.license: an SPDX expression expected")
    if entry["license_class"] not in suite.LICENSE_CLASSES:
        raise OwnImageError(f"{where}.license_class: one of {', '.join(suite.LICENSE_CLASSES)}")
    return OwnImage(name, dockerfile, inputs, tuple(services), entry["license"],
                    entry["license_class"])


def load(repo_root: Path) -> list[OwnImage]:
    """The validated declaration; empty when the checkout has none."""
    root = Path(repo_root)
    path = root / DECLARATION_PATH
    if not path.is_file():
        return []
    try:
        doc = suite._parse_yaml(suite._read_limited(path, 64 * 1024, "own images"),
                                str(DECLARATION_PATH))
    except suite.SuiteError as exc:
        raise OwnImageError(str(exc)) from exc
    if not isinstance(doc, dict) or set(doc) != {"schema", "images"} or doc["schema"] != SCHEMA:
        raise OwnImageError(f"{DECLARATION_PATH}: expected exactly schema {SCHEMA} and images")
    if not isinstance(doc["images"], list) or len(doc["images"]) > MAX_IMAGES:
        raise OwnImageError(f"{DECLARATION_PATH}: images must be a list of at most {MAX_IMAGES}")
    found: list[OwnImage] = []
    names: set[str] = set()
    services: set[str] = set()
    for index, entry in enumerate(doc["images"]):
        image = _image(root, entry, f"{DECLARATION_PATH}: images[{index}]")
        if image.name in names or services & set(image.services):
            raise OwnImageError(f"{DECLARATION_PATH}: images[{index}] names an image or a "
                                "service twice")
        names.add(image.name)
        services.update(image.services)
        found.append(image)
    return found


# ── rules ────────────────────────────────────────────────────────────────────


def _instructions(text: str) -> list[tuple[str, str]]:
    """(INSTRUCTION, arguments) of a Dockerfile, continuation lines joined."""
    found: list[tuple[str, str]] = []
    pending = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        whole = (pending + stripped).strip()
        pending = ""
        keyword, _, rest = whole.partition(" ")
        found.append((keyword.upper(), rest.strip()))
    return found


def _flags(args: str) -> tuple[dict[str, str], list[str]]:
    flags: dict[str, str] = {}
    words: list[str] = []
    for word in args.split():
        if word.startswith("--") and not words:
            key, _, value = word[2:].partition("=")
            flags[key] = value
        else:
            words.append(word)
    return flags, words


def dockerfile_problems(repo_root: Path, image: OwnImage) -> list[str]:
    """Why the Dockerfile of `image` breaks the rules of an own image: every base and
    every `COPY --from` image pinned by tag and digest; no FROM flag but
    `--platform=$BUILDPLATFORM`; no ADD; COPY only from the
    declared inputs; the license label; the notice files under
    /usr/share/licenses/<image>/; the last USER numeric and not root."""
    where = image.dockerfile
    text = (Path(repo_root) / image.dockerfile).read_text(encoding="utf-8")
    problems: list[str] = []
    stages: set[str] = set()
    user = None
    copied: set[str] = set()
    available = set(image.inputs) | {"LICENSE"}
    for keyword, args in _instructions(text):
        if keyword == "FROM":
            flags, words = _flags(args)
            # A stage may run on the build platform (fetching files for the target, such
            # as wheels pinned by hash), so both variants build without emulation. Any
            # other platform or flag would make the variants differ.
            for flag, value in flags.items():
                if flag != "platform" or value != "$BUILDPLATFORM":
                    problems.append(f"{where}: FROM --{flag}={value}: only "
                                    "--platform=$BUILDPLATFORM is used")
            base = words[0] if words else ""
            if images.pin_problem(base) is not None:
                problems.append(f"{where}: FROM {base}: {images.pin_problem(base)}")
            if len(words) == 3 and words[1].upper() == "AS":
                stages.add(words[2].lower())
        elif keyword == "ADD":
            problems.append(f"{where}: ADD is not used; COPY a declared input instead")
        elif keyword == "COPY":
            flags, words = _flags(args)
            if words and words[0].startswith("["):
                problems.append(f"{where}: COPY in JSON form is not checked; use plain form")
                continue
            sources, target = words[:-1], (words[-1] if words else "")
            source_image = flags.get("from")
            if source_image is not None:
                if source_image.lower() not in stages and images.pin_problem(source_image):
                    problems.append(f"{where}: COPY --from={source_image}: "
                                    f"{images.pin_problem(source_image)}")
                continue
            for source in sources:
                if source not in available:
                    problems.append(f"{where}: COPY {source} is not one of the declared inputs")
                elif target.startswith(f"/usr/share/licenses/{image.short}/"):
                    copied.add(target.rsplit("/", 1)[1])
        elif keyword == "USER":
            user = args
    licenses = re.search(r'org\.opencontainers\.image\.licenses="([^"]*)"', text)
    if licenses is None or licenses.group(1) != image.license:
        problems.append(f"{where}: LABEL org.opencontainers.image.licenses must be "
                        f"\"{image.license}\"")
    for notice in ("LICENSE", "THIRD_PARTY_LICENSES.md"):
        if notice not in copied:
            problems.append(f"{where}: {notice} is not copied to "
                            f"/usr/share/licenses/{image.short}/")
    match = _NUMERIC_USER_RE.match(user or "")
    if match is None or int(match.group(1)) == 0 or match.group(2) == "0":
        problems.append(f"{where}: the last USER must be a numeric user and group other than "
                        f"root (found {user!r})")
    return problems


def _compose_files(root: Path) -> list[Path]:
    return sorted((root / "src").rglob("docker-compose*.yml"))


def compose_problems(repo_root: Path, own: list[OwnImage] | None = None) -> list[str]:
    """Why the compose files do not run the own images as built here: each declared
    service must exist and name `<name>:<VERSION>@sha256:<digest>`; no service is
    built by compose; no core service (`papaia-*`) mounts a code file of the checkout."""
    root = Path(repo_root)
    own = load(root) if own is None else own
    version = images.core_version(root)
    problems: list[str] = []
    services: dict[str, tuple[str, object]] = {}
    for path in _compose_files(root):
        rel = path.relative_to(root).as_posix()
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, body in (doc.get("services") or {}).items():
            if not isinstance(body, dict):
                continue
            services[name] = (rel, body.get("image"))
            if "build" in body:
                problems.append(f"{rel}: services.{name} is built by compose; an image is "
                                "built by tools/build-images and pinned by digest")
            if not str(name).startswith("papaia-"):
                continue
            for mount in body.get("volumes") or []:
                if isinstance(mount, dict):
                    source = mount.get("source")
                else:
                    source = str(mount).split(":")[0]
                if isinstance(source, str) and source.startswith(".") and (
                    source.endswith(_CODE_SUFFIXES)
                ):
                    problems.append(f"{rel}: services.{name} mounts {source}; code of this "
                                    "repository runs from an own image")
    for image in own:
        for service in image.services:
            if service not in services:
                problems.append(f"{DECLARATION_PATH}: service {service} of {image.name} is in "
                                "no compose file")
                continue
            rel, ref = services[service]
            expected = f"{image.name}:{version}@sha256:<digest>"
            try:
                parsed = images.parse_ref(ref) if isinstance(ref, str) else None
            except images.ImageError:
                parsed = None
            if (parsed is None or not ref.startswith(f"{image.name}:")
                    or f"{parsed.registry}/{parsed.repository}" != image.name):
                problems.append(f"{rel}: services.{service}.image is {ref!r}, expected {expected}")
            elif parsed.digest is None:
                problems.append(f"{rel}: services.{service}.image has no digest, expected "
                                f"{expected}")
            elif parsed.tag != version:
                problems.append(f"{rel}: services.{service}.image has tag {parsed.tag}, "
                                f"expected {version} (VERSION)")
    return problems


def check(repo_root: Path) -> list[str]:
    """Every rule of the declaration, the Dockerfiles and the compose pins."""
    try:
        own = load(repo_root)
    except OwnImageError as exc:
        return [str(exc)]
    problems: list[str] = []
    for image in own:
        problems += dockerfile_problems(repo_root, image)
    return problems + compose_problems(repo_root, own)


# ── build ────────────────────────────────────────────────────────────────────


def _git(root: Path, *args: str) -> str:
    done = _run(["git", "-C", str(root), *args])
    if done.returncode != 0:
        raise OwnImageError(f"git {args[0]} failed in {root}: {(done.stderr or '').strip()}")
    return done.stdout.strip()


def source_revision(repo_root: Path, image: OwnImage) -> str:
    """The commit the image is built from. Refuses inputs with uncommitted changes: the
    pinned digest must be reproducible from a commit."""
    root = Path(repo_root)
    paths = [*ALWAYS_INPUTS, *image.inputs]
    dirty = _git(root, "status", "--porcelain", "--untracked-files=all", "--", *paths)
    if dirty:
        raise OwnImageError(f"{image.name}: inputs with uncommitted changes:\n{dirty}")
    revision = _git(root, "rev-parse", "HEAD")
    if not _REVISION_RE.match(revision):
        raise OwnImageError(f"{image.name}: no commit to build from")
    return revision


def stage_context(repo_root: Path, image: OwnImage, dest: Path) -> Path:
    """A build context with only the declared inputs and LICENSE, at their paths.

    Modes are set here, not taken from the checkout or the umask: COPY keeps them, so
    they are part of the digest, and the image's user (not root) must read every file."""
    root = Path(repo_root)
    dest = Path(dest) / image.short
    if dest.exists():
        shutil.rmtree(dest)
    for rel in ("LICENSE", *image.inputs):
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / rel, target)
        os.chmod(target, 0o644)
    for path in [dest, *dest.rglob("*")]:
        if path.is_dir():
            os.chmod(path, 0o755)
    return dest


def _prefix(value: str) -> str:
    try:
        return images.validate_mirror(value)
    except images.ImageError as exc:
        raise OwnImageError(f"registry prefix: {exc}") from exc


def build(repo_root: Path, image: OwnImage, *, prefix: str, workdir: Path,
          run: Runner = _run) -> dict:
    """Build and push `image` for both platforms; {name, tag, digest, revision}."""
    root = Path(repo_root)
    prefix = _prefix(prefix)
    tag = images.core_version(root)
    revision = source_revision(root, image)
    context = stage_context(root, image, Path(workdir) / "context")
    metadata = Path(workdir) / f"{image.short}.metadata.json"
    metadata.unlink(missing_ok=True)
    # Every setting that shapes the bytes is named, so another builder or buildx
    # release with other defaults gives the same index.
    output = ",".join((
        "type=image", f"name={prefix}{image.name}:{tag}", "push=true", "unpack=false",
        "rewrite-timestamp=true", "oci-mediatypes=true", "compression=gzip",
    ))
    cmd = [
        "docker", "buildx", "build",
        "--platform", ",".join(PLATFORMS),
        # Attestations carry build times and host details: they would change the digest.
        # The SBOM is attached by the release as a signed attestation instead.
        "--provenance=false", "--sbom=false",
        "--build-arg", "SOURCE_DATE_EPOCH=0",
        "--build-arg", f"VERSION={tag}",
        "--file", str(context / image.dockerfile),
        "--output", output,
        "--metadata-file", str(metadata),
        str(context),
    ]  # fmt: skip
    done = run(cmd)
    if done.returncode != 0:
        raise OwnImageError(f"{image.name}: build failed:\n{(done.stderr or '')[-4000:]}")
    try:
        digest = json.loads(metadata.read_text(encoding="utf-8"))["containerimage.digest"]
    except (OSError, ValueError, KeyError) as exc:
        raise OwnImageError(f"{image.name}: the build reported no digest") from exc
    if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
        raise OwnImageError(f"{image.name}: the build reported no valid digest")
    return {"name": image.name, "tag": tag, "digest": digest, "revision": revision}


def write_builds(path: Path, prefix: str, entries: list[dict]) -> None:
    doc = {"schema": BUILDS_SCHEMA, "registry": _prefix(prefix), "images": entries}
    _validate_builds(doc)
    Path(path).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def _validate_builds(doc: object) -> None:
    if not isinstance(doc, dict) or set(doc) != {"schema", "registry", "images"} or (
        doc["schema"] != BUILDS_SCHEMA
    ):
        raise OwnImageError(f"builds file: expected exactly schema {BUILDS_SCHEMA}, registry "
                            "and images")
    if not isinstance(doc["registry"], str):
        raise OwnImageError("builds file: registry must be a prefix or empty")
    _prefix(doc["registry"])
    if not isinstance(doc["images"], list) or not 0 < len(doc["images"]) <= MAX_IMAGES:
        raise OwnImageError(f"builds file: 1 to {MAX_IMAGES} images expected")
    for index, entry in enumerate(doc["images"]):
        where = f"builds file: images[{index}]"
        if not isinstance(entry, dict) or set(entry) != _BUILD_KEYS:
            raise OwnImageError(f"{where}: needs exactly {', '.join(sorted(_BUILD_KEYS))}")
        try:
            ref = images.parse_ref(f"{entry['name']}:{entry['tag']}@{entry['digest']}")
        except (images.ImageError, TypeError) as exc:
            raise OwnImageError(f"{where}: {exc}") from exc
        if ref.tag is None or ref.digest is None or not isinstance(entry["revision"], str) or (
            not _REVISION_RE.match(entry["revision"])
        ):
            raise OwnImageError(f"{where}: name, tag, digest and a commit expected")


def read_builds(path: Path) -> tuple[str, list[dict]]:
    """(registry prefix, entries) of a builds file written by `build`."""
    try:
        doc = json.loads(suite._read_limited(Path(path), 256 * 1024, "builds file"))
    except (suite.SuiteError, ValueError) as exc:
        raise OwnImageError(f"builds file: {exc}") from exc
    _validate_builds(doc)
    return doc["registry"], doc["images"]


# ── sign ─────────────────────────────────────────────────────────────────────


def _outside(path: Path, root: Path) -> bool:
    resolved, base = path.resolve(), root.resolve()
    return resolved != base and base not in resolved.parents


def _loopback_registry(registry: str) -> bool:
    """Whether `host[:port]` is this machine (a local test registry)."""
    host = registry[: registry.index("]") + 1] if registry.startswith("[") else (
        registry.split(":", 1)[0]
    )
    return images._is_loopback(host)


def sign(repo_root: Path, prefix: str, entries: list[dict], *, key: Path,
         cosign: str | None = None, signatures: str | None = None,
         env: dict | None = None, run: Runner = _run) -> None:
    """cosign-sign each built digest with `key` into the signature repository.

    The key is a cosign key file outside the checkout; its passphrase comes from
    COSIGN_PASSWORD in the environment and is passed on by name only. With `cosign`
    (a binary) the host's registry login is used; without, cosign runs as a pinned
    container on the host network, which suits a local registry. A loopback registry
    is spoken to over plain HTTP and nothing is written to the public transparency log
    (unpublished test images)."""
    root = Path(repo_root)
    prefix = _prefix(prefix)
    env = dict(os.environ if env is None else env)
    key = Path(key)
    if not key.is_file() or key.is_symlink():
        raise OwnImageError(f"signing key {key}: not a regular file")
    if not _outside(key, root):
        raise OwnImageError("signing key: must be outside the checkout; keys never live in "
                            "the repository")
    if "COSIGN_PASSWORD" not in env:
        raise OwnImageError("COSIGN_PASSWORD is not set: the passphrase of the signing key "
                            "is taken from the environment only")
    release = signatures if signatures is not None else images.release_signature_repository(root)
    if not release:
        raise OwnImageError(f"no signature repository: {images.SIGNATURES_PATH} names none")
    repository = prefix + release
    images._signature_repository(repository, "signature repository")
    loopback = _loopback_registry(images.parse_ref(f"{prefix}{entries[0]['name']}").registry)
    for entry in entries:
        ref = f"{prefix}{entry['name']}@{entry['digest']}"
        args = ["sign", "--yes"]
        if loopback:
            args += ["--allow-http-registry", "--tlog-upload=false"]
        if cosign:
            cmd = [cosign, *args, "--key", str(key), ref]
            run_env = {**env, "COSIGN_REPOSITORY": repository}
        else:
            cmd = [
                "docker", "run", "--rm", "--network", "host", "--read-only",
                "--tmpfs", "/tmp", "-e", "HOME=/tmp", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true",
                "-e", "COSIGN_PASSWORD", "-e", f"COSIGN_REPOSITORY={repository}",
                "-v", f"{key.resolve()}:/run/cosign/cosign.key:ro",
                COSIGN_IMAGE, *args, "--key", "/run/cosign/cosign.key", ref,
            ]  # fmt: skip
            run_env = env
        done = run(cmd, env=run_env)
        if done.returncode != 0:
            raise OwnImageError(f"signing {ref} failed:\n{(done.stderr or '')[-2000:]}")


_SBOM_LIMIT = 32 * 1024 * 1024


def sign_keyless(prefix: str, entries: list[dict], *, sboms: Path, cosign: str,
                 env: dict | None = None, run: Runner = _run) -> None:
    """Sign each built digest with the identity of the CI workflow (cosign keyless,
    OIDC) and attach the CycloneDX SBOM of each platform as an attestation.

    Release registry only: the signature and the attestations stay next to the image
    (no COSIGN_REPOSITORY), apart from the release key's signatures in the signature
    repository that `sign` writes. Every SBOM (`<sboms>/<image>-<arch>.cdx.json`) is
    checked before the first signature."""
    if _prefix(prefix) != "":
        raise OwnImageError("sign-keyless signs images of the release registry only; a "
                            "local registry is signed with a key (sign)")
    env = {key: value for key, value in dict(os.environ if env is None else env).items()
           if key != "COSIGN_REPOSITORY"}
    plan: list[tuple[str, list[Path]]] = []
    for entry in entries:
        short = entry["name"].rsplit("/", 1)[1]
        files = []
        for platform in PLATFORMS:
            path = Path(sboms) / f"{short}-{platform.split('/', 1)[1]}.cdx.json"
            if not path.is_file() or path.is_symlink():
                raise OwnImageError(f"{entry['name']}: no SBOM for {platform} ({path.name})")
            try:
                doc = json.loads(suite._read_limited(path, _SBOM_LIMIT, "SBOM"))
            except (suite.SuiteError, ValueError) as exc:
                raise OwnImageError(f"{path.name}: not readable as JSON") from exc
            if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
                raise OwnImageError(f"{path.name}: not a CycloneDX document")
            files.append(path)
        plan.append((f"{entry['name']}@{entry['digest']}", files))
    for ref, files in plan:
        commands = [[cosign, "sign", "--yes", ref]] + [
            [cosign, "attest", "--yes", "--type", "cyclonedx", "--predicate", str(path), ref]
            for path in files
        ]
        for cmd in commands:
            done = run(cmd, env=env)
            if done.returncode != 0:
                raise OwnImageError(f"cosign {cmd[1]} of {ref} failed:\n"
                                    f"{(done.stderr or '')[-2000:]}")


# ── pin ──────────────────────────────────────────────────────────────────────


def _image_node(text: str, service: str):
    """The scalar node of `services.<service>.image` in a compose file, or None."""
    node = yaml.compose(text)
    if not isinstance(node, yaml.MappingNode):
        return None
    for key, value in node.value:
        if key.value == "services" and isinstance(value, yaml.MappingNode):
            for skey, svalue in value.value:
                if skey.value == service and isinstance(svalue, yaml.MappingNode):
                    for ikey, ivalue in svalue.value:
                        if ikey.value == "image" and isinstance(ivalue, yaml.ScalarNode):
                            return ivalue
    return None


def pin(repo_root: Path, entries: list[dict]) -> list[str]:
    """Write `<name>:<tag>@<digest>` of each build into the image line of its declared
    services; the locations changed (none when they already pin it)."""
    root = Path(repo_root)
    declared = {image.name: image for image in load(root)}
    version = images.core_version(root)
    files = _compose_files(root)
    changed: list[str] = []
    for entry in entries:
        image = declared.get(entry["name"])
        if image is None:
            raise OwnImageError(f"{entry['name']} is not declared in {DECLARATION_PATH}")
        if entry["tag"] != version:
            raise OwnImageError(f"{entry['name']}: built as {entry['tag']}, the checkout is "
                                f"{version}")
        wanted = f"{entry['name']}:{entry['tag']}@{entry['digest']}"
        for service in image.services:
            for path in files:
                text = path.read_text(encoding="utf-8")
                node = _image_node(text, service)
                if node is None:
                    continue
                if node.style is not None or node.start_mark.line != node.end_mark.line:
                    raise OwnImageError(f"{path}: services.{service}.image must be a plain "
                                        "one-line value")
                if node.value != wanted:
                    start, end = node.start_mark.index, node.end_mark.index
                    path.write_text(text[:start] + wanted + text[end:], encoding="utf-8")
                    changed.append(f"{path.relative_to(root).as_posix()}: "
                                   f"services.{service}.image")
                break
            else:
                raise OwnImageError(f"service {service} of {image.name} is in no compose file")
    return changed


def pin_mismatches(repo_root: Path, entries: list[dict]) -> list[str]:
    """Every declared image that was not built, or whose build is not the digest its
    compose services pin. A release signs only what an installation pulls."""
    root = Path(repo_root)
    services = images.compose_services(root)
    built = {entry["name"]: entry for entry in entries}
    problems: list[str] = []
    for image in load(root):
        entry = built.pop(image.name, None)
        if entry is None:
            problems.append(f"{image.name}: not built")
            continue
        wanted = f"{image.name}:{entry['tag']}@{entry['digest']}"
        for service in image.services:
            if services.get(service) != wanted:
                problems.append(f"{image.name}: built {entry['digest']}, but service "
                                f"{service} pins {services.get(service)}; rebuild and pin "
                                "(build-images pin) before the tag")
    problems += [f"{name}: built but not declared in {DECLARATION_PATH}" for name in built]
    return problems


# ── bill of materials ────────────────────────────────────────────────────────


def file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def bom_entries(repo_root: Path, sboms: dict[str, Path]) -> list[dict]:
    """The entries of the own images in the core's `images` of the suite bill of
    materials, from the pins in compose; `sboms` maps each image name to its SBOM file
    (the document attached to the image), whose digest the entry carries."""
    root = Path(repo_root)
    problems = compose_problems(root)
    if problems:
        raise OwnImageError("compose does not pin the own images:\n" + "\n".join(problems))
    services = images.compose_services(root)
    entries: list[dict] = []
    for image in load(root):
        if image.name not in sboms:
            raise OwnImageError(f"{image.name}: no SBOM given (--sbom={image.name}=FILE)")
        pins = {services[service] for service in image.services}
        if len(pins) != 1:
            raise OwnImageError(f"{image.name}: its services pin different digests")
        ref = images.parse_ref(pins.pop())
        entry = {
            "name": image.name,
            "tag": ref.tag,
            "digest": ref.digest,
            "license": image.license,
            "license_class": image.license_class,
            "sbom_digest": file_digest(sboms[image.name]),
            "delivery": "shipped",
        }
        try:
            suite._validate_image(entry, image.name, "delivery", "core")
        except suite.SuiteError as exc:
            raise OwnImageError(str(exc)) from exc
        entries.append(entry)
    return entries


# ── command line (tools/build-images) ────────────────────────────────────────


def _selected(root: Path, names: list[str] | None) -> list[OwnImage]:
    own = load(root)
    if not names:
        return own
    known = {image.name: image for image in own}
    unknown = [name for name in names if name not in known]
    if unknown:
        raise OwnImageError(f"not declared in {DECLARATION_PATH}: {', '.join(unknown)}")
    return [known[name] for name in names]


def _sbom_args(values: list[str]) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for value in values:
        name, sep, path = value.partition("=")
        if not sep or not path or name in found:
            raise OwnImageError("--sbom: NAME=FILE, once per image")
        found[name] = Path(path)
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build-images", description=__doc__.split("\n")[0])
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[2]))
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("check", help="check the declaration, the Dockerfiles and the pins")
    p_build = sub.add_parser("build", help="build and push linux/amd64 and linux/arm64")
    p_build.add_argument("--registry", default="", help="registry prefix ending in '/'")
    p_build.add_argument("--image", action="append", help="only this image (repeatable)")
    p_build.add_argument("--out", required=True, help="builds file to write")
    p_sign = sub.add_parser("sign", help="sign the built digests with cosign")
    p_sign.add_argument("--builds", required=True)
    p_sign.add_argument("--key", required=True, help="cosign key file outside the checkout")
    p_sign.add_argument("--cosign", default=None, help="cosign binary (default: container)")
    p_sign.add_argument("--signatures", default=None, help="signature repository override")
    p_pin = sub.add_parser("pin", help="pin the built digests in compose")
    p_pin.add_argument("--builds", required=True)
    p_verify = sub.add_parser("verify", help="check that the builds are the pinned digests")
    p_verify.add_argument("--builds", required=True)
    p_keyless = sub.add_parser("sign-keyless",
                               help="sign and attest the SBOMs with the CI identity")
    p_keyless.add_argument("--builds", required=True)
    p_keyless.add_argument("--sboms", required=True, help="folder of <image>-<arch>.cdx.json")
    p_keyless.add_argument("--cosign", default="cosign", help="cosign binary")
    p_bom = sub.add_parser("bom-entries", help="print the bill of materials entries (YAML)")
    p_bom.add_argument("--sbom", action="append", default=[], help="NAME=FILE per image")
    args = parser.parse_args(argv)
    root = Path(args.repo_root)
    try:
        if args.action == "check":
            problems = check(root)
            for problem in problems:
                print(f"ERROR: {problem}", file=sys.stderr)
            if not problems:
                print(f"{len(load(root))} own image(s) declared, built and pinned as required.")
            return 2 if problems else 0
        if args.action == "build":
            entries = []
            with tempfile.TemporaryDirectory(prefix="papaia-build-") as work:
                for image in _selected(root, args.image):
                    entry = build(root, image, prefix=args.registry, workdir=Path(work))
                    print(f"{args.registry}{image.name}:{entry['tag']}@{entry['digest']}")
                    entries.append(entry)
            write_builds(Path(args.out), args.registry, entries)
            return 0
        if args.action == "sign":
            prefix, entries = read_builds(Path(args.builds))
            sign(root, prefix, entries, key=Path(args.key), cosign=args.cosign,
                 signatures=args.signatures)
            print(f"{len(entries)} image(s) signed.")
            return 0
        if args.action == "verify":
            _, entries = read_builds(Path(args.builds))
            problems = pin_mismatches(root, entries)
            for problem in problems:
                print(f"ERROR: {problem}", file=sys.stderr)
            if not problems:
                print(f"{len(entries)} build(s) match the compose pins.")
            return 1 if problems else 0
        if args.action == "sign-keyless":
            prefix, entries = read_builds(Path(args.builds))
            sign_keyless(prefix, entries, sboms=Path(args.sboms), cosign=args.cosign)
            print(f"{len(entries)} image(s) signed and attested.")
            return 0
        if args.action == "pin":
            _, entries = read_builds(Path(args.builds))
            for location in pin(root, entries):
                print(f"pinned {location}")
            return 0
        entries = bom_entries(root, _sbom_args(args.sbom))
        print(yaml.safe_dump(entries, sort_keys=False), end="")
        return 0
    except (OwnImageError, images.ImageError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
