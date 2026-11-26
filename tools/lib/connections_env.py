"""The variables of the connection registry (core profile `connections`, ADR 0021).

Which environment variables the registry reads is not written down by hand:
`src/infra/connections/service-env.json` is generated from the package of the pinned
image's source,

    python -m lib.connections_env generate --source <papaia-connections checkout> \\
        --image <name:tag@sha256:...>

and records the image with its source commit next to every name the package reads (each
string literal of `src/papaia_connections/**/*.py` that is a `CONNECTIONS_*` or
`PAPAIA_*` variable name). `check` (also `python -m lib.connections_env check`, and the
test suite in CI) passes only when

- `connections` and `connections-migrate` run exactly the listed image;
- every listed name is set in the registry's `environment:`, or is on `DEFAULTS` (the
  image's default is kept, with the reason), or is on `NEVER_SET` (with the reason);
- no name of `NEVER_SET` is set in the registry, and the development setting
  `CONNECTIONS_DEV_OWNER_LOGIN` nowhere: not in a service, not in `.env.example`;
- each service sets only names the image reads (or `RUNTIME_READS`);
- `DEFAULTS` and `NEVER_SET` name only names the image still reads.

Every problem is one line that names the service or file and the variable.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path

import yaml

from . import common, me_profile

FORMAT = "papaia.connections-service-env/1"
REPOSITORY = "papaia-connections"
SERVICE = "connections"
MIGRATE = "connections-migrate"
IMAGE_SERVICES = (SERVICE, MIGRATE)

COMPOSE_REL = Path("src/infra/connections/docker-compose.yml")
ENV_EXAMPLE_REL = Path("src/infra/connections/.env.example")
ENV_LIST_REL = Path("src/infra/connections/service-env.json")
PACKAGE_REL = Path("src/papaia_connections")

# Read by the HTTP client of the registry (httpx honours it for the trust store), not by
# the package: the local CA of the realm's internal address.
RUNTIME_READS = ("SSL_CERT_FILE",)
DEV_OWNER_LOGIN = "CONNECTIONS_DEV_OWNER_LOGIN"

# Names the registry reads that the core leaves unset on purpose: the image's default
# applies. Each one with the reason; the check refuses a default for a name the image no
# longer reads, and a name that is both set and listed here.
DEFAULTS: dict[str, str] = {
    "CONNECTIONS_PORT": (
        "8080, the port the catalog declaration (exposes.yaml), the healthcheck and the "
        "override of Mein Bereich name; a second value would split them"
    ),
    "CONNECTIONS_OPENSSL_KRITIS_CONF": (
        "the OpenSSL configuration of the security profile kritis that the image ships "
        "(/app/openssl-connections-kritis.cnf); the core has none of its own"
    ),
    "CONNECTIONS_OPENBAO_KEY": (
        "name of the Transit key, read only with CONNECTIONS_KEY_PROVIDER=openbao; the "
        "image's default papaia-connections is the name the key ceremony creates"
    ),
    "CONNECTIONS_OPENBAO_JOURNAL_KEY": (
        "name of the journal's Transit key, read only with CONNECTIONS_KEY_PROVIDER="
        "openbao; the image's default papaia-connections-journal is the ceremony's name"
    ),
    **{
        name: (
            "write-once copy of the journal (export-journal): read only by that command, "
            "which no service of the core profile runs; an operator who copies the "
            "journal runs it with these settings in an override"
        )
        for name in (
            "CONNECTIONS_WORM_DIR",
            "CONNECTIONS_WORM_EVERY_S",
            "CONNECTIONS_WORM_MAX_FAILURES",
            "CONNECTIONS_WORM_RETENTION_DAYS",
            "CONNECTIONS_WORM_S3_ACCESS_KEY_FILE",
            "CONNECTIONS_WORM_S3_BUCKET",
            "CONNECTIONS_WORM_S3_PREFIX",
            "CONNECTIONS_WORM_S3_REGION",
            "CONNECTIONS_WORM_S3_SECRET_KEY_FILE",
            "CONNECTIONS_WORM_S3_URL",
        )
    },
}

# Names the registry must never get. The owner's login belongs to connections-migrate only.
NEVER_SET: dict[str, str] = {
    DEV_OWNER_LOGIN: (
        "development only: lets the registry run as the owner of the schema; set in no "
        "service and documented in no .env.example of the core"
    ),
    "CONNECTIONS_MIGRATE_DB_URL": (
        "the owner login of the schema, for connections-migrate only; the registry refuses "
        "to start with it in its environment"
    ),
}
# Services in which a NEVER_SET name is still the right setting.
NEVER_SET_EXCEPT: dict[str, str] = {"CONNECTIONS_MIGRATE_DB_URL": MIGRATE}

PINNED_IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9./_-]*(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_READ_NAME_RE = re.compile(r"^(CONNECTIONS|PAPAIA)_[A-Z0-9_]{1,60}$")
_MAX_SOURCE_BYTES = 512 * 1024
_MAX_FILES = 256


class ConnectionsEnvError(ValueError):
    """A source, list or compose file that cannot be read as the profile expects."""


# ── generate ─────────────────────────────────────────────────────────────────


def _names_in(path: Path) -> set[str]:
    if path.stat().st_size > _MAX_SOURCE_BYTES:
        raise ConnectionsEnvError(f"{path}: larger than {_MAX_SOURCE_BYTES} bytes")
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and _READ_NAME_RE.fullmatch(node.value)
    }


def generate(source: Path, *, image: str, commit: str) -> dict:
    """The variable list of the registry image from a papaia-connections checkout."""
    if not PINNED_IMAGE_RE.fullmatch(image):
        raise ConnectionsEnvError(f"image {image!r} is not pinned by digest (name:tag@sha256:...)")
    if not _COMMIT_RE.fullmatch(commit):
        raise ConnectionsEnvError("commit must be a full 40-character hash")
    package = Path(source) / PACKAGE_REL
    if not package.is_dir():
        raise ConnectionsEnvError(f"{source}: no package {PACKAGE_REL}")
    files = sorted(package.rglob("*.py"))
    if not files or len(files) > _MAX_FILES:
        raise ConnectionsEnvError(f"{package}: expected 1 to {_MAX_FILES} Python files")
    names: set[str] = set()
    for path in files:
        names |= _names_in(path)
    return {
        "format": FORMAT,
        "image": image,
        "source": {"repository": REPOSITORY, "commit": commit},
        "reads": sorted(names),
        "runtime": list(RUNTIME_READS),
    }


# ── check ────────────────────────────────────────────────────────────────────


def _load_list(path: Path) -> dict:
    try:
        listed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConnectionsEnvError(f"{path}: not readable: {exc}") from exc
    if not isinstance(listed, dict) or listed.get("format") != FORMAT:
        raise ConnectionsEnvError(f"{path}: format is not {FORMAT}")
    if set(listed) != {"format", "image", "source", "reads", "runtime"}:
        raise ConnectionsEnvError(f"{path}: fields must be format, image, source, reads, runtime")
    reads = listed["reads"]
    if not isinstance(reads, list) or not all(
        isinstance(n, str) and _READ_NAME_RE.fullmatch(n) for n in reads
    ):
        raise ConnectionsEnvError(f"{path}: reads must be a list of variable names")
    if listed["runtime"] != list(RUNTIME_READS):
        raise ConnectionsEnvError(f"{path}: runtime must be {list(RUNTIME_READS)}")
    source = listed["source"]
    if (
        not isinstance(source, dict)
        or set(source) != {"repository", "commit"}
        or source.get("repository") != REPOSITORY
        or not _COMMIT_RE.fullmatch(str(source.get("commit", "")))
    ):
        raise ConnectionsEnvError(f"{path}: source must name {REPOSITORY} and a full commit")
    return listed


def check(repo_root: Path) -> list[str]:
    """Every difference between the profile and the variable list, one line each."""
    root = Path(repo_root)
    try:
        doc = yaml.safe_load((root / COMPOSE_REL).read_text(encoding="utf-8")) or {}
        listed = _load_list(root / ENV_LIST_REL)
    except (OSError, yaml.YAMLError, ConnectionsEnvError) as exc:
        return [str(exc)]
    problems: list[str] = []
    image = listed["image"]
    if not isinstance(image, str) or not PINNED_IMAGE_RE.fullmatch(image):
        problems.append(f"{ENV_LIST_REL}: image {image!r} is not pinned by digest")
    reads = set(listed["reads"])
    known = reads | set(RUNTIME_READS)
    services = doc.get("services") or {}
    environments: dict[str, set[str]] = {}
    for name in IMAGE_SERVICES:
        service = services.get(name)
        if not isinstance(service, dict):
            problems.append(f"{COMPOSE_REL}: service {name} is missing")
            continue
        if service.get("image") != image:
            problems.append(f"{name}: image {service.get('image')} is not the listed image {image}")
        if "env_file" in service:
            problems.append(f"{name}: env_file is not allowed; values come through environment")
        environment = service.get("environment") or {}
        if not isinstance(environment, dict):
            problems.append(f"{name}: environment must be a mapping")
            continue
        environments[name] = set(environment)
        problems += [
            f"{name}: {v} is not read by the image" for v in sorted(set(environment) - known)
        ]
    for name, environment in environments.items():
        for v in sorted(environment & set(NEVER_SET)):
            if NEVER_SET_EXCEPT.get(v) != name:
                problems.append(f"{name}: {v} must never be set here: {NEVER_SET[v]}")
    for name, service in services.items():
        if name in IMAGE_SERVICES or not isinstance(service, dict):
            continue
        if DEV_OWNER_LOGIN in (service.get("environment") or {}):
            problems.append(f"{name}: {DEV_OWNER_LOGIN} must never be set")
    registry = environments.get(SERVICE, set())
    for v in sorted(reads - registry - set(DEFAULTS) - set(NEVER_SET)):
        problems.append(
            f"{SERVICE}: {v} is read by the image but neither set nor kept at its default "
            f"with a reason (lib/connections_env.py DEFAULTS)"
        )
    for v in sorted(registry & set(DEFAULTS)):
        problems.append(f"{SERVICE}: {v} is set and on the default list; decide for one")
    for v in sorted((set(DEFAULTS) | set(NEVER_SET)) - reads):
        problems.append(f"lib/connections_env.py: {v} is no longer read by the image")
    example = common.parse_env_file(root / ENV_EXAMPLE_REL)
    if DEV_OWNER_LOGIN in example:
        problems.append(f"{ENV_EXAMPLE_REL}: {DEV_OWNER_LOGIN} must never be documented")
    return problems


# ── command line ─────────────────────────────────────────────────────────────


def _commit_of(source: Path) -> str:
    """The checked-out commit of the source, read as for the Mein Bereich list."""
    try:
        return me_profile._commit_of(source)
    except me_profile.MeProfileError as exc:
        raise ConnectionsEnvError(str(exc)) from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m lib.connections_env")
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate", help="write src/infra/connections/service-env.json")
    gen.add_argument("--source", type=Path, required=True, help="papaia-connections checkout")
    gen.add_argument("--image", required=True, help="name:tag@sha256:<digest> of that source")
    gen.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    chk = sub.add_parser("check", help="compare the profile with the list")
    chk.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args(argv)

    if args.command == "generate":
        try:
            listed = generate(args.source, image=args.image, commit=_commit_of(args.source))
        except ConnectionsEnvError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        common.atomic_write(args.repo / ENV_LIST_REL, json.dumps(listed, indent=2) + "\n")
        return 0
    problems = check(args.repo)
    for line in problems:
        print(line, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
