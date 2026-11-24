"""The core profile `me`: Mein Bereich (`me-web`) and the preference store (`prefs`, `prefs-db`).

Both services run from one pinned image of papaia-me (ADR 0020). Which environment
variables they read is not written down twice: `src/infra/me/service-env.json` is
generated from the configuration modules of the image's source,

    python -m lib.me_profile generate --source <papaia-me checkout> --image <name:tag@sha256:...>

and `check` (also `python -m lib.me_profile check`, and the test suite in CI) passes only
when

- the compose file has exactly `me-web`, `prefs` and `prefs-db` on the profile `me`,
  `me-web` and `prefs` on the listed image, every image pinned by digest;
- no service publishes a host port (architecture A-02: only the edge does);
- the `environment:` of `me-web` and `prefs` holds exactly the names the service reads:
  every listed name, one name of each alias group, the names the HTTP client of the image
  honours (`RUNTIME_READS`), and nothing else; no `env_file:`;
- the profile's `.env.example` documents exactly the variables the compose file
  interpolates that the root `src/.env.example` does not hold;
- the names a service gets only while another profile is on as well (`with_profiles`,
  set by a generated override, `HANDED_OVER`) are listed as such and are not in the
  compose file: the paths of me-web's client certificate for the connection registry
  (lib/me_connections.py).

Every problem is one line that names the service or file and the variable.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import yaml

from . import common, me_connections

PROFILE = "me"
SERVICES = ("me-web", "prefs")
DATABASE = "prefs-db"
DB_NETWORK = "papaia-prefs-db-net"
FORMAT = "papaia.me-service-env/1"

COMPOSE_REL = Path("src/infra/me/docker-compose.yml")
ENV_EXAMPLE_REL = Path("src/infra/me/.env.example")
ENV_LIST_REL = Path("src/infra/me/service-env.json")
ROOT_ENV_EXAMPLE_REL = Path("src/.env.example")

# Configuration module of each service in the papaia-me source.
SOURCES = {"me-web": Path("src/app/config.py"), "prefs": Path("src/prefs/config.py")}
# Read by the HTTP client of both services (httpx honours it for the trust store), not by
# the configuration module: the local CA of the realm's internal address.
RUNTIME_READS = ("SSL_CERT_FILE",)
# Names a service gets only while another profile is on as well, from an override the core
# generates, never from the compose file: service -> profile -> names.
HANDED_OVER: dict[str, dict[str, tuple[str, ...]]] = {
    "me-web": {me_connections.CONNECTIONS_PROFILE: tuple(sorted(me_connections.ME_ENV))},
    "prefs": {},
}

PINNED_IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9./_-]*(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$")
_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
# `${NAME}`, `${NAME:-x}`, `${NAME-x}`, `${NAME:?x}`, `${NAME?x}`; `$$` is a literal dollar.
_INTERPOLATION_RE = re.compile(r"(?<!\$)\$\{([A-Za-z_][A-Za-z0-9_]*)(?:[:?-][^}]*)?\}")
# Helpers of the configuration modules whose arguments are variable names. `opt` takes
# alternatives (the first set one wins), the others take one name and a default.
_ALTERNATIVES = "opt"
_SINGLE = ("req", "get", "path")
_MAX_SOURCE_BYTES = 256 * 1024


class MeProfileError(ValueError):
    """A source, list or compose file that cannot be read as the profile expects."""


# ── generate ─────────────────────────────────────────────────────────────────


def _name(node: ast.expr, where: str) -> str:
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        raise MeProfileError(f"{where}: a variable name must be a string literal")
    if not _NAME_RE.fullmatch(node.value):
        raise MeProfileError(f"{where}: {node.value!r} is not a variable name")
    return node.value


def _reads(path: Path) -> tuple[list[str], list[list[str]]]:
    """(names, alias groups) the `from_env` methods of one configuration module read."""
    if not path.is_file() or path.stat().st_size > _MAX_SOURCE_BYTES:
        raise MeProfileError(f"{path}: not a readable configuration module")
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    groups: list[list[str]] = []
    found = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name != "from_env":
            continue
        found = True
        for call in ast.walk(node):
            # A helper forwarding its own parameter (`e.get(name, "")`) names nothing.
            if not isinstance(call, ast.Call) or not call.args:
                continue
            if isinstance(call.args[0], ast.Name):
                continue
            func = call.func
            where = f"{path.name}:{call.lineno}"
            if isinstance(func, ast.Name) and func.id == _ALTERNATIVES:
                group = [_name(arg, where) for arg in call.args]
                if len(group) == 1:
                    names.add(group[0])
                elif group not in groups:
                    groups.append(group)
            elif (isinstance(func, ast.Name) and func.id in _SINGLE) or (
                isinstance(func, ast.Attribute) and func.attr == "get"
            ):
                names.add(_name(call.args[0], where))
    if not found:
        raise MeProfileError(f"{path}: no from_env method")
    grouped = {name for group in groups for name in group}
    return sorted(names - grouped), sorted(groups)


def generate(source: Path, *, image: str, commit: str) -> dict:
    """The variable list of both services from a papaia-me checkout at `commit`."""
    if not PINNED_IMAGE_RE.fullmatch(image):
        raise MeProfileError(f"image {image!r} is not pinned by digest (name:tag@sha256:...)")
    if not _COMMIT_RE.fullmatch(commit):
        raise MeProfileError("commit must be a full 40-character hash")
    services = {}
    for service, rel in SOURCES.items():
        reads, groups = _reads(source / rel)
        handed = HANDED_OVER[service]
        apart = {name for names in handed.values() for name in names}
        services[service] = {
            "reads": [name for name in reads if name not in apart],
            "one_of": groups,
            "runtime": list(RUNTIME_READS),
            "with_profiles": {profile: list(names) for profile, names in handed.items()},
        }
    return {
        "format": FORMAT,
        "image": image,
        "source": {"repository": "papaia-me", "commit": commit},
        "services": services,
    }


# ── check ────────────────────────────────────────────────────────────────────


def expected_names(listed: dict, present: set[str]) -> set[str]:
    """The names a service's `environment:` must hold: the listed and runtime names, and
    of each alias group the one name `present` sets (the first one when it sets none, so
    a missing group is reported under that name)."""
    required = set(listed.get("reads", [])) | set(listed.get("runtime", []))
    for group in listed.get("one_of", []):
        if required.intersection(group):
            continue
        chosen = [name for name in group if name in present]
        required.add(chosen[0] if len(chosen) == 1 else group[0])
    return required


def interpolated(compose_path: Path) -> set[str]:
    """Every variable a compose file takes from the interpolation scope: `${NAME}` outside
    comments, and the source of each `secrets.<name>.environment`."""
    text = compose_path.read_text(encoding="utf-8")
    lines = (line for line in text.splitlines() if not line.lstrip().startswith("#"))
    names = {match.group(1) for line in lines for match in _INTERPOLATION_RE.finditer(line)}
    secrets = (yaml.safe_load(text) or {}).get("secrets") or {}
    names.update(
        spec["environment"]
        for spec in secrets.values()
        if isinstance(spec, dict) and isinstance(spec.get("environment"), str)
    )
    return names


def _load_list(path: Path) -> dict:
    try:
        listed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise MeProfileError(f"{path}: not readable: {exc}") from exc
    if not isinstance(listed, dict) or listed.get("format") != FORMAT:
        raise MeProfileError(f"{path}: format is not {FORMAT}")
    services = listed.get("services")
    if not isinstance(services, dict) or set(services) != set(SERVICES):
        raise MeProfileError(f"{path}: services must be exactly {', '.join(SERVICES)}")
    return listed


def _service_problems(name: str, service: dict, listed: dict) -> list[str]:
    problems = []
    environment = service.get("environment") or {}
    if not isinstance(environment, dict):
        return [f"{name}: environment must be a mapping"]
    if "env_file" in service:
        problems.append(f"{name}: env_file is not allowed; values come through environment")
    handed = {
        v: profile for profile, names in (listed.get("with_profiles") or {}).items() for v in names
    }
    wanted = {profile: list(names) for profile, names in HANDED_OVER.get(name, {}).items()}
    if (listed.get("with_profiles") or {}) != wanted:
        problems.append(f"{name}: with_profiles must be {json.dumps(wanted, sort_keys=True)}")
    for v in sorted(set(environment) & set(handed)):
        problems.append(f"{name}: {v} is set by the override of the profile {handed[v]} only")
    present = set(environment) - set(handed)
    expected = expected_names(listed, present)
    problems += [
        f"{name}: {v} is read by the service but missing" for v in sorted(expected - present)
    ]
    groups = {v: group for group in listed.get("one_of", []) for v in group}
    for v in sorted(present - expected):
        if v in groups:
            problems.append(f"{name}: {v} is a second name of {', '.join(groups[v])}; set one")
        else:
            problems.append(f"{name}: {v} is not read by the service")
    return problems


def check(repo_root: Path) -> list[str]:
    """Every difference between the profile and the variable list, one line each."""
    compose_path = repo_root / COMPOSE_REL
    try:
        doc = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
        listed = _load_list(repo_root / ENV_LIST_REL)
    except (OSError, yaml.YAMLError, MeProfileError) as exc:
        return [str(exc)]
    services = doc.get("services") or {}
    problems: list[str] = []
    if set(services) != {*SERVICES, DATABASE}:
        wanted = ", ".join((*SERVICES, DATABASE))
        problems.append(f"{COMPOSE_REL}: services must be exactly {wanted}")
    for name, service in services.items():
        service = service or {}
        if service.get("profiles") != [PROFILE]:
            problems.append(f"{name}: profiles must be [{PROFILE}]")
        if service.get("ports") or service.get("network_mode") == "host":
            problems.append(f"{name}: publishes a host port; only the edge proxy does")
        image = str(service.get("image", ""))
        if not PINNED_IMAGE_RE.fullmatch(image):
            problems.append(f"{name}: image {image!r} is not pinned by digest")
        elif name in SERVICES and image != listed.get("image"):
            problems.append(f"{name}: image {image} is not the listed image {listed.get('image')}")
    for name in SERVICES:
        if name in services:
            problems += _service_problems(name, services[name] or {}, listed["services"][name])

    root = set(common.parse_env_file(repo_root / ROOT_ENV_EXAMPLE_REL))
    example = set(common.parse_env_file(repo_root / ENV_EXAMPLE_REL))
    own = interpolated(compose_path) - root
    problems += [
        f"{ENV_EXAMPLE_REL}: {v} is interpolated but not documented" for v in sorted(own - example)
    ]
    problems += [
        f"{ENV_EXAMPLE_REL}: {v} is not interpolated by the profile" for v in sorted(example - own)
    ]
    return problems


# ── command line ─────────────────────────────────────────────────────────────


def _commit_of(source: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise MeProfileError(f"{source}: not a git checkout")
    return result.stdout.strip()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m lib.me_profile")
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate", help="write src/infra/me/service-env.json")
    gen.add_argument("--source", type=Path, required=True, help="papaia-me checkout")
    gen.add_argument("--image", required=True, help="name:tag@sha256:<digest> of that source")
    gen.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    chk = sub.add_parser("check", help="compare the profile with the list")
    chk.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args(argv)

    if args.command == "generate":
        try:
            listed = generate(args.source, image=args.image, commit=_commit_of(args.source))
        except MeProfileError as exc:
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
