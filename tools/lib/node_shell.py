"""The forced command behind a node's SSH key: the only thing the controller can run there.

On a node of a distributed installation, the unprivileged user `papaia` belongs to the
Docker group, which is root-equivalent. Its `authorized_keys` line therefore pins the key to
one command,

    restrict,from="<controller>",command="bash <root>/checkout/tools/papaia-ctl node-shell
        --node-root=<root>" ssh-ed25519 AAAA...

and this module is that command. It is the security boundary, not the SSH login:

* The requested command arrives in `SSH_ORIGINAL_COMMAND` and is parsed here, without a
  shell: split on whitespace, every word restricted to a small character set, at most a
  handful of words. Quotes, `$`, `;`, `/` and `..` cannot get through.
* Only the verbs in `VERBS` exist. Their arguments are names, checked against what the
  node's bundle declares (its services, its hooks); a caller can never pass a path.
* Uploads (`bundle-put`, `checkout-put`, `image-load`) arrive on stdin with a size limit.
  Archives are checked member by member before anything is written: no absolute names, no
  `..`, no links, no devices. A bundle is installed only once it is complete, and only
  for this node.
* Output streams as it is produced and the exit code is passed through. Every call leaves
  one line in the node's audit log.

The controller runs its own node through the same code (`--controller-config`), so the
local and the SSH executor cannot drift apart.

Exit codes: 0 done, 2 refused (unknown verb, bad argument), 3 failed, anything else is the
exit code of the command that ran.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from . import common, envtree, link, topology

# One word of a command. No path separators, no shell metacharacters, no leading dash
# except for the few `--name=value` options a verb declares.
_WORD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:=,+-]{0,127}$")
_OPTION_RE = re.compile(r"^--[a-z][a-z-]{0,30}=[A-Za-z0-9._:,+-]{1,64}$")
_VERSION_RE = re.compile(r"^[0-9][A-Za-z0-9.+-]{0,63}$")
MAX_WORDS = 24
MAX_COMMAND_LENGTH = 2048

MiB = 1024 * 1024
BUNDLE_LIMIT = 64 * MiB
CHECKOUT_LIMIT = 512 * MiB
IMAGE_LIMIT = 16 * 1024 * MiB
# A compressed archive may expand; the members together may not exceed this multiple.
EXPANSION_FACTOR = 8
LOG_TAIL_MAX = 10000
KEEP_RELEASES = 2

BUNDLE_FILES = ".bundle-files"
NODE_NAME_FILE = "node-name"
RUNTIME_OVERRIDE = "docker-compose.link-gateway-user.override.yml"

# Hook name -> the catalogue service that has to run on the node for it.
HOOKS = {
    "npm-provision": "nginx",
    "keycloak-role-sync": "keycloak",
}


class Refused(Exception):
    """A request the shim does not accept. Exit 2."""


class Failed(Exception):
    """A request that was accepted and did not work. Exit 3."""


# ─────────────────────────────────────────────────────────────────────────
# parsing
# ─────────────────────────────────────────────────────────────────────────


def parse_command(raw: str | None) -> list[str]:
    """Split the requested command into words, refusing anything unexpected."""
    if raw is None or not raw.strip():
        raise Refused("this key only runs papaia node commands; no command was given")
    if len(raw) > MAX_COMMAND_LENGTH:
        raise Refused("command too long")
    if any(ch in raw for ch in "\0\n\r"):
        raise Refused("command contains control characters")
    words = raw.split()
    if len(words) > MAX_WORDS:
        raise Refused("too many arguments")
    for word in words:
        if not (_WORD_RE.match(word) or _OPTION_RE.match(word)):
            shown = word if len(word) <= 40 else word[:37] + "..."
            raise Refused(f"argument not allowed: {shown!r}")
    return words


# ─────────────────────────────────────────────────────────────────────────
# context
# ─────────────────────────────────────────────────────────────────────────


@dataclass
class Context:
    node: str
    checkout: Path
    config_dir: Path  # $PAPAIA_CONFIG_DIR on this node
    bundle: Path  # where the bundle's files are (the config dir on a remote node)
    audit_log: Path
    staging: Path
    remote: bool
    stdin: BinaryIO = field(default_factory=lambda: sys.stdin.buffer)
    run: Callable[..., int] = field(default=None)  # type: ignore[assignment]
    _manifest: dict | None = None

    def __post_init__(self) -> None:
        if self.run is None:
            self.run = _run

    @property
    def manifest(self) -> dict:
        if self._manifest is None:
            path = self.bundle / topology.NODE_MANIFEST
            if not path.is_file():
                raise Failed(f"no bundle installed on node '{self.node}' yet")
            try:
                self._manifest = json.loads(path.read_text(encoding="utf-8"))
            except ValueError as exc:
                raise Failed(f"the installed bundle is damaged: {exc}") from exc
        return self._manifest

    @property
    def services(self) -> list[str]:
        return list(self.manifest.get("services") or [])

    @property
    def profiles(self) -> list[str]:
        return list(self.manifest.get("profiles") or [])

    @property
    def releases(self) -> Path:
        return self.checkout.parent / "releases"


def _run(argv: list[str], **kwargs) -> int:
    """Run a command with this process's stdout and stderr, so its output streams."""
    try:
        return subprocess.run(argv, check=False, **kwargs).returncode  # noqa: S603
    except FileNotFoundError as exc:
        raise Failed(f"{argv[0]} not found on this node") from exc


def context_from_args(argv: list[str] | None = None) -> Context:
    parser = argparse.ArgumentParser(prog="papaia-ctl node-shell")
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--node-root")
    parser.add_argument("--controller-config")
    parser.add_argument("--node")
    args = parser.parse_args(argv)
    if args.node_root:
        root = Path(args.node_root)
        # Written once by the node's install script: which node this is. A bundle for any
        # other node is refused.
        identity = root / NODE_NAME_FILE
        name = identity.read_text(encoding="utf-8").strip() if identity.is_file() else ""
        if not name:
            raise Refused(f"{identity} is missing; the node was not installed by papaia-ctl")
        return Context(
            node=name,
            checkout=root / "checkout",
            config_dir=root / "config",
            bundle=root / "config",
            audit_log=root / "audit.log",
            staging=root / "staging",
            remote=True,
        )
    if args.controller_config and args.node:
        config = Path(args.controller_config)
        node_dir = config / topology.NODES_DIR / args.node
        return Context(
            node=args.node,
            checkout=Path(args.repo_root),
            config_dir=config,
            bundle=node_dir / topology.BUNDLE_DIR,
            audit_log=node_dir / "audit.log",
            staging=node_dir / "staging",
            remote=False,
        )
    raise Refused("node-shell needs --node-root, or --controller-config with --node")


# ─────────────────────────────────────────────────────────────────────────
# archives
# ─────────────────────────────────────────────────────────────────────────


def read_limited(stream: BinaryIO, limit: int) -> bytes:
    """All of stdin, or a refusal once it exceeds `limit` bytes."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise Refused(f"upload larger than {limit // MiB} MiB")
        chunks.append(chunk)
    return b"".join(chunks)


def safe_members(tar: tarfile.TarFile, limit: int) -> list[tarfile.TarInfo]:
    """The archive's members, once every one of them is a plain file or directory with a
    relative name that stays inside the target."""
    members = tar.getmembers()
    total = 0
    for member in members:
        name = member.name
        path = PurePosixPath(name)
        if not name or name.startswith("/") or path.is_absolute() or "\\" in name:
            raise Refused(f"archive member with an absolute name: {name!r}")
        if any(part == ".." for part in path.parts):
            raise Refused(f"archive member outside the target: {name!r}")
        if not (member.isfile() or member.isdir()):
            raise Refused(f"archive member is not a plain file or directory: {name!r}")
        total += member.size
        if total > limit * EXPANSION_FACTOR:
            raise Refused("archive expands beyond its size limit")
    return members


def extract(data: bytes, target: Path, limit: int) -> list[str]:
    """Extract a tar archive (plain or compressed) into an empty `target`. Returns the
    relative paths of the files written."""
    try:
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError as exc:
        raise Refused(f"not a tar archive: {exc}") from exc
    files: list[str] = []
    with tar:
        members = safe_members(tar, limit)
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True)
        for member in members:
            rel = PurePosixPath(member.name)
            if rel.parts and rel.parts[0] == ".":
                rel = PurePosixPath(*rel.parts[1:]) if len(rel.parts) > 1 else PurePosixPath()
            if not rel.parts:
                continue
            dest = target.joinpath(*rel.parts)
            if member.isdir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                raise Refused(f"archive member cannot be read: {member.name!r}")
            with open(dest, "wb") as out:
                shutil.copyfileobj(source, out)
            # The mode the controller wrote, without write access for anyone else: rendered
            # configuration is read by the containers it is mounted into, while `.env` files
            # and keys arrive as 0600.
            os.chmod(dest, member.mode & 0o755)
            files.append(rel.as_posix())
    return files


# ─────────────────────────────────────────────────────────────────────────
# verbs
# ─────────────────────────────────────────────────────────────────────────


def _version(ctx: Context) -> str:
    return envtree.resolve_platform_version(ctx.checkout)


def verb_ping(ctx: Context, args: list[str]) -> int:
    _no_args(args)
    print(f"pong {ctx.node} {_version(ctx)}", flush=True)
    return 0


def _probe(argv: list[str]) -> str:
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout.strip() if done.returncode == 0 else ""


def verb_version(ctx: Context, args: list[str]) -> int:
    _no_args(args)
    bundle_version = ctx.manifest.get("papaia_version") if _has_bundle(ctx) else None
    print(
        json.dumps(
            {
                "node": ctx.node,
                "papaia_version": _version(ctx),
                "bundle_version": bundle_version,
                "docker": _probe(["docker", "version", "--format", "{{.Server.Version}}"]),
                "compose": _probe(["docker", "compose", "version", "--short"]),
                "python": sys.version.split()[0],
                "time": time.time(),
            }
        ),
        flush=True,
    )
    return 0


def _has_bundle(ctx: Context) -> bool:
    return (ctx.bundle / topology.NODE_MANIFEST).is_file()


def verb_status(ctx: Context, args: list[str]) -> int:
    _no_args(args)
    from . import status

    # The bundle, not the config dir: on the controller the config dir is the whole
    # installation, and this answers for the node.
    report = status.collect(ctx.bundle, ctx.checkout, include_addons=True)
    print(status.to_json(report), flush=True)
    return 0


def probe_link(peer: str, address: str, port: int, link_dir: Path, *, timeout: float = 5.0) -> dict:
    """A TLS handshake with a peer's link port, as the node's gateway makes it: client
    certificate, the link CA, the peer's name. Touches no service behind it: the peer
    refuses the connection right after the handshake, since nothing is routed for it."""
    result: dict = {"peer": peer, "address": address, "port": port}
    try:
        context = ssl.create_default_context(cafile=str(link_dir / "ca.crt"))
        context.load_cert_chain(str(link_dir / "node.crt"), str(link_dir / "node.key"))
    except (OSError, ssl.SSLError) as exc:
        result.update(ok=False, stage="certificates", reason=str(exc))
        return result
    try:
        with socket.create_connection((address, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=peer) as tls:
                cert = tls.getpeercert() or {}
    except ssl.SSLCertVerificationError as exc:
        result.update(ok=False, stage="tls", reason=exc.verify_message or str(exc))
        return result
    except ssl.SSLError as exc:
        result.update(ok=False, stage="tls", reason=str(exc))
        return result
    except OSError as exc:
        result.update(ok=False, stage="connect", reason=str(exc))
        return result
    not_after = cert.get("notAfter")
    result.update(ok=True, stage="tls", peer_not_after=not_after)
    return result


def verb_doctor(ctx: Context, args: list[str]) -> int:
    _no_args(args)
    from . import doctor

    report = doctor.run_checks(ctx.bundle, ctx.checkout, skip=["addon_compat"])
    edges_file = ctx.bundle / link.LINK_DIR / "edges.json"
    links: list[dict] = []
    if edges_file.is_file():
        summary = json.loads(edges_file.read_text(encoding="utf-8"))
        peers = {}
        for out in summary.get("outgoing") or []:
            peers.setdefault(out["peer"], out["peer_address"])
        for peer, address in sorted(peers.items()):
            links.append(
                probe_link(peer, address, int(summary["link_port"]), ctx.bundle / link.LINK_DIR)
            )
    own = link.cert_not_after(ctx.bundle / link.LINK_DIR / "node.crt")
    print(
        json.dumps(
            {
                "node": ctx.node,
                "papaia_version": _version(ctx),
                "time": time.time(),
                "doctor": report.to_dict(),
                "links": links,
                "link_cert_not_after": own.strftime("%Y-%m-%dT%H:%M:%SZ") if own else None,
            }
        ),
        flush=True,
    )
    return 0


# --- compose -----------------------------------------------------------------


def materialize(ctx: Context) -> None:
    """Hand the bundle to Compose: the `.env` files into the checkout, the state
    directories created, and the gateway told which user it runs as.

    A `.env` the bundle does not carry is removed from the checkout: it belongs to a
    service that no longer runs on this node, and its secrets have no business here."""
    for rel_dir in envtree.discover_env_examples(ctx.checkout):
        source = ctx.bundle / rel_dir / ".env" if rel_dir else ctx.bundle / ".env"
        target = ctx.checkout / "src" / rel_dir / ".env"
        if source.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        elif target.is_file():
            target.unlink()
    for rel in ctx.manifest.get("state_dirs") or []:
        common.ensure_dir(ctx.config_dir / rel)
    if link.GATEWAY_PROFILE in ctx.profiles:
        # The gateway reads the node's key file, which belongs to the user running this.
        override = {"services": {link.GATEWAY_SERVICE: {"user": f"{os.getuid()}:{os.getgid()}"}}}
        common.atomic_write(
            ctx.bundle / "overrides" / RUNTIME_OVERRIDE,
            json.dumps(override, indent=2) + "\n",
        )


def _network_exists(name: str) -> bool:
    return (
        subprocess.run(
            ["docker", "network", "inspect", name],
            capture_output=True,
            timeout=15,
            check=False,
        ).returncode
        == 0
    )


def compose_files(ctx: Context) -> list[str]:
    files = ["-f", str(ctx.checkout / "src" / "docker-compose.yml")]
    if link.GATEWAY_PROFILE in ctx.profiles:
        files += ["-f", str(ctx.checkout / link.GATEWAY_FRAGMENT)]
    overrides = ctx.bundle / "overrides"
    if overrides.is_dir():
        from . import gen_override

        for path in sorted(overrides.glob("docker-compose.*.override.yml")):
            nets = gen_override.external_networks(path)
            # An add-on's network exists once the add-on runs; until then its override is
            # left out, as `start` does on a single host.
            if nets and not all(_network_exists(net) for net in nets):
                continue
            files += ["-f", str(path)]
    return files


def compose_argv(ctx: Context, *args: str) -> list[str]:
    return [
        "docker",
        "compose",
        *compose_files(ctx),
        "--env-file",
        str(ctx.checkout / "src" / ".env"),
        *args,
    ]


def compose_targets(ctx: Context, names: list[str]) -> list[str]:
    """Compose services for the requested targets: catalogue services placed on this
    node, or the gateway. Anything else is refused."""
    services: list[str] = []
    for name in names:
        if name == link.GATEWAY_SERVICE and link.GATEWAY_PROFILE in ctx.profiles:
            candidates = [link.GATEWAY_SERVICE]
        elif name in ctx.services:
            candidates = [s.name for s in topology.services_of(ctx.checkout, [name])]
        else:
            raise Refused(f"'{name}' does not run on node '{ctx.node}'")
        services += [c for c in candidates if c not in services]
    return services


def _split_options(args: list[str], allowed: set[str]) -> tuple[list[str], dict[str, str]]:
    names: list[str] = []
    options: dict[str, str] = {}
    for arg in args:
        if arg.startswith("--"):
            key, _, value = arg[2:].partition("=")
            if key not in allowed:
                raise Refused(f"option not allowed: --{key}")
            options[key] = value
        else:
            names.append(arg)
    return names, options


def _compose(ctx: Context, *args: str) -> int:
    materialize(ctx)
    return ctx.run(compose_argv(ctx, *args))


def verb_compose_up(ctx: Context, args: list[str]) -> int:
    names, _ = _split_options(args, set())
    return _compose(ctx, "up", "-d", *compose_targets(ctx, names))


def verb_compose_down(ctx: Context, args: list[str]) -> int:
    names, _ = _split_options(args, set())
    if names:
        # Only the named services: stop and remove their containers, keep the rest.
        return _compose(ctx, "rm", "--stop", "--force", *compose_targets(ctx, names))
    return _compose(ctx, "down")


def verb_compose_stop(ctx: Context, args: list[str]) -> int:
    names, _ = _split_options(args, set())
    return _compose(ctx, "stop", *compose_targets(ctx, names))


def verb_compose_restart(ctx: Context, args: list[str]) -> int:
    names, _ = _split_options(args, set())
    return _compose(ctx, "restart", *compose_targets(ctx, names))


def verb_compose_pull(ctx: Context, args: list[str]) -> int:
    names, _ = _split_options(args, set())
    return _compose(ctx, "pull", *compose_targets(ctx, names))


def verb_compose_ps(ctx: Context, args: list[str]) -> int:
    _no_args(args)
    return _compose(ctx, "ps", "--all")


def verb_compose_logs(ctx: Context, args: list[str]) -> int:
    names, options = _split_options(args, {"tail"})
    tail = options.get("tail", "200")
    if not tail.isdigit() or not 0 < int(tail) <= LOG_TAIL_MAX:
        raise Refused(f"--tail must be a number between 1 and {LOG_TAIL_MAX}")
    return _compose(ctx, "logs", "--no-color", "--tail", tail, *compose_targets(ctx, names))


# --- uploads -------------------------------------------------------------


def _remote_only(ctx: Context, verb: str) -> None:
    if not ctx.remote:
        raise Refused(f"{verb} is for remote nodes; the controller reads its own tree")


def verb_bundle_put(ctx: Context, args: list[str]) -> int:
    """Install a bundle from stdin. The archive is checked and unpacked completely before
    the first file of the installed bundle is replaced, and it must be this node's."""
    _no_args(args)
    _remote_only(ctx, "bundle-put")
    data = read_limited(ctx.stdin, BUNDLE_LIMIT)
    incoming = ctx.staging / "bundle"
    files = extract(data, incoming, BUNDLE_LIMIT)
    manifest_path = incoming / topology.NODE_MANIFEST
    if not manifest_path.is_file():
        raise Refused("the archive is not a node bundle (no node.json)")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise Refused(f"the bundle's node.json is damaged: {exc}") from exc
    if manifest.get("node") != ctx.node:
        raise Refused(f"this bundle is for node '{manifest.get('node')}', not for '{ctx.node}'")
    previous_list = ctx.config_dir / BUNDLE_FILES
    previous = (
        set(previous_list.read_text(encoding="utf-8").split("\n")) - {""}
        if previous_list.is_file()
        else set()
    )
    common.ensure_dir(ctx.config_dir)
    for rel in files:
        dest = ctx.config_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.is_dir():
            shutil.rmtree(dest)
        os.replace(incoming / rel, dest)
    for rel in sorted(previous - set(files)):
        stale = ctx.config_dir / rel
        if stale.is_file() and not rel.startswith(".."):
            stale.unlink()
    common.atomic_write(previous_list, "\n".join(sorted(files)) + "\n")
    shutil.rmtree(incoming, ignore_errors=True)
    ctx._manifest = manifest
    for rel in manifest.get("state_dirs") or []:
        common.ensure_dir(ctx.config_dir / rel)
    print(f"bundle installed on {ctx.node}: {len(files)} files", flush=True)
    return 0


def verb_checkout_put(ctx: Context, args: list[str]) -> int:
    """Install a release of the checkout from stdin and point `checkout` at it."""
    _remote_only(ctx, "checkout-put")
    if len(args) != 1 or not _VERSION_RE.match(args[0]):
        raise Refused("checkout-put needs the release version as its only argument")
    version = args[0]
    data = read_limited(ctx.stdin, CHECKOUT_LIMIT)
    releases = ctx.releases
    common.ensure_dir(releases)
    incoming = releases / f".incoming-{version}"
    extract(data, incoming, CHECKOUT_LIMIT)
    if (
        not (incoming / "tools" / "papaia-ctl").is_file()
        or not (incoming / "src" / "docker-compose.yml").is_file()
    ):
        shutil.rmtree(incoming, ignore_errors=True)
        raise Refused("the archive is not a papAIa checkout")
    target = releases / version
    if target.exists():
        retired = releases / f".retired-{version}-{int(time.time())}"
        os.replace(target, retired)
        shutil.rmtree(retired, ignore_errors=True)
    os.replace(incoming, target)
    link_tmp = ctx.checkout.with_name(ctx.checkout.name + ".new")
    if link_tmp.is_symlink() or link_tmp.exists():
        link_tmp.unlink()
    os.symlink(Path("releases") / version, link_tmp)
    os.replace(link_tmp, ctx.checkout)
    _prune_releases(releases, keep=version)
    print(f"checkout on {ctx.node} is now {version}", flush=True)
    return 0


def _prune_releases(releases: Path, keep: str) -> None:
    others = sorted(
        (
            p
            for p in releases.iterdir()
            if p.is_dir() and not p.name.startswith(".") and p.name != keep
        ),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for old in others[KEEP_RELEASES - 1 :]:
        shutil.rmtree(old, ignore_errors=True)


def verb_image_load(ctx: Context, args: list[str]) -> int:
    """`docker load` from stdin, for a node without registry access."""
    _no_args(args)
    try:
        proc = subprocess.Popen(["docker", "load"], stdin=subprocess.PIPE)  # noqa: S603
    except FileNotFoundError as exc:
        raise Failed("docker not found on this node") from exc
    assert proc.stdin is not None
    total = 0
    try:
        while True:
            chunk = ctx.stdin.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > IMAGE_LIMIT:
                proc.kill()
                raise Refused(f"image upload larger than {IMAGE_LIMIT // MiB} MiB")
            proc.stdin.write(chunk)
    finally:
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()
    return proc.wait()


def verb_hook(ctx: Context, args: list[str]) -> int:
    """A provisioning step that has to run where its service runs."""
    if len(args) != 1 or args[0] not in HOOKS:
        raise Refused(f"hook needs one of: {', '.join(sorted(HOOKS))}")
    hook = args[0]
    if HOOKS[hook] not in ctx.services:
        raise Refused(f"hook {hook} needs '{HOOKS[hook]}', which does not run on '{ctx.node}'")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ctx.checkout / "tools")
    return ctx.run(
        [
            sys.executable,
            "-m",
            "lib.cli",
            "--repo-root",
            str(ctx.checkout),
            "--config-dir",
            str(ctx.config_dir),
            hook,
        ],
        env=env,
    )


def _no_args(args: list[str]) -> None:
    if args:
        raise Refused("this verb takes no arguments")


Verb = Callable[[Context, list[str]], int]

VERBS: dict[str, Verb] = {
    "ping": verb_ping,
    "version": verb_version,
    "status": verb_status,
    "doctor": verb_doctor,
    "compose-up": verb_compose_up,
    "compose-down": verb_compose_down,
    "compose-stop": verb_compose_stop,
    "compose-restart": verb_compose_restart,
    "compose-ps": verb_compose_ps,
    "compose-pull": verb_compose_pull,
    "compose-logs": verb_compose_logs,
    "bundle-put": verb_bundle_put,
    "checkout-put": verb_checkout_put,
    "image-load": verb_image_load,
    "hook": verb_hook,
}


# ─────────────────────────────────────────────────────────────────────────
# entry point
# ─────────────────────────────────────────────────────────────────────────


def audit(ctx: Context, words: list[str], code: int, started: float) -> None:
    client = (os.environ.get("SSH_CLIENT") or "local").split()[0]
    line = (
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}"
        f" node={ctx.node} client={client} verb={words[0] if words else '-'}"
        f" args={','.join(words[1:]) or '-'} rc={code}"
        f" duration={time.monotonic() - started:.1f}s\n"
    )
    try:
        ctx.audit_log.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(ctx.audit_log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        pass  # A full disk must not turn a finished command into a failed one.


def execute(ctx: Context, raw: str | None) -> int:
    started = time.monotonic()
    words: list[str] = []
    try:
        words = parse_command(raw)
        verb = VERBS.get(words[0])
        if verb is None:
            raise Refused(f"unknown verb '{words[0]}' (one of {', '.join(VERBS)})")
        code = verb(ctx, words[1:])
    except Refused as exc:
        print(f"refused: {exc}", file=sys.stderr, flush=True)
        code = 2
    except Failed as exc:
        print(f"failed: {exc}", file=sys.stderr, flush=True)
        code = 3
    audit(ctx, words, code, started)
    return code


def main(argv: list[str] | None = None) -> int:
    try:
        ctx = context_from_args(argv)
    except Refused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    return execute(ctx, os.environ.get("SSH_ORIGINAL_COMMAND"))


if __name__ == "__main__":
    sys.exit(main())
