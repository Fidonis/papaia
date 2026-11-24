"""The access material of papaia-replay (docs/replay.md).

papaia-replay deletes in chat and model gateway for the core start gate. It needs one
login for each, as a file in `$PAPAIA_CONFIG_DIR/security/replay/` (folder 0700, files
0600), which the container mounts read-only:

* `chat-password`: the password of the fixed role `papaia-replay-chat` in the chat
  database, made once by `render` while the profiles `lifecycle` and `librechat` are on.
  `papaia-ctl start` (`replay-chat-sync`, after `up`) creates or updates the role and
  its login inside the running database container, which may find and remove documents
  of the named collections only.
* `gateway-key`: the management key of the model gateway while `lifecycle` and `litellm`
  are on. The pinned gateway has no key limited to the deletion routes, so this is its
  master key: a named residual risk (docs/replay.md).

A file whose profile is off is removed, so the container never holds a login it does
not need. Nothing here prints a password or a key.
"""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Callable
from pathlib import Path

from . import common, images

SECRET_DIR = Path("security") / "replay"
CHAT_PASSWORD = "chat-password"
GATEWAY_KEY = "gateway-key"
CHAT_SERVICE = "librechat-mongodb"
CHAT_DATABASE = "LibreChat"
CHAT_ROLE = "papaia-replay-chat"
# The collections the role may find and remove documents in; the same as CHAT_OBJECTS of
# src/infra/replay/replay.py plus the accounts (`users`), which are matched by `sub`.
CHAT_COLLECTIONS: tuple[str, ...] = (
    "users",
    "conversations",
    "messages",
    "files",
    "presets",
    "prompts",
    "promptgroups",
    "sharedlinks",
    "conversationtags",
    "toolcalls",
    "memoryentries",
    "pluginauths",
    "keys",
    "balances",
    "transactions",
    "tokens",
    "sessions",
)
RESULT_MARKER = "PAPAIA_REPLAY_ROLE "
_KEY_PLACEHOLDERS = frozenset({"", "CHANGE_ME", "__GENERATED__"})
DOCKER_TIMEOUT_SECONDS = 60

Runner = Callable[[list[str], "str | None", int], object]


class ReplayAccessError(Exception):
    """The access material could not be written or the role not be set up."""


def _profiles(config_dir: Path) -> set[str]:
    raw = common.parse_env_file(Path(config_dir) / ".env").get("COMPOSE_PROFILES", "")
    return {p.strip() for p in raw.split(",") if p.strip()}


def _remove(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def render(config_dir: Path) -> None:
    """With the `lifecycle` profile: the folder papaia-replay mounts (Compose must not make
    it), the chat password once, and the gateway key as LiteLLM's own environment holds
    it. Without it, the files go."""
    config_dir = Path(config_dir)
    folder = config_dir / SECRET_DIR
    profiles = _profiles(config_dir)
    if "lifecycle" not in profiles:
        for name in (CHAT_PASSWORD, GATEWAY_KEY):
            _remove(folder / name)
        return
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(folder, 0o700)
    password = folder / CHAT_PASSWORD
    if "librechat" in profiles:
        try:
            fd = os.open(password, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            _check_private(password)
        else:
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(secrets.token_urlsafe(32) + "\n")
    else:
        _remove(password)
    key_file = folder / GATEWAY_KEY
    key = common.parse_env_file(config_dir / "ai" / "litellm" / ".env").get(
        "LITELLM_MASTER_KEY", ""
    ).strip()
    if "litellm" in profiles and key not in _KEY_PLACEHOLDERS and not key.startswith("GENERATE"):
        try:
            current = key_file.read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError):
            current = None
        if current != key:
            common.atomic_write_private(key_file, key + "\n")
    else:
        _remove(key_file)


def _check_private(path: Path) -> None:
    st = os.lstat(path)
    if not os.path.isfile(path) or os.path.islink(path) or st.st_mode & 0o077:
        raise ReplayAccessError(f"{path} must be a regular file with mode 0600")


def role_script(password: str) -> str:
    """The mongosh script that creates or updates the role and its login. The password
    goes in on stdin, never on a command line."""
    spec = {
        "role": CHAT_ROLE,
        "password": password,
        "privileges": [
            {"resource": {"db": CHAT_DATABASE, "collection": name}, "actions": ["find", "remove"]}
            for name in CHAT_COLLECTIONS
        ],
    }
    return (
        f"const spec = {json.dumps(spec)};\n"
        "const adm = db.getSiblingDB('admin');\n"
        "if (adm.getRole(spec.role)) {\n"
        "  adm.updateRole(spec.role, {privileges: spec.privileges, roles: []});\n"
        "} else {\n"
        "  adm.createRole({role: spec.role, privileges: spec.privileges, roles: []});\n"
        "}\n"
        "const grant = [{role: spec.role, db: 'admin'}];\n"
        "if (adm.getUser(spec.role)) {\n"
        "  adm.updateUser(spec.role, {pwd: spec.password, roles: grant,"
        " mechanisms: ['SCRAM-SHA-256']});\n"
        "} else {\n"
        "  adm.createUser({user: spec.role, pwd: spec.password, roles: grant,"
        " mechanisms: ['SCRAM-SHA-256']});\n"
        "}\n"
        f"print('{RESULT_MARKER}' + JSON.stringify({{collections: spec.privileges.length}}));\n"
    )


def _run(cmd: list[str], stdin: str | None, timeout: int):
    """`docker` with literal programs and the container of this installation; the script
    goes on stdin (librechat_history.run_with_input, no shell)."""
    from . import librechat_history

    return librechat_history.run_with_input(cmd, stdin, float(timeout))


def sync_chat_role(config_dir: Path, *, runner: Runner | None = None,
                   correlation: str | None = None) -> str:
    """After `up`: the role `papaia-replay-chat` and its login in the running chat
    database. Returns `skipped` (a profile is off), `absent` (the database does not run
    on this host) or `synced`; one audit row for `synced` and for a failure."""
    runner = runner or _run
    config_dir = Path(config_dir)
    profiles = _profiles(config_dir)
    if not {"lifecycle", "librechat"} <= profiles:
        return "skipped"
    password_file = config_dir / SECRET_DIR / CHAT_PASSWORD
    try:
        _check_private(password_file)
        password = password_file.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError, ReplayAccessError) as exc:
        raise ReplayAccessError(f"the chat password of papaia-replay: {exc}") from None
    project = common.parse_env_file(config_dir / ".env").get("COMPOSE_PROJECT_NAME") or "papaia"
    found = runner(
        ["docker", "ps", "-q",
         "--filter", f"label=com.docker.compose.project={project}",
         "--filter", f"label=com.docker.compose.service={CHAT_SERVICE}",
         "--filter", "status=running"],
        None, DOCKER_TIMEOUT_SECONDS,
    )  # fmt: skip
    ids = (found.stdout or "").split() if found.returncode == 0 else []
    if len(ids) != 1:
        return "absent"
    correlation = images.correlation_id(correlation)
    done = runner(
        ["docker", "exec", "-i", ids[0], "mongosh", "--quiet", "--norc",
         "mongodb://127.0.0.1:27017/admin"],
        role_script(password), DOCKER_TIMEOUT_SECONDS,
    )  # fmt: skip
    # mongosh echoes its prompt on piped input, so the marker is looked for in the text.
    ok = done.returncode == 0 and RESULT_MARKER in (done.stdout or "")
    row = images._row(
        "replay-chat-sync", "replay_chat_role" if ok else "replay_chat_role_failed",
        {"role": CHAT_ROLE, "collections": len(CHAT_COLLECTIONS)}, correlation,
    )
    if not ok:
        row["result"], row["error_code"] = "error", "role_sync_failed"
    images.append_audit(config_dir, row)
    if not ok:
        # The output of mongosh is not repeated: the script holds the password.
        raise ReplayAccessError(
            f"the chat database refused the role {CHAT_ROLE} (exit {done.returncode})"
        )
    return "synced"
