"""The paths of the core services for `papaia-ctl person export|erase` (security 1.14
no. 2a, RE-64, RE-100): chat, model gateway and identity provider hold personal data
without a module contract, so the core brings one export and one erasure path for each.
The operator never reaches into a database; lib/person.py runs these paths in the order
of an erasure and checks, audits and journals every answer.

* `core-chat` (LibreChat's database): a `mongosh` script on stdin of `docker exec` in
  the chat database container. The script creates a role and a login for this one call
  (read only for an export, find and remove for an erasure, on the chat's collections
  alone), does its work signed in with that login and drops both in `finally`. The
  password is made here, lives in memory and on the script's stdin only. The person's
  chat accounts are found by the OIDC id (`openidId` = `sub`); everything filed under
  them goes with them, the accounts last. The answer holds the account ids and the mail
  address of the accounts (for the gateway and the reconciliation) and, for an export,
  the documents.
* `model-gateway` (LiteLLM): the management API inside the gateway's container
  (lib/model_gateway.py, two more routes: `GET /customer/info`, `POST /customer/delete`).
  Usage is kept per end user; an end user is whatever id a caller sent, here the `sub`,
  the chat account id or the mail. The export keeps the usage sum (`spend`) and nothing
  else of the answer. The erase removes the end-user records only: the per-request usage
  rows and the daily sums under the chat account id stay (MN-17), and lib/person.py names
  them as not included.
* `identity` (Keycloak): papaia-lifecycle's `person` command through `docker exec`, so
  the request runs as `svc-papaia-lifecycle`, the one account that holds the rights to
  end sessions and delete persons (no further account gets them). `revoke` disables the
  account, ends its sessions and removes its consents; `delete` removes it. The running
  papaia-lifecycle journals both from the admin events (`account_disable`,
  `account_delete`) and keeps the tombstone.

Every operation also has `check`, the reconciliation after an erasure: the number of
documents, end users and accounts that still name the person by `sub`, chat account or
mail. Answers are counts and ids, never content, except the documents of an export.
"""

from __future__ import annotations

import json
import re
import secrets
import urllib.parse
from collections.abc import Callable
from pathlib import Path

from . import model_gateway, status

CHAT = "core-chat"
GATEWAY = "model-gateway"
IDENTITY = "identity"
SERVICES = (IDENTITY, CHAT, GATEWAY)
OPERATIONS = {
    CHAT: ("export", "erase", "check"),
    GATEWAY: ("export", "erase", "check"),
    IDENTITY: ("export", "revoke", "delete", "check"),
}
TITLES = {CHAT: "Chat", GATEWAY: "Modellzugang (Nutzung)", IDENTITY: "Anmeldedienst"}
CATALOG_IDS = {CHAT: "core.chat", GATEWAY: "core.model-gateway", IDENTITY: "core.identity"}

CHAT_SERVICE = "librechat-mongodb"
CHAT_DATABASE = "LibreChat"
CHAT_MARKER = "PAPAIA_PERSON_CHAT "
# Collection and the field that names the account, as papaia-replay erases them
# (src/infra/replay/replay.py CHAT_OBJECTS); the accounts (`users`) go last.
CHAT_OBJECTS: tuple[tuple[str, str], ...] = (
    ("conversations", "user"),
    ("messages", "user"),
    ("files", "user"),
    ("presets", "user"),
    ("prompts", "author"),
    ("promptgroups", "author"),
    ("sharedlinks", "user"),
    ("conversationtags", "user"),
    ("toolcalls", "user"),
    ("memoryentries", "userId"),
    ("pluginauths", "userId"),
    ("keys", "userId"),
    ("balances", "user"),
    ("transactions", "user"),
    ("tokens", "userId"),
    ("sessions", "user"),
)
# Sign-in material of the account, not data about the person: erased, never exported.
CHAT_NOT_EXPORTED = ("pluginauths", "keys", "tokens", "sessions")
CHAT_ACCOUNT_FIELDS = ("name", "username", "email", "provider", "role", "createdAt",
                       "updatedAt")
MAX_ACCOUNTS = 16

LIFECYCLE_SERVICE = "papaia-lifecycle"
LIFECYCLE_COMMAND = (
    "python3", "-I", "/opt/papaia-lifecycle/lifecycle.py", "person",
    "--keycloak-url=https://keycloak:8443",
    "--ca-file=/etc/papaia-lifecycle/local-ca.crt",
    "--account-dir=/run/papaia-lifecycle/account",
)

EXEC_TIMEOUT_SECONDS = 900
DOCKER_TIMEOUT_SECONDS = 30
MAX_ANSWER_BYTES = 100 * 1024 * 1024

_KEYCLOAK_ID_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
_ACCOUNT_RE = re.compile(r"[0-9a-f]{24}")
_COUNT_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_MAIL_RE = re.compile(r"[^@\s\x00-\x1f\x7f]{1,64}@[^@\s\x00-\x1f\x7f]{1,255}")

Runner = Callable[[list[str], "str | None", int], object]


class CoreError(Exception):
    """A backend did not answer, refused, or answered outside its shape. The message is a
    short code; it never names the person."""


# ── answers ──────────────────────────────────────────────────────────────────

_SHAPES = {
    (CHAT, "export"): {"accounts", "mails", "data"},
    (CHAT, "erase"): {"accounts", "mails", "counts"},
    (GATEWAY, "export"): {"data"},
    (IDENTITY, "export"): {"found", "mails", "data"},
    (IDENTITY, "revoke"): {"found", "mails", "counts"},
}


def check_answer(service: str, operation: str, doc: object) -> dict:
    """The answer of one path in its shape, or CoreError("invalid_answer")."""
    fields = _SHAPES.get((service, operation), {"counts"})
    if not isinstance(doc, dict) or set(doc) != fields:
        raise CoreError("invalid_answer")
    if "found" in doc and not isinstance(doc["found"], bool):
        raise CoreError("invalid_answer")
    if "data" in doc and not isinstance(doc["data"], dict):
        raise CoreError("invalid_answer")
    accounts = doc.get("accounts", [])
    if not isinstance(accounts, list) or len(accounts) > MAX_ACCOUNTS or not all(
        isinstance(a, str) and _ACCOUNT_RE.fullmatch(a) for a in accounts
    ):
        raise CoreError("invalid_answer")
    mails = doc.get("mails", [])
    if not isinstance(mails, list) or len(mails) > MAX_ACCOUNTS or not all(
        isinstance(m, str) and _MAIL_RE.fullmatch(m) for m in mails
    ):
        raise CoreError("invalid_answer")
    counts = doc.get("counts", {})
    if not isinstance(counts, dict) or len(counts) > 32 or not all(
        isinstance(k, str) and _COUNT_RE.fullmatch(k) and type(v) is int and 0 <= v <= 2**53
        for k, v in counts.items()
    ):
        raise CoreError("invalid_answer")
    return doc


# ── the paths ────────────────────────────────────────────────────────────────


def chat_script(operation: str, request: dict, user: str, password: str) -> str:
    """The mongosh script of one chat call. Its first line is the request as JSON; the
    login of this call is created, used and dropped inside it."""
    actions = ["find", "remove"] if operation == "erase" else ["find"]
    req = {
        "operation": operation,
        "sub": request["sub"],
        "mails": list(request.get("mails", [])),
        "accounts": list(request.get("accounts", [])),
        "database": CHAT_DATABASE,
        "objects": [list(o) for o in CHAT_OBJECTS],
        "export": [list(o) for o in CHAT_OBJECTS if o[0] not in CHAT_NOT_EXPORTED],
        "account_fields": {name: 1 for name in CHAT_ACCOUNT_FIELDS},
        "max_accounts": MAX_ACCOUNTS,
        "actions": actions,
        "login": {"user": user, "password": password},
    }
    return (
        f"const req = {json.dumps(req, sort_keys=True)};\n"
        "const adm = db.getSiblingDB('admin');\n"
        "const names = req.objects.map(o => o[0]).concat(['users']);\n"
        "const privileges = names.map(c => ({resource: {db: req.database, collection: c},"
        " actions: req.actions}));\n"
        "let out = null;\n"
        "try {\n"
        "  adm.createRole({role: req.login.user, privileges: privileges, roles: []});\n"
        "  adm.createUser({user: req.login.user, pwd: req.login.password,"
        " roles: [{role: req.login.user, db: 'admin'}], mechanisms: ['SCRAM-SHA-256']});\n"
        "  const conn = new Mongo('mongodb://' + encodeURIComponent(req.login.user) + ':'"
        " + encodeURIComponent(req.login.password) + '@127.0.0.1:27017/' + req.database"
        " + '?authSource=admin&authMechanism=SCRAM-SHA-256');\n"
        "  const ldb = conn.getDB(req.database);\n"
        "  const found = ldb.getCollection('users').find({openidId: req.sub},"
        " {_id: 1, email: 1}).limit(req.max_accounts + 1).toArray();\n"
        "  if (found.length > req.max_accounts) throw new Error('too many accounts');\n"
        "  const ids = found.map(a => a._id);\n"
        "  const hex = ids.map(i => i.toHexString());\n"
        "  const known = req.accounts.map(h => ObjectId(h));\n"
        "  // LibreChat files some objects under the id as a string, others as an object id.\n"
        "  const refs = ids.concat(known, hex, req.accounts);\n"
        "  const mails = [...new Set(found.map(a => a.email)"
        ".filter(m => typeof m === 'string' && m.length > 0))];\n"
        "  const by = (f) => ({[f]: {$in: refs}});\n"
        "  if (req.operation === 'export') {\n"
        "    const data = {accounts: ldb.getCollection('users').find({_id: {$in: ids}},"
        " req.account_fields).toArray()};\n"
        "    for (const [c, f] of req.export) data[c] = ldb.getCollection(c).find(by(f))"
        ".toArray();\n"
        "    out = {accounts: hex, mails: mails, data: data};\n"
        "  } else if (req.operation === 'erase') {\n"
        "    const counts = {};\n"
        "    for (const [c, f] of req.objects) counts['chat_' + c] = ldb.getCollection(c)"
        ".deleteMany(by(f)).deletedCount;\n"
        "    counts.chat_accounts = ldb.getCollection('users').deleteMany({_id: {$in: ids}})"
        ".deletedCount;\n"
        "    out = {accounts: hex, mails: mails, counts: counts};\n"
        "  } else {\n"
        "    const counts = {};\n"
        "    for (const [c, f] of req.objects) counts['chat_' + c] = ldb.getCollection(c)"
        ".countDocuments(by(f));\n"
        "    counts.chat_accounts = ldb.getCollection('users').countDocuments({$or: ["
        "{openidId: req.sub}, {_id: {$in: ids.concat(known)}}, {email: {$in: req.mails}}]});\n"
        "    out = {counts: counts};\n"
        "  }\n"
        "  conn.close();\n"
        "} finally {\n"
        "  try { adm.dropUser(req.login.user); } catch (e) { print('drop login failed'); }\n"
        "  try { adm.dropRole(req.login.user); } catch (e) { print('drop role failed'); }\n"
        "}\n"
        f"print('{CHAT_MARKER}' + EJSON.stringify(out, {{relaxed: true}}));\n"
    )


def _run(argv: list[str], stdin: str | None, timeout: int):
    """`docker` with literal programs and the containers of this installation, the data
    on stdin, no shell (librechat_history.run_with_input)."""
    from . import librechat_history

    return librechat_history.run_with_input(argv, stdin, float(timeout))


class DockerCore:
    """The three paths on this host, each through `docker exec` of its own container."""

    def __init__(self, config_dir: Path, repo_root: Path, *, runner: Runner | None = None):
        self.config_dir, self.repo_root = Path(config_dir), Path(repo_root)
        self.runner = runner or _run

    def call(self, service: str, operation: str, request: dict) -> dict:
        if operation not in OPERATIONS.get(service, ()):
            raise CoreError("unknown_operation")
        if service == CHAT:
            doc = self._chat(operation, request)
        elif service == GATEWAY:
            doc = self._gateway(operation, request)
        else:
            doc = self._identity(operation, request)
        return check_answer(service, operation, doc)

    def _container(self, service: str) -> str:
        project = status.compose_project(self.config_dir)
        done = self.runner(
            ["docker", "ps", "-q",
             "--filter", f"label=com.docker.compose.project={project}",
             "--filter", f"label=com.docker.compose.service={service}",
             "--filter", "status=running"],
            None, DOCKER_TIMEOUT_SECONDS,
        )  # fmt: skip
        ids = (done.stdout or "").split() if done.returncode == 0 else []
        if len(ids) != 1:
            raise CoreError("not_running")
        return ids[0]

    def _chat(self, operation: str, request: dict) -> dict:
        container = self._container(CHAT_SERVICE)
        user = f"papaia-person-{secrets.token_hex(8)}"
        script = chat_script(operation, request, user, secrets.token_urlsafe(32))
        done = self.runner(
            ["docker", "exec", "-i", container, "mongosh", "--quiet", "--norc",
             "mongodb://127.0.0.1:27017/admin"],
            script, EXEC_TIMEOUT_SECONDS,
        )  # fmt: skip
        # mongosh echoes the piped script, which holds the password: only the marker
        # line is read, nothing of the output is printed or kept.
        line = next((ln for ln in (done.stdout or "").splitlines()
                     if ln.startswith(CHAT_MARKER)), None)
        if done.returncode != 0 or line is None or len(line) > MAX_ANSWER_BYTES:
            raise CoreError("backend_failed")
        try:
            return json.loads(line[len(CHAT_MARKER):])
        except ValueError:
            raise CoreError("invalid_answer") from None

    def _gateway(self, operation: str, request: dict) -> dict:
        try:
            admin = model_gateway.connect(self.config_dir, runner=self.runner)
            found: list[tuple[str, dict]] = []
            for end_user in request["ids"]:
                status_code, body = admin.call(
                    "GET", "/customer/info?" + urllib.parse.urlencode({"end_user_id": end_user})
                )
                if status_code == 200 and isinstance(body, dict):
                    found.append((end_user, body))
                elif status_code not in (400, 404):
                    raise CoreError("backend_failed")
            if operation == "erase" and found:
                status_code, _ = admin.call(
                    "POST", "/customer/delete", {"user_ids": [u for u, _ in found]}
                )
                if status_code != 200:
                    raise CoreError("backend_failed")
        except model_gateway.ModelGatewayError:
            raise CoreError("backend_failed") from None
        if operation != "export":
            return {"counts": {"gateway_end_users": len(found)}}
        rows = []
        for end_user, body in found:
            spend = body.get("spend", 0)
            if isinstance(spend, bool) or not isinstance(spend, (int, float)):
                raise CoreError("invalid_answer")
            rows.append({"end_user_id": end_user, "spend": spend})
        return {"data": {"end_users": rows}}

    def _identity(self, operation: str, request: dict) -> dict:
        if not _KEYCLOAK_ID_RE.fullmatch(request["sub"]):
            # Not an id of the identity provider: there is no account to look at.
            if operation in ("export", "revoke"):
                empty: dict = {"found": False, "mails": []}
                return empty | ({"data": {"account": None}} if operation == "export"
                                else {"counts": {}})
            return {"counts": {"identity_accounts": 0}}
        container = self._container(LIFECYCLE_SERVICE)
        done = self.runner(
            ["docker", "exec", "-i", container, *LIFECYCLE_COMMAND],
            json.dumps({"operation": operation, "sub": request["sub"]}),
            EXEC_TIMEOUT_SECONDS,
        )
        lines = (done.stdout or "").strip().splitlines()
        if done.returncode != 0 or not lines:
            raise CoreError("backend_failed")
        try:
            return json.loads(lines[-1])
        except ValueError:
            raise CoreError("invalid_answer") from None
