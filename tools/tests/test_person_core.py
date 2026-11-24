"""`papaia-ctl person export|erase` for the core services without a module contract
(security 1.14 no. 2, 2a; RE-64, RE-100): the chat by `sub`, the model gateway's usage
rows by `sub`, mail or chat account, the identity provider's account and sessions through
`svc-papaia-lifecycle`. The order of an erasure (sessions ended first, the account deleted
last, `partial` with the account kept disabled when a step fails), the journal entries
`core-chat` and `model-gateway`, and the reconciliation after it (GV-30 for the core
services, by `sub`, chat account and mail).

The three backends are simulated by FakeCore, which answers as the real paths do; the
real paths are tested against their command lines (the chat database, the gateway's
management API) and against an in-memory Keycloak (papaia-lifecycle's `person`)."""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from lib import doctor, lifecycle_account, model_gateway, person, person_core
from lib import person_request as pr
from lib import realm_sync as rs
from tests import test_person as tp
from tests.test_audit_read import signer as signer  # noqa: F401 - the shared fixture
from tests.test_lifecycle import FakeKeycloak, lc
from tests.test_person import ANNA, BEN, REPO, SUBMISSION, Modules, _gate, _open_archive

MAIL = "anna.berger@example.org"
CHAT_ID = "65a1b2c3d4e5f60718293a4b"
CONTENT = "Gehaltsverhandlung am Freitag, vertraulich"
PROFILES = "librechat,litellm,keycloak,lifecycle,audit"


@pytest.fixture()
def install(tmp_path):
    """The installation of test_person (two modules with the person actions, one without)
    with chat, model gateway and identity provider switched on."""
    return tp.make_install(tmp_path, PROFILES)


@pytest.fixture()
def desk(install, signer):  # noqa: F811
    return tp.make_desk(install, signer)


class FakeCore:
    """Chat database, gateway and identity provider of one installation, answering as the
    core paths do. `fail` makes one (service, operation) fail like an unreachable backend."""

    def __init__(self, *, account: bool = False) -> None:
        self.chat_accounts = {CHAT_ID: {"openidId": ANNA, "email": MAIL}}
        self.chat: dict[str, list[dict]] = {
            "conversations": [
                {"conversationId": f"c{i}", "user": CHAT_ID, "title": f"{CONTENT} {i}"}
                for i in range(3)
            ],
            "messages": [{"messageId": f"m{i}", "user": CHAT_ID, "text": CONTENT}
                         for i in range(5)],
            "presets": [{"presetId": "p1", "user": CHAT_ID}],
        }
        # End users of the gateway with their spend: the sub, the chat account, the mail.
        self.usage = {ANNA: 0.25, CHAT_ID: 1.5, MAIL: 0.125, "someone-else": 9.0}
        self.accounts = {ANNA: {"email": MAIL, "enabled": True}} if account else {}
        self.fail: set[tuple[str, str]] = set()
        self.calls: list[tuple[str, str, dict]] = []

    def _mine(self, accounts: list[str]) -> dict[str, list[dict]]:
        return {name: [d for d in docs if d["user"] in accounts]
                for name, docs in self.chat.items()}

    def call(self, service: str, operation: str, request: dict) -> dict:
        self.calls.append((service, operation, dict(request)))
        if (service, operation) in self.fail:
            raise person_core.CoreError("backend_failed")
        if service == person_core.CHAT:
            accounts = sorted(i for i, a in self.chat_accounts.items()
                              if a["openidId"] == request["sub"])
            mails = sorted({self.chat_accounts[i]["email"] for i in accounts})
            if operation == "export":
                return {"accounts": accounts, "mails": mails,
                        "data": {"accounts": [{"email": m} for m in mails],
                                 **self._mine(accounts)}}
            if operation == "erase":
                counts = {}
                for name, docs in self.chat.items():
                    keep = [d for d in docs if d["user"] not in accounts]
                    counts[f"chat_{name}"] = len(docs) - len(keep)
                    self.chat[name] = keep
                for i in accounts:
                    del self.chat_accounts[i]
                counts["chat_accounts"] = len(accounts)
                return {"accounts": accounts, "mails": mails, "counts": counts}
            left = set(request["accounts"]) | set(accounts)
            counts = {f"chat_{n}": len(d) for n, d in self._mine(sorted(left)).items()}
            counts["chat_accounts"] = len(accounts) + sum(
                1 for a in self.chat_accounts.values() if a["email"] in request["mails"])
            return {"counts": counts}
        if service == person_core.GATEWAY:
            found = [i for i in request["ids"] if i in self.usage]
            if operation == "export":
                return {"data": {"end_users": [{"end_user_id": i, "spend": self.usage[i]}
                                               for i in found]}}
            if operation == "erase":
                for i in found:
                    del self.usage[i]
            return {"counts": {"gateway_end_users": len(found)}}
        account = self.accounts.get(request["sub"])
        if operation == "export":
            return {"found": account is not None,
                    "mails": [account["email"]] if account else [],
                    "data": {"account": dict(account) if account else None}}
        if operation == "revoke":
            if account is None:
                return {"found": False, "mails": [], "counts": {}}
            account["enabled"] = False
            return {"found": True, "mails": [account["email"]],
                    "counts": {"accounts_disabled": 1, "sessions_ended": 1}}
        if operation == "delete":
            gone = self.accounts.pop(request["sub"], None)
            return {"counts": {"identity_accounts": 0 if gone is None else 1}}
        return {"counts": {"identity_accounts": int(account is not None)}}


def _run(install, desk, operation: str, core: FakeCore, *, sub: str = ANNA, **kw):
    request = tp._confirmed(install, desk, operation, sub=sub, **kw)
    report = person.run(install["config"], REPO, request=request, gate=_gate(desk),
                        runner=Modules(install), core=core)
    return report, request


def _journal(install, source: str) -> list[dict]:
    path = install["backup"] / "erasure-journal" / f"{source}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


# ─────────────────────────────────────────────────────────────────────────
# the case of the ticket: a person without an account, three chat conversations and
# usage rows at the gateway
# ─────────────────────────────────────────────────────────────────────────


def test_export_of_a_person_without_account_contains_chat_and_gateway_usage(install, desk):
    core = FakeCore()
    report, request = _run(install, desk, "export", core)

    assert report.ok
    rows = {(r.module, r.entry): r for r in report.rows}
    for row in (("core:chat", "librechat"), ("core:model-gateway", "litellm"),
                ("core:identity", "keycloak")):
        assert rows[row].included, row
    # The chat's uploaded file contents and its search index are named, not hidden.
    assert not rows[("core:chat", "librechat-files")].included
    assert rows[("core:chat", "librechat-files")].reason

    archive = _open_archive(report.archive, desk.passphrases[request])
    chat = json.loads(archive.read("core-chat.json"))
    assert len(chat["data"]["conversations"]) == 3
    assert chat["data"]["conversations"][0]["title"].startswith(CONTENT)
    usage = json.loads(archive.read("model-gateway.json"))["data"]["end_users"]
    # Found by the sub, by the chat account and by the mail the chat account carries.
    assert {u["end_user_id"] for u in usage} == {ANNA, CHAT_ID, MAIL}
    assert "someone-else" not in json.dumps(usage)
    identity = json.loads(archive.read("identity.json"))
    assert identity["found"] is False
    index = json.loads(archive.read("index.json"))
    states = {m["module"]: m["status"] for m in index["modules"]}
    assert states["core-chat"] == states["model-gateway"] == states["identity"] == "ok"
    # The gateway was asked with the ids the chat step found.
    asked = next(r for s, o, r in core.calls if s == person_core.GATEWAY)
    assert set(asked["ids"]) == {ANNA, CHAT_ID, MAIL}


def test_erase_removes_chat_and_usage_and_the_reconciliation_finds_nothing(install, desk):
    core = FakeCore()
    report, request = _run(install, desk, "erase", core)

    assert report.state == "done", person.render(report)
    assert core.chat_accounts == {}
    assert all(not docs for docs in core.chat.values())
    assert set(core.usage) == {"someone-else"}
    assert report.findings == []
    assert "reconciliation: nothing of the person left" in person.render(report)
    proof = {(p["module"], p["category"]): p for p in report.proof}
    assert proof[("core-chat", "chat_conversations")]["deleted"] == 3
    assert proof[("core-chat", "chat_messages")]["deleted"] == 5
    assert proof[("model-gateway", "gateway_end_users")]["deleted"] == 3
    # One journal entry per core service, naming the person by HMAC only.
    ref = hmac.new(install["key"], ANNA.encode(), hashlib.sha256).hexdigest()
    for source in ("core-chat", "model-gateway"):
        lines = _journal(install, source)
        assert [(e["kind"], e["subject_ref"]) for e in lines] == [("erase_subject", ref)]
        assert ANNA not in json.dumps(lines)
        assert proof[(source, "chat_conversations" if source == "core-chat"
                      else "gateway_end_users")]["journal"] == "at_target"
    assert pr.get(_gate(desk), request)["state"] == "done"


def test_a_failing_gateway_leaves_the_request_partial(install, desk):
    core = FakeCore()
    core.fail.add((person_core.GATEWAY, "erase"))
    report, request = _run(install, desk, "erase", core)

    assert report.state == "partial"
    assert pr.get(_gate(desk), request)["state"] == "partial"
    assert report.modules["model-gateway"] == "failed"
    # The chat went; the reconciliation names what the gateway still holds.
    assert core.chat_accounts == {}
    assert {f["place"] for f in report.findings} == {"model-gateway/gateway_end_users"}
    assert report.findings[0]["count"] == 3
    assert _journal(install, "model-gateway") == []
    errors = [r for r in tp._rows(install["config"]) if r["catalog_id"] == "core.model-gateway"]
    assert [(r["operation"], r["result"], r["error_code"]) for r in errors][0] == (
        "person.erase", "error", "backend_failed")


# ─────────────────────────────────────────────────────────────────────────
# order: sessions first, the account last, kept disabled when a step fails
# ─────────────────────────────────────────────────────────────────────────


def test_erase_ends_the_sessions_first_and_deletes_the_account_last(install, desk):
    core = FakeCore(account=True)
    report, _ = _run(install, desk, "erase", core)

    assert report.state == "done", person.render(report)
    order = [(s, o) for s, o, _ in core.calls]
    assert order[0] == (person_core.IDENTITY, "revoke")
    erase_at = order.index((person_core.CHAT, "erase"))
    assert order.index((person_core.GATEWAY, "erase")) > erase_at
    delete_at = order.index((person_core.IDENTITY, "delete"))
    assert delete_at > order.index((person_core.GATEWAY, "erase"))
    assert all(o == "check" for _, o in order[delete_at + 1:])
    assert core.accounts == {}


def test_a_failing_step_keeps_the_account_disabled_not_deleted(install, desk):
    core = FakeCore(account=True)
    core.fail.add((person_core.CHAT, "erase"))
    report, _ = _run(install, desk, "erase", core)

    assert report.state == "partial"
    assert core.accounts[ANNA]["enabled"] is False
    assert (person_core.IDENTITY, "delete") not in [(s, o) for s, o, _ in core.calls]
    held = {(p["module"], p["category"]): p["state"] for p in report.proof}
    assert held[("identity", "account")] == "held"
    assert "disabled, not deleted" in person.render(report)
    # The gateway still ran: a failure of one service does not stop the others.
    assert (person_core.GATEWAY, "erase") in [(s, o) for s, o, _ in core.calls]


def test_a_failed_transfer_erases_nothing_in_the_core_either(install, desk):
    core = FakeCore(account=True)
    modules = Modules(install)
    modules.fail.add(("tasks", person.TRANSFER))
    request = tp._confirmed(install, desk, "erase", transfer_to=BEN)
    report = person.run(install["config"], REPO, request=request, gate=_gate(desk),
                        runner=modules, core=core)
    assert report.state == "partial"
    assert [(s, o) for s, o, _ in core.calls] == [(person_core.IDENTITY, "revoke")]
    assert core.accounts[ANNA]["enabled"] is False


# ─────────────────────────────────────────────────────────────────────────
# audit: every call one row with the request id, counts only
# ─────────────────────────────────────────────────────────────────────────


def test_every_core_call_is_one_audit_row_with_counts_and_no_content(install, desk):
    core = FakeCore(account=True)
    _, request = _run(install, desk, "erase", core)

    rows = tp._rows(install["config"])
    assert {r["correlation_id"] for r in rows} == {request}
    for row in rows:
        assert list(SUBMISSION.iter_errors(row)) == [], row
    chat = [r for r in rows if r["catalog_id"] == "core.chat" and r["operation"] == "person.erase"]
    # One row per collection of the chat, with its count.
    by_object = {r["detail"]["objects"][0]: r["detail"]["count"] for r in chat}
    assert by_object["chat_conversations"] == 3 and by_object["chat_messages"] == 5
    identity = [r["operation"] for r in rows if r["catalog_id"] == "core.identity"]
    assert identity[0] == "person.identity_revoke" and "person.identity_delete" in identity
    assert any(r["operation"] == "person.reconcile" for r in rows)
    text = rs.audit_path(install["config"]).read_text(encoding="utf-8")
    assert CONTENT not in text and MAIL not in text


def test_a_core_answer_outside_its_shape_is_a_failed_service(install, desk):
    class Odd(FakeCore):
        def call(self, service, operation, request):
            answer = super().call(service, operation, request)
            if service == person_core.CHAT and operation == "erase":
                answer["counts"]["chat_messages"] = -1
            return answer

    report, _ = _run(install, desk, "erase", Odd())
    assert report.state == "partial"
    assert report.modules["core-chat"] == "failed"
    assert _journal(install, "core-chat") == []


def test_without_the_lifecycle_profile_the_identity_provider_is_named_not_included(
    install, desk
):
    env = install["config"] / ".env"
    env.write_text(env.read_text().replace(PROFILES, "librechat,litellm,keycloak,audit"))
    core = FakeCore()
    report, _ = _run(install, desk, "export", core)
    rows = {(r.module, r.entry): r for r in report.rows}
    assert not rows[("core:identity", "keycloak")].included
    assert "lifecycle" in rows[("core:identity", "keycloak")].reason
    assert person_core.IDENTITY not in {s for s, _, _ in core.calls}


# ─────────────────────────────────────────────────────────────────────────
# the real paths: chat database, gateway management API, papaia-lifecycle
# ─────────────────────────────────────────────────────────────────────────


class Docker:
    """`docker` as the core paths call it: one container per service, the answer of
    `exec` from `answers` by program."""

    def __init__(self, answers: dict[str, str], code: int = 0) -> None:
        self.answers, self.code = answers, code
        self.calls: list[tuple[list[str], str | None]] = []

    def __call__(self, argv, stdin, timeout):
        self.calls.append((list(argv), stdin))
        if argv[1] == "ps":
            service = next(a.split("=", 1)[1] for a in argv if "compose.service=" in a)
            return subprocess.CompletedProcess(argv, 0, f"itk-{service}-1\n", "")
        program = next(p for p in self.answers if p in argv)
        return subprocess.CompletedProcess(argv, self.code, self.answers[program], "")


def _chat_answer(doc: dict) -> str:
    # mongosh echoes the piped script before the result line.
    return "> const req = …\n" + person_core.CHAT_MARKER + json.dumps(doc) + "\n"


def test_the_chat_path_uses_a_login_of_this_run_only_and_drops_it(install):
    docker = Docker({"mongosh": _chat_answer(
        {"accounts": [CHAT_ID], "mails": [MAIL], "counts": {"chat_messages": 5}})})
    core = person_core.DockerCore(install["config"], REPO, runner=docker)

    answer = core.call(person_core.CHAT, "erase", {"sub": ANNA, "mails": [], "accounts": []})

    assert answer["counts"] == {"chat_messages": 5}
    argv, script = docker.calls[-1]
    assert argv[:3] == ["docker", "exec", "-i"] and "mongosh" in argv
    assert not any(ANNA in a for a in argv)
    request = json.loads(script.splitlines()[0].removeprefix("const req = ").rstrip(";"))
    assert request["operation"] == "erase" and request["sub"] == ANNA
    login = request["login"]
    assert login["user"].startswith("papaia-person-") and len(login["password"]) >= 32
    # The login exists only while the script runs: created, then dropped in `finally`.
    assert "createUser" in script and "dropUser" in script and "dropRole" in script
    assert script.index("finally") < script.index("dropUser")
    # Removal is granted only for an erasure; an export may only read.
    assert request["actions"] == ["find", "remove"]
    docker.answers["mongosh"] = _chat_answer({"accounts": [], "mails": [], "data": {}})
    core.call(person_core.CHAT, "export", {"sub": ANNA, "mails": [], "accounts": []})
    exported = json.loads(docker.calls[-1][1].splitlines()[0].removeprefix(
        "const req = ").rstrip(";"))
    assert exported["actions"] == ["find"]
    assert exported["login"]["password"] != login["password"]


@pytest.mark.parametrize("output", ["", "no marker\n", person_core.CHAT_MARKER + "[]\n",
                                    person_core.CHAT_MARKER + '{"counts": {"x": "1"}}\n'])
def test_a_chat_answer_outside_its_shape_is_refused(install, output):
    core = person_core.DockerCore(install["config"], REPO, runner=Docker({"mongosh": output}))
    with pytest.raises(person_core.CoreError):
        core.call(person_core.CHAT, "erase", {"sub": ANNA, "mails": [], "accounts": []})


def test_the_chat_collections_are_those_of_papaia_replay():
    from tests.test_replay import rp

    assert person_core.CHAT_OBJECTS == tuple(
        (coll, field) for coll, field, _ in rp.CHAT_OBJECTS)


def _litellm(statuses: dict[str, tuple[int, dict | None]]):
    """The management API inside the LiteLLM container: answers by path."""
    seen: list[dict] = []

    def run(argv, stdin, timeout):
        if argv[1] == "ps":
            return subprocess.CompletedProcess(argv, 0, "itk-litellm-1\n", "")
        request = json.loads(stdin)
        seen.append(request)
        status, body = statuses.get(request["path"], (404, None))
        return subprocess.CompletedProcess(
            argv, 0, json.dumps({"status": status, "body": json.dumps(body)}) + "\n", "")

    return run, seen


def test_the_gateway_path_reads_only_usage_sums_and_deletes_found_end_users(install):
    info = f"/customer/info?end_user_id={ANNA}"
    runner, seen = _litellm({
        info: (200, {"user_id": ANNA, "spend": 0.25, "metadata": {"prompt": CONTENT}}),
        "/customer/delete": (200, {}),
    })
    core = person_core.DockerCore(install["config"], REPO, runner=runner)

    exported = core.call(person_core.GATEWAY, "export", {"ids": [ANNA, MAIL]})
    assert exported == {"data": {"end_users": [{"end_user_id": ANNA, "spend": 0.25}]}}
    erased = core.call(person_core.GATEWAY, "erase", {"ids": [ANNA, MAIL]})
    assert erased == {"counts": {"gateway_end_users": 1}}
    assert seen[-1] == {"method": "POST", "path": "/customer/delete",
                        "body": {"user_ids": [ANNA]}}
    assert {r["path"].split("?")[0] for r in seen} == {"/customer/info", "/customer/delete"}


def test_a_gateway_error_is_a_failed_step(install):
    runner, _ = _litellm({f"/customer/info?end_user_id={ANNA}": (500, None)})
    core = person_core.DockerCore(install["config"], REPO, runner=runner)
    with pytest.raises(person_core.CoreError):
        core.call(person_core.GATEWAY, "erase", {"ids": [ANNA]})


def test_only_the_usage_routes_are_added_to_the_gateway_management_calls():
    allowed = set(model_gateway._ADMIN_PATHS)
    assert ("GET", "/customer/info?") in allowed and ("POST", "/customer/delete") in allowed
    admin = model_gateway.Admin("c", lambda *a: None)
    with pytest.raises(model_gateway.ModelGatewayError):
        admin.call("GET", "/spend/logs")


def test_the_identity_path_asks_papaia_lifecycle_and_never_a_malformed_id(install):
    answer = json.dumps({"found": True, "mails": [MAIL], "counts": {"sessions_ended": 1}})
    docker = Docker({"python3": answer + "\n"})
    core = person_core.DockerCore(install["config"], REPO, runner=docker)
    assert core.call(person_core.IDENTITY, "revoke", {"sub": ANNA})["mails"] == [MAIL]
    argv, stdin = docker.calls[-1]
    assert "/opt/papaia-lifecycle/lifecycle.py" in argv and "person" in argv
    assert json.loads(stdin) == {"operation": "revoke", "sub": ANNA}
    # A sub the identity provider cannot have names no account there; nothing is asked.
    calls = len(docker.calls)
    assert core.call(person_core.IDENTITY, "revoke", {"sub": "anna@legacy"}) == {
        "found": False, "mails": [], "counts": {}}
    assert len(docker.calls) == calls


# ─────────────────────────────────────────────────────────────────────────
# papaia-lifecycle `person`: svc-papaia-lifecycle exports, revokes, deletes
# ─────────────────────────────────────────────────────────────────────────


class Keycloak(FakeKeycloak):
    def __init__(self) -> None:
        super().__init__()
        self.user_events.append({"time": 1, "type": "LOGIN", "clientId": "librechat",
                                 "userId": ANNA, "ipAddress": "192.0.2.7",
                                 "details": {"code_id": "x"}})

    def call(self, method, path, body=None):
        base = path.partition("?")[0].strip("/").split("/")
        if base[0] == "users" and len(base) == 2 and method == "DELETE":
            self.calls.append((method, path))
            if base[1] not in self.users:
                raise lc.HttpError(404)
            del self.users[base[1]]
            return None
        if base[0] == "users" and len(base) >= 3 and base[2] in (
            "groups", "role-mappings", "federated-identity"
        ):
            self.calls.append((method, path))
            if base[1] not in self.users:
                raise lc.HttpError(404)
            return [{"name": "papaia-user", "path": "/papaia-persons", "id": "r1",
                     "identityProvider": "upstream", "userId": "u", "userName": "anna"}]
        if base == ["events"]:
            self.calls.append((method, path))
            return [e for e in self.user_events if f"user={e['userId']}" in path]
        return super().call(method, path, body)


def test_lifecycle_person_exports_the_account_without_secrets():
    kc = Keycloak()
    kc.add_user(ANNA, consents=("librechat",))
    kc.users[ANNA].update(email=MAIL, firstName="Anna", credentials=[{"value": "x"}])

    answer = lc.person_request(kc, {"operation": "export", "sub": ANNA})

    assert answer["found"] is True and answer["mails"] == [MAIL]
    data = answer["data"]
    assert data["account"]["email"] == MAIL and "credentials" not in data["account"]
    assert data["consents"] == [{"clientId": "librechat", "createdDate": 0,
                                 "lastUpdatedDate": 0, "grantedClientScopes": []}]
    assert data["events"] == [{"time": 1, "type": "LOGIN", "clientId": "librechat",
                               "ipAddress": "192.0.2.7"}]
    assert all(m == "GET" for m, _ in kc.calls)


def test_lifecycle_person_revokes_then_deletes():
    kc = Keycloak()
    kc.add_user(ANNA, consents=("flow-engine", "assist-gate"))
    kc.users[ANNA]["email"] = MAIL

    revoked = lc.person_request(kc, {"operation": "revoke", "sub": ANNA})
    assert revoked["counts"] == {"accounts_disabled": 1, "sessions_ended": 1,
                                 "consents_removed": 2}
    assert kc.users[ANNA]["enabled"] is False and kc.consents[ANNA] == []
    assert lc.person_request(kc, {"operation": "check", "sub": ANNA}) == {
        "counts": {"identity_accounts": 1}}
    assert lc.person_request(kc, {"operation": "delete", "sub": ANNA}) == {
        "counts": {"identity_accounts": 1}}
    assert lc.person_request(kc, {"operation": "delete", "sub": ANNA}) == {
        "counts": {"identity_accounts": 0}}
    assert lc.person_request(kc, {"operation": "revoke", "sub": ANNA}) == {
        "found": False, "mails": [], "counts": {}}


@pytest.mark.parametrize("request_doc", [
    {"operation": "drop", "sub": ANNA},
    {"operation": "export", "sub": "../users"},
    {"operation": "export", "sub": ANNA, "extra": 1},
    {"operation": "export"},
    [],
])
def test_lifecycle_person_refuses_anything_else(request_doc):
    kc = Keycloak()
    with pytest.raises(lc.LifecycleError):
        lc.person_request(kc, request_doc)
    assert kc.calls == []


def test_the_purpose_of_svc_papaia_lifecycle_names_information_and_erasure():
    purpose = json.loads(lifecycle_account._ATTRIBUTES["papaia.purpose"])
    assert "Löschung" in purpose["de"] and "erasure" in purpose["en"]
    # No further account and no further right: the same client, the realm role
    # view-events and the two scopes on papaia-persons, no manage-users.
    assert lc.CLIENT_ID == lifecycle_account.CLIENT_ID == "svc-papaia-lifecycle"
    assert lifecycle_account.EVENT_ROLES == ("view-events",)
    assert lifecycle_account.GROUP_SCOPES == ("manage-members", "view-members")


# ─────────────────────────────────────────────────────────────────────────
# doctor model_gateway_content
# ─────────────────────────────────────────────────────────────────────────


def _gateway_install(tmp_path: Path, settings: dict, env: str = "") -> Path:
    config = tmp_path / "config"
    (config / "ai" / "litellm").mkdir(parents=True)
    (config / ".env").write_text("COMPOSE_PROFILES=litellm\n", encoding="utf-8")
    (config / "ai" / "litellm" / "config.yaml").write_text(yaml.safe_dump(settings))
    (config / "ai" / "litellm" / ".env").write_text(env, encoding="utf-8")
    return config


SAFE = {
    "general_settings": {"store_prompts_in_spend_logs": False},
    "litellm_settings": {"turn_off_message_logging": True, "redact_user_api_key_info": True},
}


def test_doctor_passes_a_gateway_that_keeps_no_content(tmp_path):
    assert doctor.check_model_gateway_content_file(_gateway_install(tmp_path, SAFE)).status \
        == doctor.PASS


@pytest.mark.parametrize("settings,env", [
    ({**SAFE, "general_settings": {"store_prompts_in_spend_logs": True}}, ""),
    ({**SAFE, "litellm_settings": {"turn_off_message_logging": False,
                                   "redact_user_api_key_info": True}}, ""),
    ({"general_settings": {}, "litellm_settings": {}}, ""),
    ({**SAFE, "litellm_settings": {**SAFE["litellm_settings"], "success_callback": ["s3"]}}, ""),
    (SAFE, "LITELLM_LOG=DEBUG\n"),
])
def test_doctor_fails_a_gateway_that_keeps_request_content(tmp_path, settings, env):
    result = doctor.check_model_gateway_content_file(_gateway_install(tmp_path, settings, env))
    assert result.status == doctor.FAIL
    assert "content" in result.summary


def test_doctor_skips_the_content_check_without_the_gateway(tmp_path):
    config = _gateway_install(tmp_path, SAFE)
    (config / ".env").write_text("COMPOSE_PROFILES=keycloak\n", encoding="utf-8")
    assert doctor.check_model_gateway_content_file(config).status == doctor.SKIP
    assert "model_gateway_content" in doctor.CHECK_NAMES
