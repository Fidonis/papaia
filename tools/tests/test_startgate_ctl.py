"""papaia-ctl side of the core start gate: the override, `doctor startgate` and the edge.

`papaia-ctl startgate open --unverified` needs two persons with papaia-admin, the
second freshly signed in; one person is enough only with the four-eyes rule off, never
in the profile `kritis` (E-18). The edge gets one managed block in the proxy's
`server_proxy.conf` that asks the check service for every request of every proxy host.
"""

from __future__ import annotations

import json
import subprocess
import types

import pytest

from lib import doctor, npm_provision, paperless_gate, startgate
from lib import realm_sync as rs

REQ = "2a1b0c9d-8e7f-4a6b-9c5d-4e3f2a1b0c9d"
CONF = "8f7e6d5c-4b3a-4291-8f7e-6d5c4b3a2910"
NOW = 1_800_000_000


class Realm:
    """The admin calls the override check makes, with the realm's answers."""

    def __init__(self) -> None:
        self.users = {
            REQ: {"id": REQ, "enabled": True},
            CONF: {"id": CONF, "enabled": True},
        }
        self.roles = {REQ: ["papaia-admin"], CONF: ["papaia-admin", "default-roles-papaia"]}
        self.logins = {REQ: (NOW - 3600) * 1000, CONF: (NOW - 120) * 1000}
        self.calls: list[tuple[str, str]] = []

    def call(self, method: str, path: str, body=None):
        self.calls.append((method, path))
        assert method == "GET", path
        base, _, query = path.partition("?")
        parts = base.strip("/").split("/")
        if parts == ["events"]:
            q = dict(p.split("=", 1) for p in query.split("&"))
            assert q["type"] == "LOGIN"
            when = self.logins.get(q["user"])
            return [] if when is None else [{"time": when, "type": "LOGIN", "userId": q["user"]}]
        uid = parts[1]
        if uid not in self.users:
            raise rs.RealmSyncError("HTTP 404")
        if len(parts) == 2:
            return self.users[uid]
        if parts[2:] == ["role-mappings", "realm", "composite"]:
            return [{"name": n} for n in self.roles[uid]]
        raise AssertionError(path)


class Exec:
    def __init__(self, code: int = 0) -> None:
        self.code = code
        self.args: list[list[str]] = []

    def __call__(self, args: list[str]) -> subprocess.CompletedProcess:
        self.args.append(args)
        return subprocess.CompletedProcess(args, self.code, "override recorded\n", "")


class Audit:
    def __init__(self) -> None:
        self.rows: list[tuple] = []

    def write(self, change, result, error_code=None, **kw) -> None:
        self.rows.append((change.operation, change.event, result, error_code, kw.get("detail")))


def _open(realm, run, audit, *, requested=REQ, confirmed=CONF, four_eyes="on", profile="standard"):
    return startgate.open_unverified(
        realm.call,
        run,
        audit,
        reason="journal disk replaced",
        requested_by=requested,
        confirmed_by=confirmed,
        four_eyes=four_eyes,
        profile=profile,
        now=NOW,
    )


def test_two_admins_with_a_fresh_sign_in_open_the_gate():
    realm, run, audit = Realm(), Exec(), Audit()
    assert _open(realm, run, audit) == 0
    (args,) = run.args
    assert args[:2] == ["startgate-override", "--reason=journal disk replaced"]
    assert f"--requested-by={REQ}" in args and f"--confirmed-by={CONF}" in args
    assert "--single-person" not in args
    assert audit.rows[-1][:3] == ("startgate_override", "operation", "allowed")


@pytest.mark.parametrize(
    ("four_eyes", "profile"), [("on", "standard"), ("on", "kritis"), ("off", "kritis")]
)
def test_one_person_is_refused_with_four_eyes_on_and_in_kritis(four_eyes, profile, capsys):
    realm, run, audit = Realm(), Exec(), Audit()
    code = _open(realm, run, audit, confirmed=REQ, four_eyes=four_eyes, profile=profile)
    assert code == 2
    assert run.args == []
    err = capsys.readouterr().err
    assert "Die Übersteuerung wurde nicht ausgeführt; sie braucht eine zweite Person" in err
    assert "Kennung: CORE-STARTGATE-OVERRIDE-DENIED" in err
    assert audit.rows[-1][:4] == ("startgate_override", "operation", "denied", "four_eyes")


def test_one_person_is_enough_with_four_eyes_off_in_standard():
    realm, run, audit = Realm(), Exec(), Audit()
    realm.logins[REQ] = (NOW - 10) * 1000
    assert _open(realm, run, audit, confirmed=REQ, four_eyes="off", profile="standard") == 0
    assert "--single-person" in run.args[0]


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.roles.__setitem__(CONF, ["default-roles-papaia"]),
        lambda r: r.users[CONF].__setitem__("enabled", False),
        lambda r: r.logins.__setitem__(CONF, (NOW - 301) * 1000),
        lambda r: r.logins.pop(CONF),
        lambda r: r.users.pop(REQ),
    ],
    ids=["no-admin-role", "disabled", "sign-in-too-old", "never-signed-in", "unknown"],
)
def test_the_confirming_person_must_be_an_admin_freshly_signed_in(change, capsys):
    realm, run, audit = Realm(), Exec(), Audit()
    change(realm)
    assert _open(realm, run, audit) == 2
    assert run.args == []
    assert "CORE-STARTGATE-OVERRIDE-DENIED" in capsys.readouterr().err


@pytest.mark.parametrize(
    "kwargs",
    [{"requested": "../x"}, {"confirmed": "a" * 65}, {"four_eyes": "maybe"}, {"profile": "x"}],
)
def test_malformed_input_is_refused_before_any_call(kwargs):
    realm, run, audit = Realm(), Exec(), Audit()
    with pytest.raises(startgate.StartgateError):
        _open(realm, run, audit, **kwargs)
    assert realm.calls == [] and run.args == []


def test_a_reason_is_checked():
    for reason in ("", "x" * 501, "two\nlines"):
        with pytest.raises(startgate.StartgateError):
            startgate.check_reason(reason)


@pytest.mark.parametrize("failing", ["role-mappings", "events"])
def test_a_keycloak_error_after_the_user_lookup_is_a_denied_row(failing, capsys):
    """Every refusal is one audit row, also when Keycloak fails half way."""
    realm, run, audit = Realm(), Exec(), Audit()
    plain = realm.call

    def call(method, path, body=None):
        if failing in path:
            raise rs.RealmSyncError("HTTP 503")
        return plain(method, path, body)

    realm.call = call
    assert _open(realm, run, audit) == 1
    assert run.args == []
    assert audit.rows[-1][:4] == ("startgate_override", "operation", "error", "keycloak_error")
    assert "Keycloak" in capsys.readouterr().err


def _acknowledge(realm, run, audit, *, by=CONF, reason="reviewed with operations"):
    return startgate.acknowledge(realm.call, run, audit, reason=reason, by=by, now=NOW)


def test_an_admin_freshly_signed_in_acknowledges_a_revoked_actor():
    realm, run, audit = Realm(), Exec(), Audit()
    assert _acknowledge(realm, run, audit) == 0
    (args,) = run.args
    assert args == ["startgate-acknowledge", "--reason=reviewed with operations", f"--by={CONF}"]
    assert audit.rows[-1][:3] == ("startgate_override_acknowledged", "operation", "allowed")


def test_an_acknowledgement_needs_a_fresh_admin_and_a_service_that_applies_it(capsys):
    realm, run, audit = Realm(), Exec(), Audit()
    realm.logins[CONF] = (NOW - 301) * 1000
    assert _acknowledge(realm, run, audit) == 2
    assert run.args == []
    assert audit.rows[-1][:4] == (
        "startgate_override_acknowledged", "operation", "denied", "no_fresh_login",
    )  # fmt: skip
    realm, run, audit = Realm(), Exec(code=3), Audit()
    assert _acknowledge(realm, run, audit) == 2
    assert audit.rows[-1][:4] == (
        "startgate_override_acknowledged", "operation", "error", "lifecycle_refused",
    )  # fmt: skip
    with pytest.raises(startgate.StartgateError):
        _acknowledge(realm, run, audit, by="../x")
    with pytest.raises(startgate.StartgateError):
        _acknowledge(realm, run, audit, reason="a\nb")


def test_the_acknowledgement_reaches_papaia_lifecycle_on_stdin():
    request = json.loads(
        startgate._exec_request(["startgate-acknowledge", "--reason=ok; x", f"--by={CONF}"])
    )
    assert request == {"reason": "ok; x", "by": CONF}
    for bad in (
        ["startgate-acknowledge", "--reason=ok", f"--requested-by={CONF}"],
        ["startgate-acknowledge", "--reason=ok"],
        ["startgate-acknowledge", "--reason=ok", f"--by={CONF}", "--single-person"],
    ):
        with pytest.raises(startgate.StartgateError):
            startgate._exec_request(bad)


# ─────────────────────────────────────────────────────────────────────────
# doctor startgate
# ─────────────────────────────────────────────────────────────────────────


def _report(**gate) -> dict:
    base = {
        "status": "open",
        "lease": "open",
        "failed": [],
        "credential_replay": [],
        "role_replay": [],
        "override": None,
        "revoked_actors": [],
        "correlation_id": "0190f0c8-0000-7000-8000-000000000001",
    }
    return {"status": "ok", "startgate": {**base, **gate}}


@pytest.mark.parametrize(
    ("gate", "status", "code"),
    [
        ({}, doctor.PASS, None),
        ({"status": "behind", "lease": "closed"}, doctor.FAIL, "CORE-STARTGATE-BEHIND"),
        ({"status": "unverified", "lease": "closed"}, doctor.FAIL, "CORE-STARTGATE-UNVERIFIED"),
        (
            {"status": "replay_failed", "lease": "closed", "failed": ["core-chat"]},
            doctor.FAIL,
            "CORE-STARTGATE-REPLAY-FAILED",
        ),
        (
            {
                "status": "override",
                "override": {"requested_by": REQ, "confirmed_by": CONF, "at": NOW},
            },
            doctor.WARN,
            "CORE-STARTGATE-OVERRIDE",
        ),
        ({"credential_replay": [REQ]}, doctor.WARN, "CORE-STARTGATE-CREDENTIAL-REPLAY"),
        ({"revoked_actors": [CONF]}, doctor.FAIL, "CORE-STARTGATE-OVERRIDE-REVOKED-ACTOR"),
    ],
)
def test_doctor_startgate_maps_the_gate_to_pattern_8_messages(gate, status, code):
    result, message = startgate.doctor_result(_report(**gate)["startgate"])
    assert result == status
    if code:
        assert f"Kennung: {code} " in message
    if gate.get("credential_replay"):
        assert REQ in message
    if gate.get("failed"):
        assert "Das Nachspielen ist für core-chat fehlgeschlagen" in message


def test_doctor_startgate_is_registered_and_skips_without_the_profile(tmp_path):
    assert "startgate" in doctor.CHECK_NAMES
    ctx = types.SimpleNamespace(configured=True, active_profiles=set())
    assert doctor.check_startgate(ctx).status == doctor.SKIP


def test_doctor_startgate_fails_on_an_unreadable_report():
    with pytest.raises(ValueError):
        startgate.doctor_result({"status": "open"})
    with pytest.raises(ValueError):
        startgate.doctor_result({**_report()["startgate"], "status": "nope"})


# ─────────────────────────────────────────────────────────────────────────
# the edge
# ─────────────────────────────────────────────────────────────────────────


def test_the_edge_block_asks_the_check_service_for_every_request():
    block = startgate.edge_block(
        {
            "auth.example.org": "identity",
            "npm.example.org": "admin",
            "flow.example.org": "papaia-flow",
        },
        contact="IT-Service",
    )
    assert "auth_request /.papaia-startgate;" in block
    assert "error_page 401 500 502 503 504 = @papaia_startgate;" in block
    assert 'set $papaia_gate_service "core";' in block
    assert 'if ($host = "auth.example.org") { set $papaia_gate_service "identity"; }' in block
    assert 'if ($host = "npm.example.org") { set $papaia_gate_service "admin"; }' in block
    assert "proxy_set_header X-Papaia-Gate-Service $papaia_gate_service;" in block
    assert 'proxy_set_header X-Papaia-Gate-Contact "IT-Service";' in block
    assert "papaia-startgate-check:8080" in block
    assert "internal;" in block
    # The check service sees the original request URI: the administrators' sign-in at the
    # identity provider passes a closed gate (sicherheit §4.9 (2a): the administration
    # path stays open).
    assert "    proxy_set_header X-Papaia-Gate-Uri $request_uri;" in block


@pytest.mark.parametrize(
    "hosts",
    [{"a b.example.org": "core"}, {'x".example.org': "core"}, {"ok.example.org": "Bad$"}],
)
def test_the_edge_block_refuses_unsafe_names(hosts):
    with pytest.raises(startgate.StartgateError):
        startgate.edge_block(hosts, contact=None)


def test_the_contact_is_quoted_for_a_header():
    block = startgate.edge_block({}, contact='IT "Service" $x; Tel. 0991/1234')
    line = next(x for x in block.splitlines() if "X-Papaia-Gate-Contact" in x)
    assert "$x" not in line and '"Service"' not in line and ";" not in line.split('"')[1]


def test_the_managed_blocks_of_server_proxy_conf_keep_the_operators_lines():
    gate = startgate.edge_block({}, contact=None)
    merged = paperless_gate.merge_strip("# own line\n", extra=gate)
    assert merged.startswith(paperless_gate.strip_config())
    assert gate in merged and merged.endswith("# own line\n")
    # Again: the same file; without the gate block it goes.
    assert paperless_gate.merge_strip(merged, extra=gate) == merged
    assert gate not in paperless_gate.merge_strip(merged)
    assert paperless_gate.merge_strip(merged).endswith("# own line\n")


def test_npm_provision_maps_the_core_hosts_to_gate_keys():
    tree = {
        "": {
            "AUTH_HOST": "https://auth.example.org",
            "LITELLM_PUBLIC_URL": "https://litellm.example.org",
            "NPM_ADMIN_HOST": "https://npm.example.org",
            "MANAGER_PUBLIC_URL": "https://manager.example.org",
            "COMPOSE_PROFILES": "keycloak,litellm,librechat,nginx,manager,lifecycle",
        },
        "ai/librechat": {"DOMAIN_SERVER": "https://chat.example.org"},
    }
    keys = npm_provision.gate_host_keys(tree, [])
    assert keys == {
        "auth.example.org": "identity",
        "chat.example.org": "core-chat",
        "litellm.example.org": "model-gateway",
        "npm.example.org": "admin",
        "manager.example.org": "core",
    }


def test_the_request_reaches_papaia_lifecycle_on_stdin_not_the_command_line():
    args = ["startgate-override", "--reason=disk; rm -rf /", f"--requested-by={REQ}"]
    request = json.loads(startgate._exec_request([*args, f"--confirmed-by={CONF}"]))
    assert request == {
        "reason": "disk; rm -rf /",
        "requested_by": REQ,
        "confirmed_by": CONF,
        "single_person": False,
    }
    for bad in ([*args, "--confirmed-by=../x"], [*args, "--other=1"], ["sh", "-c"]):
        with pytest.raises(startgate.StartgateError):
            startgate._exec_request(bad)
