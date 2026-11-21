"""papaia-ctl realm sync: public keys of module clients (`client_keys[]`).

A module declares, for clients it owns, a file in its add-on configuration folder that
holds the public JWK set of the client; the module writes the file, the realm sync
registers it with `private_key_jwt`. No module needs a realm admin token for that.

- `flow-engine` and `flow-console` authenticate with `client-jwt` and exactly the keys of
  their files; a second run reports no change;
- a declaration for a client of another owner, an unmanaged client or a client without
  credentials is refused before any write; so is a key set with private members, more
  than two keys, a symmetric key, a weak RSA key or a point not on P-256;
- a changed file is applied by the next sync or `realm keys apply <module>`, one audit
  row each; `--check` reports a missing file, a changed key and `client-secret` as fail;
- no file under the configuration directory holds a realm admin token afterwards.

The same flows run against a real Keycloak in tests/test_realm_sync_client_keys_live.py.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import subprocess

import pytest
import yaml

from lib import client_keys as ck
from lib import realm_sync as rs
from lib import service_account_keys as sak
from tests.realm_fake import FakeRealm
from tests.test_ctl_standalone_commands import BASH, CTL, _call, _seeded, needs_bash
from tests.test_realm_sync import DELEGATION, REGISTER, _flow, _run, _tree

ENGINE, CONSOLE = "flow-engine", "flow-console"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def ec_jwk() -> dict:
    """The public JWK of a fresh P-256 key; the private key is not kept."""
    pem = sak._openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"], b"")
    return sak.public_jwk(pem)


def rsa_jwk(bits: int) -> dict:
    """An RSA public key of `bits` bits (the modulus need not factor for these checks)."""
    n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
    return {
        "kty": "RSA",
        "kid": f"rsa-{bits}",
        "use": "sig",
        "alg": "PS256",
        "n": _b64(n.to_bytes(bits // 8, "big")),
        "e": "AQAB",
    }


def _write(folder, keys: list[dict], name: str = "engine.jwks.json") -> None:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text(json.dumps({"keys": keys}))
    path.chmod(0o644)


def _module(folder, declarations=None, **extra) -> rs.Module:
    module = _flow(delegation=DELEGATION, **extra)
    module.client_keys = (
        [
            {"client": ENGINE, "jwks_file": "engine.jwks.json"},
            {"client": CONSOLE, "jwks_file": "console.jwks.json"},
        ]
        if declarations is None
        else declarations
    )
    module.folder = folder
    return module


def _plan(*modules: rs.Module) -> rs.Plan:
    return rs.build_plan(REGISTER, list(modules), [])


@pytest.fixture
def keyed(tmp_path):
    """Flow's add-on folder with one key file per declared client."""
    folder = tmp_path / "addons" / "papaia-flow"
    engine, console = ec_jwk(), ec_jwk()
    _write(folder, [engine])
    _write(folder, [console], "console.jwks.json")
    return folder, engine, console


def _registered(realm: FakeRealm, client_id: str) -> list[dict]:
    return json.loads(realm.by_client_id(client_id)["attributes"]["jwks.string"])["keys"]


def _rows(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


# ─────────────────────────────────────────────────────────────────────────
# registration
# ─────────────────────────────────────────────────────────────────────────


def test_declared_clients_authenticate_with_the_keys_of_their_files(keyed, tmp_path):
    folder, engine, console = keyed
    realm = FakeRealm()
    plan = _plan(_module(folder))
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-1") as audit:
        _run(realm, plan, audit=audit)
    for client_id, jwk in ((ENGINE, engine), (CONSOLE, console)):
        client = realm.by_client_id(client_id)
        assert client["clientAuthenticatorType"] == "client-jwt"
        assert client["attributes"]["use.jwks.string"] == "true"
        assert client["attributes"]["use.jwks.url"] == "false"
        assert _registered(realm, client_id) == [jwk]
    rows = [r for r in _rows(tmp_path / "audit.jsonl") if r["operation"].endswith("client_key")]
    assert {(r["object_ref"]["id"], r["operation"]) for r in rows} == {
        (ENGINE, "realm_sync.set_client_key"),
        (CONSOLE, "realm_sync.set_client_key"),
    }
    assert all(r["result"] == "allowed" and r["effect"] == "write" for r in rows)
    assert _run(realm, plan) == []
    assert _run(realm, plan, apply=False) == []


def test_an_undeclared_holder_keeps_the_authenticator_keycloak_gives_it(keyed):
    folder, _, _ = keyed
    realm = FakeRealm()
    _run(realm, _plan(_module(folder, [{"client": CONSOLE, "jwks_file": "console.jwks.json"}])))
    assert "clientAuthenticatorType" not in realm.by_client_id(ENGINE)
    assert "jwks.string" not in realm.by_client_id(ENGINE)["attributes"]


def test_the_private_key_never_reaches_the_realm(keyed):
    folder, _, _ = keyed
    realm = FakeRealm()
    _run(realm, _plan(_module(folder)))
    for client_id in (ENGINE, CONSOLE):
        for key in _registered(realm, client_id):
            assert set(key) <= {"kty", "crv", "x", "y", "kid", "use", "alg"}


# ─────────────────────────────────────────────────────────────────────────
# refused declarations: nothing is written
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("declarations", "message"),
    [
        ([{"client": "assist-gate", "jwks_file": "a.json"}], "belongs to papaia-assist"),
        ([{"client": "papaia-data-ui", "jwks_file": "a.json"}], "belongs to papaia-data"),
        ([{"client": "svc-flow-events", "jwks_file": "a.json"}], "not a registered client"),
        ([{"client": "papaia-kit-testclient", "jwks_file": "a.json"}], "not a registered client"),
        ([{"client": "flow-cli", "jwks_file": "a.json"}], "public client"),
        ([{"client": "flow", "jwks_file": "a.json"}], "bearer-only"),
        (
            [
                {"client": ENGINE, "jwks_file": "a.json"},
                {"client": ENGINE, "jwks_file": "b.json"},
            ],
            "declared twice",
        ),
        ([{"client": ENGINE, "jwks_file": "../flow/a.json"}], "jwks_file"),
        ([{"client": ENGINE, "jwks_file": "/etc/a.json"}], "jwks_file"),
        ([{"client": ENGINE, "jwks_file": "keys/.hidden.json"}], "jwks_file"),
        ([{"client": ENGINE, "jwks_file": "a.json", "kid": "x"}], "unknown field kid"),
        ([{"client": ENGINE}], "missing field jwks_file"),
        ({"client": ENGINE}, "must be a list"),
        ([ENGINE], "must be a mapping"),
    ],
)
def test_a_declaration_outside_the_own_clients_is_refused(tmp_path, declarations, message):
    with pytest.raises(rs.RealmSyncError, match=message):
        _plan(_module(tmp_path, declarations))


def _refused_file(tmp_path, keys, message, document=None):
    folder = tmp_path / "addons" / "papaia-flow"
    folder.mkdir(parents=True)
    path = folder / "engine.jwks.json"
    path.write_text(json.dumps(document if document is not None else {"keys": keys}))
    path.chmod(0o644)
    declarations = [{"client": ENGINE, "jwks_file": "engine.jwks.json"}]
    with pytest.raises(rs.RealmSyncError, match=message):
        _plan(_module(folder, declarations))


def test_a_key_set_with_a_private_member_is_refused(tmp_path):
    jwk = dict(ec_jwk(), d=_b64(os.urandom(32)))
    _refused_file(tmp_path, [jwk], "private key member d")


@pytest.mark.parametrize("member", ["p", "q", "dp", "dq", "qi", "oth"])
def test_every_private_rsa_member_is_refused(tmp_path, member):
    _refused_file(
        tmp_path, [dict(rsa_jwk(3072), **{member: "AQAB"})], f"private key member {member}"
    )


def test_three_keys_are_refused(tmp_path):
    _refused_file(tmp_path, [ec_jwk(), ec_jwk(), ec_jwk()], "at most 2 keys")


def test_a_symmetric_hs256_key_is_refused(tmp_path):
    hs = {"kty": "oct", "kid": "h", "use": "sig", "alg": "HS256", "k": _b64(os.urandom(32))}
    _refused_file(tmp_path, [hs], "private key member k")
    _refused_file(tmp_path / "2", [dict(ec_jwk(), alg="HS256")], "alg HS256")


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"use": "enc"}, "use must be sig"),
        ({"crv": "P-384"}, "EC keys must use P-256"),
        ({"kty": "OKP"}, "kty must be EC or RSA"),
        ({"x5c": ["MII"]}, "unknown member x5c"),
        ({"kid": ""}, "kid"),
        ({"x": "not base64!"}, "x is not base64url"),
    ],
)
def test_a_key_outside_the_profile_is_refused(tmp_path, change, message):
    _refused_file(tmp_path, [dict(ec_jwk(), **change)], message)


def test_a_point_that_is_not_on_p256_is_refused(tmp_path):
    jwk = ec_jwk()
    y = int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + "=="), "big")
    jwk["y"] = _b64(((y + 1) % (1 << 256)).to_bytes(32, "big"))
    _refused_file(tmp_path, [jwk], "not a point on P-256")


def test_rsa_below_3072_bits_is_refused_and_3072_bits_pass(tmp_path):
    _refused_file(tmp_path, [rsa_jwk(2048)], "at least 3072 bits")
    folder = tmp_path / "ok"
    _write(folder, [rsa_jwk(3072)])
    plan = _plan(_module(folder, [{"client": ENGINE, "jwks_file": "engine.jwks.json"}]))
    assert plan.clients[ENGINE].jwks[0]["kty"] == "RSA"


def test_duplicate_key_ids_and_extra_fields_are_refused(tmp_path):
    jwk = ec_jwk()
    _refused_file(tmp_path, [jwk, dict(jwk)], "kid .* twice")
    _refused_file(tmp_path / "2", None, "unknown field note", {"keys": [ec_jwk()], "note": "x"})
    _refused_file(tmp_path / "3", [], "at least one key")


def test_an_unsafe_key_file_is_refused(tmp_path):
    folder = tmp_path / "addons" / "papaia-flow"
    _write(folder, [ec_jwk()], "real.json")
    (folder / "engine.jwks.json").symlink_to(folder / "real.json")
    declarations = [{"client": ENGINE, "jwks_file": "engine.jwks.json"}]
    with pytest.raises(rs.RealmSyncError, match="cannot be opened safely"):
        _plan(_module(folder, declarations))
    (folder / "engine.jwks.json").unlink()
    _write(folder, [ec_jwk()])
    (folder / "engine.jwks.json").chmod(0o666)
    with pytest.raises(rs.RealmSyncError, match="writable by group or others"):
        _plan(_module(folder, declarations))
    (folder / "engine.jwks.json").chmod(0o644)
    folder.chmod(0o777)
    try:
        with pytest.raises(rs.RealmSyncError, match="writable by group or others"):
            _plan(_module(folder, declarations))
    finally:
        folder.chmod(0o755)
    (folder / "engine.jwks.json").write_text("{not json")
    with pytest.raises(rs.RealmSyncError, match="not a JWK set"):
        _plan(_module(folder, declarations))


def test_a_refused_key_file_changes_nothing(keyed):
    folder, _, _ = keyed
    realm = FakeRealm()
    _run(realm, _plan(_module(folder)))
    writes = len(realm.writes)
    _write(folder, [dict(ec_jwk(), d="AAAA")])
    with pytest.raises(rs.RealmSyncError):
        _plan(_module(folder))
    assert len(realm.writes) == writes


# ─────────────────────────────────────────────────────────────────────────
# rotation and --check
# ─────────────────────────────────────────────────────────────────────────


def test_a_changed_file_is_applied_on_the_next_sync_with_an_audit_row(keyed, tmp_path):
    folder, engine, _ = keyed
    realm = FakeRealm()
    _run(realm, _plan(_module(folder)))
    new = ec_jwk()
    _write(folder, [new])
    drift = _run(realm, _plan(_module(folder)), apply=False)
    assert [(c.name, c.operation) for c in drift] == [(ENGINE, "rotate_client_key")]
    assert _registered(realm, ENGINE) == [engine]
    with rs.AuditLog(tmp_path / "audit.jsonl", "run-2") as audit:
        _run(realm, _plan(_module(folder)), audit=audit)
    (row,) = _rows(tmp_path / "audit.jsonl")
    assert row["operation"] == "realm_sync.rotate_client_key"
    assert row["object_ref"] == {"type": "client", "id": ENGINE}
    assert row["event"] == rs.KEY_EVENT
    assert json.dumps(new["x"]) not in json.dumps(row)
    assert _registered(realm, ENGINE) == [new]
    # During a rotation both keys may be listed; the old one goes with the next file.
    _write(folder, [new, engine])
    _run(realm, _plan(_module(folder)))
    assert _registered(realm, ENGINE) == [new, engine]
    _write(folder, [new])
    _run(realm, _plan(_module(folder)))
    assert _registered(realm, ENGINE) == [new]


def test_check_reports_a_missing_key_file_as_fail(keyed, capsys):
    folder, _, _ = keyed
    realm = FakeRealm()
    _run(realm, _plan(_module(folder)))
    (folder / "console.jwks.json").unlink()
    plan = _plan(_module(folder))
    assert any("console.jwks.json" in note for note in plan.notes)
    drift = _run(realm, plan, apply=False)
    out = capsys.readouterr().out
    assert "fail: client flow-console: no key file" in out
    assert {c.name for c in drift} == {CONSOLE}
    # The sync removes the keys Keycloak still holds: none come from a file any more.
    _run(realm, plan)
    # Keycloak drops an attribute set to the empty string.
    assert not realm.by_client_id(CONSOLE)["attributes"].get("jwks.string")
    assert realm.by_client_id(CONSOLE)["clientAuthenticatorType"] == "client-jwt"
    assert _run(realm, plan) == []
    assert [c.name for c in _run(realm, plan, apply=False)] == [CONSOLE]


def test_check_reports_a_manual_key_change_as_fail(keyed, capsys):
    folder, engine, _ = keyed
    realm = FakeRealm()
    plan = _plan(_module(folder))
    _run(realm, plan)
    stranger = ec_jwk()
    realm.by_client_id(ENGINE)["attributes"]["jwks.string"] = json.dumps({"keys": [stranger]})
    drift = _run(realm, plan, apply=False)
    assert [(c.name, c.operation) for c in drift] == [(ENGINE, "rotate_client_key")]
    assert "fail: client flow-engine: registered keys replaced" in capsys.readouterr().out
    _run(realm, plan)
    assert _registered(realm, ENGINE) == [engine]


def test_check_reports_client_secret_authentication_as_fail(keyed, capsys):
    folder, _, _ = keyed
    realm = FakeRealm()
    plan = _plan(_module(folder))
    _run(realm, plan)
    realm.by_client_id(ENGINE)["clientAuthenticatorType"] = "client-secret"
    drift = _run(realm, plan, apply=False)
    assert [c.name for c in drift] == [ENGINE]
    assert "clientAuthenticatorType" in capsys.readouterr().out
    _run(realm, plan)
    assert realm.by_client_id(ENGINE)["clientAuthenticatorType"] == "client-jwt"


# ─────────────────────────────────────────────────────────────────────────
# the commands: realm sync, realm keys apply <module>
# ─────────────────────────────────────────────────────────────────────────


@pytest.fixture
def connected(monkeypatch):
    realm = FakeRealm()

    def sign_in(base_url, ctx, secret):
        client = next((c for c in realm.clients.values() if c["clientId"] == rs.SYNC_CLIENT), None)
        if client is None or client.get("secret") != secret:
            raise rs.urllib.error.HTTPError("u", 401, "unauthorized", {}, None)
        return "sync-token-value"

    monkeypatch.setattr(rs.kcs, "_wait_for_keycloak", lambda *a, **k: None)
    monkeypatch.setattr(rs.kcs, "_get_admin_token", lambda *a: "master-token-value")
    monkeypatch.setattr(rs.kcs, "_admin_connection", lambda *a: ("http://kc.invalid", None))
    monkeypatch.setattr(rs, "_client_credentials", sign_in)
    monkeypatch.setattr(rs.AdminApi, "call", lambda self, *a: realm.call(*a))
    return realm


def _config(tmp_path, client_keys) -> tuple:
    config_dir, repo_root = tmp_path / "config", tmp_path / "repo"
    flow = repo_root / "papaia-flow"
    flow.mkdir(parents=True)
    manifest = {
        "name": "papaia-flow",
        "exposes": [_flow(delegation=DELEGATION).exposes[0]],
        "client_keys": client_keys,
    }
    (flow / "papaia-app.yaml").write_text(yaml.safe_dump(manifest))
    config_dir.mkdir()
    (config_dir / "deployment.yaml").write_text(
        yaml.safe_dump({"addons": [{"name": "papaia-flow", "path": str(flow), "active": True}]})
    )
    return config_dir, repo_root


DECLARED = [
    {"client": ENGINE, "jwks_file": "keys/engine.jwks.json"},
    {"client": CONSOLE, "jwks_file": "keys/console.jwks.json"},
]


def test_sync_registers_the_keys_and_leaves_no_admin_token_on_the_host(tmp_path, connected, capsys):
    config_dir, repo_root = _config(tmp_path, DECLARED)
    keys = config_dir / "addons" / "papaia-flow" / "keys"
    engine = ec_jwk()
    _write(keys, [engine])
    _write(keys, [ec_jwk()], "console.jwks.json")
    assert rs.sync(_tree(), config_dir, repo_root) == 0
    assert connected.by_client_id(ENGINE)["clientAuthenticatorType"] == "client-jwt"
    assert _registered(connected, ENGINE) == [engine]
    assert rs.sync(_tree(), config_dir, repo_root, check=True) == 0
    # FLO-34-A6: no file on the host holds a token of the realm or of the master admin.
    for path in tmp_path.rglob("*"):
        if path.is_file():
            text = path.read_bytes()
            assert b"master-token-value" not in text, path
            assert b"sync-token-value" not in text, path
    capsys.readouterr()


def test_keys_apply_rotates_one_module_without_a_full_sync(tmp_path, connected, capsys):
    config_dir, repo_root = _config(tmp_path, DECLARED)
    keys = config_dir / "addons" / "papaia-flow" / "keys"
    _write(keys, [ec_jwk()])
    _write(keys, [ec_jwk()], "console.jwks.json")
    assert rs.sync(_tree(), config_dir, repo_root) == 0
    new = ec_jwk()
    _write(keys, [new])
    assert rs.sync(_tree(), config_dir, repo_root, check=True) == 1
    rows = len(rs.audit_path(config_dir).read_text().splitlines())
    assert rs.apply_keys(_tree(), config_dir, repo_root, "papaia-flow") == 0
    assert "Client keys of papaia-flow applied: 1 change(s)" in capsys.readouterr().out
    assert _registered(connected, ENGINE) == [new]
    row = json.loads(rs.audit_path(config_dir).read_text().splitlines()[-1])
    assert row["operation"] == "realm_sync.rotate_client_key"
    assert len(rs.audit_path(config_dir).read_text().splitlines()) == rows + 1
    assert rs.sync(_tree(), config_dir, repo_root, check=True) == 0
    assert rs.apply_keys(_tree(), config_dir, repo_root, "papaia-flow") == 0


def test_keys_apply_refuses_a_module_without_declared_keys(tmp_path, connected, capsys):
    config_dir, repo_root = _config(tmp_path, DECLARED)
    assert rs.apply_keys(_tree(), config_dir, repo_root, "papaia-assist") == 2
    assert "declares no client_keys" in capsys.readouterr().err
    assert rs.apply_keys(_tree(), config_dir, repo_root, "../x") == 2


def test_a_refused_key_file_stops_the_sync_before_keycloak_is_contacted(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(rs.kcs, "_wait_for_keycloak", lambda *a, **k: pytest.fail("contacted"))
    config_dir, repo_root = _config(tmp_path, DECLARED)
    _write(config_dir / "addons" / "papaia-flow" / "keys", [ec_jwk(), ec_jwk(), ec_jwk()])
    assert rs.sync(_tree(), config_dir, repo_root) == 2
    assert rs.apply_keys(_tree(), config_dir, repo_root, "papaia-flow") == 2
    assert "at most 2 keys" in capsys.readouterr().err
    assert not rs.audit_path(config_dir).exists()


def test_a_manifest_with_client_keys_but_no_exposes_is_loaded(tmp_path):
    config_dir, repo_root = _config(tmp_path, DECLARED)
    manifest_path = repo_root / "papaia-flow" / "papaia-app.yaml"
    manifest = yaml.safe_load(manifest_path.read_text())
    del manifest["exposes"]
    manifest_path.write_text(yaml.safe_dump(manifest))
    (module,) = rs.load_modules(config_dir, repo_root)
    assert module.exposes == []
    assert module.client_keys == DECLARED
    assert module.folder == config_dir / "addons" / "papaia-flow"


def test_the_jwks_check_is_usable_on_its_own():
    jwk = ec_jwk()
    assert ck.check_jwks({"keys": [jwk]}, "x") == [jwk]


@needs_bash
def test_the_keys_apply_command_hands_the_module_to_py_cli(tmp_path):
    config_dir = _seeded(tmp_path / "c")
    result = _call("cmd_realm_keys", "apply", "papaia-flow", f"--config-dir={config_dir}")
    assert result.returncode == 0, result.stderr
    assert f"py_cli realm-keys-apply --module papaia-flow CONFIG_DIR={config_dir}" in result.stdout


@needs_bash
@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("apply",), "realm keys apply needs a module"),
        (("apply", "Bad/Name"), "not a module name"),
        (("apply", "a", "b"), "Unknown argument for realm keys apply: b"),
        (("list",), "Unknown 'realm keys' subcommand: 'list'. Valid: apply."),
    ],
)
def test_the_keys_command_refuses_bad_input(tmp_path, args, message):
    result = _call("cmd_realm_keys", *args, default=_seeded(tmp_path / "c"))
    assert result.returncode == 2
    assert message in result.stderr


@needs_bash
def test_the_dispatcher_lists_realm_keys_apply_in_help():
    assert BASH is not None
    out = subprocess.run(
        [BASH, str(CTL), "help"], capture_output=True, text=True, timeout=60, check=False
    ).stdout
    assert "papaia-ctl realm keys apply <module> [--config-dir=PATH]" in out
