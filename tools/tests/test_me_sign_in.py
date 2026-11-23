"""Signing in to Mein Bereich: the realm client `papaia-me`, the module list of the area and
the `azp` allow-list of `prefs` (core profile `me`, ADR 0020).

With the profile on, the realm sync plans the sign-in client `papaia-me`, the bearer client
of the audience `papaia-prefs` and the role `prefs-read` from `src/infra/me/exposes.yaml`,
and pairs `papaia-me` with `papaia-audit` (effect x) itself while the `audit` profile is on.
`papaia-ctl` renders `personal-settings/registry.yaml` and `module-ca/` from the
`personal_settings:` declarations of the active add-ons, and the realm sync writes
`security/azp/azp-allowlist.json` from the confirmed pairings of `papaia-prefs` only.
With the profile off, none of it exists.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
import yaml
from papaia_kit.authz import AzpAllowList

from lib import exposes, keycloak_role_sync, me_area, realm_hardening
from lib import realm_sync as rs

REPO = Path(__file__).resolve().parents[2]
ME_DIR = REPO / "src" / "infra" / "me"
ROOT = {"OIDC_ISSUER": "https://auth.papaia.example/realms/papaia"}
CA_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBszCCAVmgAwIBAgIUXRTEST0000000000000000000000000wCgYIKoZIzj0E\n"
    "-----END CERTIFICATE-----\n"
)


def _config(tmp_path: Path, profiles: str) -> Path:
    config_dir = tmp_path / "papaia-config"
    config_dir.mkdir(parents=True, exist_ok=True)
    values = {**ROOT, "COMPOSE_PROFILES": profiles}
    (config_dir / ".env").write_text("".join(f"{k}={v}\n" for k, v in values.items()))
    return config_dir


def _tree(profiles: str, **me: str) -> dict:
    return {"": {**ROOT, "COMPOSE_PROFILES": profiles}, "infra/me": dict(me)}


def _pairings(*rows: tuple) -> list[rs.Pairing]:
    doc = {"format": rs.PAIRINGS_FORMAT, "pairings": []}
    for client, audience, effects, state, *persons in rows:
        row = {"client": client, "audience": audience, "effects": effects, "state": state}
        if persons:
            row["requested_by"], row["confirmed_by"] = persons
        doc["pairings"].append(row)
    return rs.parse_pairings(doc, rs.load_register())


def _plan(config_dir: Path, pairings: list[rs.Pairing], tree: dict) -> rs.Plan:
    from lib import audit_report_account

    return rs.build_plan(
        rs.load_register(),
        rs.load_modules(config_dir, REPO),
        pairings,
        core_audiences=audit_report_account.core_audiences(tree),
        platform_pairings=audit_report_account.platform_pairings(tree)
        + me_area.platform_pairings(tree),
    )


PREFS_RW = ("papaia-me", "papaia-prefs", ["r", "w"], "confirmed", "host:anna", "host:dora")


# ── the declaration and the realm plan ───────────────────────────────────────


def test_the_profile_is_a_core_profile_module_of_the_realm_sync():
    assert rs.CORE_PROFILE_MODULES["me"] == ("papaia-me", "src/infra/me")


def test_the_declaration_is_valid_exposes_and_names_only_registered_names():
    doc = yaml.safe_load((ME_DIR / "exposes.yaml").read_text(encoding="utf-8"))
    assert set(doc) == {"exposes"}
    exposes.check(doc["exposes"], "core:me")
    register = rs.load_register()
    for entry in doc["exposes"]:
        register.check(entry["audience"], "audience", entry["id"])
        assert register.audiences and entry["audience"] == "papaia-prefs"
        for role in entry.get("roles") or []:
            assert register.check(role["name"], "role", entry["id"]) == "prefs-read"
            assert register.roles[role["name"]].owner == "papaia-me"
    assert register.clients["papaia-me"].owner == "papaia-me"
    assert register.clients["papaia-me"].token_exchange


def test_profile_on_plans_the_sign_in_client_the_audience_and_the_role(tmp_path):
    config_dir = _config(tmp_path, "keycloak,audit,me")
    tree = _tree("keycloak,audit,me")
    plan = _plan(config_dir, _pairings(PREFS_RW), tree)

    me = plan.clients["papaia-me"]
    assert (me.kind, me.owner, me.token_exchange) == ("confidential", "papaia-me", True)
    prefs = plan.clients["papaia-prefs"]
    assert (prefs.kind, prefs.owner, prefs.token_exchange) == ("bearer", "papaia-me", False)
    assert plan.roles["prefs-read"] == "papaia-me"
    # The write pairing, confirmed by a second person, and the platform pairing with the
    # audit service: one exchange scope each, never a default scope.
    assert {"aud-papaia-prefs", "aud-papaia-audit"} <= me.optional_scopes
    assert not {s for s in me.default_scopes if rs.is_exchange_scope(s)}
    assert plan.exchange_scopes["aud-papaia-prefs"] == "papaia-prefs"
    representation = me.representation()
    assert representation["fullScopeAllowed"] is False
    assert representation["directAccessGrantsEnabled"] is False
    assert representation["standardFlowEnabled"] is True


def test_profile_off_plans_none_of_it(tmp_path):
    config_dir = _config(tmp_path, "keycloak,audit")
    tree = _tree("keycloak,audit")
    plan = _plan(config_dir, _pairings(PREFS_RW), tree)
    assert "papaia-me" not in plan.clients
    assert "papaia-prefs" not in plan.clients
    assert "prefs-read" not in plan.roles
    assert "aud-papaia-prefs" not in plan.exchange_scopes
    assert any("inactive until both sides are installed" in n for n in plan.notes)


def test_a_waiting_write_pairing_assigns_nothing(tmp_path):
    config_dir = _config(tmp_path, "keycloak,audit,me")
    waiting = ("papaia-me", "papaia-prefs", ["r", "w"], "pending", "host:anna", "host:anna")
    plan = _plan(config_dir, _pairings(waiting), _tree("keycloak,audit,me"))
    assert "aud-papaia-prefs" not in plan.clients["papaia-me"].optional_scopes


def test_the_audit_pairing_is_set_by_the_platform_only_with_both_profiles():
    (pairing,) = me_area.platform_pairings(_tree("keycloak,audit,me"))
    assert (pairing.client, pairing.audience, pairing.effects) == (
        "papaia-me",
        "papaia-audit",
        ("x",),
    )
    assert pairing.confirmed and pairing.requested_by == rs.PLATFORM_PERSON
    assert me_area.platform_pairings(_tree("keycloak,me")) == []
    assert me_area.platform_pairings(_tree("keycloak,audit")) == []
    # pairings.yaml still cannot name the audit service.
    with pytest.raises(rs.RealmSyncError, match="paired by the realm sync itself"):
        _pairings(("papaia-me", "papaia-audit", ["x"], "confirmed"))


# ── the client and its secret, the redirect ──────────────────────────────────


def test_the_core_creates_the_sign_in_client_with_the_generated_secret():
    secret = "canary-me-client-secret-1"
    (client,) = keycloak_role_sync.core_profile_clients(
        _tree("keycloak,me", ME_OIDC_CLIENT_SECRET=secret)
    )
    assert client["clientId"] == "papaia-me"
    assert client["clientAuthenticatorType"] == "client-secret"
    assert client["secret"] == secret
    assert client["standardFlowEnabled"] is True
    for switch in (
        "publicClient",
        "implicitFlowEnabled",
        "directAccessGrantsEnabled",
        "serviceAccountsEnabled",
        "fullScopeAllowed",
    ):
        assert client[switch] is False, switch


def test_no_client_without_the_profile_or_without_a_generated_secret():
    assert keycloak_role_sync.core_profile_clients(
        _tree("keycloak", ME_OIDC_CLIENT_SECRET="canary-me-client-secret-1")
    ) == []
    for placeholder in ("", "GENERATE_ME_OIDC_CLIENT_SECRET"):
        assert keycloak_role_sync.core_profile_clients(
            _tree("keycloak,me", ME_OIDC_CLIENT_SECRET=placeholder)
        ) == []


def test_the_sign_in_client_redirects_only_to_the_callback_of_its_address():
    hardening = realm_hardening.load({"ME_PUBLIC_URL": "https://me.papaia.example"})
    uris = hardening.clients["papaia-me"]
    assert uris.redirects == ("https://me.papaia.example/auth/callback",)
    assert uris.origins == ("https://me.papaia.example",)
    assert "papaia-me" not in realm_hardening.load({}).clients


# ── the azp allow-list of prefs ──────────────────────────────────────────────


def test_the_allow_list_holds_only_the_confirmed_pairings_of_prefs(tmp_path):
    config_dir = _config(tmp_path, "keycloak,audit,me")
    pairings = _pairings(PREFS_RW)
    plan = _plan(config_dir, pairings, _tree("keycloak,audit,me"))
    doc = me_area.allowlist(plan, pairings)
    assert doc == {"version": 1, "audiences": {"papaia-prefs": {"papaia-me": ["read", "write"]}}}
    parsed = AzpAllowList.from_dict(doc)  # the kit's reader, which prefs uses
    assert {e.value for e in parsed.effects("papaia-prefs", "papaia-me")} == {"read", "write"}
    # The audit pairing is no pairing of prefs.
    assert parsed.effects("papaia-prefs", "papaia-audit") is None


def test_a_waiting_write_pairing_is_not_on_the_allow_list(tmp_path):
    config_dir = _config(tmp_path, "keycloak,audit,me")
    pairings = _pairings(
        ("papaia-me", "papaia-prefs", ["r", "w"], "pending", "host:anna", "host:anna")
    )
    plan = _plan(config_dir, pairings, _tree("keycloak,audit,me"))
    doc = me_area.allowlist(plan, pairings)
    assert doc == {"version": 1, "audiences": {"papaia-prefs": {}}}
    assert AzpAllowList.from_dict(doc).effects("papaia-prefs", "papaia-me") is None


def _allowlist_file(config_dir: Path) -> Path:
    return config_dir / "security" / "azp" / "azp-allowlist.json"


def test_the_sync_writes_the_list_atomically_and_only_when_it_changes(tmp_path):
    config_dir = _config(tmp_path, "keycloak,audit,me")
    me_area.ensure_allowlist(config_dir)
    path = _allowlist_file(config_dir)
    assert json.loads(path.read_text()) == {"version": 1, "audiences": {"papaia-prefs": {}}}
    before = path.stat().st_ino

    pairings = _pairings(PREFS_RW)
    plan = _plan(config_dir, pairings, _tree("keycloak,audit,me"))
    # --check reports the deviation and writes nothing.
    changes = me_area.sync_allowlist(plan, pairings, config_dir, enabled=True, apply=False)
    assert [c.operation for c in changes] == ["prefs_azp_allowlist.write"]
    assert json.loads(path.read_text())["audiences"]["papaia-prefs"] == {}

    changes = me_area.sync_allowlist(plan, pairings, config_dir, enabled=True, apply=True)
    assert [c.operation for c in changes] == ["prefs_azp_allowlist.write"]
    assert json.loads(path.read_text())["audiences"]["papaia-prefs"] == {
        "papaia-me": ["read", "write"]
    }
    # Replaced by rename: a new inode, nothing left beside it, readable by prefs' own uid.
    assert path.stat().st_ino != before
    assert sorted(p.name for p in path.parent.iterdir()) == ["azp-allowlist.json"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o755
    assert me_area.sync_allowlist(plan, pairings, config_dir, enabled=True, apply=True) == []


def test_a_failed_write_leaves_the_old_list_in_place(tmp_path, monkeypatch):
    config_dir = _config(tmp_path, "keycloak,audit,me")
    me_area.ensure_allowlist(config_dir)
    path = _allowlist_file(config_dir)
    old = path.read_bytes()
    pairings = _pairings(PREFS_RW)
    plan = _plan(config_dir, pairings, _tree("keycloak,audit,me"))

    def broken(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(me_area.os, "replace", broken)
    with pytest.raises(OSError):
        me_area.sync_allowlist(plan, pairings, config_dir, enabled=True, apply=True)
    assert path.read_bytes() == old
    assert sorted(p.name for p in path.parent.iterdir()) == ["azp-allowlist.json"]


def test_the_list_is_removed_with_the_profile(tmp_path):
    config_dir = _config(tmp_path, "keycloak,audit,me")
    me_area.ensure_allowlist(config_dir)
    plan = _plan(config_dir, [], _tree("keycloak,audit"))
    changes = me_area.sync_allowlist(plan, [], config_dir, enabled=False, apply=True)
    assert [c.operation for c in changes] == ["prefs_azp_allowlist.delete"]
    assert not _allowlist_file(config_dir).exists()
    assert me_area.sync_allowlist(plan, [], config_dir, enabled=False, apply=True) == []


def test_a_symbolic_link_in_place_of_the_folder_is_refused(tmp_path):
    config_dir = _config(tmp_path, "keycloak,audit,me")
    (config_dir / "security").mkdir(mode=0o700)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (config_dir / "security" / "azp").symlink_to(elsewhere)
    with pytest.raises(rs.RealmSyncError, match="symbolic link"):
        me_area.ensure_allowlist(config_dir)
    assert list(elsewhere.iterdir()) == []


# ── the module list of the area ──────────────────────────────────────────────


def _settings(module: str, scheme: str = "https", service: str = "demo-api") -> dict:
    return {
        "api": 1,
        "module": module,
        "title": {"de": "Demo", "en": "Demo"},
        "endpoint": {
            "service": service,
            "scheme": scheme,
            "port": 8444,
            "base_path": "/api/v1/me/settings",
            "audience": "flow",
        },
        "data": {"erasure": "request"},
        "groups": [],
    }


def _addon(tmp_path: Path, name: str, manifest: dict) -> dict:
    path = tmp_path / "addons" / name
    path.mkdir(parents=True)
    (path / "papaia-app.yaml").write_text(yaml.safe_dump({"name": name, **manifest}))
    return {"name": name, "path": str(path), "active": True, "state": "running"}


def _install(tmp_path: Path, profiles: str, entries: list[dict]) -> Path:
    config_dir = _config(tmp_path, profiles)
    (config_dir / "deployment.yaml").write_text(yaml.safe_dump({"addons": entries}))
    return config_dir


def _registry(config_dir: Path) -> dict:
    return json.loads((config_dir / "personal-settings" / "registry.yaml").read_text())


def test_the_registry_lists_exactly_the_active_modules_with_personal_settings(tmp_path):
    entries = [
        _addon(tmp_path, "papaia-flow", {"personal_settings": _settings("papaia-flow")}),
        _addon(tmp_path, "papaia-studio", {"version": "1.0.0"}),
        {
            **_addon(tmp_path, "papaia-assist", {"personal_settings": _settings("papaia-assist")}),
            "active": False,
        },
    ]
    config_dir = _install(tmp_path, "keycloak,me", entries)
    assert me_area.render(config_dir, REPO) is True

    registry = _registry(config_dir)
    assert registry == {"registry": 1, "modules": [_settings("papaia-flow")]}
    folder = config_dir / "personal-settings"
    assert stat.S_IMODE(folder.stat().st_mode) == 0o755
    assert stat.S_IMODE((folder / "registry.yaml").stat().st_mode) == 0o644
    assert stat.S_IMODE((folder / "module-ca").stat().st_mode) == 0o755
    assert (folder / "registry.yaml").stat().st_uid == os.geteuid()
    # Nothing changed: nothing is written again.
    assert me_area.render(config_dir, REPO) is False


def test_a_module_that_is_removed_or_switched_off_leaves_the_registry(tmp_path):
    flow = _addon(tmp_path, "papaia-flow", {"personal_settings": _settings("papaia-flow")})
    config_dir = _install(tmp_path, "keycloak,me", [flow])
    me_area.render(config_dir, REPO)
    (config_dir / "deployment.yaml").write_text(
        yaml.safe_dump({"addons": [{**flow, "active": False}]})
    )
    assert me_area.render(config_dir, REPO) is True
    assert _registry(config_dir) == {"registry": 1, "modules": []}


def test_a_declaration_for_another_module_is_left_out(tmp_path):
    entries = [
        _addon(tmp_path, "papaia-flow", {"personal_settings": _settings("papaia-assist")}),
        _addon(tmp_path, "papaia-data", {"personal_settings": "not a mapping"}),
        _addon(
            tmp_path,
            "papaia-studio",
            {"personal_settings": {**_settings("papaia-studio"), "api": "2"}},
        ),
    ]
    config_dir = _install(tmp_path, "keycloak,me", entries)
    me_area.render(config_dir, REPO)
    assert _registry(config_dir) == {"registry": 1, "modules": []}


def test_the_module_ca_is_the_platform_ca_of_the_module_endpoint(tmp_path):
    entries = [
        _addon(tmp_path, "papaia-flow", {"personal_settings": _settings("papaia-flow")}),
        _addon(
            tmp_path,
            "papaia-assist",
            {"personal_settings": _settings("papaia-assist", scheme="http")},
        ),
    ]
    config_dir = _install(tmp_path, "keycloak,me", entries)
    for module in ("papaia-flow", "papaia-assist"):
        issued = config_dir / "pki" / module / "demo-api"
        issued.mkdir(parents=True)
        (issued / "ca.crt").write_text(CA_PEM)
    me_area.render(config_dir, REPO)
    folder = config_dir / "personal-settings" / "module-ca"
    # Only for an https endpoint; plain http trusts nothing.
    assert sorted(p.name for p in folder.iterdir()) == ["papaia-flow.pem"]
    assert (folder / "papaia-flow.pem").read_text() == CA_PEM
    assert stat.S_IMODE((folder / "papaia-flow.pem").stat().st_mode) == 0o644

    # A module that is gone takes its CA file with it.
    (config_dir / "deployment.yaml").write_text(yaml.safe_dump({"addons": entries[1:]}))
    assert me_area.render(config_dir, REPO) is True
    assert list(folder.iterdir()) == []


def test_a_ca_file_with_a_key_is_never_copied(tmp_path):
    flow = _addon(tmp_path, "papaia-flow", {"personal_settings": _settings("papaia-flow")})
    config_dir = _install(tmp_path, "keycloak,me", [flow])
    issued = config_dir / "pki" / "papaia-flow" / "demo-api"
    issued.mkdir(parents=True)
    key = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
    (issued / "ca.crt").write_text(CA_PEM + key)
    me_area.render(config_dir, REPO)
    assert list((config_dir / "personal-settings" / "module-ca").iterdir()) == []


def test_nothing_is_rendered_without_the_profile(tmp_path):
    flow = _addon(tmp_path, "papaia-flow", {"personal_settings": _settings("papaia-flow")})
    config_dir = _install(tmp_path, "keycloak", [flow])
    assert me_area.render(config_dir, REPO) is False
    assert not (config_dir / "personal-settings").exists()
    assert not (config_dir / "security" / "azp").exists()


def test_the_render_prepares_the_mounted_folders_before_the_start(tmp_path):
    config_dir = _install(tmp_path, "keycloak,me", [])
    me_area.render(config_dir, REPO)
    # Compose would otherwise create them as root, and the sync could not write there.
    assert _registry(config_dir) == {"registry": 1, "modules": []}
    assert json.loads(_allowlist_file(config_dir).read_text()) == {
        "version": 1,
        "audiences": {"papaia-prefs": {}},
    }


def test_every_write_of_the_render_is_one_audit_row(tmp_path):
    flow = _addon(tmp_path, "papaia-flow", {"personal_settings": _settings("papaia-flow")})
    config_dir = _install(tmp_path, "keycloak,me", [flow])
    issued = config_dir / "pki" / "papaia-flow" / "demo-api"
    issued.mkdir(parents=True)
    (issued / "ca.crt").write_text(CA_PEM)
    me_area.render(config_dir, REPO)
    rows = [json.loads(line) for line in rs.audit_path(config_dir).read_text().splitlines()]
    operations = sorted(r["operation"] for r in rows)
    assert operations == [
        "me_area.module_ca.write",
        "me_area.prefs_azp_allowlist.write",
        "me_area.registry.write",
    ]
    assert {r["writer"] for r in rows} == {"papaia-ctl/me-area"}
    assert len({r["correlation_id"] for r in rows}) == 1
    assert all(r["result"] == "allowed" and r["detail"] is None for r in rows)


def test_only_me_web_mounts_the_module_list_and_only_prefs_the_allow_list():
    from lib import compat

    mounts: dict[str, list[str]] = {}
    for path in compat.compose_files(REPO / "src" / "docker-compose.yml"):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, body in (doc.get("services") or {}).items():
            for volume in (body or {}).get("volumes") or []:
                source = volume if isinstance(volume, str) else str(volume.get("source"))
                mounts.setdefault(source.split(":", 1)[0], []).append(name)
    assert mounts["${PAPAIA_CONFIG_DIR}/personal-settings"] == ["me-web"]
    assert mounts["${PAPAIA_CONFIG_DIR}/security/azp"] == ["prefs"]


# ── documentation ────────────────────────────────────────────────────────────


def _me_section() -> str:
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    return readme.split("### Mein Bereich (`me`)", 1)[1].split("\n### ", 1)[0]


def test_the_readme_describes_me_without_the_known_limit():
    section = _me_section()
    assert "Known limit of this release" not in section
    assert "papaia-ctl pairing confirm" in section
    assert "papaia-ctl pairing approve" in section
