"""Mein Bereich as a person client of the connection registry (profiles `me` and `connections`).

Me lists a person's accounts, mandates and uses at the registry and ends a mandate, with
the person's own token exchanged for exactly `papaia-connections` and with a client
certificate of the platform CA (the registry asks every caller for one). The core wires the
two profiles only while both are on:

- the platform PKI issues `me-web` a client certificate next to its server certificate;
- the override `docker-compose.me-connections.override.yml` puts `me-web` on the registry's
  network with the certificate's directory and its three paths, and gives the registry
  `CONNECTIONS_PERSON_CLIENTS` with `papaia-me` merged into the operator's value;
- the pairing `papaia-me` -> `papaia-connections` (effects r and d) comes from the bill of
  materials, waits after `pairing confirm` and is assigned only after a second person's
  `pairing approve`.

The tests read the real checkout; files are written into temporary directories only.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from lib import common, gen_override, me_connections, me_profile, pki
from lib import pairing_approval as pa
from lib import realm_sync as rs
from tests.test_suite import _bom

REPO = Path(__file__).resolve().parents[2]
ME_DIR = REPO / "src" / "infra" / "me"
CONNECTIONS_DIR = REPO / "src" / "infra" / "connections"
REGISTER = rs.load_register()
REQUIRE_COMPOSE = os.environ.get("PAPAIA_REQUIRE_GOLDEN_COMPOSE") == "1"
AUDIT_SCHEMA = json.loads(
    (REPO / "src/infra/audit/papaia_audit/audit.v1.schema.json").read_text(encoding="utf-8")
)
SUBMISSION = Draft202012Validator(
    {**AUDIT_SCHEMA, "$ref": "#/$defs/submission", "required": [], "allOf": []}
)
ME_PAIRING = {"client": "papaia-me", "audience": "papaia-connections", "effects": ["r", "d"]}
NETWORK = "papaia-connections-net"
SCOPE = "aud-papaia-connections"
CERT_ENV = {
    "ME_CONNECTIONS_CA_FILE": "/run/papaia/tls/ca.crt",
    "ME_CONNECTIONS_CERT_FILE": "/run/papaia/tls/client.crt",
    "ME_CONNECTIONS_KEY_FILE": "/run/papaia/tls/client.key",
}
PKI_MOUNT = "${PAPAIA_PKI_DIR}/core/me-web:/run/papaia/tls:ro"


def _networks(service: dict) -> set[str]:
    networks = service.get("networks") or []
    return set(networks if isinstance(networks, list) else networks.keys())


def _config(tmp_path: Path, profiles: str, operator: str | None = None) -> Path:
    config = tmp_path / "config"
    config.mkdir(mode=0o700, exist_ok=True)
    (config / ".env").write_text(
        f"COMPOSE_PROFILES={profiles}\nPAPAIA_SECURITY_PROFILE=standard\n", encoding="utf-8"
    )
    if operator is not None:
        env = config / "infra" / "connections" / ".env"
        env.parent.mkdir(parents=True, exist_ok=True)
        env.write_text(f"CONNECTIONS_PERSON_CLIENTS={operator}\n", encoding="utf-8")
    return config


def _override(config: Path) -> dict | None:
    path = config / "overrides" / me_connections.OVERRIDE
    if not path.is_file():
        return None
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _rows(config: Path) -> list[dict]:
    path = rs.audit_path(config)
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# ── the client certificate of me-web ─────────────────────────────────────────


@pytest.mark.parametrize(
    ("profiles", "client"),
    [({"me", "connections"}, True), ({"me"}, False), ({"me", "audit"}, False)],
)
def test_me_web_gets_a_client_certificate_only_with_both_profiles(profiles, client):
    ours = [r for r in pki.core_requests(REPO, profiles) if r.name == "me-web"]
    assert [(r.module, r.uid, r.dns, r.client) for r in ours] == [
        ("core", 10001, ("me-web",), client)
    ]


def test_without_the_profile_me_there_is_no_request_of_me_web():
    assert [r for r in pki.core_requests(REPO, {"connections"}) if r.name == "me-web"] == []


@pytest.mark.parametrize(
    ("client", "message"),
    [
        ({"with_profiles": []}, "with_profiles"),
        ({"with_profiles": "connections"}, "with_profiles"),
        ({"with_profiles": ["Connections"]}, "with_profiles"),
        ({"with_profiles": ["connections"], "always": True}, "unknown keys: always"),
    ],
)
def test_a_malformed_profile_condition_is_refused(client, message):
    block = {"services": [{"name": "me-web", "uid": 10001, "client": client}]}
    with pytest.raises(pki.PkiError, match=message):
        pki.parse_request(block, "core", "src/infra/me/pki.yaml")


def test_an_add_on_cannot_tie_its_client_certificate_to_core_profiles():
    block = {"services": [{"name": "gate", "uid": 10001,
                           "client": {"with_profiles": ["connections"]}}]}  # fmt: skip
    with pytest.raises(pki.PkiError, match="true or false"):
        pki.parse_request(block, "studio", "studio/papaia-app.yaml", addon=True)


@pytest.fixture
def pki_install(tmp_path: Path) -> dict[str, Path]:
    """A checkout with the request files of both profiles and a configuration directory."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not available")
    repo = tmp_path / "repo"
    for directory in (ME_DIR, CONNECTIONS_DIR):
        target = repo / "src" / "infra" / directory.name / "pki.yaml"
        target.parent.mkdir(parents=True)
        shutil.copyfile(directory / "pki.yaml", target)
    return {"repo": repo, "config": _config(tmp_path, "keycloak,me,connections")}


def _issue(install: dict[str, Path]) -> pki.Result:
    return pki.issue(install["config"], pki.collect(install["config"], install["repo"]))


def test_the_client_certificate_is_one_of_the_platform_ca_and_private_to_me_web(pki_install):
    _issue(pki_install)
    folder = pki.pki_dir(pki_install["config"]) / "core" / "me-web"

    assert {"tls.crt", "tls.key", "client.crt", "client.key", "ca.crt"} <= {
        p.name for p in folder.iterdir()
    }
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    assert stat.S_IMODE((folder / "client.key").stat().st_mode) == 0o600
    request = json.loads((folder / "request.json").read_text(encoding="utf-8"))
    assert (request["uid"], request["client"]) == (10001, True)
    text = subprocess.run(
        ["openssl", "x509", "-in", str(folder / "client.crt"), "-noout", "-text"],
        capture_output=True, text=True, check=True,
    ).stdout  # fmt: skip
    assert "TLS Web Client Authentication" in text
    verified = subprocess.run(
        ["openssl", "verify", "-CAfile", str(folder / "ca.crt"), str(folder / "client.crt")],
        capture_output=True, text=True, check=True,
    ).stdout  # fmt: skip
    assert verified.strip().endswith("OK")
    # The registry's server certificate is of the same CA: Me checks it with ca.crt.
    registry = pki.pki_dir(pki_install["config"]) / "core" / "connections"
    assert (registry / "ca.crt").read_bytes() == (folder / "ca.crt").read_bytes()


def test_switching_the_registry_off_removes_the_client_certificate(pki_install):
    _issue(pki_install)
    (pki_install["config"] / ".env").write_text("COMPOSE_PROFILES=keycloak,me\n", "utf-8")

    _issue(pki_install)

    folder = pki.pki_dir(pki_install["config"]) / "core" / "me-web"
    assert (folder / "tls.crt").is_file()
    assert not (folder / "client.crt").exists()
    assert not (folder / "client.key").exists()


# ── compose: the base files ──────────────────────────────────────────────────


def test_me_web_is_not_on_the_registry_network_in_the_base_file():
    services = yaml.safe_load((ME_DIR / "docker-compose.yml").read_text(encoding="utf-8"))
    assert NETWORK not in _networks(services["services"]["me-web"])
    for name in ("prefs", "prefs-db"):
        assert NETWORK not in _networks(services["services"][name])


# ── compose: the override of both profiles ───────────────────────────────────


def test_with_both_profiles_me_web_joins_the_registry_with_its_certificate(tmp_path):
    config = _config(tmp_path, "keycloak,me,connections,audit")

    path = gen_override.generate_overrides(config, REPO)

    assert config / "overrides" / me_connections.OVERRIDE in path
    services = _override(config)["services"]
    assert set(services) == {"me-web", "connections"}
    me_web = services["me-web"]
    assert me_web["networks"] == [NETWORK]
    assert me_web["volumes"] == [PKI_MOUNT]
    assert me_web["environment"] == CERT_ENV
    assert services["connections"] == {"environment": {"CONNECTIONS_PERSON_CLIENTS": "papaia-me"}}


def test_no_other_me_service_joins_the_registry(tmp_path):
    config = _config(tmp_path, "keycloak,me,connections")
    me_connections.generate_override(config)
    assert not {"prefs", "prefs-db"} & set(_override(config)["services"])


@pytest.mark.parametrize(
    ("operator", "expected"),
    [
        ("", "papaia-me"),
        ("connections-web", "connections-web,papaia-me"),
        ("connections-web, flow-console", "connections-web,flow-console,papaia-me"),
        ("papaia-me,connections-web", "papaia-me,connections-web"),
        ("connections-web,,connections-web", "connections-web,papaia-me"),
    ],
)
def test_the_operator_value_is_kept_and_papaia_me_merged_in(tmp_path, operator, expected):
    config = _config(tmp_path, "keycloak,me,connections", operator)
    me_connections.generate_override(config)
    environment = _override(config)["services"]["connections"]["environment"]
    assert environment == {"CONNECTIONS_PERSON_CLIENTS": expected}


@pytest.mark.parametrize(
    ("operator", "expected"),
    [("", ""), ("connections-web", "connections-web"), ("papaia-me,flow-console", "flow-console")],
)
def test_without_me_papaia_me_is_never_a_person_client(tmp_path, operator, expected):
    config = _config(tmp_path, "keycloak,connections", operator)
    me_connections.generate_override(config)
    services = _override(config)["services"]
    assert set(services) == {"connections"}
    assert services["connections"]["environment"] == {"CONNECTIONS_PERSON_CLIENTS": expected}


def test_without_the_registry_on_this_host_nothing_is_written(tmp_path):
    config = _config(tmp_path, "keycloak,me,connections")
    me_connections.generate_override(config)
    (config / ".env").write_text("COMPOSE_PROFILES=keycloak,me\n", encoding="utf-8")

    assert me_connections.generate_override(config) is None
    assert _override(config) is None


@pytest.mark.parametrize("operator", ["flow console", "a$b", "x" * 200, "flow-console;rm"])
def test_an_operator_value_that_names_no_client_is_refused(tmp_path, operator):
    config = _config(tmp_path, "keycloak,me,connections", operator)
    with pytest.raises(me_connections.MeConnectionsError, match="CONNECTIONS_PERSON_CLIENTS"):
        me_connections.generate_override(config)
    assert _override(config) is None


def test_each_change_of_the_override_is_one_audit_row_and_a_rerun_writes_none(tmp_path):
    config = _config(tmp_path, "keycloak,me,connections")
    me_connections.generate_override(config)
    me_connections.generate_override(config)
    (config / ".env").write_text("COMPOSE_PROFILES=keycloak\n", encoding="utf-8")
    me_connections.generate_override(config)

    rows = _rows(config)
    assert [r["operation"] for r in rows] == [
        "me_connections.override.write",
        "me_connections.override.delete",
    ]
    for row in rows:
        assert list(SUBMISSION.iter_errors(row)) == []
        assert row["object_ref"] == {"type": "file", "id": f"overrides/{me_connections.OVERRIDE}"}
        assert row["result"] == "allowed"
        assert row["detail"] is None  # no client name, no value
    assert _override(config) is None


# ── compose: rendered by Compose ─────────────────────────────────────────────


def _compose_cli() -> list[str] | None:
    docker = shutil.which("docker")
    if docker is None:
        return None
    probe = subprocess.run([docker, "compose", "version"], capture_output=True, check=False)
    return [docker, "compose"] if probe.returncode == 0 else None


def _render(tmp_path: Path, config: Path) -> dict:
    cli = _compose_cli()
    if cli is None:
        if REQUIRE_COMPOSE:
            pytest.fail("PAPAIA_REQUIRE_GOLDEN_COMPOSE is set but Docker Compose is missing")
        pytest.skip("Docker Compose not installed")
    env = {
        **common.parse_env_file(REPO / "src" / ".env.example"),
        **common.parse_env_file(ME_DIR / ".env.example"),
        **common.parse_env_file(CONNECTIONS_DIR / ".env.example"),
        "PAPAIA_CONFIG_DIR": str(config),
        "PAPAIA_PKI_DIR": str(config / "pki"),
        "DOCKER_NETWORK": "itk-core-082-net",
    }
    env_file = tmp_path / "render.env"
    env_file.write_text("".join(f"{k}={v}\n" for k, v in env.items()), encoding="utf-8")
    files = [
        ME_DIR / "docker-compose.yml",
        CONNECTIONS_DIR / "docker-compose.yml",
        Path(__file__).parent / "fixtures" / "me" / "networks.yml",
    ]
    override = config / "overrides" / me_connections.OVERRIDE
    if override.is_file():
        files.append(override)
    # `config` only renders the model; it starts nothing and needs no daemon.
    rendered = subprocess.run(
        [
            *cli,
            "--project-name", "itk-core-082",
            "--project-directory", str(ME_DIR),
            "--env-file", str(env_file),
            *[arg for path in files for arg in ("-f", str(path))],
            "--profile", "me", "--profile", "connections",
            "config", "--format", "json",
        ],
        capture_output=True, text=True, check=False, env={"PATH": os.environ.get("PATH", "")},
    )  # fmt: skip
    assert rendered.returncode == 0, rendered.stderr
    return json.loads(rendered.stdout)["services"]


def test_the_rendered_stack_with_both_profiles(tmp_path):
    config = _config(tmp_path, "keycloak,me,connections", "connections-web")
    me_connections.generate_override(config)

    services = _render(tmp_path, config)

    me_web = services["me-web"]
    assert NETWORK in me_web["networks"]
    assert "papaia-net" in me_web["networks"]
    assert {k: me_web["environment"][k] for k in CERT_ENV} == CERT_ENV
    mounts = {(v["source"], v["target"], v.get("read_only")) for v in me_web["volumes"]}
    assert (str(config / "pki" / "core" / "me-web"), "/run/papaia/tls", True) in mounts
    registry = services["connections"]["environment"]
    assert registry["CONNECTIONS_PERSON_CLIENTS"] == "connections-web,papaia-me"
    for name in ("prefs", "prefs-db"):
        assert NETWORK not in services[name]["networks"]


def test_the_rendered_stack_without_the_override_keeps_me_web_off_the_registry(tmp_path):
    config = _config(tmp_path, "keycloak,me")

    services = _render(tmp_path, config)

    assert NETWORK not in services["me-web"]["networks"]
    assert not set(CERT_ENV) & set(services["me-web"]["environment"])
    assert "papaia-me" not in services["connections"]["environment"]["CONNECTIONS_PERSON_CLIENTS"]


# ── the variable list of me-web ──────────────────────────────────────────────


def test_the_variable_list_names_the_paths_handed_over_with_the_registry():
    listed = json.loads((ME_DIR / "service-env.json").read_text(encoding="utf-8"))
    handed = listed["services"]["me-web"]["with_profiles"]
    assert handed == {"connections": sorted(CERT_ENV)}
    assert listed["services"]["prefs"]["with_profiles"] == {}
    assert sorted(me_connections.ME_ENV) == sorted(CERT_ENV)
    assert me_profile.check(REPO) == []


def test_a_handed_over_path_in_the_base_file_fails_the_check(tmp_path):
    root = tmp_path / "repo"
    for rel in (me_profile.COMPOSE_REL, me_profile.ENV_EXAMPLE_REL, me_profile.ENV_LIST_REL,
                Path("src/.env.example")):  # fmt: skip
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / rel, root / rel)
    doc = yaml.safe_load((root / me_profile.COMPOSE_REL).read_text(encoding="utf-8"))
    doc["services"]["me-web"]["environment"]["ME_CONNECTIONS_CERT_FILE"] = "/x"
    (root / me_profile.COMPOSE_REL).write_text(yaml.safe_dump(doc, sort_keys=False), "utf-8")

    assert me_profile.check(root) == [
        "me-web: ME_CONNECTIONS_CERT_FILE is set by the override of the profile connections only"
    ]


def test_the_generator_keeps_the_handed_over_paths_apart_from_the_base_reads(tmp_path):
    source = tmp_path / "me"
    for rel, body in (
        (me_profile.SOURCES["me-web"],
         "class S:\n    def from_env(e):\n        opt('ME_PUBLIC_URL')\n"
         "        opt('ME_CONNECTIONS_CERT_FILE')\n"),
        (me_profile.SOURCES["prefs"],
         "class P:\n    def from_env(e):\n        req('PREFS_LANG')\n"),
        (me_profile.CHANNELS_SOURCE, "CHANNELS = ('chat_window', 'mail')\n"),
    ):  # fmt: skip
        (source / rel).parent.mkdir(parents=True, exist_ok=True)
        (source / rel).write_text(body, encoding="utf-8")

    listed = me_profile.generate(
        source, image="ghcr.io/fidonis/papaia-me:0.1.0@sha256:" + "a" * 64, commit="b" * 40
    )

    assert listed["services"]["me-web"]["reads"] == ["ME_PUBLIC_URL"]
    assert listed["services"]["me-web"]["with_profiles"] == {"connections": sorted(CERT_ENV)}
    assert listed["services"]["prefs"]["with_profiles"] == {}


# ── the pairing papaia-me -> papaia-connections ──────────────────────────────


def _modules(*profiles: str) -> list[rs.Module]:
    found = []
    for profile, (name, directory) in rs.CORE_PROFILE_MODULES.items():
        if profile in profiles:
            doc = yaml.safe_load((REPO / directory / "exposes.yaml").read_text(encoding="utf-8"))
            found.append(rs.Module(name, doc["exposes"], {}))
    return found


def _exchange_scopes(config: Path, *profiles: str) -> dict[str, set[str]]:
    plan = rs.build_plan(
        REGISTER, _modules(*profiles), rs.load_pairings(rs.pairings_path(config), REGISTER)
    )
    return {
        name: {s for s in spec.optional_scopes if s.startswith("aud-")}
        for name, spec in plan.clients.items()
    }


def _bom_config(tmp_path: Path) -> tuple[Path, list[rs.Pairing]]:
    config = tmp_path / "papaia-config"
    config.mkdir(mode=0o700)
    doc = _bom()
    doc["pairings"] = [ME_PAIRING]
    return config, pa.bom_pairings(doc, REGISTER)


def test_the_bill_of_materials_may_ship_the_pairing_as_a_write_pairing(tmp_path):
    _, entries = _bom_config(tmp_path)
    (entry,) = entries
    assert (entry.client, entry.audience, entry.effects) == (
        "papaia-me", "papaia-connections", ("r", "d"),
    )  # fmt: skip
    assert entry.writes  # it ends mandates: a second person approves it


def test_the_scope_is_assigned_only_after_confirm_and_a_second_persons_approval(tmp_path):
    config, entries = _bom_config(tmp_path)

    result = pa.confirm_installation(
        config, REGISTER, entries, pa.list_digest(entries), person="host:anna"
    )
    assert [(p.client, p.audience) for p in result.waiting] == [
        ("papaia-me", "papaia-connections")
    ]
    assert SCOPE not in _exchange_scopes(config, "me", "connections")["papaia-me"]

    with pytest.raises(pa.PairingError, match="second person"):
        pa.approve(config, REGISTER, "papaia-me", "papaia-connections", ["r", "d"],
                   person="host:anna")  # fmt: skip
    assert SCOPE not in _exchange_scopes(config, "me", "connections")["papaia-me"]

    assert pa.approve(config, REGISTER, "papaia-me", "papaia-connections", ["r", "d"],
                      person="host:bert") == "confirmed"  # fmt: skip
    scopes = _exchange_scopes(config, "me", "connections")
    assert "aud-papaia-connections" in scopes["papaia-me"]
    # the scope never reaches another client
    assert [c for c, s in scopes.items() if "aud-papaia-connections" in s] == ["papaia-me"]


def test_the_approved_pairing_is_inactive_without_the_registry(tmp_path):
    config, entries = _bom_config(tmp_path)
    pa.confirm_installation(config, REGISTER, entries, pa.list_digest(entries), person="host:anna")
    pa.approve(config, REGISTER, "papaia-me", "papaia-connections", None, person="host:bert")

    plan = rs.build_plan(
        REGISTER, _modules("me"), rs.load_pairings(rs.pairings_path(config), REGISTER)
    )

    assert "aud-papaia-connections" not in plan.clients["papaia-me"].optional_scopes
    assert any("inactive until both sides are installed" in n for n in plan.notes)


@pytest.mark.parametrize("effects", [["r", "w"], ["r", "d", "x"], ["w"], ["x"]])
def test_me_never_writes_to_the_registry_through_a_pairing(effects):
    doc = {
        "format": rs.PAIRINGS_FORMAT,
        "pairings": [{**ME_PAIRING, "effects": effects, "state": "pending"}],
    }
    with pytest.raises(rs.RealmSyncError, match="papaia-me -> papaia-connections"):
        rs.parse_pairings(doc, REGISTER)


@pytest.mark.parametrize("effects", [["r"], ["d"], ["r", "w"], ["r", "d", "x"]])
def test_the_pairing_holds_exactly_reading_and_ending(effects):
    # The registry does not limit operations per person client: any token with
    # aud papaia-connections and azp papaia-me can end mandates. A narrower letter set
    # would only skip the second person, so the pair is fixed to r and d.
    doc = {
        "format": rs.PAIRINGS_FORMAT,
        "pairings": [{**ME_PAIRING, "effects": effects, "state": "pending"}],
    }
    with pytest.raises(rs.RealmSyncError, match="effects rd only"):
        rs.parse_pairings(doc, REGISTER)


@pytest.mark.parametrize("effects", [["r", "d"], ["d", "r"]])
def test_reading_and_ending_are_the_effects_me_holds(effects):
    doc = {
        "format": rs.PAIRINGS_FORMAT,
        "pairings": [{**ME_PAIRING, "effects": effects, "state": "pending"}],
    }
    (pairing,) = rs.parse_pairings(doc, REGISTER)
    assert pairing.audience == "papaia-connections"
    assert pairing.writes


@pytest.mark.parametrize("effects", [["r"], ["d"]])
def test_a_bill_of_materials_cannot_ship_a_narrower_pairing(tmp_path, effects):
    doc = _bom()
    doc["pairings"] = [{**ME_PAIRING, "effects": effects}]
    with pytest.raises(pa.PairingError, match="effects rd only"):
        pa.bom_pairings(doc, REGISTER)


@pytest.mark.parametrize("effects", [["r"], ["d"]])
def test_one_person_never_assigns_the_registry_scope(tmp_path, effects):
    config = tmp_path / "papaia-config"
    config.mkdir(mode=0o700)
    (config / "security").mkdir(mode=0o700)

    # approve on the host: refused before anything is written
    with pytest.raises(pa.PairingError, match="effects rd only"):
        pa.approve(config, REGISTER, "papaia-me", "papaia-connections", effects,
                   person="host:anna")  # fmt: skip
    assert not rs.pairings_path(config).exists()

    # a hand-edited file confirmed by one person is refused by the realm sync
    rs.pairings_path(config).write_text(yaml.safe_dump({
        "format": rs.PAIRINGS_FORMAT,
        "pairings": [{**ME_PAIRING, "effects": effects, "state": "confirmed",
                      "confirmed_by": "host:anna"}],
    }), encoding="utf-8")  # fmt: skip
    with pytest.raises(rs.RealmSyncError, match="effects rd only"):
        _exchange_scopes(config, "me", "connections")

    # the full pair confirmed by one person is refused as well
    rs.pairings_path(config).write_text(yaml.safe_dump({
        "format": rs.PAIRINGS_FORMAT,
        "pairings": [{**ME_PAIRING, "state": "confirmed", "requested_by": "host:anna",
                      "confirmed_by": "host:anna"}],
    }), encoding="utf-8")  # fmt: skip
    with pytest.raises(rs.RealmSyncError, match="second person"):
        _exchange_scopes(config, "me", "connections")
