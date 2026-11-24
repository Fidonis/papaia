"""Joining the network a required add-on offers (addon_api 17, ADR 0027).

A `networks.join_addons` entry may name the network the target add-on offers through one
of its `exposes` entries instead of joining the target's `app_network`:

    networks:
      join_addons:
        - addon: flow
          services: [gate]
          network: ${PAPAIA_PROJECT:-papaia}-flow-modules

The target offers a network when its compose file declares it with a `name` and
`internal: true`, the `address.service` of one of its `exposes` entries joins it, and it is
not the target's app, egress or isolated network. The listed services join exactly that
network; the target's `app_network` appears in no override of the consumer. Every manifest
that would widen this is refused, and an older core refuses the key instead of falling
back to the app network.
"""

from __future__ import annotations

import argparse
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from lib import cli_addon, compat, deployment, doctor, envtree, gen_override
from lib.status import CommandResult

GOLDEN = Path(__file__).parent / "golden" / "addon-overrides"
REPO = Path(__file__).resolve().parents[2]
UPDATE = os.environ.get("PAPAIA_UPDATE_GOLDEN") == "1"

OFFER = "${PAPAIA_PROJECT:-papaia}-flow-modules"
FLOW_APP = "${PAPAIA_PROJECT:-papaia}-flow-net"


def _target_compose(**extra_networks: dict) -> dict:
    """The target's own compose file: the API on the app network and on a data network,
    the relay (the address of the `flow.runs` exposes entry) on the offered network."""
    return {
        "services": {
            "api": {"image": "busybox", "networks": ["app", "data", "relay"]},
            "db": {"image": "busybox", "networks": ["data"]},
            "relay": {
                "image": "busybox",
                "networks": {"relay": {}, "modules": {"aliases": ["flow-api"]},
                             **{key: {} for key in extra_networks}},
            },
        },
        "networks": {
            "app": {"name": FLOW_APP},
            "data": {"internal": True},
            "relay": {"internal": True},
            "modules": {"name": OFFER, "internal": True},
            **extra_networks,
        },
    }


def _target_manifest(**networks: object) -> dict:
    return {
        "name": "flow",
        "version": "1.0.0",
        "requires": {"addon_api": [7]},
        "networks": {"app_network": FLOW_APP, **networks},
        "exposes": [
            {
                "id": "flow.runs",
                "kind": "mcp",
                "title": {"de": "Abläufe", "en": "Runs"},
                "address": {"service": "relay", "port": 8080},
                "audience": "mcp-flow",
                "identity": ["service"],
                "operations": [{
                    "name": "start_run", "version": 1, "title": {"de": "Start", "en": "Start"},
                    "via": "tools", "effect": "read", "retry": "safe",
                    "input_schema": {"type": "object"}, "output_schema": {"type": "object"},
                    "data_class_max": "internal", "rights_check": "server",
                }],
            },
        ],
    }


def _consumer_manifest(*entries: dict, addon_api: object = (17,), optional: bool = True) -> dict:
    return {
        "name": "assist",
        "version": "1.0.0",
        "requires": {
            "addon_api": list(addon_api),
            "addons": [{"name": "flow", "optional": optional}],
        },
        "networks": {
            "app_network": "${PAPAIA_PROJECT:-papaia}-assist-net",
            "join_addons": list(entries)
            or [{"addon": "flow", "services": ["gate"], "network": OFFER}],
        },
    }


_CONSUMER_COMPOSE = {
    "services": {
        "gate": {"image": "busybox", "networks": ["own"]},
        "web": {"image": "busybox", "networks": ["own"]},
    },
    "networks": {"own": {"name": "${PAPAIA_PROJECT:-papaia}-assist-net"}},
}


def _write(root: Path, name: str, manifest: dict, compose: dict | None) -> Path:
    path = root / name
    path.mkdir(parents=True, exist_ok=True)
    (path / "papaia-app.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    if compose is not None:
        (path / "docker-compose.yml").write_text(yaml.safe_dump(compose), encoding="utf-8")
    return path


def _install(
    config_dir: Path,
    tmp_path: Path,
    consumer: dict | None = None,
    target: dict | None = None,
    target_compose: dict | None = None,
    *,
    target_registered: bool = True,
    target_active: bool = True,
) -> tuple[Path, Path]:
    flow = _write(tmp_path / "addons", "flow", target or _target_manifest(),
                  target_compose or _target_compose())
    assist = _write(tmp_path / "addons", "assist", consumer or _consumer_manifest(),
                    _CONSUMER_COMPOSE)
    deployed = deployment.load(config_dir)
    entries = [{"name": "assist", "path": str(assist), "active": True}]
    if target_registered:
        entries.insert(0, {"name": "flow", "path": str(flow), "active": target_active})
    deployed["addons"] = entries
    (config_dir / "deployment.yaml").write_text(yaml.safe_dump(deployed), encoding="utf-8")
    return flow, assist


def _is_network_override(path: Path) -> bool:
    """A join or offer override; the log rotation override (BE-27) of every active
    add-on joins no network and is not part of what these tests pin."""
    return not path.name.endswith("-logging.override.yml")


def _overrides(config_dir: Path, name: str) -> dict[str, dict]:
    """Every join and offer override file of `name` in overrides/addons/, by file name."""
    return {
        path.name: yaml.safe_load(path.read_text(encoding="utf-8"))
        for path in deployment.addon_override_files(config_dir, name)
        if _is_network_override(path)
    }


def _offer_path(config_dir: Path) -> Path:
    return config_dir / "overrides" / "addons" / "docker-compose.assist-offer-flow.override.yml"


def _join_path(config_dir: Path) -> Path:
    return config_dir / "overrides" / "addons" / "docker-compose.assist-join.override.yml"


@pytest.fixture
def installed(config_dir, repo_root):
    envtree.init(config_dir, repo_root, env_name="papaia")
    return config_dir


# ── rendering ─────────────────────────────────────────────────────────────────


def test_the_listed_services_join_the_offered_network_only(installed, repo_root, tmp_path):
    _install(installed, tmp_path)

    gen_override.generate_addon_join_overrides(installed, repo_root)

    offer = yaml.safe_load(_offer_path(installed).read_text(encoding="utf-8"))
    # The service keeps its own network (a compose `networks:` override may replace the
    # list) and gains exactly the offered one, declared external.
    assert offer["services"] == {"gate": {"networks": ["own", "papaia-flow-modules"]}}
    assert offer["networks"] == {"papaia-flow-modules": {"external": True}}
    # Nothing of the consumer joins the target's app network.
    assert not _join_path(installed).exists()


def test_the_target_app_network_is_in_no_override_of_the_consumer(
    installed, repo_root, tmp_path
):
    _install(installed, tmp_path)

    gen_override.generate_overrides(installed, repo_root)
    gen_override.generate_addon_join_overrides(installed, repo_root)

    rendered = [
        path.read_text(encoding="utf-8")
        for path in (installed / "overrides").rglob("*.yml")
        if "assist" in path.name
    ]
    assert rendered
    for text in rendered:
        assert "papaia-flow-net" not in text
    # Other services of the consumer stay off the offered network.
    offer = yaml.safe_load(_offer_path(installed).read_text(encoding="utf-8"))
    assert "web" not in offer["services"]


def test_the_offered_network_follows_the_deployment_scope(installed, repo_root, tmp_path):
    env = installed / ".env"
    env.write_text(env.read_text(encoding="utf-8") + "PAPAIA_PROJECT=acme\n", encoding="utf-8")
    _install(installed, tmp_path)

    gen_override.generate_addon_join_overrides(installed, repo_root)

    offer = yaml.safe_load(_offer_path(installed).read_text(encoding="utf-8"))
    assert offer["networks"] == {"acme-flow-modules": {"external": True}}


def test_an_entry_without_the_key_and_one_with_it_render_apart(installed, repo_root, tmp_path):
    wiki = _write(tmp_path / "addons", "wiki", {"networks": {"app_network": "papaia-wiki-net"}},
                  None)
    consumer = _consumer_manifest(
        {"addon": "wiki", "services": ["web"]},
        {"addon": "flow", "services": ["gate"], "network": OFFER},
    )
    consumer["requires"]["addons"].append("wiki")
    _install(installed, tmp_path, consumer)
    deployed = deployment.load(installed)
    deployed["addons"].append({"name": "wiki", "path": str(wiki), "active": True})
    (installed / "deployment.yaml").write_text(yaml.safe_dump(deployed), encoding="utf-8")

    gen_override.generate_addon_join_overrides(installed, repo_root)

    files = _overrides(installed, "assist")
    assert files["docker-compose.assist-join.override.yml"] == {
        "services": {"web": {"networks": ["own", "papaia-wiki-net"]}},
        "networks": {"papaia-wiki-net": {"external": True}},
    }
    assert files["docker-compose.assist-offer-flow.override.yml"]["services"] == {
        "gate": {"networks": ["own", "papaia-flow-modules"]}
    }


def test_a_stale_offer_override_is_removed(installed, repo_root, tmp_path):
    _install(installed, tmp_path)
    gen_override.generate_addon_join_overrides(installed, repo_root)
    assert _offer_path(installed).is_file()

    _install(installed, tmp_path, _consumer_manifest({"addon": "flow", "services": ["gate"]}))
    gen_override.generate_addon_join_overrides(installed, repo_root)

    assert not _offer_path(installed).exists()
    assert _join_path(installed).is_file()


def _join_golden_case(tmp_path: Path) -> tuple[Path, Path]:
    """A consumer with entries in the form before generation 17: the rendered join
    override must stay byte for byte what it was."""
    config_dir = tmp_path / "golden-config"
    (config_dir / "overrides" / "addons").mkdir(parents=True)
    (config_dir / ".env").write_text("PAPAIA_PROJECT=papaia\n", encoding="utf-8")
    root = tmp_path / "golden-addons"
    wiki = _write(root, "wiki", {"networks": {"app_network": "papaia-wiki-net"}}, None)
    flow = _write(root, "flow", {"networks": {"app_network": FLOW_APP}}, None)
    joiner = _write(
        root,
        "joiner",
        {
            "requires": {"addons": ["wiki", "flow"]},
            "networks": {"join_addons": [
                {"addon": "wiki", "services": ["job", "web"]},
                {"addon": "flow", "services": ["job"]},
            ]},
        },
        {
            "services": {
                "job": {"image": "busybox", "networks": ["own"]},
                "web": {"image": "busybox"},
                "db": {"image": "busybox", "networks": {"own": {}}},
            },
            "networks": {"own": {}},
        },
    )
    (config_dir / "deployment.yaml").write_text(
        yaml.safe_dump({"addons": [
            {"name": p.name, "path": str(p), "active": True} for p in (wiki, flow, joiner)
        ]}),
        encoding="utf-8",
    )
    return config_dir, root


def test_without_the_key_the_join_override_is_byte_identical(tmp_path, repo_root):
    config_dir, _ = _join_golden_case(tmp_path)

    gen_override.generate_addon_join_overrides(config_dir, repo_root)

    out = config_dir / "overrides" / "addons" / "docker-compose.joiner-join.override.yml"
    text = out.read_text(encoding="utf-8")
    golden = GOLDEN / "join.override.yml.golden"
    if UPDATE:
        golden.write_text(text, encoding="utf-8")
    assert text == golden.read_text(encoding="utf-8")
    assert sorted(p.name for p in out.parent.iterdir() if _is_network_override(p)) == [
        out.name
    ]


# ── absent or inactive target, missing network ────────────────────────────────


@pytest.mark.parametrize("registered,active", [(False, False), (True, False)])
def test_an_absent_or_inactive_target_is_skipped_with_a_warning(
    installed, repo_root, tmp_path, capsys, registered, active
):
    _install(installed, tmp_path, target_registered=registered, target_active=active)

    gen_override.generate_addon_join_overrides(installed, repo_root)

    assert _overrides(installed, "assist") == {}
    err = capsys.readouterr().err
    assert "'flow'" in err and "papaia-flow-modules" in err and "assist" in err


def test_the_consumer_starts_without_its_optional_target(installed, repo_root, tmp_path):
    shutil_copy_addon_api(repo_root)
    _, assist = _install(installed, tmp_path, target_registered=False)
    deployed = deployment.load(installed)
    manifest, _ = deployment.load_addon_manifest(assist)

    result, code = cli_addon._evaluate_gate(
        "assist", manifest, deployed, repo_root, force=False, addon_path=assist
    )

    assert code == 0, result.reason
    assert any("flow" in warning for warning in result.warnings)


def test_a_missing_offered_network_is_left_out_at_start(
    installed, repo_root, tmp_path, capsys, monkeypatch
):
    _install(installed, tmp_path)
    gen_override.generate_addon_join_overrides(installed, repo_root)
    monkeypatch.setattr(gen_override, "network_exists", lambda name: False)

    usable = gen_override.usable_addon_override_files(installed, "assist")

    assert _offer_path(installed) not in usable
    err = capsys.readouterr().err
    assert "papaia-flow-modules" in err and "'flow'" in err and "assist" in err


def test_an_existing_offered_network_is_kept_at_start(installed, repo_root, tmp_path,
                                                      monkeypatch):
    _install(installed, tmp_path)
    gen_override.generate_addon_join_overrides(installed, repo_root)
    asked: list[str] = []
    monkeypatch.setattr(gen_override, "network_exists", lambda name: asked.append(name) or True)

    usable = gen_override.usable_addon_override_files(installed, "assist")

    assert [path for path in usable if _is_network_override(path)] == [_offer_path(installed)]
    assert asked == ["papaia-flow-modules"]


def test_the_override_files_command_leaves_a_missing_network_out(
    installed, repo_root, tmp_path, capsys, monkeypatch
):
    _install(installed, tmp_path)
    gen_override.generate_addon_join_overrides(installed, repo_root)
    monkeypatch.setattr(gen_override, "network_exists", lambda name: False)
    args = argparse.Namespace(config_dir=str(installed), name="assist", usable=True)

    assert cli_addon.cmd_addon_override_files(args) == 0
    assert "offer-flow" not in capsys.readouterr().out

    args.usable = False
    assert cli_addon.cmd_addon_override_files(args) == 0
    assert "offer-flow" in capsys.readouterr().out


def test_doctor_reports_a_missing_offered_network(installed, repo_root, tmp_path):
    _install(installed, tmp_path)
    shutil_copy_addon_api(repo_root)
    gen_override.generate_addon_join_overrides(installed, repo_root)
    calls: list[list[str]] = []

    def run(cmd, timeout):
        calls.append(list(cmd))
        if cmd[:3] == ["docker", "network", "inspect"]:
            return CommandResult(1, "", "No such network")
        return CommandResult(0, "", "")

    ctx = doctor.Context(installed, repo_root, run=run, probes=None,
                         now=datetime(2026, 11, 23, tzinfo=UTC))
    check = doctor.check_addon_compat(ctx)

    assert check.status == doctor.WARN, check.summary
    assert "papaia-flow-modules" in check.summary and "flow" in check.summary
    assert ["docker", "network", "inspect", "papaia-flow-modules"] in calls


def shutil_copy_addon_api(repo_root: Path) -> None:
    (repo_root / "ADDON_API").write_text(
        (REPO / "ADDON_API").read_text(encoding="utf-8"), encoding="utf-8"
    )


# ── refusals at render ────────────────────────────────────────────────────────


def test_the_render_never_joins_a_network_the_target_stopped_offering(
    installed, repo_root, tmp_path, capsys
):
    # The target was upgraded and its relay left the network: the consumer's join is
    # dropped, never widened to anything else.
    compose = _target_compose()
    compose["services"]["relay"]["networks"] = {"relay": {}}
    _install(installed, tmp_path, target_compose=compose)

    gen_override.generate_addon_join_overrides(installed, repo_root)

    assert _overrides(installed, "assist") == {}
    assert "networks.join_addons[0]" in capsys.readouterr().err


# ── compatibility check ───────────────────────────────────────────────────────


def _core(addon_api: tuple[int, int] = (1, 17), networks: frozenset[str] | None = None):
    return compat.CoreTarget(platform_version="1.10.0", addon_api=addon_api,
                             services={"litellm": ["litellm"]}, networks=networks)


def _gate(config_dir: Path, repo_root: Path, assist: Path) -> compat.CompatResult:
    deployed = deployment.load(config_dir)
    manifest, _ = deployment.load_addon_manifest(assist)
    result, _ = cli_addon._evaluate_gate(
        "assist", manifest, deployed, repo_root, force=True, addon_path=assist
    )
    return result


def test_an_offered_network_is_compatible(installed, repo_root, tmp_path):
    shutil_copy_addon_api(repo_root)
    _, assist = _install(installed, tmp_path)
    result = _gate(installed, repo_root, assist)
    assert result.status == compat.STATUS_OK, result.reason


@pytest.mark.parametrize(
    "variant,fragment",
    [
        ("no-exposes-service", "no exposes entry"),
        ("not-internal", "internal: true"),
        ("not-declared", "does not create"),
        ("app-network", "app_network"),
        ("egress", "egress network"),
        ("isolated", "isolated network"),
    ],
)
def test_a_network_the_target_does_not_offer_is_refused(
    installed, repo_root, tmp_path, variant, fragment
):
    shutil_copy_addon_api(repo_root)
    target = _target_manifest()
    compose = _target_compose()
    network = OFFER
    if variant == "no-exposes-service":
        network = "${PAPAIA_PROJECT:-papaia}-flow-side"
        compose["networks"]["side"] = {"name": network, "internal": True}
        compose["services"]["db"]["networks"] = ["data", "side"]
    elif variant == "not-internal":
        compose["networks"]["modules"] = {"name": OFFER}
    elif variant == "not-declared":
        network = "${PAPAIA_PROJECT:-papaia}-flow-elsewhere"
    elif variant == "app-network":
        network = FLOW_APP
        compose["services"]["relay"]["networks"]["app"] = {}
    elif variant == "egress":
        network = "${PAPAIA_PROJECT:-papaia}-flow-egress"
        compose["networks"]["out"] = {"name": network, "internal": True}
        compose["services"]["relay"]["networks"]["out"] = {}
        target["networks"]["egress"] = {"network": network, "allow": []}
    elif variant == "isolated":
        network = "${PAPAIA_PROJECT:-papaia}-flow-reader-net"
        compose["networks"]["iso"] = {"name": network, "internal": True}
        compose["services"]["relay"]["networks"]["iso"] = {}
        target["networks"]["isolated"] = [{"network": network, "attach": ["litellm"]}]
    consumer = _consumer_manifest({"addon": "flow", "services": ["gate"], "network": network})
    _, assist = _install(installed, tmp_path, consumer, target, compose)

    result = _gate(installed, repo_root, assist)

    assert result.status == compat.STATUS_ERROR
    assert "networks.join_addons[0]" in result.reason
    assert fragment in result.reason
    # A refusal is a malformed manifest: not even --force or warn mode lets it in.
    assert compat.gate([result], mode=compat.MODE_WARN, force=True) == 2


def test_doctor_and_addon_check_see_the_refusal(installed, repo_root, tmp_path):
    shutil_copy_addon_api(repo_root)
    compose = _target_compose()
    compose["networks"]["modules"] = {"name": OFFER}
    _install(installed, tmp_path, target_compose=compose)
    deployed = deployment.load(installed)

    results = cli_addon.evaluate_active_addons(deployed, repo_root, _core())

    by_name = {r.name: r for r in results}
    assert by_name["assist"].status == compat.STATUS_ERROR
    assert "networks.join_addons[0]" in by_name["assist"].reason


def test_a_core_network_cannot_be_joined():
    manifest = _consumer_manifest()
    manifest["requires"]["addons"] = ["audit"]
    manifest["networks"]["join_addons"] = [
        {"addon": "audit", "services": ["gate"], "network": "papaia-audit-net"}
    ]
    core = _core(networks=compat.resolve_core_networks(REPO))

    result = compat.evaluate_addon("assist", manifest, core)

    assert result.status == compat.STATUS_ERROR
    assert "networks.join_addons[0]" in result.reason
    assert "core network" in result.reason


@pytest.mark.parametrize(
    "entry,fragment",
    [
        ({"addon": "flow", "services": ["gate"], "network": OFFER, "alias": "x"},
         "unknown field"),
        ({"addon": "flow", "services": ["gate"], "network": ""}, "network name"),
        ({"addon": "flow", "services": ["gate"], "network": 7}, "network name"),
        ({"addon": "flow", "services": ["gate"], "network": "papaia-other-modules"},
         "scoped to the add-on 'flow'"),
        ({"addon": "flow", "services": ["gate"], "network": "bridge"},
         "scoped to the add-on 'flow'"),
        ({"addon": "flow", "services": ["gate"], "network": "papaia-flow-" + "x" * 70},
         "scoped to the add-on 'flow'"),
    ],
)
def test_a_malformed_entry_is_refused_with_the_entry_named(entry, fragment):
    manifest = _consumer_manifest(entry)
    result = compat.evaluate_addon("assist", manifest, _core())
    assert result.status == compat.STATUS_ERROR
    assert "networks.join_addons[0]" in result.reason
    assert fragment in result.reason


def test_the_app_network_of_a_target_joined_through_its_offer_is_refused():
    manifest = _consumer_manifest(
        {"addon": "flow", "services": ["gate"], "network": OFFER},
        {"addon": "flow", "services": ["web"]},
    )
    result = compat.evaluate_addon("assist", manifest, _core())
    assert result.status == compat.STATUS_ERROR
    assert "networks.join_addons[1]" in result.reason
    assert "app_network of 'flow'" in result.reason


def test_a_core_below_the_generation_refuses_the_key():
    result = compat.evaluate_addon("assist", _consumer_manifest(), _core(addon_api=(1, 16)))
    assert result.status == compat.STATUS_INCOMPATIBLE
    assert "networks.join_addons[0].network" in result.reason
    assert "missing generation 17" in result.reason
    assert compat.gate([result], mode=compat.MODE_ENFORCE) == 2


@pytest.mark.parametrize("addon_api", [(4,), (4, 17), (16, 17)])
def test_the_key_needs_a_manifest_an_older_core_refuses(addon_api):
    # An older core reads the entry without `network` and would join the app network;
    # only a manifest whose every generation is 17 or later is refused there.
    result = compat.evaluate_addon("assist", _consumer_manifest(addon_api=addon_api), _core())
    assert result.status == compat.STATUS_ERROR
    assert "networks.join_addons[0]" in result.reason
    assert "17" in result.reason


def test_the_key_is_a_generation_feature():
    assert compat.GENERATION_FEATURES["networks.join_addons.network"] == 17
    assert compat.manifest_generation_features(_consumer_manifest()) == [
        ("networks.join_addons[0].network", 17)
    ]
    plain = _consumer_manifest({"addon": "flow", "services": ["gate"]})
    assert compat.manifest_generation_features(plain) == []


def test_joined_addons_keeps_its_shape():
    manifest = _consumer_manifest()
    assert compat.joined_addons(manifest) == [("flow", ["gate"])]
    (entry,) = compat.join_entries(manifest)
    assert (entry.addon, entry.services, entry.network, entry.index) == (
        "flow", ["gate"], OFFER, 0
    )
