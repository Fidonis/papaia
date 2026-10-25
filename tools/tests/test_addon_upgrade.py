"""`addon upgrade | rollback | list`: the plan, the refusals, the apply step, the way back.

The handlers run in-process against a synthetic checkout and a throwaway config
directory, with two versions of the paperless fixture in directories of the same
name (`<tmp>/v1/paperless`, `<tmp>/v2/paperless`), the way a caller that keeps one
directory per version lays them out. The bash half is covered by
test_addon_upgrade_cli.py.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from lib import addon_upgrade, cli_addon, common, envtree

FIXTURES = Path(__file__).parent / "fixtures"
SCHEMAS = Path(__file__).resolve().parents[1] / "schemas"
UPGRADE_SCHEMA = json.loads((SCHEMAS / "addon-upgrade.schema.json").read_text("utf-8"))
LIST_SCHEMA = json.loads((SCHEMAS / "addon-list.schema.json").read_text("utf-8"))


def _args(config_dir: Path, repo_root: Path, **fields) -> argparse.Namespace:
    base = {"config_dir": str(config_dir), "repo_root": str(repo_root), "name": "paperless"}
    return argparse.Namespace(**{**base, **fields})


def _plan(config_dir, repo_root, path, **fields) -> int:
    fields = {
        "force": False,
        "json": False,
        "answers_file": None,
        "answers_out": None,
        **fields,
    }
    return cli_addon.cmd_addon_upgrade_plan(_args(config_dir, repo_root, path=str(path), **fields))


def _apply(config_dir, repo_root, path, **fields) -> int:
    fields = {"force": False, "answers_file": None, "restore_point": None, **fields}
    return cli_addon.cmd_addon_upgrade_apply(_args(config_dir, repo_root, path=str(path), **fields))


def _deployment(config_dir: Path) -> dict:
    return yaml.safe_load((config_dir / "deployment.yaml").read_text(encoding="utf-8"))


def _entry(config_dir: Path) -> dict:
    return next(a for a in _deployment(config_dir)["addons"] if a["name"] == "paperless")


def _bundle(config_dir: Path) -> dict[str, str]:
    return common.parse_env_file(config_dir / "addons" / "paperless" / ".env")


def _snapshot(config_dir: Path) -> tuple[bytes, bytes]:
    return (
        (config_dir / "deployment.yaml").read_bytes(),
        (config_dir / "addons" / "paperless" / ".env").read_bytes(),
    )


def _write_answers(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    return path


@pytest.fixture
def world(tmp_path, repo_root, config_dir) -> dict:
    """v1 installed, v2 next to it, nothing answered yet."""
    envtree.init(config_dir, repo_root, env_name="papaia")
    v1 = tmp_path / "v1" / "paperless"
    v2 = tmp_path / "v2" / "paperless"
    shutil.copytree(FIXTURES / "addon-paperless", v1)
    shutil.copytree(FIXTURES / "addon-paperless-v2", v2)
    installed = cli_addon.cmd_addon_install(
        _args(config_dir, repo_root, path=str(v1), version=None, force=False)
    )
    assert installed == 0
    return {
        "tmp": tmp_path,
        "repo": repo_root,
        "config": config_dir,
        "v1": v1,
        "v2": v2,
        "answers": _write_answers(tmp_path / "answers", "PAPERLESS_ADMIN_MAIL=ops@example.org\n"),
    }


# ── the plan, as a pure function ─────────────────────────────────────────────


def _candidate(old: dict, new: dict, *, same_path: bool = False) -> addon_upgrade.Candidate:
    old_path = Path("/srv/v1/demo")
    return addon_upgrade.Candidate(
        name="demo",
        entry={"name": "demo", "path": str(old_path), "active": True},
        current_path=old_path,
        current_manifest={"name": "demo", **old},
        new_path=old_path if same_path else Path("/srv/v2/demo"),
        new_manifest={"name": "demo", **new},
    )


def _plan_of(candidate, *, old_env=None, new_env=None, bundle=None, core=None) -> dict:
    return addon_upgrade.plan_upgrade(
        candidate,
        current_example=old_env or {},
        new_example=new_env or {},
        bundle_env=bundle or {},
        core_env=core or {},
    )


def test_a_new_key_is_classified_by_what_its_example_value_says():
    new_env = {
        "SECRET": "GENERATE_SECRET",
        "ASK": "CHANGE_ME",
        "CLIENT": "REPLACE_WITH_CLIENT",
        "PLAIN": "eng",
    }
    plan = _plan_of(_candidate({}, {}), new_env=new_env)

    assert {i["key"]: i["class"] for i in plan["env"]["new"]} == {
        "SECRET": "generated",
        "ASK": "change_me",
        "CLIENT": "replace_secret",
        "PLAIN": "literal",
    }
    literal = next(i for i in plan["env"]["new"] if i["key"] == "PLAIN")
    assert literal["value"] == "eng"


def test_a_key_the_manifest_lists_as_a_replaced_secret_is_one_whatever_its_value():
    candidate = _candidate({}, {"env_replace_secrets": {"TOKEN": {"hint": "copy it"}}})
    plan = _plan_of(candidate, new_env={"TOKEN": "placeholder"})

    item = plan["env"]["new"][0]
    assert item["class"] == "replace_secret"
    assert item["label"] == "copy it"


def test_only_a_change_me_key_without_a_default_needs_input():
    prompts = {
        "PLAIN_DEFAULT": {"default": "Europe/Berlin"},
        "FROM_CORE": {"default_from_core": "OIDC_ISSUER"},
        "CORE_UNSET": {"default_from_core": "NOT_THERE"},
        "ASK": {"label": "Mail"},
    }
    keys = ["PLAIN_DEFAULT", "FROM_CORE", "CORE_UNSET", "ASK", "BARE"]
    new_env = dict.fromkeys(keys, "CHANGE_ME")
    plan = _plan_of(
        _candidate({}, {"env_prompts": prompts}),
        new_env=new_env,
        core={"OIDC_ISSUER": "https://auth.example.org"},
    )

    defaults = {i["key"]: i["default"] for i in plan["env"]["new"]}
    assert defaults == {
        "PLAIN_DEFAULT": "Europe/Berlin",
        "FROM_CORE": "https://auth.example.org",
        "CORE_UNSET": None,
        "ASK": None,
        "BARE": None,
    }
    assert plan["needs_input"] == ["CORE_UNSET", "ASK", "BARE"]


def test_a_core_value_that_is_itself_a_placeholder_is_no_default():
    candidate = _candidate({}, {"env_prompts": {"URL": {"default_from_core": "PUBLIC"}}})

    for placeholder in ("CHANGE_ME", "GENERATE_SECRET"):
        plan = _plan_of(candidate, new_env={"URL": "CHANGE_ME"}, core={"PUBLIC": placeholder})
        assert plan["needs_input"] == ["URL"]


def test_a_key_the_bundle_already_has_is_not_new_whatever_the_examples_say():
    plan = _plan_of(
        _candidate({}, {}),
        old_env={"KEPT": "a"},
        new_env={"KEPT": "b", "LOST_FROM_BUNDLE": "x"},
        bundle={"KEPT": "mine"},
    )

    assert [i["key"] for i in plan["env"]["new"]] == ["LOST_FROM_BUNDLE"]


def test_removed_and_changed_defaults_are_reported_but_secrets_are_not_diffed():
    plan = _plan_of(
        _candidate({}, {}),
        old_env={"GONE": "1", "PORT": "8010", "SEED": "GENERATE_A", "ASK": "CHANGE_ME"},
        new_env={"PORT": "8011", "SEED": "GENERATE_B", "ASK": "CHANGE_ME"},
    )

    assert plan["env"]["removed"] == ["GONE"]
    assert plan["env"]["default_changed"] == [{"key": "PORT", "from": "8010", "to": "8011"}]


def test_the_component_delta_is_by_id():
    def comp(ident, version):
        return {"id": ident, "name": ident.title(), "version": version}

    plan = _plan_of(
        _candidate(
            {"components": [comp("app", "1"), comp("db", "16"), comp("old", "2")]},
            {"components": [comp("app", "2"), comp("db", "16"), comp("cache", "7")]},
        )
    )

    delta = plan["components"]
    assert delta["added"] == [{"id": "cache", "name": "Cache", "version": "7"}]
    assert delta["removed"] == [{"id": "old", "name": "Old", "version": "2"}]
    assert delta["changed"] == [{"id": "app", "name": "App", "from": "1", "to": "2"}]


def test_the_manifest_delta_covers_what_a_reviewer_has_to_know():
    old = {
        "version": "1.0.0",
        "requires": {"addon_api": 1},
        "networks": {"attach": ["librechat", "keycloak"]},
        "integration": {"keycloak": {"clients": ["a.json"], "client_mappers": {"lc": ["m1.json"]}}},
        "env_replace_secrets": {"OLD": {}},
    }
    new = {
        "version": "1.1.0",
        "requires": {"addon_api": 3},
        "networks": {"attach": ["librechat", "smtp-relay"]},
        "integration": {
            "keycloak": {
                "clients": ["a.json", "b.json"],
                "client_mappers": {"lc": ["m1.json", "m2.json"], "other": ["m3.json"]},
            }
        },
        "env_replace_secrets": {"OLD": {}, "NEW": {}},
    }

    delta = _plan_of(_candidate(old, new))["manifest"]

    assert delta["version"] == {"from": "1.0.0", "to": "1.1.0"}
    assert delta["addon_api"] == {"from": 1, "to": 3}
    assert delta["attach"] == {"added": ["smtp-relay"], "removed": ["keycloak"]}
    assert delta["replace_secrets_added"] == ["NEW"]
    assert delta["keycloak"]["clients_added"] == ["b.json"]
    assert delta["keycloak"]["mappers_added"] == {"lc": ["m2.json"], "other": ["m3.json"]}


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        ("1.0.0", "1.1.0", "upgrade"),
        ("1.1.0", "1.0.0", "downgrade"),
        ("1.0.0", "1.0.0", "same"),
        ("1.0.0-rc.1", "1.0.0", "upgrade"),
        ("nightly", "1.0.0", "unknown"),
    ],
)
def test_direction_follows_semver_precedence(old, new, expected):
    plan = _plan_of(_candidate({"version": old}, {"version": new}))

    assert plan["direction"] == expected


def test_a_manifest_without_a_version_gives_an_unknown_direction():
    assert _plan_of(_candidate({}, {"version": "1.0.0"}))["direction"] == "unknown"


def test_the_same_directory_is_an_in_place_upgrade():
    plan = _plan_of(_candidate({}, {}, same_path=True))

    assert plan["in_place"] is True
    assert "no way back" in addon_upgrade.format_plan(plan)


# ── dry run ──────────────────────────────────────────────────────────────────


def test_a_dry_run_changes_nothing_and_its_json_matches_the_schema(world, capsys):
    before = _snapshot(world["config"])
    capsys.readouterr()

    rc = _plan(world["config"], world["repo"], world["v2"], json=True)

    assert rc == 0
    plan = json.loads(capsys.readouterr().out)
    assert list(Draft202012Validator(UPGRADE_SCHEMA).iter_errors(plan)) == []
    assert plan["blocked"] is False
    assert plan["compat"]["status"] == "OK"
    assert plan["needs_input"] == ["PAPERLESS_ADMIN_MAIL"]
    assert plan["current"]["version"] == "1.0.0"
    assert plan["candidate"]["version"] == "1.1.0"
    assert _snapshot(world["config"]) == before
    assert not (world["v2"] / ".env").exists()


def test_the_text_plan_names_what_changes(world, capsys):
    capsys.readouterr()

    assert _plan(world["config"], world["repo"], world["v2"]) == 0

    out = capsys.readouterr().out
    assert "Upgrade paperless: 1.0.0 -> 1.1.0" in out
    assert "PAPERLESS_ADMIN_MAIL: needs a value" in out
    assert "PAPERLESS_API_TOKEN: a secret is generated" in out
    assert "PAPERLESS_EXT_PORT: 8010 -> 8011" in out
    assert "+ Paperless-ngx 3.0.6" in out
    assert "PAPERLESS_DBUSER" in out


def test_json_is_only_for_a_dry_run(world, capsys):
    rc = _plan(world["config"], world["repo"], world["v2"], json=True, answers_out="x")

    assert rc == 2
    assert "--dry-run" in capsys.readouterr().err


def test_a_dry_run_against_a_version_the_gate_refuses_still_prints_the_plan(world, capsys):
    manifest = world["v2"] / "papaia-app.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(">=0.8.0", ">=99.0.0"), encoding="utf-8"
    )
    capsys.readouterr()

    rc = _plan(world["config"], world["repo"], world["v2"], json=True)

    assert rc == 2
    captured = capsys.readouterr()
    plan = json.loads(captured.out)
    assert plan["blocked"] is True
    assert plan["compat"]["status"] == "INCOMPATIBLE"
    assert "incompatible" in captured.err


# ── refusals leave everything as it was ──────────────────────────────────────


def test_a_version_the_gate_refuses_changes_nothing(world, capsys):
    manifest = world["v2"] / "papaia-app.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(">=0.8.0", ">=99.0.0"), encoding="utf-8"
    )
    before = _snapshot(world["config"])

    rc = _apply(world["config"], world["repo"], world["v2"], answers_file=str(world["answers"]))

    assert rc == 2
    assert "incompatible" in capsys.readouterr().err
    assert _snapshot(world["config"]) == before
    assert not (world["v2"] / ".env").exists()


def test_force_applies_a_version_the_gate_would_refuse(world):
    manifest = world["v2"] / "papaia-app.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(">=0.8.0", ">=99.0.0"), encoding="utf-8"
    )

    rc = _apply(
        world["config"], world["repo"], world["v2"], answers_file=str(world["answers"]), force=True
    )

    assert rc == 0
    assert _entry(world["config"])["version"] == "1.1.0"


def test_a_directory_with_another_name_is_refused(world, capsys):
    other = world["tmp"] / "v2" / "paperless-next"
    shutil.copytree(world["v2"], other)
    before = _snapshot(world["config"])

    assert _plan(world["config"], world["repo"], other) == 2
    assert _apply(world["config"], world["repo"], other) == 2

    err = capsys.readouterr().err
    assert "paperless-next" in err
    assert "project" in err
    assert _snapshot(world["config"]) == before


def test_a_manifest_of_another_add_on_is_refused(world, capsys):
    manifest = world["v2"] / "papaia-app.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace("name: paperless", "name: stranger", 1),
        encoding="utf-8",
    )

    assert _plan(world["config"], world["repo"], world["v2"]) == 2
    assert "'stranger', not of 'paperless'" in capsys.readouterr().err


def test_a_path_that_is_no_directory_is_refused(world, capsys):
    assert _plan(world["config"], world["repo"], world["tmp"] / "nowhere" / "paperless") == 2
    assert "not a directory" in capsys.readouterr().err


def test_an_add_on_that_is_not_registered_or_not_active_is_refused(world, capsys):
    args = _args(world["config"], world["repo"], path=str(world["v2"]), force=False, json=False)
    args.answers_file = args.answers_out = None
    args.name = "ghost"
    assert cli_addon.cmd_addon_upgrade_plan(args) == 2
    assert "not registered" in capsys.readouterr().err

    cli_addon.cmd_addon_remove(_args(world["config"], world["repo"]))
    assert _plan(world["config"], world["repo"], world["v2"]) == 2
    assert "not active" in capsys.readouterr().err


def test_a_missing_value_stops_the_plan_before_any_answers_are_written(world, capsys):
    out = world["tmp"] / "collected"
    before = _snapshot(world["config"])

    rc = _plan(world["config"], world["repo"], world["v2"], answers_out=str(out))

    assert rc == 2
    assert "no value for: PAPERLESS_ADMIN_MAIL" in capsys.readouterr().err
    assert not out.exists()
    assert _snapshot(world["config"]) == before


def test_the_apply_step_checks_for_missing_values_again(world, capsys):
    before = _snapshot(world["config"])

    rc = _apply(world["config"], world["repo"], world["v2"])

    assert rc == 2
    assert "PAPERLESS_ADMIN_MAIL" in capsys.readouterr().err
    assert _snapshot(world["config"]) == before
    assert not (world["v2"] / ".env").exists()


def test_an_empty_answer_counts_as_missing(world):
    answers = _write_answers(world["tmp"] / "empty", "PAPERLESS_ADMIN_MAIL=\n")

    rc = _plan(
        world["config"],
        world["repo"],
        world["v2"],
        answers_file=str(answers),
        answers_out=str(world["tmp"] / "out"),
    )

    assert rc == 2


def test_an_answers_file_may_only_set_keys_the_plan_asks_about(world, capsys):
    answers = _write_answers(
        world["tmp"] / "extra",
        "PAPERLESS_ADMIN_MAIL=ops@example.org\nPAPERLESS_DBPASS=takeover\nUNRELATED=1\n",
    )
    before = _snapshot(world["config"])

    rc = _apply(world["config"], world["repo"], world["v2"], answers_file=str(answers))

    assert rc == 2
    err = capsys.readouterr().err
    assert "PAPERLESS_DBPASS" in err
    assert "UNRELATED" in err
    assert "takeover" not in err
    assert _snapshot(world["config"]) == before


def test_a_missing_answers_file_is_refused(world, capsys):
    rc = _apply(
        world["config"], world["repo"], world["v2"], answers_file=str(world["tmp"] / "nope")
    )

    assert rc == 2
    assert "--answers-file not found" in capsys.readouterr().err


@pytest.mark.skipif(os.name != "posix", reason="file modes")
def test_an_answers_file_other_users_can_read_is_warned_about_without_echoing_it(world, capsys):
    answers = world["tmp"] / "loose"
    answers.write_text("PAPERLESS_ADMIN_MAIL=ops@example.org\n", encoding="utf-8")
    answers.chmod(0o644)

    assert _apply(world["config"], world["repo"], world["v2"], answers_file=str(answers)) == 0

    err = capsys.readouterr().err
    assert "readable by other users" in err
    assert "ops@example.org" not in err


def _asks_for(plan_keys: list[str]) -> dict:
    return {
        "env": {
            "new": [
                {"key": k, "class": "change_me", "default": None, "label": f"label {k}"}
                for k in plan_keys
            ]
        },
        "needs_input": plan_keys,
    }


def test_a_terminal_is_prompted_for_each_missing_value(monkeypatch):
    asked = []
    monkeypatch.setattr("builtins.input", lambda text: asked.append(text) or "ops@example.org")
    monkeypatch.setattr("getpass.getpass", lambda text: asked.append(text) or "s3cret")

    answers = addon_upgrade.collect_answers(
        _asks_for(["ADMIN_MAIL", "ADMIN_PASSWORD"]), {}, interactive=True
    )

    assert answers == {"ADMIN_MAIL": "ops@example.org", "ADMIN_PASSWORD": "s3cret"}
    assert asked == ["  label ADMIN_MAIL: ", "  label ADMIN_PASSWORD: "]


def test_a_prompt_is_only_for_what_the_answers_file_left_open(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda text: "second")

    answers = addon_upgrade.collect_answers(
        _asks_for(["FIRST", "SECOND"]), {"FIRST": "given"}, interactive=True
    )

    assert answers == {"FIRST": "given", "SECOND": "second"}


def test_a_prompt_that_meets_the_end_of_input_ends_in_a_refusal_not_a_crash(monkeypatch):
    def end_of_input(_text):
        raise EOFError

    monkeypatch.setattr("builtins.input", end_of_input)

    with pytest.raises(addon_upgrade.UpgradeError, match="no value for: ADMIN_MAIL"):
        addon_upgrade.collect_answers(_asks_for(["ADMIN_MAIL"]), {}, interactive=True)


def test_a_blank_reply_at_the_prompt_leaves_the_value_missing(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda text: "  ")

    with pytest.raises(addon_upgrade.UpgradeError, match="no value for: ADMIN_MAIL"):
        addon_upgrade.collect_answers(_asks_for(["ADMIN_MAIL"]), {}, interactive=True)


def test_the_collected_answers_are_written_privately(world):
    out = world["tmp"] / "collected"

    rc = _plan(
        world["config"],
        world["repo"],
        world["v2"],
        answers_file=str(world["answers"]),
        answers_out=str(out),
    )

    assert rc == 0
    assert common.parse_env_file(out) == {"PAPERLESS_ADMIN_MAIL": "ops@example.org"}
    if os.name == "posix":
        assert out.stat().st_mode & 0o077 == 0


# ── applying ─────────────────────────────────────────────────────────────────


def test_an_upgrade_repoints_the_add_on_keeps_secrets_and_seeds_only_the_new_keys(world):
    before = _bundle(world["config"])

    rc = _apply(
        world["config"],
        world["repo"],
        world["v2"],
        answers_file=str(world["answers"]),
        restore_point="2026-10-25_10-00-00",
    )

    assert rc == 0
    entry = _entry(world["config"])
    assert entry["path"] == str(world["v2"].resolve())
    assert entry["version"] == "1.1.0"
    assert entry["active"] is True
    assert entry["previous"] == {
        "path": str(world["v1"].resolve()),
        "version": "1.0.0",
        "restore_point": "2026-10-25_10-00-00",
    }

    after = _bundle(world["config"])
    for key, value in before.items():
        assert after[key] == value, f"{key} must not change"
    assert after["PAPERLESS_DBPASS"] == before["PAPERLESS_DBPASS"]
    assert after["PAPERLESS_EXT_PORT"] == "8010"
    assert after["PAPERLESS_DBUSER"] == "paperless"
    assert after["PAPERLESS_ADMIN_MAIL"] == "ops@example.org"
    assert after["PAPERLESS_TIME_ZONE"] == "Europe/Berlin"
    assert after["PAPERLESS_OCR_LANGUAGE"] == "eng"
    assert not common.marks_generated_secret(after["PAPERLESS_API_TOKEN"])
    assert after["PAPERLESS_API_TOKEN"] not in ("", "GENERATE_SECRET")
    assert after["KC_PAPERLESS_MCP_CLIENT_SECRET"].startswith("REPLACE_WITH_")


def test_the_new_directory_gets_the_bundle_env_and_the_old_one_is_left_alone(world):
    old_files = sorted(p.name for p in world["v1"].rglob("*"))

    assert _apply(
        world["config"], world["repo"], world["v2"], answers_file=str(world["answers"])
    ) == 0

    assert common.parse_env_file(world["v2"] / ".env") == _bundle(world["config"])
    assert sorted(p.name for p in world["v1"].rglob("*")) == old_files
    assert not (world["v1"] / ".env").exists()


def test_the_result_lists_what_is_left_to_do_by_hand(world, capsys):
    capsys.readouterr()

    assert _apply(
        world["config"], world["repo"], world["v2"], answers_file=str(world["answers"])
    ) == 0

    out = capsys.readouterr().out
    assert "Addon upgraded: paperless 1.0.0 -> 1.1.0" in out
    assert "Import the Keycloak client integration/keycloak/paperless-mcp.json" in out
    assert "Set KC_PAPERLESS_MCP_CLIENT_SECRET" in out


def test_an_upgrade_without_a_restore_point_records_none(world):
    assert _apply(
        world["config"], world["repo"], world["v2"], answers_file=str(world["answers"])
    ) == 0

    assert "restore_point" not in _entry(world["config"])["previous"]


def test_a_value_the_operator_gave_wins_over_a_manifest_default(world):
    answers = _write_answers(
        world["tmp"] / "both", "PAPERLESS_ADMIN_MAIL=a@b.c\nPAPERLESS_TIME_ZONE=UTC\n"
    )

    assert _apply(world["config"], world["repo"], world["v2"], answers_file=str(answers)) == 0

    assert _bundle(world["config"])["PAPERLESS_TIME_ZONE"] == "UTC"


def test_an_upgrade_in_the_same_directory_keeps_no_way_back(world):
    assert _apply(
        world["config"], world["repo"], world["v1"], answers_file=None
    ) == 0

    entry = _entry(world["config"])
    assert "previous" not in entry
    assert entry["path"] == str(world["v1"].resolve())


def test_only_one_step_is_kept_when_upgrading_twice(world):
    v3 = world["tmp"] / "v3" / "paperless"
    shutil.copytree(world["v2"], v3)
    manifest = v3 / "papaia-app.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace("version: 1.1.0", "version: 1.2.0"),
        encoding="utf-8",
    )
    assert _apply(
        world["config"], world["repo"], world["v2"], answers_file=str(world["answers"]),
        restore_point="first",
    ) == 0

    assert _apply(world["config"], world["repo"], v3, restore_point="second") == 0

    entry = _entry(world["config"])
    assert entry["version"] == "1.2.0"
    assert entry["previous"]["path"] == str(world["v2"].resolve())
    assert entry["previous"]["version"] == "1.1.0"
    assert entry["previous"]["restore_point"] == "second"


def test_an_upgrade_renders_the_add_ons_integration_again(world):
    rendered = world["config"] / "ai" / "librechat" / "librechat.yaml"
    assert "PaperlessMCP" in rendered.read_text(encoding="utf-8")
    (world["v2"] / "integration" / "ai" / "librechat" / "librechat.yaml").write_text(
        "mcpServers:\n  PaperlessMCPv2:\n    type: streamable-http\n    url: http://x/mcp\n",
        encoding="utf-8",
    )

    assert _apply(
        world["config"], world["repo"], world["v2"], answers_file=str(world["answers"])
    ) == 0

    assert "PaperlessMCPv2" in rendered.read_text(encoding="utf-8")


# ── rollback ─────────────────────────────────────────────────────────────────


def _rollback_args(world, **fields) -> argparse.Namespace:
    return _args(world["config"], world["repo"], force=False, **fields)


def _upgraded(world) -> None:
    assert _apply(
        world["config"], world["repo"], world["v2"], answers_file=str(world["answers"]),
        restore_point="2026-10-25_10-00-00",
    ) == 0


def test_a_rollback_plan_names_both_versions_the_directory_and_the_restore_point(world, capsys):
    _upgraded(world)
    capsys.readouterr()

    assert cli_addon.cmd_addon_rollback_plan(_rollback_args(world)) == 0

    lines = dict(line.split("\t", 1) for line in capsys.readouterr().out.splitlines())
    assert lines == {
        "FROM": "1.1.0",
        "TO": "1.0.0",
        "PATH": str(world["v1"].resolve()),
        "RESTORE_POINT": "2026-10-25_10-00-00",
    }


def test_a_rollback_goes_back_one_step_and_forgets_it(world):
    _upgraded(world)
    bundle_after_upgrade = _bundle(world["config"])

    assert cli_addon.cmd_addon_rollback_apply(_rollback_args(world)) == 0

    entry = _entry(world["config"])
    assert entry["path"] == str(world["v1"].resolve())
    assert entry["version"] == "1.0.0"
    assert "previous" not in entry
    # Nothing is taken out of the bundle: the keys of the newer version stay.
    assert _bundle(world["config"]) == bundle_after_upgrade
    assert common.parse_env_file(world["v1"] / ".env") == bundle_after_upgrade


def _install(world, path) -> int:
    return cli_addon.cmd_addon_install(
        _args(world["config"], world["repo"], path=str(path), version=None, force=False)
    )


def test_installing_another_directory_starts_over_and_forgets_the_previous_version(world):
    _upgraded(world)
    assert "previous" in _entry(world["config"])
    third = world["tmp"] / "v3" / "paperless"
    shutil.copytree(world["v2"], third)

    assert _install(world, third) == 0

    entry = _entry(world["config"])
    assert entry["path"] == str(third.resolve())
    assert "previous" not in entry


def test_installing_the_registered_directory_again_keeps_the_previous_version(world):
    _upgraded(world)
    before = _entry(world["config"])["previous"]

    assert _install(world, world["v2"]) == 0

    assert _entry(world["config"])["previous"] == before


def test_a_second_rollback_has_nothing_to_go_back_to(world, capsys):
    _upgraded(world)
    assert cli_addon.cmd_addon_rollback_apply(_rollback_args(world)) == 0
    capsys.readouterr()

    assert cli_addon.cmd_addon_rollback_plan(_rollback_args(world)) == 2
    assert cli_addon.cmd_addon_rollback_apply(_rollback_args(world)) == 2
    assert "no previous version" in capsys.readouterr().err


def test_a_rollback_to_a_directory_that_is_gone_is_refused(world, capsys):
    _upgraded(world)
    shutil.rmtree(world["v1"])
    before = _snapshot(world["config"])

    assert cli_addon.cmd_addon_rollback_apply(_rollback_args(world)) == 2

    assert "is gone" in capsys.readouterr().err
    assert _snapshot(world["config"]) == before


def test_a_rollback_runs_the_gate_against_the_current_core(world, capsys):
    _upgraded(world)
    manifest = world["v1"] / "papaia-app.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(">=0.8.0", ">=99.0.0"), encoding="utf-8"
    )
    before = _snapshot(world["config"])

    assert cli_addon.cmd_addon_rollback_apply(_rollback_args(world)) == 2

    assert "incompatible" in capsys.readouterr().err
    assert _snapshot(world["config"]) == before
    assert _entry(world["config"])["version"] == "1.1.0"


# ── list ─────────────────────────────────────────────────────────────────────


def test_the_json_list_matches_the_schema_and_shows_the_way_back(world, capsys):
    _upgraded(world)
    capsys.readouterr()

    assert cli_addon.cmd_addon_list(_args(world["config"], world["repo"], json=True)) == 0

    document = json.loads(capsys.readouterr().out)
    assert list(Draft202012Validator(LIST_SCHEMA).iter_errors(document)) == []
    (row,) = document["addons"]
    assert row["name"] == "paperless"
    assert row["version"] == "1.1.0"
    assert row["active"] is True
    assert row["compat"]["status"] == "OK"
    assert [c["id"] for c in row["components"]] == ["paperless-ngx", "redis"]
    assert row["previous"] == {
        "path": str(world["v1"].resolve()),
        "version": "1.0.0",
        "restore_point": "2026-10-25_10-00-00",
        "available": True,
    }
    assert document["core"]["version"] == "0.8.0"


def test_the_list_says_when_the_previous_directory_is_gone(world, capsys):
    _upgraded(world)
    shutil.rmtree(world["v1"])
    capsys.readouterr()

    cli_addon.cmd_addon_list(_args(world["config"], world["repo"], json=True))

    (row,) = json.loads(capsys.readouterr().out)["addons"]
    assert row["previous"]["available"] is False


def test_the_list_reports_an_unreadable_manifest_instead_of_failing(world, capsys):
    (world["v1"] / "papaia-app.yaml").unlink()
    capsys.readouterr()

    assert cli_addon.cmd_addon_list(_args(world["config"], world["repo"], json=True)) == 0

    document = json.loads(capsys.readouterr().out)
    assert list(Draft202012Validator(LIST_SCHEMA).iter_errors(document)) == []
    (row,) = document["addons"]
    assert "not found" in row["error"]
    assert row["compat"] is None
    assert row["components"] == []


def test_the_text_list_is_a_table(world, capsys):
    _upgraded(world)
    capsys.readouterr()

    assert cli_addon.cmd_addon_list(_args(world["config"], world["repo"], json=False)) == 0

    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == ["NAME", "VERSION", "ACTIVE", "COMPAT", "PREVIOUS"]
    assert lines[1].split() == ["paperless", "1.1.0", "yes", "OK", "1.0.0"]


def test_the_list_without_a_deployment_asks_for_setup(tmp_path, repo_root, capsys):
    rc = cli_addon.cmd_addon_list(_args(tmp_path / "empty", repo_root, json=False))

    assert rc == 2
    assert "papaia-ctl setup" in capsys.readouterr().err
