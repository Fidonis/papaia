"""Lifetime of delegations (offline sessions): one setting per installation (PLT-58-A6,
PLT-58-A9 after Ä-57; security 1.7, 1.10, 1.16).

`delegations.idle_days` / `delegations.max_days` default to 90 / 180 days in profile
`standard` and may be set from 1 to 365 days each, idle never above the maximum age; in
profile `kritis` 7 / 30 days are default and upper bound. The administration changes them
with `papaia-ctl delegations lifetime`, which keeps them in
`$PAPAIA_CONFIG_DIR/settings/delegations.json`; the rendered realm and `realm sync` write
them as Offline Session Idle / Max (maximum switched on), the platform catalog publishes
them, every change and every refused change is one `delegation_lifetime_changed` audit
row, and the permission report shows the values in effect.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from lib import catalog, render_core
from lib import delegation_lifetime as dl
from lib import realm_hardening as rh
from lib import realm_sync as rs
from tests.test_audit import FakeStore, _ingest
from tests.test_catalog import NOW, REPO, _install, _services
from tests.test_realm_hardening import HOSTS, LIBRECHAT, _bake
from tests.test_realm_sync import _config, _tree, connected  # noqa: F401  (fixture)

TOOLS = Path(__file__).resolve().parents[1]
CTL = TOOLS / "papaia-ctl"
BASH = shutil.which("bash")
needs_bash = pytest.mark.skipif(BASH is None, reason="bash is not available")
DAY = 86400


def _root(config_dir: Path, profile: str = "standard") -> dict[str, str]:
    """A root .env with the security profile; returns it as papaia-ctl reads it."""
    config_dir.mkdir(parents=True, exist_ok=True)
    env_file = config_dir / ".env"
    lines = [
        line
        for line in (env_file.read_text().splitlines() if env_file.exists() else [])
        if not line.startswith(f"{rh.PROFILE_KEY}=")
    ]
    env_file.write_text("\n".join([*lines, f"{rh.PROFILE_KEY}={profile}"]) + "\n")
    return {rh.PROFILE_KEY: profile}


def _rows(config_dir: Path) -> list[dict]:
    path = rs.audit_path(config_dir)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _set(config_dir: Path, idle: str | None, age: str | None, capsys=None) -> int:
    return dl.main(config_dir, idle, age)


# ─────────────────────────────────────────────────────────────────────────
# defaults and bounds
# ─────────────────────────────────────────────────────────────────────────


def test_a_fresh_standard_installation_has_90_and_180_days(tmp_path):
    config_dir = tmp_path / "config"
    env = _root(config_dir)
    assert dl.effective(config_dir, env) == dl.Lifetime(90, 180, "default")
    realm = rh.load(env).settings.realm()
    assert realm["offlineSessionIdleTimeout"] == 90 * DAY
    assert realm["offlineSessionMaxLifespanEnabled"] is True
    assert realm["offlineSessionMaxLifespan"] == 180 * DAY


def test_a_fresh_kritis_installation_has_7_and_30_days(tmp_path):
    config_dir = tmp_path / "config"
    env = _root(config_dir, "kritis")
    assert dl.effective(config_dir, env) == dl.Lifetime(7, 30, "default")
    realm = rh.load(env).settings.realm()
    assert realm["offlineSessionIdleTimeout"] == 7 * DAY
    assert realm["offlineSessionMaxLifespan"] == 30 * DAY


@pytest.mark.parametrize(
    ("profile", "idle", "age"),
    [
        ("standard", 365, 365),
        ("standard", 1, 1),
        ("standard", 7, 30),  # the handbook's recommendation with federation
        ("standard", 120, 365),
        ("kritis", 7, 30),
        ("kritis", 5, 20),
        ("kritis", 1, 14),
    ],
)
def test_values_within_the_bounds_of_the_profile_are_accepted(profile, idle, age):
    dl.check(profile, idle, age)
    settings = rh.load({rh.PROFILE_KEY: profile}, lifetime=(idle, age)).settings
    assert (settings.idle_days, settings.max_days) == (idle, age)
    assert settings.realm()["offlineSessionIdleTimeout"] == idle * DAY
    assert settings.realm()["offlineSessionMaxLifespan"] == age * DAY


@pytest.mark.parametrize(
    ("profile", "idle", "age", "message"),
    [
        ("standard", 400, 400, "1 to 365"),
        ("standard", 365, 366, "1 to 365"),
        ("standard", 0, 10, "1 to 365"),
        ("standard", -1, 10, "1 to 365"),
        ("standard", 200, 100, "greater than"),
        ("kritis", 8, 30, "1 to 7"),
        ("kritis", 7, 31, "1 to 30"),
        ("kritis", 90, 180, "1 to 7"),
        ("kritis", 365, 365, "1 to 7"),
        ("kritis", 7, 5, "greater than"),
    ],
)
def test_values_outside_the_bounds_are_refused(profile, idle, age, message):
    with pytest.raises(dl.LifetimeError, match=message):
        dl.check(profile, idle, age)
    with pytest.raises(rh.HardeningError, match=message):
        rh.load({rh.PROFILE_KEY: profile}, lifetime=(idle, age))


@pytest.mark.parametrize("value", [True, 7.0, "7", None])
def test_only_whole_numbers_are_days(value):
    with pytest.raises(dl.LifetimeError):
        dl.check("standard", value, 30)


# ─────────────────────────────────────────────────────────────────────────
# the change: papaia-ctl delegations lifetime --idle-days=N --max-days=N
# ─────────────────────────────────────────────────────────────────────────


def test_the_administration_sets_365_and_365(tmp_path, capsys):
    config_dir = tmp_path / "config"
    env = _root(config_dir)
    assert _set(config_dir, "365", "365") == 0
    assert dl.stored(config_dir) == (365, 365)
    assert dl.effective(config_dir, env) == dl.Lifetime(365, 365, "setting")
    assert "365" in capsys.readouterr().out
    mode = dl.settings_path(config_dir).stat().st_mode & 0o777
    assert mode == 0o600


@pytest.mark.parametrize(
    ("idle", "age"),
    [
        ("400", "400"),
        ("365", "400"),
        ("400", None),
        ("0", "10"),
        ("-1", "10"),
        ("7.5", "30"),
        ("abc", "30"),
        ("", "30"),
        ("2" * 30, "30"),
        ("200", "100"),
        ("200", None),  # above the default maximum age of 180
        (None, None),
    ],
)
def test_a_refused_value_changes_nothing_and_is_audited_without_values(tmp_path, capsys, idle, age):
    config_dir = tmp_path / "config"
    _root(config_dir)
    assert _set(config_dir, idle, age) == 2
    assert "Nothing was changed" in capsys.readouterr().err
    assert not dl.settings_path(config_dir).exists()
    rows = _rows(config_dir)
    if idle is None and age is None:
        assert rows == []  # a call without values only shows them
        return
    (row,) = rows
    assert (row["event"], row["result"], row["error_code"]) == (
        "delegation_lifetime_changed",
        "denied",
        "PK-INPUT-001",
    )
    assert row["detail"] is None
    # The value asked for appears nowhere (the correlation id and the time are random).
    text = json.dumps({k: v for k, v in row.items() if k not in ("correlation_id", "time")})
    assert "400" not in text and "abc" not in text


def test_one_value_alone_keeps_the_other(tmp_path):
    config_dir = tmp_path / "config"
    env = _root(config_dir)
    assert _set(config_dir, None, "365") == 0
    assert dl.effective(config_dir, env) == dl.Lifetime(90, 365, "setting")
    assert _set(config_dir, "120", None) == 0
    assert dl.effective(config_dir, env) == dl.Lifetime(120, 365, "setting")


def test_kritis_takes_shorter_values_and_refuses_higher_ones(tmp_path):
    config_dir = tmp_path / "config"
    env = _root(config_dir, "kritis")
    assert _set(config_dir, "5", "20") == 0
    assert dl.effective(config_dir, env) == dl.Lifetime(5, 20, "setting")
    assert _set(config_dir, "8", "30") == 2
    assert _set(config_dir, "7", "31") == 2
    assert dl.effective(config_dir, env) == dl.Lifetime(5, 20, "setting")
    assert _set(config_dir, "7", "30") == 0
    assert dl.effective(config_dir, env) == dl.Lifetime(7, 30, "setting")
    rows = _rows(config_dir)
    assert [(r["result"], r["detail"]) for r in rows] == [
        ("allowed", {"idle_days_old": 7, "idle_days_new": 5, "max_days_old": 30,
                     "max_days_new": 20}),
        ("denied", None),
        ("denied", None),
        ("allowed", {"idle_days_old": 5, "idle_days_new": 7, "max_days_old": 20,
                     "max_days_new": 30}),
    ]


def test_every_change_is_one_audit_row_with_old_and_new_values(tmp_path):
    config_dir = tmp_path / "config"
    _root(config_dir)
    assert _set(config_dir, "365", "365") == 0
    assert _set(config_dir, "120", "365") == 0
    rows = _rows(config_dir)
    assert [r["detail"] for r in rows] == [
        {"idle_days_old": 90, "idle_days_new": 365, "max_days_old": 180, "max_days_new": 365},
        {"idle_days_old": 365, "idle_days_new": 120, "max_days_old": 365, "max_days_new": 365},
    ]
    for row in rows:
        assert row["format"] == "papaia.audit/1"
        assert row["event"] == "delegation_lifetime_changed"
        assert row["result"] == "allowed" and row["error_code"] is None
        assert row["writer"] == "papaia-ctl/delegations"
        assert row["operation"] == "delegations.set_lifetime"
        assert row["effect"] == "write"
        assert row["object_ref"] == {"type": "setting", "id": "delegations"}
        assert row["sub"].startswith("host:")
        assert row["time"] and row["correlation_id"]
    assert rows[0]["correlation_id"] != rows[1]["correlation_id"]
    assert [r["source_seq"] for r in rows] == [1, 2]


def test_the_audit_rows_pass_the_audit_service(tmp_path):
    config_dir = tmp_path / "config"
    _root(config_dir)
    _set(config_dir, "365", "365")
    _set(config_dir, "400", "400")
    store = FakeStore()
    result = _ingest(store, *_rows(config_dir), source="papaia-ctl")
    assert result.refused is None
    assert [r["source_seq"] for r in result.acknowledged] == [1, 2]


def test_setting_the_values_in_effect_changes_nothing(tmp_path, capsys):
    config_dir = tmp_path / "config"
    _root(config_dir)
    assert _set(config_dir, "90", "180") == 0
    assert "unchanged" in capsys.readouterr().out
    assert _rows(config_dir) == []
    assert not dl.settings_path(config_dir).exists()


def test_without_values_the_command_shows_the_values_in_effect(tmp_path, capsys):
    config_dir = tmp_path / "config"
    _root(config_dir, "kritis")
    assert dl.main(config_dir, None, None, show=True) == 0
    out = capsys.readouterr().out
    assert "7" in out and "30" in out and "kritis" in out
    assert dl.main(config_dir, None, None, show=True, as_json=True) == 0
    assert json.loads(capsys.readouterr().out) == dl.report(config_dir)
    assert _rows(config_dir) == []


# ─────────────────────────────────────────────────────────────────────────
# the stored setting: strict, and the kritis bound holds for every path
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        '{"format": "papaia.delegation-lifetime/1", "idle_days": 90}',
        '{"format": "papaia.delegation-lifetime/2", "idle_days": 90, "max_days": 180}',
        '{"format": "papaia.delegation-lifetime/1", "idle_days": 90, "max_days": 180, "x": 1}',
        '{"format": "papaia.delegation-lifetime/1", "idle_days": true, "max_days": 180}',
        '{"format": "papaia.delegation-lifetime/1", "idle_days": "90", "max_days": 180}',
        '{"format": "papaia.delegation-lifetime/1", "idle_days": 90.0, "max_days": 180}',
        '{"format": "papaia.delegation-lifetime/1", "idle_days": 366, "max_days": 366}',
        '{"format": "papaia.delegation-lifetime/1", "idle_days": 200, "max_days": 100}',
    ],
)
def test_a_settings_file_that_is_not_valid_is_refused(tmp_path, content):
    config_dir = tmp_path / "config"
    env = _root(config_dir)
    dl.settings_path(config_dir).parent.mkdir(parents=True)
    dl.settings_path(config_dir).write_text(content)
    with pytest.raises(dl.LifetimeError):
        dl.effective(config_dir, env)
    assert _set(config_dir, "30", "60") == 1
    assert dl.settings_path(config_dir).read_text() == content
    assert _rows(config_dir) == []


def test_showing_a_settings_file_that_is_not_valid_fails_without_calling_it_refused(
    tmp_path, capsys
):
    config_dir = tmp_path / "config"
    _root(config_dir)
    dl.settings_path(config_dir).parent.mkdir(parents=True)
    dl.settings_path(config_dir).write_text("not json")
    assert dl.main(config_dir, None, None, show=True) == 1
    err = capsys.readouterr().err
    assert "cannot be used" in err and "refused" not in err


def _over_the_kritis_bound(tmp_path, idle: str = "90", age: str = "365", config_dir=None) -> Path:
    """A setting above 7 / 30 days made in profile standard, then the profile changed."""
    config_dir = tmp_path / "config" if config_dir is None else config_dir
    _root(config_dir)
    # 90 / 180 days are the default of standard: set another value first, so that the
    # file holds them as a setting.
    assert _set(config_dir, "1", "1") == 0
    assert _set(config_dir, idle, age) == 0
    assert dl.stored(config_dir) == (int(idle), int(age))
    _root(config_dir, "kritis")
    return config_dir


@pytest.mark.parametrize(("idle", "age"), [(90, 365), (90, 180), (8, 30)])
def test_a_setting_above_the_kritis_bound_is_replaced_by_one_within_it(tmp_path, idle, age):
    config_dir = _over_the_kritis_bound(tmp_path, str(idle), str(age))
    before = len(_rows(config_dir))
    assert _set(config_dir, "7", "30") == 0
    rows = _rows(config_dir)[before:]
    assert [(r["event"], r["result"], r["detail"]) for r in rows] == [
        (
            "delegation_lifetime_changed",
            "allowed",
            {"idle_days_old": idle, "idle_days_new": 7, "max_days_old": age, "max_days_new": 30},
        )
    ]
    assert dl.effective(config_dir) == dl.Lifetime(7, 30, "setting")
    env = {"AUTH_HOST": "https://auth.example.org", rh.PROFILE_KEY: "kritis", **HOSTS}
    realm = _bake(tmp_path, env, LIBRECHAT)
    assert realm["offlineSessionIdleTimeout"] == 7 * DAY
    assert realm["offlineSessionMaxLifespan"] == 30 * DAY


def test_a_setting_above_the_kritis_bound_takes_only_values_within_it(tmp_path):
    config_dir = _over_the_kritis_bound(tmp_path)
    before = len(_rows(config_dir))
    # A value left out keeps the stored one, which is above the bound.
    assert _set(config_dir, "7", None) == 2
    assert _set(config_dir, "8", "30") == 2
    assert dl.stored(config_dir) == (90, 365)
    assert [(r["result"], r["detail"]) for r in _rows(config_dir)[before:]] == [
        ("denied", None),
        ("denied", None),
    ]


def test_the_report_names_a_setting_above_the_kritis_bound(tmp_path, capsys):
    config_dir = _over_the_kritis_bound(tmp_path, "90", "180")
    assert dl.report(config_dir) == {
        "security_profile": "kritis",
        "idle_days": 90,
        "max_days": 180,
        "source": "setting",
        "within_bound": False,
        "upper_bound": {"idle_days": 7, "max_days": 30},
    }
    assert dl.main(config_dir, None, None, show=True) == 1
    captured = capsys.readouterr()
    assert "90" in captured.out and "180" in captured.out
    assert "above the upper bound" in captured.err and "refused" not in captured.err
    assert dl.main(config_dir, None, None, show=True, as_json=True) == 1
    assert json.loads(capsys.readouterr().out)["within_bound"] is False
    assert _set(config_dir, "7", "30") == 0
    assert dl.report(config_dir)["within_bound"] is True
    assert dl.main(config_dir, None, None, show=True) == 0


def test_a_change_whose_file_write_fails_is_audited_as_an_error(tmp_path, monkeypatch, capsys):
    config_dir = tmp_path / "config"
    _root(config_dir)

    def full_disk(*_args):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(dl, "_write", full_disk)
    assert _set(config_dir, "365", "365") == 1
    assert "failed" in capsys.readouterr().err
    assert not dl.settings_path(config_dir).exists()
    allowed, error = _rows(config_dir)
    assert (allowed["result"], error["result"], error["error_code"]) == ("allowed", "error", "io")
    assert error["correlation_id"] == allowed["correlation_id"]
    assert error["detail"] is None
    store = FakeStore()
    assert _ingest(store, allowed, error, source="papaia-ctl").refused is None


def test_a_stored_setting_above_the_kritis_bound_is_never_used(tmp_path):
    config_dir = _over_the_kritis_bound(tmp_path)
    with pytest.raises(dl.LifetimeError, match="1 to 7"):
        dl.effective(config_dir, {rh.PROFILE_KEY: "kritis"})
    with pytest.raises(rh.HardeningError):
        rh.load({rh.PROFILE_KEY: "kritis"}, lifetime=dl.stored(config_dir))


def test_the_render_refuses_a_setting_above_the_kritis_bound(tmp_path):
    config_dir = tmp_path / "config"
    dl.settings_path(config_dir).parent.mkdir(parents=True)
    dl.settings_path(config_dir).write_text(
        '{"format": "papaia.delegation-lifetime/1", "idle_days": 90, "max_days": 180}'
    )
    env = {"AUTH_HOST": "https://auth.example.org", rh.PROFILE_KEY: "kritis", **HOSTS}
    with pytest.raises(render_core.RenderError, match="1 to 7"):
        _bake(tmp_path, env, LIBRECHAT)


def test_the_rendered_realm_carries_the_setting(tmp_path):
    config_dir = tmp_path / "config"
    dl.settings_path(config_dir).parent.mkdir(parents=True)
    dl.settings_path(config_dir).write_text(
        '{"format": "papaia.delegation-lifetime/1", "idle_days": 365, "max_days": 365}'
    )
    realm = _bake(tmp_path, {"AUTH_HOST": "https://auth.example.org", **HOSTS}, LIBRECHAT)
    assert realm["offlineSessionIdleTimeout"] == 365 * DAY
    assert realm["offlineSessionMaxLifespan"] == 365 * DAY
    assert realm["offlineSessionMaxLifespanEnabled"] is True


def test_the_catalog_refuses_a_setting_above_the_kritis_bound(tmp_path):
    config_dir = _install(tmp_path, "rag", [])
    _root(config_dir, "kritis")
    dl.settings_path(config_dir).parent.mkdir(parents=True)
    dl.settings_path(config_dir).write_text(
        '{"format": "papaia.delegation-lifetime/1", "idle_days": 90, "max_days": 180}'
    )
    with pytest.raises(catalog.CatalogError, match="1 to 7"):
        catalog.build(config_dir, REPO, NOW)


def test_the_catalog_works_again_once_a_value_within_the_kritis_bound_is_set(tmp_path):
    config_dir = _over_the_kritis_bound(
        tmp_path, "90", "180", config_dir=_install(tmp_path, "rag", [])
    )
    with pytest.raises(catalog.CatalogError, match="1 to 7"):
        catalog.build(config_dir, REPO, NOW)
    assert _set(config_dir, "7", "30") == 0
    doc = catalog.build(config_dir, REPO, NOW)
    assert doc is not None
    assert doc["delegations"] == {"idle_days": 7, "max_days": 30}


# ─────────────────────────────────────────────────────────────────────────
# realm sync and catalog apply the values in effect
# ─────────────────────────────────────────────────────────────────────────


def test_realm_sync_writes_the_setting_into_the_realm(tmp_path, connected, capsys):  # noqa: F811
    config_dir, repo_root = _config(tmp_path)
    tree = _tree()
    assert rs.sync(tree, config_dir, repo_root) == 0
    assert connected.realm["offlineSessionIdleTimeout"] == 90 * DAY
    assert connected.realm["offlineSessionMaxLifespan"] == 180 * DAY
    assert connected.realm["offlineSessionMaxLifespanEnabled"] is True
    out = capsys.readouterr().out
    assert "offline sessions: idle 90 d, max age 180 d (profile standard)" in out

    assert dl.main(config_dir, "365", "365") == 0
    assert rs.sync(tree, config_dir, repo_root, check=True) == 1
    assert rs.sync(tree, config_dir, repo_root) == 0
    assert connected.realm["offlineSessionIdleTimeout"] == 365 * DAY
    assert connected.realm["offlineSessionMaxLifespan"] == 365 * DAY
    assert rs.sync(tree, config_dir, repo_root, check=True) == 0


def test_realm_sync_refuses_a_setting_above_the_kritis_bound(tmp_path, connected, capsys):  # noqa: F811
    config_dir, repo_root = _config(tmp_path)
    tree = _tree()
    dl.settings_path(config_dir).parent.mkdir(parents=True)
    dl.settings_path(config_dir).write_text(
        '{"format": "papaia.delegation-lifetime/1", "idle_days": 8, "max_days": 30}'
    )
    tree[""][rh.PROFILE_KEY] = "kritis"
    assert rs.sync(tree, config_dir, repo_root) == 2
    assert "Nothing was changed" in capsys.readouterr().err
    assert connected.writes == []


def test_realm_sync_works_again_once_a_value_within_the_kritis_bound_is_set(
    tmp_path, connected, capsys  # noqa: F811
):
    config_dir, repo_root = _config(tmp_path)
    _over_the_kritis_bound(tmp_path, "90", "180", config_dir=config_dir)
    tree = _tree()
    tree[""][rh.PROFILE_KEY] = "kritis"
    assert rs.sync(tree, config_dir, repo_root) == 2
    assert connected.writes == []
    assert dl.main(config_dir, "7", "30") == 0
    assert rs.sync(tree, config_dir, repo_root) == 0
    assert connected.realm["offlineSessionIdleTimeout"] == 7 * DAY
    assert connected.realm["offlineSessionMaxLifespan"] == 30 * DAY


def test_the_catalog_publishes_the_values_in_effect(tmp_path):
    config_dir = _install(tmp_path, "rag", [])
    assert catalog.render(config_dir, REPO, now=NOW) is True
    assert _services(config_dir)["delegations"] == {"idle_days": 90, "max_days": 180}
    assert dl.main(config_dir, "365", "365") == 0
    assert catalog.render(config_dir, REPO, now=NOW) is True
    assert _services(config_dir)["delegations"] == {"idle_days": 365, "max_days": 365}


def test_the_catalog_of_a_kritis_installation_publishes_7_and_30_days(tmp_path):
    config_dir = _install(tmp_path, "rag", [])
    _root(config_dir, "kritis")
    doc = catalog.build(config_dir, REPO, NOW)
    assert doc is not None
    assert doc["security_profile"] == "kritis"
    assert doc["delegations"] == {"idle_days": 7, "max_days": 30}


# ─────────────────────────────────────────────────────────────────────────
# permission report
# ─────────────────────────────────────────────────────────────────────────


def test_the_permission_report_lists_the_values_in_effect(tmp_path):
    config_dir = tmp_path / "config"
    _root(config_dir, "kritis")
    assert dl.report(config_dir) == {
        "security_profile": "kritis",
        "idle_days": 7,
        "max_days": 30,
        "source": "default",
        "within_bound": True,
        "upper_bound": {"idle_days": 7, "max_days": 30},
    }
    assert _set(config_dir, "3", "14") == 0
    assert dl.report(config_dir)["idle_days"] == 3
    assert dl.report(config_dir)["max_days"] == 14
    assert dl.report(config_dir)["source"] == "setting"
    _root(config_dir)
    assert dl.report(config_dir)["upper_bound"] == {"idle_days": 365, "max_days": 365}


# ─────────────────────────────────────────────────────────────────────────
# the shell command
# ─────────────────────────────────────────────────────────────────────────


def _seeded(path: Path, profile: str = "standard") -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / ".env").write_text(
        f"COMPOSE_PROJECT_NAME=papaia\n{rh.PROFILE_KEY}={profile}\n", encoding="utf-8"
    )
    (path / "deployment.yaml").write_text("core: {}\n", encoding="utf-8")
    return path


def _ctl(config_dir: Path, *args: str) -> subprocess.CompletedProcess[str]:
    assert BASH is not None
    env = dict(os.environ)
    env["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{env.get('PATH', '')}"
    return subprocess.run(
        [BASH, str(CTL), "delegations", *args, f"--config-dir={config_dir}"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )


@needs_bash
def test_the_command_is_dispatched_and_documented():
    text = CTL.read_text(encoding="utf-8")
    assert 'delegations)   cmd_delegations "$@" ;;' in text
    help_text = subprocess.run(
        [BASH, str(CTL), "help"], capture_output=True, text=True, timeout=60, check=False
    ).stdout
    assert (
        "papaia-ctl delegations lifetime [--idle-days=N] [--max-days=N] [--json]" in help_text
    )
    assert "--resume-from=X.Y.Z" in help_text


@needs_bash
def test_the_command_shows_and_refuses_without_keycloak(tmp_path):
    config_dir = _seeded(tmp_path / "config", "kritis")
    done = _ctl(config_dir, "lifetime", "--json")
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["idle_days"] == 7
    done = _ctl(config_dir, "lifetime", "--idle-days=8", "--max-days=30")
    assert done.returncode == 2
    assert "Nothing was changed" in done.stderr
    assert not dl.settings_path(config_dir).exists()
    for args, message in [
        (("renew",), "Unknown 'delegations' subcommand: 'renew'"),
        (("lifetime", "--bogus"), "Unknown option for delegations lifetime: --bogus"),
        (("lifetime", "--idle-days=7", "--json"), "--json only shows the values"),
    ]:
        done = _ctl(config_dir, *args)
        assert done.returncode == 2, args
        assert message in done.stderr, done.stderr


@needs_bash
def test_the_command_shows_a_setting_above_the_kritis_bound(tmp_path):
    config_dir = _seeded(tmp_path / "config", "kritis")
    dl.settings_path(config_dir).parent.mkdir(parents=True)
    dl.settings_path(config_dir).write_text(
        '{"format": "papaia.delegation-lifetime/1", "idle_days": 90, "max_days": 180}'
    )
    done = _ctl(config_dir, "lifetime", "--json")
    assert done.returncode == 1, done.stderr
    shown = json.loads(done.stdout)
    assert (shown["idle_days"], shown["max_days"], shown["within_bound"]) == (90, 180, False)
    assert "above the upper bound" in done.stderr


@pytest.mark.parametrize(
    ("profile", "block", "valid"),
    [
        ("standard", {"idle_days": 365, "max_days": 365}, True),
        ("standard", {"idle_days": 400, "max_days": 400}, False),
        ("kritis", {"idle_days": 7, "max_days": 30}, True),
        ("kritis", {"idle_days": 90, "max_days": 180}, False),
        ("standard", {"idle_days": 90, "max_days": 180, "extra": 1}, False),
    ],
)
def test_the_vendored_catalog_schema_holds_the_bounds(tmp_path, profile, block, valid):
    from lib import exposes, schema_check

    config_dir = _install(tmp_path, "rag", [])
    doc = catalog.build(config_dir, REPO, NOW)
    assert doc is not None
    doc = dict(doc, security_profile=profile, delegations=block)
    schema = exposes.load_schema(exposes.SERVICES_SCHEMA)
    if valid:
        schema_check.validate(doc, schema)
    else:
        with pytest.raises(schema_check.SchemaError):
            schema_check.validate(doc, schema)
