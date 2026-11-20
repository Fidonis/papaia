"""The `pki` profile: requests, settings, the inventory, the doctor check, and (with Docker,
on request) the issuer itself. See docs/pki.md and ADR 0019."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from test_doctor import NOW, result, run_doctor

from lib import cli, common, pki
from lib.doctor import FAIL, PASS, SKIP, WARN

REPO = Path(__file__).resolve().parents[2]
ISSUER_COMPOSE = REPO / "src" / "infra" / "pki" / "docker-compose.yml"

STUDIO_BLOCK = {
    "services": [
        {
            "name": "studio-gateway",
            "uid": 10001,
            "server": {"dns": ["studio-gateway"]},
            "client": True,
        },
        {"name": "studio-app-host", "uid": 10001, "client": True},
        {"name": "studio-postgres", "uid": 70, "server": {"dns": ["studio-postgres", "db.local"]}},
    ]
}


def _addon_manifest(stack, block) -> None:
    path = stack["addon"] / "papaia-app.yaml"
    manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
    manifest["pki"] = block
    path.write_text(yaml.safe_dump(manifest), encoding="utf-8")


def _env(stack) -> dict[str, str]:
    return common.parse_env_file(stack["config"] / ".env")


# ─────────────────────────────────────────────────────────────────────────
# requests
# ─────────────────────────────────────────────────────────────────────────


def test_a_pki_block_becomes_one_request_per_service():
    requests = pki.parse_request(STUDIO_BLOCK, "papaia-studio", "x")

    assert [r.line() for r in requests] == [
        "papaia-studio\tstudio-gateway\t10001\tstudio-gateway\t1",
        "papaia-studio\tstudio-app-host\t10001\t-\t1",
        "papaia-studio\tstudio-postgres\t70\tstudio-postgres,db.local\t0",
    ]


def test_no_block_requests_nothing():
    assert pki.parse_request(None, "a", "x") == []
    assert pki.parse_request({}, "a", "x") == []


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"name": "Gateway", "uid": 1}, "DNS label"),
        ({"name": "../x", "uid": 1}, "DNS label"),
        ({"name": "gw", "uid": -1}, "numeric user"),
        ({"name": "gw", "uid": "1000"}, "numeric user"),
        ({"name": "gw", "uid": True}, "numeric user"),
        ({"name": "gw", "uid": 1, "server": {"dns": []}}, "at least one"),
        ({"name": "gw", "uid": 1, "server": {"dns": ["bad name"]}}, "not a DNS name"),
        ({"name": "gw", "uid": 1, "server": ["gw"]}, "`dns` list"),
        ({"name": "gw", "uid": 1, "client": "yes"}, "true or false"),
        ({"name": "gw", "uid": 1, "ca": True}, "unknown keys: ca"),
    ],
)
def test_a_request_that_cannot_be_served_is_refused_with_the_reason(entry, message):
    with pytest.raises(pki.PkiError, match=message):
        pki.parse_request({"services": [entry]}, "mod", "mod/papaia-app.yaml")


def test_a_service_cannot_be_requested_twice():
    block = {"services": [{"name": "gw", "uid": 1}, {"name": "gw", "uid": 2}]}
    with pytest.raises(pki.PkiError, match="twice"):
        pki.parse_request(block, "mod", "x")


def test_core_modules_ask_in_a_pki_yaml_while_their_profile_is_on(tmp_path):
    (tmp_path / "src" / "ai" / "rag").mkdir(parents=True)
    (tmp_path / "src" / "ai" / "rag" / "pki.yaml").write_text(
        yaml.safe_dump(
            {
                "profile": "rag",
                "pki": {
                    "services": [{"name": "qdrant", "uid": 1000, "server": {"dns": ["qdrant"]}}]
                },
            }
        ),
        encoding="utf-8",
    )

    assert pki.core_requests(tmp_path, {"keycloak"}) == []
    (only,) = pki.core_requests(tmp_path, {"rag"})
    assert (only.module, only.name, only.dns) == ("core", "qdrant", ("qdrant",))


def test_the_release_ships_no_core_request():
    assert pki.core_requests(REPO, {"rag", "smtp", "localai", "keycloak", "nginx"}) == []


def test_requests_of_active_addons_are_collected(stack):
    _addon_manifest(stack, STUDIO_BLOCK)

    plan = pki.collect(stack["config"], stack["repo"])

    assert {r.module for r in plan.requests} == {"paperless"}
    assert len(plan.requests) == 3
    assert plan.skipped == []


def test_an_addon_on_another_node_is_reported_not_served(stack):
    _addon_manifest(stack, STUDIO_BLOCK)
    path = stack["config"] / "deployment.yaml"
    manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
    manifest["topology"] = {
        "mode": "distributed",
        "controller": "internal",
        "nodes": {
            "internal": {"address": "10.0.0.1", "executor": "local"},
            "dmz": {"address": "10.0.0.2", "executor": "ssh", "ssh": {"user": "root"}},
        },
    }
    manifest["addons"][0]["node"] = "dmz"
    path.write_text(yaml.safe_dump(manifest), encoding="utf-8")

    plan = pki.collect(stack["config"], stack["repo"])

    assert plan.requests == []
    assert len(plan.skipped) == 1 and "controller 'internal' only" in plan.skipped[0]


# ─────────────────────────────────────────────────────────────────────────
# settings
# ─────────────────────────────────────────────────────────────────────────


def test_the_profile_is_off_by_default_and_off_changes_nothing(stack):
    before = (stack["config"] / ".env").read_bytes()

    assert pki.configure(stack["config"], stack["repo"], enable=None) is False
    assert pki.configure(stack["config"], stack["repo"], enable=False) is False

    assert (stack["config"] / ".env").read_bytes() == before
    assert not pki.enabled(stack["config"])


def test_switching_on_stores_the_profile_and_the_directory_and_stays_on(stack):
    assert pki.configure(stack["config"], stack["repo"], enable=True) is True

    env = _env(stack)
    assert "pki" in env["COMPOSE_PROFILES"].split(",")
    assert env[pki.KEY_DIR] == str(stack["config"] / "pki")
    manifest = yaml.safe_load((stack["config"] / "deployment.yaml").read_text(encoding="utf-8"))
    assert "pki" in manifest["core"]["profiles"]
    # A later setup without --pki/--no-pki keeps the choice.
    assert pki.configure(stack["config"], stack["repo"], enable=None) is True
    assert pki.enabled(stack["config"])


def test_switching_off_removes_the_directory_key_again(stack):
    pki.configure(stack["config"], stack["repo"], enable=True)
    pki.configure(stack["config"], stack["repo"], enable=False)

    env = _env(stack)
    assert pki.KEY_DIR not in env
    assert "pki" not in env["COMPOSE_PROFILES"].split(",")


def test_an_own_directory_is_kept(stack, tmp_path):
    own = tmp_path / "certs-internal"
    pki.configure(stack["config"], stack["repo"], enable=True, directory=str(own))

    assert pki.settings(stack["config"])["PKI_DIR"] == str(own)
    assert pki.settings(stack["config"])["PKI_INSIDE_CONFIG"] == "false"


@pytest.mark.parametrize("bad", ["relative/pki", "/", "{config}", "{parent}"])
def test_a_directory_that_purge_would_hurt_is_refused(stack, bad):
    value = bad.format(config=stack["config"], parent=stack["config"].parent)
    with pytest.raises(pki.PkiError):
        pki.configure(stack["config"], stack["repo"], enable=True, directory=value)


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [(pki.KEY_MODE, "acme", "must be one of"), (pki.KEY_LEAF_DAYS, "365", "between 1 and 90")],
)
def test_bad_settings_are_named(stack, key, value, message):
    pki.configure(stack["config"], stack["repo"], enable=True)
    with (stack["config"] / ".env").open("a", encoding="utf-8") as handle:
        handle.write(f"{key}={value}\n")

    with pytest.raises(pki.PkiError, match=message):
        pki.settings(stack["config"])


def test_the_request_list_is_written_for_the_issuer(stack):
    _addon_manifest(stack, STUDIO_BLOCK)
    pki.configure(stack["config"], stack["repo"], enable=True)

    pki.write_requests(stack["config"], stack["repo"])

    lines = (stack["config"] / "pki" / "requests.tsv").read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("#")
    assert lines[1:] == [r.line() for r in pki.parse_request(STUDIO_BLOCK, "paperless", "x")]


def test_plan_writes_nothing_while_off(stack, capsys):
    _addon_manifest(stack, STUDIO_BLOCK)

    code = cli.main(
        ["--config-dir", str(stack["config"]), "--repo-root", str(stack["repo"]), "pki-plan"]
    )

    assert code == 0
    out = capsys.readouterr()
    assert out.out.strip() == "PKI_ENABLED=false"
    assert "paperless can use internal TLS certificates" in out.err
    assert not (stack["config"] / "pki").exists()


def test_plan_while_off_ignores_a_broken_request(stack):
    _addon_manifest(stack, {"services": "nope"})

    code = cli.main(
        ["--config-dir", str(stack["config"]), "--repo-root", str(stack["repo"]), "pki-plan"]
    )

    assert code == 0


# ─────────────────────────────────────────────────────────────────────────
# inventory, status, doctor
# ─────────────────────────────────────────────────────────────────────────


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _inventory(stack, leaf_days_left: int) -> None:
    pki.configure(stack["config"], stack["repo"], enable=True)
    directory = stack["config"] / "pki"
    directory.mkdir(exist_ok=True)
    leaf_end = NOW + timedelta(days=leaf_days_left, hours=1)
    (directory / "inventory.json").write_text(
        json.dumps(
            {
                "format": pki.FORMAT,
                "generated_at": _iso(NOW),
                "mode": "issue",
                "ca": [
                    {
                        "subject": "CN=papaia internal CA x,O=papAIa",
                        "not_after": _iso(NOW + timedelta(days=3650)),
                        "role": "active",
                        "source": "pki",
                    }
                ],
                "services": [
                    {
                        "module": "paperless",
                        "name": "gw",
                        "uid": 1000,
                        "generation": 3,
                        "server": {"dns": ["gw"], "not_after": _iso(leaf_end)},
                        "client": {"cn": "gw", "not_after": _iso(leaf_end)},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_status_lists_every_certificate_with_its_days_left(stack):
    _inventory(stack, 60)

    report = pki.status(stack["config"], now=NOW.replace(tzinfo=timezone.utc))

    assert report["enabled"] is True and report["attention"] is False
    assert [row["certificate"] for row in report["certificates"]] == [
        "CA CN=papaia internal CA x,O=papAIa (active)",
        "paperless/gw/tls.crt",
        "paperless/gw/client.crt",
    ]
    assert report["certificates"][1]["days_left"] == 60
    assert "paperless/gw/tls.crt" in pki.format_status(report)


def test_status_asks_for_attention_14_days_before_the_end(stack):
    _inventory(stack, 13)

    report = pki.status(stack["config"], now=NOW.replace(tzinfo=timezone.utc))

    assert report["attention"] is True
    assert report["certificates"][1]["state"] == "expiring"


@pytest.mark.parametrize(
    ("days", "expected"), [(60, PASS), (14, PASS), (13, WARN), (6, FAIL), (-1, FAIL)]
)
def test_doctor_checks_the_internal_certificates(stack, days, expected):
    _inventory(stack, days)

    check = result(run_doctor(stack), "certs")

    assert check.status == expected
    paths = [c["path"] for c in check.details["certificates"]]
    assert "pki:paperless/gw/tls.crt" in paths


def test_doctor_does_not_look_at_the_inventory_while_off(stack):
    _inventory(stack, 1)
    pki.configure(stack["config"], stack["repo"], enable=False)

    assert result(run_doctor(stack), "certs").status == SKIP


# ─────────────────────────────────────────────────────────────────────────
# the issuer container (opt-in: PAPAIA_PKI_DOCKER_TESTS=1, needs Docker)
# ─────────────────────────────────────────────────────────────────────────

needs_docker = pytest.mark.skipif(
    os.environ.get("PAPAIA_PKI_DOCKER_TESTS") != "1" or shutil.which("docker") is None,
    reason="set PAPAIA_PKI_DOCKER_TESTS=1 to run the issuer in Docker",
)


def _issuer(project: str, directory: Path, command: str, *env: str) -> subprocess.CompletedProcess:
    argv = ["docker", "compose", "-p", project, "-f", str(ISSUER_COMPOSE), "run", "--rm", "-T"]
    argv += ["-v", f"{directory}:/pki"]
    for item in env:
        argv += ["-e", item]
    argv += ["pki-issuer", command]
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        env={**os.environ, "COMPOSE_IGNORE_ORPHANS": "1"},
    )


@needs_docker
def test_the_issuer_issues_renews_and_rotates(tmp_path):
    project = f"pkitest{os.getpid()}"
    directory = tmp_path / "pki"
    directory.mkdir()
    requests = pki.parse_request(STUDIO_BLOCK, "papaia-studio", "x")
    (directory / "requests.tsv").write_text("\n".join(r.line() for r in requests) + "\n")
    try:
        first = _issuer(project, directory, "sync")
        assert first.returncode == 0, first.stderr
        assert "changed papaia-studio" in first.stdout
        inventory = json.loads((directory / "inventory.json").read_text())
        assert inventory["format"] == pki.FORMAT
        assert len(inventory["services"]) == 3

        again = _issuer(project, directory, "sync")
        assert again.returncode == 0 and "changed" not in again.stdout

        later = int(datetime.now(timezone.utc).timestamp()) + 61 * 86400
        renewed = _issuer(project, directory, "sync", f"PKI_NOW={later}")
        assert "service papaia-studio studio-gateway" in renewed.stdout

        assert _issuer(project, directory, "stage-ca").returncode == 0
        promoted = _issuer(project, directory, "promote-ca")
        assert promoted.returncode == 0, promoted.stderr
        roles = [ca["role"] for ca in json.loads((directory / "inventory.json").read_text())["ca"]]
        assert roles == ["active", "retired"]
    finally:
        _issuer(project, directory, "purge")
        subprocess.run(
            ["docker", "volume", "rm", f"{project}_pki-ca"], capture_output=True, check=False
        )


# ─────────────────────────────────────────────────────────────────────────
# the wizard question
# ─────────────────────────────────────────────────────────────────────────

BASH = shutil.which("bash")
SH = Path(__file__).resolve().parents[1] / "lib" / "sh"


@pytest.mark.skipif(BASH is None, reason="bash is not available")
@pytest.mark.parametrize(
    ("stored", "answer", "expected"),
    [("false", "", "false"), ("false", "1", "true"), ("true", "", "true"), ("true", "2", "false")],
)
def test_the_wizard_defaults_to_off_and_keeps_an_earlier_opt_in(stored, answer, expected):
    script = (
        "set -euo pipefail\n"
        f'REPO_ROOT="{REPO.as_posix()}"\n'
        f'source "{(SH / "prompt.sh").as_posix()}"\n'
        "CYAN='' NC=''\n"
        'warn() { echo "$*" >&2; }\n'
        f'source "{(SH / "pki.sh").as_posix()}"\n'
        f"_pki_load_state() {{ PKI_ENABLED={stored}; }}\n"
        'printf "VALUE=%s" "$(_prompt_pki)"\n'
    )
    done = subprocess.run(
        [BASH, "-c", script], input=(answer + "\n").encode(), capture_output=True, check=False
    )

    assert done.stdout.decode().strip() == f"VALUE={expected}", done.stderr.decode()
