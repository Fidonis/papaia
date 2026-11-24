"""`papaia-ctl hostnames` (BE-03, command 2): the DNS names to create, as patterns before
`setup` (no configuration needed, no switch) and as the names themselves after it."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import yaml

from lib import cli, cli_setup_round, envtree, ingress, setup_answers

TOOLS = Path(__file__).resolve().parents[1]
REPO = TOOLS.parent


def test_before_setup_the_patterns_are_printed(tmp_path):
    done = subprocess.run(
        [sys.executable, "-m", "lib.cli", "--repo-root", str(REPO), "--config-dir",
         str(tmp_path / "papaia-config"), "hostnames"],
        cwd=TOOLS, capture_output=True, text=True, check=False,
        env={**os.environ, "PYTHONPATH": str(TOOLS)},
    )

    assert done.returncode == 0, done.stderr
    assert "<base domain>" in done.stdout
    assert "*.<base domain>" in done.stdout
    assert "*.apps.<base domain>" in done.stdout
    assert not (tmp_path / "papaia-config").exists(), "nothing is written"


def _route(host: str) -> ingress.Route:
    return ingress.Route("core", host.split(".")[0], (host,), f"https://{host}", "svc", 80,
                         "http", "papaia-net")


def test_after_setup_the_names_themselves_are_printed(tmp_path, monkeypatch, capsys):
    config = tmp_path / "papaia-config"
    config.mkdir()
    (config / ".env").write_text("PAPAIA_HOST=https://example.org\n")
    root = {"PAPAIA_HOST": "https://example.org", "INGRESS_APP_SINGLE_SITE": "true"}
    monkeypatch.setattr(envtree, "load_config_dir_tree", lambda c, r: {"": root})
    monkeypatch.setattr(ingress, "routes", lambda tree, c, r: [
        _route("auth.example.org"), _route("chat.example.org")])
    record = {"format": setup_answers.FORMAT,
              "answers": {"domain": "example.org", "size_profile": "small", "tls": "internal",
                          "backup_target": "/b", "backup_key": "generate", "mail": "none",
                          "modules": ["studio"]},
              "inputs": {"rows": [], "flags": [], "total": 0}}
    (config / setup_answers.RECORD_FILE).write_text(yaml.safe_dump(record))

    names = cli_setup_round.concrete_hostnames(config, REPO)
    assert names == ["*.apps.example.org", "apps.example.org", "auth.example.org",
                     "chat.example.org"]

    rc = cli.main(["--repo-root", str(REPO), "--config-dir", str(config), "hostnames"])
    assert rc == 0
    assert "  auth.example.org" in capsys.readouterr().out


def test_without_studio_no_app_names(tmp_path, monkeypatch):
    config = tmp_path / "papaia-config"
    config.mkdir()
    (config / ".env").write_text("")
    monkeypatch.setattr(envtree, "load_config_dir_tree",
                        lambda c, r: {"": {"PAPAIA_HOST": "https://example.org"}})
    monkeypatch.setattr(ingress, "routes", lambda tree, c, r: [_route("auth.example.org")])

    assert cli_setup_round.concrete_hostnames(config, REPO) == ["auth.example.org"]
