"""The `flow:` section of an add-on at its installation.

`papaia-ctl addon install` keeps the manifest of every installed add-on in
`$PAPAIA_CONFIG_DIR/addon-manifests/<name>/` and, when the workflow module is
installed, shows the operator what the link of the add-on may do and asks the
module to approve exactly that declaration. The module itself is a stand-in
here: no container is started and no request leaves the test.
"""

from __future__ import annotations

import argparse
import io
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

from lib import cli, cli_addon, envtree, flow_link

FIXTURES_DIR = Path(__file__).parent / "fixtures"
ADDON_PAPERLESS = FIXTURES_DIR / "addon-paperless"
DIGEST = "sha256:" + "a" * 64
FLOW_SECTION: dict[str, Any] = {
    "api": 1,
    "source": "urn:papaia:addon:paperless",
    "events": [
        {
            "name": "document.added",
            "version": 1,
            "title": {"en": "Document added"},
            "delivery": "webhook",
            "auth": "hmac",
            "format": "cloudevents",
            "data_schema": "integration/flow/schemas/document-added.v1.json",
            "data_class_hint": "internal",
        }
    ],
    "actions": [
        {
            "name": "get-document",
            "version": 1,
            "title": {"en": "Read a document"},
            "via": "tools",
            "server": "paperless-mcp",
            "tool": "get_document",
            "identity": "person",
            "effect": "read",
            "input_schema": {"type": "object"},
            "output_schema": {"type": "object"},
            "data_class_max": "internal",
        }
    ],
}


def _addon(tmp_path: Path, version: str = "1.0.0", flow: dict | None = FLOW_SECTION) -> Path:
    """A copy of the paperless fixture with a `flow:` section, a schema
    file the section names, and files that must never be copied."""
    path = tmp_path / f"addon-{version}"
    if path.exists():
        shutil.rmtree(path)
    shutil.copytree(ADDON_PAPERLESS, path)
    manifest = yaml.safe_load((path / "papaia-app.yaml").read_text(encoding="utf-8"))
    manifest["version"] = version
    if flow is not None:
        manifest["flow"] = flow
    (path / "papaia-app.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    schemas = path / "integration" / "flow" / "schemas"
    schemas.mkdir(parents=True)
    (schemas / "document-added.v1.json").write_text('{"type": "object"}', encoding="utf-8")
    (path / ".env").write_text("PAPERLESS_DBPASS=secret\n", encoding="utf-8")
    (path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    return path


class FakeFlow:
    """The API of the workflow module as the installer uses it."""

    def __init__(self, shown: list[dict | None], answer: dict | None = None) -> None:
        self.shown = shown
        self.answer = answer or {
            "addon": "paperless",
            "state": "active",
            "pending": False,
            "approved_at_install": True,
            "reasons": [],
            "widened": [],
        }
        self.approvals: list[tuple[str, str, str, str]] = []

    def show(self, addon: str) -> dict | None:
        return self.shown.pop(0) if len(self.shown) > 1 else self.shown[0]

    def approve(self, addon: str, digest: str, version: str, reason: str) -> dict:
        self.approvals.append((addon, digest, version, reason))
        return self.answer


def _proposal(version: str = "1.0.0", **changes: Any) -> dict:
    shown = {
        "addon": "paperless",
        "state": "proposed",
        "pending": True,
        "addon_version": version,
        "declaration_digest": DIGEST,
        "approved_digest": None,
        "declaration": FLOW_SECTION,
    }
    shown.update(changes)
    return shown


def _link(fake: FakeFlow | None, **kwargs: Any) -> tuple[str, str]:
    out = io.StringIO()
    manifest = {"name": "paperless", "version": "1.0.0", "flow": FLOW_SECTION}
    manifest.update(kwargs.pop("manifest", {}))
    options: dict[str, Any] = {
        "approve": False,
        "ask": None,
        "token": "person-token",
        "wait_s": 3.0,
        "poll_s": 1.0,
        "sleep": lambda _s: None,
    }
    options.update(kwargs)
    outcome = flow_link.link_at_install(
        "paperless", manifest, lambda _token: fake, out=out, **options
    )
    return outcome, out.getvalue()


# ── the copy of the manifest (CORE-P07) ──────────────────────────────────────


def test_only_the_manifest_and_its_flow_files_are_kept(tmp_path):
    addon = _addon(tmp_path)
    (addon / "integration" / "flow" / "linked.json").symlink_to(addon / ".env")
    config_dir = tmp_path / "config"
    kept = flow_link.keep_manifest(addon, config_dir, "paperless")
    assert kept == config_dir / "addon-manifests" / "paperless"
    files = sorted(str(p.relative_to(kept)) for p in kept.rglob("*") if p.is_file())
    assert files == ["integration/flow/schemas/document-added.v1.json", "papaia-app.yaml"]
    # A later version replaces the copy as a whole.
    newer = _addon(tmp_path, "1.1.0")
    shutil.rmtree(newer / "integration" / "flow")
    flow_link.keep_manifest(newer, config_dir, "paperless")
    assert sorted(p.name for p in kept.rglob("*") if p.is_file()) == ["papaia-app.yaml"]
    assert "1.1.0" in (kept / "papaia-app.yaml").read_text(encoding="utf-8")
    flow_link.drop_manifest(config_dir, "paperless")
    assert not kept.exists()
    flow_link.drop_manifest(config_dir, "paperless")  # nothing there: nothing to do


def test_install_keeps_the_manifest_and_skips_the_link_without_flow(
    repo_root, config_dir, tmp_path, monkeypatch, capsys
):
    envtree.init(config_dir, repo_root, env_name="papaia")
    called: list[str] = []
    monkeypatch.setattr(flow_link, "client", lambda token: called.append(token))
    args = argparse.Namespace(
        config_dir=str(config_dir),
        repo_root=str(repo_root),
        name="paperless",
        path=str(_addon(tmp_path)),
        version=None,
        force=False,
        approve_flow_link=True,
        flow_token_file=None,
    )
    assert cli_addon.cmd_addon_install(args) == 0
    kept = config_dir / "addon-manifests" / "paperless" / "papaia-app.yaml"
    assert kept.is_file()
    assert "Flow is not installed" in capsys.readouterr().out
    assert called == []
    # Removing the integration takes the copy away: the module suspends the link.
    remove = argparse.Namespace(
        config_dir=str(config_dir), repo_root=str(repo_root), name="paperless"
    )
    assert cli_addon.cmd_addon_remove(remove) == 0
    assert not kept.exists()
    assert cli_addon.cmd_addon_install(args) == 0
    assert kept.is_file()
    assert cli_addon.cmd_addon_uninstall(remove) == 0
    assert not kept.parent.exists()


def test_install_with_flow_asks_flow_with_the_token_from_the_file(
    repo_root, config_dir, tmp_path, monkeypatch, capsys
):
    envtree.init(config_dir, repo_root, env_name="papaia")
    fake = FakeFlow([_proposal()])
    tokens: list[str] = []

    def client(token: str) -> FakeFlow:
        tokens.append(token)
        return fake

    monkeypatch.setattr(flow_link, "client", client)
    monkeypatch.setattr(flow_link, "flow_installed", lambda deployed: True)
    monkeypatch.setattr(flow_link, "POLL_S", 0.0)
    token_file = tmp_path / "token"
    token_file.write_text("person-token\n", encoding="utf-8")
    monkeypatch.delenv("PAPAIA_FLOW_TOKEN", raising=False)
    args = cli.build_parser().parse_args(
        [
            "--config-dir",
            str(config_dir),
            "--repo-root",
            str(repo_root),
            "addon-install",
            "--name=paperless",
            f"--path={_addon(tmp_path)}",
            "--approve-flow-link",
            f"--flow-token-file={token_file}",
        ]
    )
    assert args.func(args) == 0
    assert tokens == ["person-token"]
    assert fake.approvals == [("paperless", DIGEST, "1.0.0", flow_link.REASON)]
    assert "approved at install" in capsys.readouterr().out


# ── the link at installation ────────────────────────────────────────────────


def test_a_confirmed_summary_is_approved_by_its_digest_and_version():
    fake = FakeFlow([None, _proposal(version="0.9.0"), _proposal()])
    outcome, text = _link(fake, approve=True)
    assert outcome == "approved"
    assert fake.approvals == [("paperless", DIGEST, "1.0.0", flow_link.REASON)]
    # What the operator is shown before anything is approved.
    for part in (
        DIGEST,
        "document.added",
        "data class hint internal",
        "get-document",
        "tools paperless-mcp/get_document",
        "identity person",
        "effect read",
        "data class up to internal",
    ):
        assert part in text, part


@pytest.mark.parametrize(
    ("ask", "approve"),
    [(lambda _q: "n", False), (lambda _q: "", False), (None, False)],
)
def test_a_refused_or_missing_confirmation_approves_nothing(ask, approve):
    fake = FakeFlow([_proposal()])
    outcome, text = _link(fake, ask=ask, approve=approve)
    assert (outcome, fake.approvals) == ("refused", [])
    assert "--approve-flow-link" in text
    assert "flow link approve paperless --at-install" in text


def test_an_answered_question_approves():
    fake = FakeFlow([_proposal()])
    asked: list[str] = []
    outcome, _ = _link(fake, ask=lambda q: asked.append(q) or "y")
    assert outcome == "approved"
    assert len(asked) == 1


def test_a_declaration_above_the_policy_stays_a_proposal():
    answer = {
        "addon": "paperless",
        "state": "proposed",
        "pending": True,
        "approved_at_install": False,
        "reasons": ["data_class:get-document"],
        "widened": ["data_class:get-document"],
    }
    fake = FakeFlow([_proposal()], answer)
    outcome, text = _link(fake, approve=True)
    assert outcome == "proposal"
    assert "second person" in text
    assert "data_class:get-document" in text


@pytest.mark.parametrize(
    ("shown", "outcome"),
    [
        # The module never read the copy (another add-on directory, not running).
        ([None], "not_read"),
        ([_proposal(version="0.9.0")], "not_read"),
        # The same section as approved before: nothing to decide.
        (
            [_proposal(pending=False, state="active", approved_digest=DIGEST)],
            "unchanged",
        ),
    ],
)
def test_nothing_is_approved_without_a_proposal_of_this_version(shown, outcome):
    fake = FakeFlow(shown)
    assert _link(fake, approve=True)[0] == outcome
    assert fake.approvals == []


def test_without_a_section_a_token_or_a_reachable_module():
    assert _link(FakeFlow([_proposal()]), manifest={"flow": None})[0] == "none"
    fake = FakeFlow([_proposal()])
    outcome, text = _link(fake, approve=True, token="")
    assert (outcome, fake.approvals) == ("no_token", [])
    assert "PAPAIA_FLOW_TOKEN" in text

    class Broken(FakeFlow):
        def approve(self, addon: str, digest: str, version: str, reason: str) -> dict:
            raise flow_link.FlowError("FLOW-API-CONFLICT")

    outcome, text = _link(Broken([_proposal()]), approve=True)
    assert outcome == "error"
    assert "FLOW-API-CONFLICT" in text


def test_the_module_is_asked_inside_its_api_container_with_the_token_in_the_environment():
    calls: list[tuple[list[str], dict[str, str]]] = []

    def runner(argv: list[str], **kwargs: Any) -> Any:
        calls.append((argv, kwargs.get("env") or {}))
        if argv[:2] == ["docker", "ps"]:
            return _Done(0, "c0ffee\n")
        if "show" in argv:
            return _Done(1, "", "FLOW-API-NOT-FOUND: not found\n")
        return _Done(0, '{"approved_at_install": true}')

    api = flow_link.DockerFlow("person-token", runner=runner)
    assert api.show("paperless") is None
    assert api.approve("paperless", DIGEST, "1.0.0", "installed") == {"approved_at_install": True}
    ps, show, approve = calls
    assert "label=de.fidonis.flow.role=api" in ps[0]
    assert approve[0][:6] == ["docker", "exec", "-i", "-e", "FLOW_TOKEN", "c0ffee"]
    assert approve[0][6:] == [
        "flow",
        "--api",
        "https://flow-api:8444",
        "--ca",
        "/run/flow/api-ca.pem",
        "link",
        "approve",
        "paperless",
        "--at-install",
        "--digest",
        DIGEST,
        "--addon-version",
        "1.0.0",
        "--reason",
        "installed",
    ]
    # The token travels in the environment of the call, never as an argument.
    assert all("person-token" not in arg for argv, _ in calls for arg in argv)
    assert approve[1]["FLOW_TOKEN"] == "person-token"
    assert show[1]["FLOW_TOKEN"] == "person-token"

    def failing(argv: list[str], **kwargs: Any) -> Any:
        return _Done(0, "") if argv[:2] == ["docker", "ps"] else _Done(0, "{}")

    with pytest.raises(flow_link.FlowError, match="not running"):
        flow_link.DockerFlow("t", runner=failing).show("paperless")


def test_the_token_comes_from_a_file_or_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("PAPAIA_FLOW_TOKEN", "from-env")
    assert flow_link.token_from(None) == "from-env"
    token_file = tmp_path / "t"
    token_file.write_text(" from-file \n", encoding="utf-8")
    assert flow_link.token_from(str(token_file)) == "from-file"
    monkeypatch.delenv("PAPAIA_FLOW_TOKEN")
    assert flow_link.token_from(None) == ""


def test_flow_is_installed_when_its_add_on_is_active():
    assert flow_link.flow_installed({"addons": [{"name": "papaia-flow", "active": True}]})
    assert not flow_link.flow_installed({"addons": [{"name": "papaia-flow", "active": False}]})
    assert not flow_link.flow_installed({"addons": [{"name": "paperless", "active": True}]})
    assert not flow_link.flow_installed({})


class _Done:
    def __init__(self, returncode: int, stdout: str, stderr: str = "") -> None:
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr
