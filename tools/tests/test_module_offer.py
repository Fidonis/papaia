"""The modules `setup` offers (lib/module_offer.py, operation BE-03 No. 6).

Paperless takes the person from a request header and is safe only behind its gate. A
release offers it only when its signed bill of materials lists the gate as the component
`paperless-gate`; a bill of materials without it, or no bill of materials at all, leaves
Paperless out of the offer. With a signed bill of materials in the checkout, `addon
install paperless` follows the same rule, and so do `addon upgrade paperless` and `addon
rollback paperless`: no route puts an add-on without its gate in place.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from lib import cli, cli_addon, deployment, module_offer, suite
from tests.test_addon_install_checks import _args, _paperless, _plain_addon, _setup
from tests.test_ctl_standalone_commands import BASH, needs_bash
from tests.test_suite import BOM_SCHEMA, _bom, _sign, keypair  # noqa: F401 (fixture)

TOOLS = Path(__file__).resolve().parents[1]
SETUP_SH = TOOLS / "lib" / "sh" / "setup.sh"
FIXTURES = Path(__file__).parent / "fixtures"


def _with_gate(doc: dict, component: str = module_offer.PAPERLESS_GATE) -> dict:
    """The add-on repo of the bill of materials ships the gate image as `component`."""
    addons = next(repo for repo in doc["repos"] if repo["role"] == "addon")
    addons["images"][0]["component"] = component
    return doc


def _checkout(tmp_path: Path, keypair, *, gate: bool, version: str = "1.10.0") -> Path:  # noqa: F811
    private, public = keypair
    root = tmp_path / "papaia"
    (root / "compat").mkdir(parents=True)
    (root / "VERSION").write_text(f"{version}\n", encoding="utf-8")
    shutil.copyfile(public, root / suite.RELEASE_KEY_PATH)
    doc = _bom(public.read_text("ascii"))
    doc["suite"] = version
    if gate:
        _with_gate(doc)
    path = root / "compat" / f"suite-{version}.yaml"
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    _sign(private, path)
    return root


def _offer(root: Path, tmp_path: Path, capsys) -> tuple[int, dict]:
    capsys.readouterr()
    rc = cli.main(["--repo-root", str(root), "--config-dir", str(tmp_path / "cfg"),
                   "module-offer", "--json"])
    out = capsys.readouterr().out
    return rc, (json.loads(out) if rc == 0 else {})


# ── the bill of materials names the gate ─────────────────────────────────────


def test_a_component_on_an_image_passes_both_validators():
    doc = _with_gate(_bom())
    suite.validate_bom(doc)
    assert list(Draft202012Validator(BOM_SCHEMA).iter_errors(doc)) == []
    assert suite.components(doc) == {"paperless-gate"}


@pytest.mark.parametrize("value", ["", "Paperless-Gate", "-gate", "x" * 65, 7, None])
def test_a_malformed_component_is_refused_by_both_validators(value):
    doc = _with_gate(_bom(), value)
    with pytest.raises(suite.SuiteError, match="component"):
        suite.validate_bom(doc)
    assert list(Draft202012Validator(BOM_SCHEMA).iter_errors(doc))


def test_a_bill_of_materials_without_components_names_none():
    assert suite.components(_bom()) == set()


def test_the_gate_is_only_a_component_of_the_add_on_repo():
    doc = _bom()
    core = next(repo for repo in doc["repos"] if repo["role"] == "core")
    core["images"][0]["component"] = module_offer.PAPERLESS_GATE

    with pytest.raises(suite.SuiteError, match="paperless-gate.*addon"):
        suite.validate_bom(doc)


def test_the_gate_is_only_a_component_of_a_shipped_image():
    doc = _with_gate(_bom())
    addons = next(repo for repo in doc["repos"] if repo["role"] == "addon")
    addons["images"][0]["delivery"] = "customer-pulled"

    with pytest.raises(suite.SuiteError, match="paperless-gate.*shipped"):
        suite.validate_bom(doc)


# ── what is offered ──────────────────────────────────────────────────────────


def test_a_bill_of_materials_without_the_gate_does_not_offer_paperless():
    offer = module_offer.offer(_bom())

    assert "paperless" not in offer.offered
    assert offer.offered == ("studio", "data", "flow", "assist")
    assert "paperless-gate" in offer.withheld["paperless"]


def test_a_bill_of_materials_with_the_gate_offers_paperless():
    offer = module_offer.offer(_with_gate(_bom()))

    assert offer.offered == ("studio", "data", "flow", "assist", "paperless")
    assert offer.withheld == {}


def test_the_gate_must_be_named_exactly():
    assert "paperless" not in module_offer.offer(_with_gate(_bom(), "paperless")).offered
    assert "paperless" not in module_offer.offer(_with_gate(_bom(), "paperless-gate2")).offered


def test_without_a_bill_of_materials_paperless_is_not_offered():
    offer = module_offer.offer(None)

    assert "paperless" not in offer.offered
    assert "no signed bill of materials" in offer.withheld["paperless"]


# ── the command setup runs ───────────────────────────────────────────────────


def test_setup_does_not_offer_paperless_from_a_signed_bill_without_the_gate(
    tmp_path, keypair, capsys  # noqa: F811
):
    root = _checkout(tmp_path, keypair, gate=False)

    rc, listing = _offer(root, tmp_path, capsys)

    assert rc == 0
    assert listing["bom"] is True
    assert listing["suite"] == "1.10.0"
    assert "paperless" not in listing["offered"]
    assert list(listing["withheld"]) == ["paperless"]


def test_setup_offers_paperless_from_a_signed_bill_with_the_gate(
    tmp_path, keypair, capsys  # noqa: F811
):
    root = _checkout(tmp_path, keypair, gate=True)

    rc, listing = _offer(root, tmp_path, capsys)

    assert rc == 0
    assert listing["offered"][-1] == "paperless"
    assert listing["withheld"] == {}


def test_a_gate_added_to_the_bill_after_signing_is_refused(tmp_path, keypair, capsys):  # noqa: F811
    root = _checkout(tmp_path, keypair, gate=False)
    path = root / "compat" / "suite-1.10.0.yaml"
    doc = yaml.safe_load(path.read_text("utf-8"))
    _with_gate(doc)
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    capsys.readouterr()
    rc = cli.main(["--repo-root", str(root), "--config-dir", str(tmp_path / "cfg"),
                   "module-offer", "--json"])

    assert rc == 2
    assert "signature" in capsys.readouterr().err


def test_a_checkout_without_a_bill_of_materials_offers_no_paperless(tmp_path, capsys):
    root = tmp_path / "papaia"
    root.mkdir()
    (root / "VERSION").write_text("1.10.0\n", encoding="utf-8")

    rc, listing = _offer(root, tmp_path, capsys)

    assert rc == 0
    assert listing["bom"] is False
    assert "paperless" not in listing["offered"]


def test_the_text_output_names_the_missing_gate(tmp_path, keypair, capsys):  # noqa: F811
    root = _checkout(tmp_path, keypair, gate=False)
    capsys.readouterr()

    assert cli.main(["--repo-root", str(root), "--config-dir", str(tmp_path / "cfg"),
                     "module-offer"]) == 0
    out = capsys.readouterr().out
    assert "Modules offered by suite 1.10.0: studio, data, flow, assist" in out
    assert "Not offered: paperless" in out
    assert "paperless-gate" in out


def test_setup_shows_the_offer_after_the_pairings():
    text = SETUP_SH.read_text("utf-8")
    body = text[text.index("cmd_setup() {"):]

    pairings = body.index('_setup_pairings "$non_interactive" "$approve_pairings"')
    offer = body.index("_setup_module_offer || return 3")
    assert pairings < offer


# The shell state papaia-ctl has when setup runs, with the real `py_cli`.
_SETUP_HARNESS = """
set -euo pipefail
error() { echo "ERROR: $*" >&2; }
warn() { echo "WARN: $*" >&2; }
info() { echo "INFO: $*"; }
success() { echo "OK: $*"; }
py_cli() {
    PYTHONPATH="$TOOLS_DIR" "$PYTHON_BIN" -m lib.cli --repo-root "$REPO_ROOT" \
        --config-dir "$CONFIG_DIR" "$@"
}
source "$SETUP_SH"
_setup_module_offer
"""


def _setup_offer_step(root: Path, tmp_path: Path) -> subprocess.CompletedProcess:
    assert BASH is not None
    env = {**os.environ, "TOOLS_DIR": str(TOOLS), "PYTHON_BIN": sys.executable,
           "REPO_ROOT": str(root), "CONFIG_DIR": str(tmp_path / "cfg"),
           "SETUP_SH": str(SETUP_SH)}
    return subprocess.run([BASH, "-c", _SETUP_HARNESS], capture_output=True, text=True,
                          timeout=60, check=False, env=env)


@needs_bash
def test_the_setup_step_stops_with_exit_3_on_a_bill_that_does_not_verify(
    tmp_path, keypair  # noqa: F811
):
    root = _checkout(tmp_path, keypair, gate=False)
    path = root / "compat" / "suite-1.10.0.yaml"
    path.write_text(yaml.safe_dump(_with_gate(yaml.safe_load(path.read_text("utf-8"))),
                                   sort_keys=False), encoding="utf-8")

    done = _setup_offer_step(root, tmp_path)

    assert done.returncode == 3
    assert "signature" in done.stderr
    assert "The modules of the bill of materials cannot be shown" in done.stderr
    assert "Modules offered" not in done.stdout


@needs_bash
def test_the_setup_step_names_the_offer_of_a_signed_bill(tmp_path, keypair):  # noqa: F811
    root = _checkout(tmp_path, keypair, gate=False)

    done = _setup_offer_step(root, tmp_path)

    assert done.returncode == 0, done.stderr
    assert "Modules offered by suite 1.10.0: studio, data, flow, assist" in done.stdout
    assert "Not offered: paperless" in done.stdout


# ── addon install follows the same rule with a signed bill of materials ──────


def _signed_repo_root(repo_root: Path, keypair, *, gate: bool) -> None:  # noqa: F811
    """The synthetic checkout gets a release key and a signed bill of materials of its
    own version."""
    private, public = keypair
    version = (repo_root / "VERSION").read_text("utf-8").strip()
    (repo_root / "compat").mkdir(exist_ok=True)
    shutil.copyfile(public, repo_root / suite.RELEASE_KEY_PATH)
    doc = _bom(public.read_text("ascii"))
    doc["suite"] = version
    if gate:
        _with_gate(doc)
    path = repo_root / "compat" / f"suite-{version}.yaml"
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    _sign(private, path)


def test_install_refuses_paperless_when_the_signed_bill_lacks_the_gate(
    repo_root, config_dir, tmp_path, keypair, capsys  # noqa: F811
):
    _setup(repo_root, config_dir)
    _signed_repo_root(repo_root, keypair, gate=False)
    before = (config_dir / "deployment.yaml").read_bytes()
    gated = _paperless(tmp_path, gate=True)
    capsys.readouterr()

    assert cli_addon.cmd_addon_install(_args(config_dir, repo_root, "paperless", gated)) == 2

    err = capsys.readouterr().err
    assert "does not list its gate 'paperless-gate'" in err
    assert (config_dir / "deployment.yaml").read_bytes() == before
    assert not (config_dir / "addons" / "paperless").exists()


def test_install_takes_paperless_when_the_signed_bill_lists_the_gate(
    repo_root, config_dir, tmp_path, keypair  # noqa: F811
):
    _setup(repo_root, config_dir)
    _signed_repo_root(repo_root, keypair, gate=True)
    gated = _paperless(tmp_path, gate=True)

    assert cli_addon.cmd_addon_install(_args(config_dir, repo_root, "paperless", gated)) == 0
    names = [entry["name"] for entry in deployment.load(config_dir)["addons"]]
    assert names == ["paperless"]


def test_install_refuses_paperless_when_the_signed_bill_does_not_verify(
    repo_root, config_dir, tmp_path, keypair, capsys  # noqa: F811
):
    _setup(repo_root, config_dir)
    _signed_repo_root(repo_root, keypair, gate=False)
    version = (repo_root / "VERSION").read_text("utf-8").strip()
    path = repo_root / "compat" / f"suite-{version}.yaml"
    path.write_text(yaml.safe_dump(_with_gate(yaml.safe_load(path.read_text("utf-8"))),
                                   sort_keys=False), encoding="utf-8")
    gated = _paperless(tmp_path, gate=True)
    capsys.readouterr()

    assert cli_addon.cmd_addon_install(_args(config_dir, repo_root, "paperless", gated)) == 2
    assert "signature" in capsys.readouterr().err


def test_other_addons_do_not_need_the_gate_in_the_bill(
    repo_root, config_dir, tmp_path, keypair  # noqa: F811
):
    _setup(repo_root, config_dir)
    _signed_repo_root(repo_root, keypair, gate=False)
    flow = _plain_addon(tmp_path, "papaia-flow")

    assert cli_addon.cmd_addon_install(_args(config_dir, repo_root, "papaia-flow", flow)) == 0


# ── addon upgrade and rollback follow the same rule ──────────────────────────


def _paperless_version(tmp_path: Path, label: str, *, gate: bool) -> Path:
    """The second version of the paperless fixture, in a directory of the same name."""
    path = tmp_path / label / "paperless"
    shutil.copytree(FIXTURES / "addon-paperless-v2", path)
    services: dict = {"paperless": {"image": "example.invalid/paperless:2.1.0"}}
    if gate:
        services["paperless-gate"] = {
            "image": "example.invalid/gate:1.0.0", "network_mode": "service:paperless"
        }
    (path / "docker-compose.yml").write_text(yaml.safe_dump({"services": services}))
    return path


def _upgrade_args(config_dir: Path, repo_root: Path, path: Path, **fields) -> argparse.Namespace:
    base = {"config_dir": str(config_dir), "repo_root": str(repo_root), "name": "paperless",
            "path": str(path), "force": False, "json": False, "answers_file": None,
            "answers_out": None, "restore_point": None}
    return argparse.Namespace(**{**base, **fields})


def _answers(tmp_path: Path) -> Path:
    path = tmp_path / "answers"
    path.write_text("PAPERLESS_ADMIN_MAIL=ops@example.org\n", encoding="utf-8")
    path.chmod(0o600)
    return path


@pytest.fixture
def gated(repo_root, config_dir, tmp_path) -> Path:
    """Paperless with its gate is installed."""
    _setup(repo_root, config_dir)
    path = _paperless(tmp_path, gate=True)
    assert cli_addon.cmd_addon_install(_args(config_dir, repo_root, "paperless", path)) == 0
    return path


@pytest.mark.parametrize("verb", ["plan", "apply"])
def test_upgrade_refuses_a_paperless_version_without_its_gate(
    gated, repo_root, config_dir, tmp_path, capsys, verb
):
    plain = _paperless_version(tmp_path, "v2", gate=False)
    before = (config_dir / "deployment.yaml").read_bytes()
    handler = (cli_addon.cmd_addon_upgrade_plan if verb == "plan"
               else cli_addon.cmd_addon_upgrade_apply)
    capsys.readouterr()

    rc = handler(_upgrade_args(config_dir, repo_root, plain, force=True,
                               answers_file=str(_answers(tmp_path))))

    assert rc == 2
    assert "brings no gate" in capsys.readouterr().err
    assert (config_dir / "deployment.yaml").read_bytes() == before


def test_upgrade_takes_a_paperless_version_with_its_gate(
    gated, repo_root, config_dir, tmp_path
):
    target = _paperless_version(tmp_path, "v2", gate=True)
    args = _upgrade_args(config_dir, repo_root, target, answers_file=str(_answers(tmp_path)))

    assert cli_addon.cmd_addon_upgrade_plan(args) == 0
    assert cli_addon.cmd_addon_upgrade_apply(args) == 0
    entry = next(a for a in deployment.load(config_dir)["addons"] if a["name"] == "paperless")
    assert entry["path"] == str(target.resolve())


@pytest.mark.parametrize("verb", ["plan", "apply"])
def test_upgrade_refuses_paperless_when_the_signed_bill_lacks_the_gate(
    gated, repo_root, config_dir, tmp_path, keypair, capsys, verb  # noqa: F811
):
    target = _paperless_version(tmp_path, "v2", gate=True)
    _signed_repo_root(repo_root, keypair, gate=False)
    before = (config_dir / "deployment.yaml").read_bytes()
    handler = (cli_addon.cmd_addon_upgrade_plan if verb == "plan"
               else cli_addon.cmd_addon_upgrade_apply)
    capsys.readouterr()

    rc = handler(_upgrade_args(config_dir, repo_root, target, force=True,
                               answers_file=str(_answers(tmp_path))))

    assert rc == 2
    assert "does not list its gate 'paperless-gate'" in capsys.readouterr().err
    assert (config_dir / "deployment.yaml").read_bytes() == before


@pytest.mark.parametrize("verb", ["plan", "apply"])
def test_rollback_refuses_a_previous_version_without_its_gate(
    gated, repo_root, config_dir, tmp_path, capsys, verb
):
    target = _paperless_version(tmp_path, "v2", gate=True)
    args = _upgrade_args(config_dir, repo_root, target, answers_file=str(_answers(tmp_path)))
    assert cli_addon.cmd_addon_upgrade_apply(args) == 0
    (gated / "docker-compose.yml").write_text(
        yaml.safe_dump({"services": {"paperless": {"image": "example.invalid/p:2.0.0"}}})
    )
    before = (config_dir / "deployment.yaml").read_bytes()
    handler = (cli_addon.cmd_addon_rollback_plan if verb == "plan"
               else cli_addon.cmd_addon_rollback_apply)
    capsys.readouterr()

    rc = handler(_upgrade_args(config_dir, repo_root, target, force=True))

    assert rc == 2
    assert "brings no gate" in capsys.readouterr().err
    assert (config_dir / "deployment.yaml").read_bytes() == before
