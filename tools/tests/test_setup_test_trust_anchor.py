"""`setup --test-trust-anchor=FILE` on a pre-release core (ADR 0030, amendment 1).

A release candidate carries a bill of materials of scope `test`, signed with a local test
key, and no release key. `setup` reads that file in two steps only: the pairing step
(`pairing list --digest`, `pairing list`, `pairing confirm`) and the module offer after
it. These tests run the real `papaia-ctl setup` with the flags of the golden single-node
fixture `default` on a copy of this checkout and hold the option to its limits:

- with the option, setup completes, shows the pairings with their digest, prints the
  banner at the start and the end and writes one `papaia.audit/1` row per check of the
  bill of materials; `--approve-pairings=<digest>` confirms the list;
- a release `VERSION` refuses the option before anything is read or written;
- without the option the `test` file still ends setup with exit code 3 and its cause;
- a wrong key and a `delivery` file are refused;
- no environment variable and no entry of the configuration turns it on.

The shell wiring (which call gets the anchor) is covered hermetically in
test_prerelease_anchor.py; the release path by the existing setup and pairing tests.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest
import yaml
from test_ctl_runtime import SETUP_FLAGS, Host
from test_images import ENTRIES, _bom, _new_keypair, _sign_bytes
from test_pairing_approval import BOM_PAIRINGS

from lib import images, suite
from lib import prerelease_anchor as pre

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None,
                                reason="openssl is needed for setup")

PRE = "1.10.0-rc.1"
BOM_NAME = "suite-1.10.0.yaml"


@pytest.fixture(scope="module")
def candidate(tmp_path_factory, ctl_wheelhouse) -> Host:
    """A pre-release checkout without a release key, its runtime built once."""
    host = Host(tmp_path_factory.mktemp("candidate"), ctl_wheelhouse)
    (host.repo / "VERSION").write_text(f"{PRE}\n", encoding="ascii")
    (host.repo / suite.RELEASE_KEY_PATH).unlink(missing_ok=True)
    keys = host.root / "keys"
    keys.mkdir()
    host.test_key = _new_keypair(keys, "test-signing")
    host.other_key = _new_keypair(keys, "other-signing")
    host.anchor = keys / "test-anchor.pub"
    host.anchor.write_text(host.test_key[1], encoding="ascii")
    host.wrong_anchor = keys / "other-anchor.pub"
    host.wrong_anchor.write_text(host.other_key[1], encoding="ascii")
    return host


def _write_bom(host: Host, *, scope: str = "test", key=None) -> None:
    """The candidate's bill of materials of `scope`, signed with `key` (the test key)."""
    private, pem = key or host.test_key
    doc = _bom(pem, ENTRIES, scope=scope)
    doc["pairings"] = BOM_PAIRINGS
    path = host.repo / "compat" / BOM_NAME
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    sig_dir = host.root / "sig"
    sig_dir.mkdir(exist_ok=True)
    Path(f"{path}.sig").write_text(_sign_bytes(private, path.read_bytes(), sig_dir), "ascii")


def _setup(host: Host, name: str, *extra: str, **env: str):
    config = host.root / f"config-{name}"
    done = host.ctl(*SETUP_FLAGS, f"--config-dir={config}", *extra, **env)
    return done, config


def _anchor_rows(config: Path) -> list[dict]:
    path = config / images.AUDIT_LOG
    if not path.is_file():
        return []
    rows = [json.loads(line) for line in path.read_text("utf-8").splitlines() if line]
    return [row for row in rows if row["event"] == pre.EVENT]


def _digest(output: str) -> str:
    found = re.search(r"sha256 of the list: (sha256:[0-9a-f]{64})", output)
    assert found, output
    return found.group(1)


# ── positive ──────────────────────────────────────────────────────────────────


def test_setup_completes_on_a_test_bill_with_the_anchor(candidate):
    _write_bom(candidate)

    done, config = _setup(candidate, "anchored", f"--test-trust-anchor={candidate.anchor}")

    output = done.stdout + done.stderr
    assert done.returncode == 0, output
    assert "setup complete" in output
    # The pairings with the digest; -y never confirms them.
    assert "Pairings of the signed bill of materials (suite 1.10.0)" in output
    digest = _digest(output)
    assert f"--approve-pairings={digest}" in output
    assert "-y never confirms exchange rights" in output
    assert re.search(r"^confirmed:", output, re.M) is None
    # The banner opens and closes the command.
    assert "TEST TRUST ANCHOR: --test-trust-anchor is set for this 'setup' only." in done.stderr
    assert "TEST TRUST ANCHOR: 'setup' ended with exit code 0." in done.stderr
    assert "NOT FOR PRODUCTION" in done.stderr
    # One row per check of the bill of materials, under the one correlation id.
    rows = _anchor_rows(config)
    assert [row["operation"] for row in rows] == ["pairing-list", "pairing-list",
                                                  "module-offer"]
    assert all(row["result"] == "allowed" for row in rows)
    assert len({row["correlation_id"] for row in rows}) == 1
    fingerprint = suite.key_fingerprint(candidate.test_key[1])
    for row in rows:
        assert row["detail"]["fingerprint"] == fingerprint
        assert row["detail"]["scope"] == "test"
        assert row["detail"]["core_version"] == PRE
        assert row["detail"]["bom_digest"].startswith("sha256:")
    assert rows[0]["correlation_id"] in done.stderr
    # Nothing of the option is stored.
    for path in config.rglob("*"):
        if path.is_file() and path != config / images.AUDIT_LOG:
            assert str(candidate.anchor) not in path.read_text("utf-8", errors="replace")


def test_setup_confirms_the_list_with_its_digest_under_the_anchor(candidate):
    _write_bom(candidate)
    shown, _ = _setup(candidate, "show", f"--test-trust-anchor={candidate.anchor}")
    assert shown.returncode == 0, shown.stdout + shown.stderr
    digest = _digest(shown.stdout + shown.stderr)

    done, config = _setup(candidate, "approve", f"--test-trust-anchor={candidate.anchor}",
                          f"--approve-pairings={digest}")

    output = done.stdout + done.stderr
    assert done.returncode == 0, output
    assert re.search(r"^confirmed: ", output, re.M)
    assert "setup complete" in output
    rows = _anchor_rows(config)
    assert [row["operation"] for row in rows] == ["pairing-list", "pairing-list",
                                                  "pairing-confirm", "module-offer"]
    assert all(row["result"] == "allowed" for row in rows)


# ── negative ──────────────────────────────────────────────────────────────────


def test_a_release_version_refuses_the_option_before_anything_is_read(candidate):
    _write_bom(candidate)
    version = candidate.repo / "VERSION"
    version.write_text("1.10.0\n", encoding="ascii")
    try:
        done, config = _setup(candidate, "release", f"--test-trust-anchor={candidate.anchor}")
    finally:
        version.write_text(f"{PRE}\n", encoding="ascii")

    assert done.returncode == 2, done.stdout + done.stderr
    assert "is not a pre-release" in done.stderr
    assert "Nothing else was read." in done.stderr
    assert not config.exists(), "setup did not run"


def test_a_test_bill_without_the_option_still_ends_setup_with_exit_3(candidate):
    _write_bom(candidate)

    done, config = _setup(candidate, "strict")

    assert done.returncode == 3, done.stdout + done.stderr
    assert "no trust anchor" in done.stderr
    assert "The pairings of the bill of materials cannot be shown" in done.stderr
    assert "TEST TRUST ANCHOR" not in done.stderr
    assert _anchor_rows(config) == []


def test_a_test_bill_signed_with_another_key_is_refused(candidate):
    _write_bom(candidate)

    done, config = _setup(candidate, "wrong-key",
                          f"--test-trust-anchor={candidate.wrong_anchor}")

    assert done.returncode == 3, done.stdout + done.stderr
    assert "The pairings of the bill of materials cannot be shown" in done.stderr
    assert "setup complete" not in done.stdout
    rows = _anchor_rows(config)
    assert [(row["operation"], row["result"]) for row in rows] == [("pairing-list", "denied")]
    assert "ended with exit code 3" in done.stderr


def test_a_delivery_bill_with_the_option_is_refused(candidate):
    _write_bom(candidate, scope="delivery")
    try:
        done, config = _setup(candidate, "delivery", f"--test-trust-anchor={candidate.anchor}")
    finally:
        _write_bom(candidate)

    assert done.returncode == 3, done.stdout + done.stderr
    assert "scope" in done.stderr
    rows = _anchor_rows(config)
    assert [(row["operation"], row["result"]) for row in rows] == [("pairing-list", "denied")]


def test_neither_the_environment_nor_the_configuration_enables_the_anchor(candidate):
    _write_bom(candidate)
    config = candidate.root / "config-env"
    config.mkdir()
    (config / ".env").write_text(
        f"TEST_TRUST_ANCHOR={candidate.anchor}\nPAPAIA_TEST_TRUST_ANCHOR={candidate.anchor}\n",
        encoding="utf-8",
    )

    done, _ = _setup(candidate, "env", TEST_TRUST_ANCHOR=str(candidate.anchor),
                     PAPAIA_TEST_TRUST_ANCHOR=str(candidate.anchor))

    assert done.returncode == 3, done.stdout + done.stderr
    assert "no trust anchor" in done.stderr
    assert "TEST TRUST ANCHOR" not in done.stderr
    assert _anchor_rows(config) == []
