"""The test trust anchor of a pre-release core (`--test-trust-anchor=FILE`, ADR 0030).

A joint test of release candidates starts, upgrades and confirms pairings against a bill of
materials of scope `test`, signed with a local test key. These tests hold the anchor to its
limits:

- a release `VERSION` refuses the option before anything else is read;
- only a `test` bill of materials signed with exactly the given key passes; a `delivery`
  one, one signed with another key and a `test` one without the option are refused;
- no environment variable, configuration entry or stored state turns it on;
- every use prints a banner and writes one `papaia.audit/1` row;
- the release path (pinned `compat/release-key.pub`, scope `delivery`) is unchanged.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
from test_images import _START as _START_HARNESS
from test_images import (
    BASH,
    ENTRIES,
    LIFECYCLE,
    REPO,
    UPGRADE,
    _audit_rows,
    _bom,
    _config,
    _core,
    _images_file,
    _new_keypair,
    _refs,
    _signed_registry,
)
from test_images_trust import _UPGRADE as _UPGRADE_HARNESS
from test_pairing_approval import BOM_PAIRINGS

from lib import cli, images, suite
from lib import prerelease_anchor as pre

PRE = "1.10.0-rc.1"
TRUST_SH = REPO / "tools" / "lib" / "sh" / "trust.sh"
PAIRING_SH = REPO / "tools" / "lib" / "sh" / "pairing.sh"


@pytest.fixture
def test_key(tmp_path: Path) -> tuple[Path, str]:
    return _new_keypair(tmp_path, "test-signing")


def _key_file(tmp_path: Path, pem: str, name: str = "test-anchor.pub") -> Path:
    path = tmp_path / name
    path.write_text(pem, encoding="ascii")
    return path


def _test_core(tmp_path: Path, key, *, version: str = PRE, scope: str = "test",
               pairings: list[dict] | None = None, with_release_key=None) -> Path:
    """A core checkout at `version` with a bill of materials of `scope` signed with `key`.
    `with_release_key` (a key pair) pins that key as the release key; by default none."""
    doc = _bom(key[1], ENTRIES, scope=scope)
    if pairings is not None:
        doc["pairings"] = pairings
    root = _core(tmp_path, key, bom=doc, version=version, with_key=False)
    if with_release_key is not None:
        (root / suite.RELEASE_KEY_PATH).write_text(with_release_key[1], encoding="ascii")
    return root


def _verify(root: Path, config: Path, tmp_path: Path, *extra: str, command="start") -> int:
    return cli.main(
        ["--repo-root", str(root), "--config-dir", str(config), "image-verify",
         f"--images-file={_images_file(tmp_path, _refs())}", f"--command={command}", *extra]
    )


def _anchor_rows(config: Path) -> list[dict]:
    return [row for row in _audit_rows(config) if row["event"] == pre.EVENT]


# ── the version gate ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("version", ["1.10.0", "2.0.0", "1.10.0+build.7"])
def test_a_release_version_refuses_before_anything_else_is_read(
    tmp_path, test_key, monkeypatch, version
):
    root = _test_core(tmp_path, test_key, version=version)
    read: list[str] = []
    original = suite._read_limited

    def spy(path, limit, what):
        read.append(Path(path).name)
        return original(path, limit, what)

    monkeypatch.setattr(suite, "_read_limited", spy)
    with pytest.raises(pre.AnchorError, match="pre-release"):
        pre.open_anchor(root, _key_file(tmp_path, test_key[1]))
    assert read == ["VERSION"]


@pytest.mark.parametrize("content", ["", "garbage\n", "1.10\n", "1.10.0-rc.1\n1.10.0\n",
                                     "v1.10.0-rc.1\n", "1.10.0-\n", "1.10.0-rc.1 \n"])
def test_any_doubt_about_the_version_refuses(tmp_path, test_key, content):
    root = _test_core(tmp_path, test_key)
    (root / "VERSION").write_text(content, encoding="utf-8")
    with pytest.raises(pre.AnchorError):
        pre.open_anchor(root, _key_file(tmp_path, test_key[1]))


def test_a_missing_version_refuses(tmp_path, test_key):
    root = _test_core(tmp_path, test_key)
    (root / "VERSION").unlink()
    with pytest.raises(pre.AnchorError):
        pre.open_anchor(root, _key_file(tmp_path, test_key[1]))


def test_a_pre_release_opens_the_anchor_with_the_key_fingerprint(tmp_path, test_key):
    root = _test_core(tmp_path, test_key)
    anchor = pre.open_anchor(root, _key_file(tmp_path, test_key[1]))
    assert anchor.fingerprint == suite.key_fingerprint(test_key[1])
    assert anchor.version == PRE


@pytest.mark.parametrize("content", ["not a key\n", "", "-----BEGIN PUBLIC KEY-----\nAAAA\n"
                                     "-----END PUBLIC KEY-----\n"])
def test_a_key_file_that_is_no_p256_public_key_refuses(tmp_path, test_key, content):
    root = _test_core(tmp_path, test_key)
    with pytest.raises(pre.AnchorError, match="test trust anchor"):
        pre.open_anchor(root, _key_file(tmp_path, content))


@pytest.mark.parametrize("value", ["", "a\nb", "x" * 5000, "nul\0byte"])
def test_a_malformed_key_path_refuses(tmp_path, test_key, value):
    root = _test_core(tmp_path, test_key)
    with pytest.raises(pre.AnchorError):
        pre.open_anchor(root, value)


def test_a_key_path_that_is_not_a_regular_file_refuses(tmp_path, test_key):
    root = _test_core(tmp_path, test_key)
    with pytest.raises(pre.AnchorError):
        pre.open_anchor(root, tmp_path)


# ── start: image-verify with the anchor ──────────────────────────────────────


def test_start_accepts_a_test_bill_signed_with_the_given_key(
    tmp_path, test_key, monkeypatch, capsys
):
    root, config = _test_core(tmp_path, test_key), _config(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(test_key, tmp_path))
    key = _key_file(tmp_path, test_key[1])

    assert _verify(root, config, tmp_path, f"--test-trust-anchor={key}") == 0
    captured = capsys.readouterr()
    assert "2 image(s) verified" in captured.out
    assert "TEST TRUST ANCHOR" in captured.err
    assert suite.key_fingerprint(test_key[1]) in captured.err
    assert "not for production" in captured.err.lower()

    (row,) = _anchor_rows(config)
    bom = root / "compat" / "suite-1.10.0.yaml"
    assert row["format"] == "papaia.audit/1"
    assert row["operation"] == "start"
    assert row["result"] == "allowed"
    assert row["correlation_id"]
    assert row["detail"]["command"] == "start"
    assert row["detail"]["fingerprint"] == suite.key_fingerprint(test_key[1])
    assert row["detail"]["scope"] == "test"
    assert row["detail"]["bom_digest"] == "sha256:" + hashlib.sha256(bom.read_bytes()).hexdigest()
    assert row["detail"]["operator"]
    assert row["detail"]["core_version"] == PRE
    # The shape of the host journal, as the row of --insecure-images.
    assert set(row) == set(images.audit_row("start", 1))
    # No key material in the journal: the fingerprint only.
    assert "BEGIN PUBLIC KEY" not in (config / images.AUDIT_LOG).read_text("utf-8")


def test_the_audit_row_carries_the_given_correlation_id(tmp_path, test_key, monkeypatch):
    root, config = _test_core(tmp_path, test_key), _config(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(test_key, tmp_path))
    key = _key_file(tmp_path, test_key[1])
    correlation = "0b5a4c84-6f0a-4f36-9a4e-0d0c5a7d1e11"
    assert _verify(root, config, tmp_path, f"--test-trust-anchor={key}",
                   f"--correlation-id={correlation}") == 0
    (row,) = _anchor_rows(config)
    assert row["correlation_id"] == correlation


def test_upgrade_accepts_the_targets_test_bill_with_the_anchor(
    tmp_path, test_key, monkeypatch
):
    target, config = _test_core(tmp_path, test_key), _config(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(test_key, tmp_path))
    key = _key_file(tmp_path, test_key[1])
    assert _verify(target, config, tmp_path, f"--test-trust-anchor={key}",
                   command="upgrade") == 0
    (row,) = _anchor_rows(config)
    assert row["operation"] == "upgrade"


def test_a_release_core_refuses_the_option_and_reads_nothing_else(
    tmp_path, test_key, monkeypatch, capsys
):
    root, config = _test_core(tmp_path, test_key, version="1.10.0"), _config(tmp_path)
    asked: list[str] = []
    monkeypatch.setattr(images, "Registry", lambda: asked.append("registry"))
    # The image list does not exist: a release core must refuse before it looks for it.
    argv = ["--repo-root", str(root), "--config-dir", str(config), "image-verify",
            f"--images-file={tmp_path / 'missing.txt'}", "--command=start",
            f"--test-trust-anchor={tmp_path / 'missing.pub'}"]
    assert cli.main(argv) == 2
    err = capsys.readouterr().err
    assert "pre-release" in err and "1.10.0" in err
    assert asked == []
    assert _audit_rows(config) == []


def test_a_test_bill_without_the_option_is_refused_as_before(
    tmp_path, test_key, monkeypatch, capsys
):
    root = _test_core(tmp_path, test_key, with_release_key=test_key)
    config = _config(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(test_key, tmp_path))
    assert _verify(root, config, tmp_path) == 2
    assert "scope" in capsys.readouterr().err
    assert _anchor_rows(config) == []


def test_a_test_bill_signed_with_another_key_is_refused(tmp_path, test_key, monkeypatch, capsys):
    root, config = _test_core(tmp_path, test_key), _config(tmp_path)
    other = _new_keypair(tmp_path, "other")
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(test_key, tmp_path))
    key = _key_file(tmp_path, other[1], "other-anchor.pub")
    assert _verify(root, config, tmp_path, f"--test-trust-anchor={key}") == 2
    assert "fingerprint" in capsys.readouterr().err
    (row,) = _anchor_rows(config)
    assert row["result"] == "denied"
    assert row["detail"]["fingerprint"] == suite.key_fingerprint(other[1])


def test_a_signature_by_another_key_over_a_bill_naming_the_test_key_is_refused(
    tmp_path, test_key, monkeypatch, capsys
):
    """The file names the test key but was signed by someone else."""
    other = _new_keypair(tmp_path, "other")
    root = _core(tmp_path, other, bom=_bom(test_key[1], ENTRIES, scope="test"), version=PRE,
                 with_key=False)
    config = _config(tmp_path)
    key = _key_file(tmp_path, test_key[1])
    assert _verify(root, config, tmp_path, f"--test-trust-anchor={key}") == 2
    assert "signature" in capsys.readouterr().err


def test_a_delivery_bill_with_the_test_key_is_refused(tmp_path, test_key, monkeypatch, capsys):
    root = _test_core(tmp_path, test_key, scope="delivery")
    config = _config(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(test_key, tmp_path))
    key = _key_file(tmp_path, test_key[1])
    assert _verify(root, config, tmp_path, f"--test-trust-anchor={key}") == 2
    assert "scope" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--insecure-images", "--anchor-fingerprint=sha256:" + "a" * 64])
def test_the_anchor_does_not_combine_with_other_trust_switches(
    tmp_path, test_key, flag, capsys
):
    root, config = _test_core(tmp_path, test_key), _config(tmp_path)
    key = _key_file(tmp_path, test_key[1])
    assert _verify(root, config, tmp_path, f"--test-trust-anchor={key}", flag) == 2
    assert "--test-trust-anchor" in capsys.readouterr().err
    assert _audit_rows(config) == []


@pytest.mark.parametrize("name", ["PAPAIA_TEST_TRUST_ANCHOR", "TEST_TRUST_ANCHOR",
                                  "PAPAIA_TRUST_ANCHOR"])
def test_no_environment_variable_or_config_entry_enables_the_anchor(
    tmp_path, test_key, monkeypatch, name, capsys
):
    root = _test_core(tmp_path, test_key, with_release_key=test_key)
    key = _key_file(tmp_path, test_key[1])
    config = _config(tmp_path, f"{name}={key}\nPAPAIA_TEST_TRUST_ANCHOR={key}\n")
    (config / "deployment.yaml").write_text(
        f"platform_version: 1.10.0\ntest_trust_anchor: {key}\n", encoding="utf-8")
    monkeypatch.setenv(name, str(key))
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(test_key, tmp_path))
    assert _verify(root, config, tmp_path) == 2
    assert "scope" in capsys.readouterr().err
    assert _anchor_rows(config) == []


def test_nothing_of_the_anchor_is_stored(tmp_path, test_key, monkeypatch):
    root, config = _test_core(tmp_path, test_key), _config(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(test_key, tmp_path))
    key = _key_file(tmp_path, test_key[1])
    before = {p.relative_to(config) for p in config.rglob("*")}
    assert _verify(root, config, tmp_path, f"--test-trust-anchor={key}") == 0
    after = {p.relative_to(config) for p in config.rglob("*")}
    # The audit journal (and the signature cache image-verify keeps anyway); nothing else.
    assert after - before <= {images.AUDIT_LOG.parent, images.AUDIT_LOG,
                              images.CACHE_PATH.parent, images.CACHE_PATH}
    assert _verify(root, config, tmp_path) == 2


# ── pairing confirm ──────────────────────────────────────────────────────────


def _pairing(root: Path, config: Path, *args: str) -> int:
    return cli.main(["--repo-root", str(root), "--config-dir", str(config), *args])


def test_pairing_confirm_accepts_a_test_bill_with_the_anchor(tmp_path, test_key, capsys):
    root = _test_core(tmp_path, test_key, pairings=BOM_PAIRINGS)
    config = _config(tmp_path)
    key = _key_file(tmp_path, test_key[1])

    assert _pairing(root, config, "pairing-list", "--json", f"--test-trust-anchor={key}") == 0
    listing = json.loads(capsys.readouterr().out)
    assert listing["pending_decision"] is True

    assert _pairing(root, config, "pairing-confirm", f"--approve-pairings={listing['digest']}",
                    f"--test-trust-anchor={key}") == 0
    captured = capsys.readouterr()
    assert "confirmed:" in captured.out
    assert "TEST TRUST ANCHOR" in captured.err
    rows = _anchor_rows(config)
    assert [row["operation"] for row in rows] == ["pairing-list", "pairing-confirm"]
    assert all(row["result"] == "allowed" for row in rows)


def test_pairing_confirm_refuses_a_test_bill_without_the_anchor(tmp_path, test_key, capsys):
    root = _test_core(tmp_path, test_key, pairings=BOM_PAIRINGS, with_release_key=test_key)
    config = _config(tmp_path)
    assert _pairing(root, config, "pairing-confirm",
                    "--approve-pairings=sha256:" + "0" * 64) == 2
    assert "scope" in capsys.readouterr().err


def test_pairing_confirm_on_a_release_core_refuses_the_anchor(tmp_path, test_key, capsys):
    root = _test_core(tmp_path, test_key, version="1.10.0", pairings=BOM_PAIRINGS)
    config = _config(tmp_path)
    key = _key_file(tmp_path, test_key[1])
    assert _pairing(root, config, "pairing-confirm", "--approve-pairings=sha256:" + "0" * 64,
                    f"--test-trust-anchor={key}") == 2
    assert "pre-release" in capsys.readouterr().err
    assert not (config / "security").exists()


def test_pairing_confirm_without_a_bill_refuses_under_the_anchor(tmp_path, test_key, capsys):
    root = _test_core(tmp_path, test_key)
    (root / "compat" / "suite-1.10.0.yaml").unlink()
    config = _config(tmp_path)
    key = _key_file(tmp_path, test_key[1])
    assert _pairing(root, config, "pairing-list", f"--test-trust-anchor={key}") == 2


# ── suite verify ─────────────────────────────────────────────────────────────


def _suite_verify(root: Path, config: Path, *args: str) -> int:
    bom = root / "compat" / "suite-1.10.0.yaml"
    return cli.main(["--repo-root", str(root), "--config-dir", str(config), "suite-verify",
                     f"--bom={bom}", *args])


def test_suite_verify_accepts_a_test_bill_with_the_anchor(tmp_path, test_key, capsys):
    root, config = _test_core(tmp_path, test_key), _config(tmp_path)
    key = _key_file(tmp_path, test_key[1])
    assert _suite_verify(root, config, "--json", f"--test-trust-anchor={key}") == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["scope"] == "test" and summary["suite_bound"] is True
    (row,) = _anchor_rows(config)
    assert row["operation"] == "suite-verify"


@pytest.mark.parametrize("extra", [["--scope=delivery"], ["--key=/x.pub"],
                                   ["--fingerprint=sha256:" + "a" * 64]])
def test_suite_verify_with_the_anchor_takes_no_other_anchor_or_scope(
    tmp_path, test_key, extra, capsys
):
    root, config = _test_core(tmp_path, test_key), _config(tmp_path)
    key = _key_file(tmp_path, test_key[1])
    assert _suite_verify(root, config, f"--test-trust-anchor={key}", *extra) == 2
    assert _audit_rows(config) == []


def test_suite_verify_on_a_release_core_refuses_the_anchor(tmp_path, test_key, capsys):
    root, config = _test_core(tmp_path, test_key, version="1.10.0"), _config(tmp_path)
    key = _key_file(tmp_path, test_key[1])
    assert _suite_verify(root, config, f"--test-trust-anchor={key}") == 2
    assert "pre-release" in capsys.readouterr().err


# ── banner of the whole command (test-anchor begin and end) ──────────────────


def _anchor_cmd(root: Path, config: Path, *args: str) -> int:
    return cli.main(["--repo-root", str(root), "--config-dir", str(config), "test-anchor",
                     *args])


def test_begin_prints_the_banner_and_the_fingerprint(tmp_path, test_key, capsys):
    root, config = _test_core(tmp_path, test_key), _config(tmp_path)
    key = _key_file(tmp_path, test_key[1])
    assert _anchor_cmd(root, config, "--phase=begin", "--command=start",
                       f"--test-trust-anchor={key}") == 0
    captured = capsys.readouterr()
    fingerprint, correlation = captured.out.strip().split("\t")
    assert fingerprint == suite.key_fingerprint(test_key[1])
    assert images.correlation_id(correlation) == correlation
    assert "TEST TRUST ANCHOR" in captured.err and fingerprint in captured.err
    assert "scope 'test'" in captured.err and "NOT FOR PRODUCTION" in captured.err
    assert "'start'" in captured.err


def test_end_prints_the_closing_banner(tmp_path, test_key, capsys):
    root, config = _test_core(tmp_path, test_key), _config(tmp_path)
    fingerprint = suite.key_fingerprint(test_key[1])
    assert _anchor_cmd(root, config, "--phase=end", "--command=upgrade",
                       f"--fingerprint={fingerprint}", "--exit-code=3",
                       "--correlation-id=0b5a4c84-6f0a-4f36-9a4e-0d0c5a7d1e11") == 0
    err = capsys.readouterr().err
    assert "TEST TRUST ANCHOR" in err and fingerprint in err and "exit code 3" in err
    assert "NOT FOR PRODUCTION" in err


def test_begin_on_a_release_core_refuses(tmp_path, test_key, capsys):
    root, config = _test_core(tmp_path, test_key, version="1.10.0"), _config(tmp_path)
    assert _anchor_cmd(root, config, "--phase=begin", "--command=start",
                       f"--test-trust-anchor={tmp_path / 'missing.pub'}") == 2
    captured = capsys.readouterr()
    assert "pre-release" in captured.err and captured.out == ""


@pytest.mark.parametrize("command", ["stop", "addon-install", "setup", "restore"])
def test_begin_names_only_the_commands_that_take_the_anchor(tmp_path, test_key, command):
    root, config = _test_core(tmp_path, test_key), _config(tmp_path)
    key = _key_file(tmp_path, test_key[1])
    with pytest.raises(SystemExit):
        _anchor_cmd(root, config, "--phase=begin", f"--command={command}",
                    f"--test-trust-anchor={key}")


# ── release path unchanged ───────────────────────────────────────────────────


def test_the_pinned_release_key_path_is_unchanged():
    assert suite.RELEASE_KEY_PATH == Path("compat") / "release-key.pub"


def test_the_pinned_release_key_is_neither_read_nor_changed_by_the_anchor(
    tmp_path, test_key, monkeypatch
):
    release = _new_keypair(tmp_path, "release")
    root = _test_core(tmp_path, test_key, with_release_key=release)
    pinned = root / suite.RELEASE_KEY_PATH
    digest = hashlib.sha256(pinned.read_bytes()).hexdigest()
    read: list[Path] = []
    original = suite._read_limited

    def spy(path, limit, what):
        read.append(Path(path))
        return original(path, limit, what)

    monkeypatch.setattr(suite, "_read_limited", spy)
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(test_key, tmp_path))
    config = _config(tmp_path)
    key = _key_file(tmp_path, test_key[1])
    assert _verify(root, config, tmp_path, f"--test-trust-anchor={key}") == 0
    assert pinned not in read
    assert hashlib.sha256(pinned.read_bytes()).hexdigest() == digest


def test_the_release_path_still_refuses_a_test_bill_signed_with_the_release_key(
    tmp_path, test_key
):
    root = _test_core(tmp_path, test_key, with_release_key=test_key)
    with pytest.raises(images.ImageError, match="scope"):
        images.load_trusted_bom(root)


def test_the_release_path_still_accepts_a_delivery_bill_with_the_release_key(
    tmp_path, test_key
):
    root = _test_core(tmp_path, test_key, scope="delivery", with_release_key=test_key)
    assert images.load_trusted_bom(root)["scope"] == "delivery"


def test_the_anchor_module_reads_no_environment():
    source = (REPO / "tools" / "lib" / "prerelease_anchor.py").read_text("utf-8")
    assert "os.environ" not in source and "getenv" not in source and "import os" not in source


# ── the shell: only the command line sets the anchor ─────────────────────────

_DISPATCH = """
set -euo pipefail
DEFAULT_CONFIG_DIR="@TMP@/config"
error() { echo "ERROR: $*" >&2; }
source "@TRUST@"
py_cli() {
    echo "py_cli $* CONFIG_DIR=$CONFIG_DIR" >> "@TMP@/calls"
    case "$*" in
        *--phase=begin*) [ "${STUB_BEGIN_RC:-0}" -eq 0 ] || return "$STUB_BEGIN_RC"
            printf 'sha256:%s\\t%s\\n' "$(printf 'a%.0s' {1..64})" \
                0b5a4c84-6f0a-4f36-9a4e-0d0c5a7d1e11 ;;
    esac
}
_dispatch() {
    echo "dispatch $* anchor=${TEST_TRUST_ANCHOR:-} corr=${IMAGES_CORRELATION_ID:-}" \
        >> "@TMP@/calls"
    false
    echo "not reached" >> "@TMP@/calls"
}
"""


def _dispatch(tmp_path: Path, *args: str, env: dict | None = None, begin_rc: int = 0):
    if BASH is None:
        pytest.skip("bash is not available")
    (tmp_path / "calls").write_text("", encoding="utf-8")
    script = _DISPATCH.replace("@TMP@", tmp_path.as_posix()).replace("@TRUST@",
                                                                      TRUST_SH.as_posix())
    quoted = " ".join(f"'{a}'" for a in args)
    done = subprocess.run(
        [BASH, "-c", f"{script}\n_dispatch_with_test_anchor _dispatch {quoted}"],
        capture_output=True, text=True, timeout=30, check=False,
        env={**os.environ, "STUB_BEGIN_RC": str(begin_rc), **(env or {})},
        cwd=tmp_path,
    )
    return done, (tmp_path / "calls").read_text("utf-8").splitlines()


def test_dispatch_without_the_option_runs_the_command_as_before(tmp_path):
    done, calls = _dispatch(tmp_path, "start", "--addons")
    assert done.returncode == 1
    assert calls == ["dispatch start --addons anchor= corr="]


def test_dispatch_with_the_option_opens_runs_and_closes(tmp_path):
    done, calls = _dispatch(tmp_path, "start", "--test-trust-anchor=keys/test.pub", "--addons")
    # The command's own exit code, after the closing banner; set -e still holds inside.
    assert done.returncode == 1
    assert calls[0].startswith("py_cli test-anchor --phase=begin --command=start "
                               f"--test-trust-anchor={tmp_path.as_posix()}/keys/test.pub")
    assert calls[1] == (f"dispatch start --addons anchor={tmp_path.as_posix()}/keys/test.pub "
                        "corr=0b5a4c84-6f0a-4f36-9a4e-0d0c5a7d1e11")
    assert calls[2].startswith("py_cli test-anchor --phase=end --command=start")
    assert "--exit-code=1" in calls[2] and "--fingerprint=sha256:" in calls[2]
    assert "not reached" not in calls


@pytest.mark.parametrize("args,label", [
    (("upgrade", "-y"), "upgrade"),
    (("pairing", "confirm", "--approve-pairings=x"), "pairing-confirm"),
    (("pairing", "list"), "pairing-list"),
    (("suite", "verify", "--bom=x"), "suite-verify"),
])
def test_dispatch_names_each_command_that_takes_the_option(tmp_path, args, label):
    done, calls = _dispatch(tmp_path, *args, "--test-trust-anchor=/k.pub")
    assert f"--command={label}" in calls[0]


@pytest.mark.parametrize("args", [("stop",), ("setup",), ("addon", "install", "x"),
                                  ("pairing", "approve"), ("restore",), ("rollback",)])
def test_dispatch_refuses_the_option_for_any_other_command(tmp_path, args):
    done, calls = _dispatch(tmp_path, *args, "--test-trust-anchor=/k.pub")
    assert done.returncode == 2
    assert calls == []
    assert "--test-trust-anchor" in done.stderr


@pytest.mark.parametrize("args", [("--test-trust-anchor=/a.pub", "--test-trust-anchor=/b.pub"),
                                  ("--test-trust-anchor=",), ("--test-trust-anchor",)])
def test_dispatch_refuses_a_missing_or_repeated_value(tmp_path, args):
    done, calls = _dispatch(tmp_path, "start", *args)
    assert done.returncode == 2
    assert calls == []


def test_dispatch_stops_when_the_core_refuses_the_anchor(tmp_path):
    done, calls = _dispatch(tmp_path, "start", "--test-trust-anchor=/k.pub", begin_rc=2)
    assert done.returncode == 2
    assert len(calls) == 1 and "--phase=begin" in calls[0]


def test_dispatch_ignores_the_environment(tmp_path):
    done, calls = _dispatch(tmp_path, "start",
                            env={"TEST_TRUST_ANCHOR": "/k.pub",
                                 "PAPAIA_TEST_TRUST_ANCHOR": "/k.pub"})
    assert calls == ["dispatch start anchor= corr="]


def _start_script(tmp_path: Path, prefix: str) -> str:
    return (
        _START_HARNESS.replace("@CONFIG@", tmp_path.as_posix())
        .replace("@LIFECYCLE@", LIFECYCLE.as_posix())
        .replace("@REF@", "postgres:18.3@sha256:" + "2" * 64)
        .replace("@VERIFY@", "0")
        .replace("cmd_start --addons @FLAGS@", f"{prefix}\ncmd_start --addons")
    )


def test_start_hands_the_anchor_to_the_image_check(tmp_path):
    if BASH is None:
        pytest.skip("bash is not available")
    script = _start_script(tmp_path, 'TEST_TRUST_ANCHOR="/keys/test.pub"')
    done = subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30,
                          check=False)
    assert done.returncode == 0, done.stderr
    verify = next(c for c in done.stdout.splitlines() if c.startswith("py_cli image-verify"))
    assert "--test-trust-anchor=/keys/test.pub" in verify


def test_an_exported_variable_does_not_reach_the_image_check(tmp_path):
    if BASH is None:
        pytest.skip("bash is not available")
    script = _start_script(tmp_path, ":")
    done = subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30,
                          check=False, env={**os.environ, "TEST_TRUST_ANCHOR": "/keys/test.pub"})
    assert done.returncode == 0, done.stderr
    assert "--test-trust-anchor" not in done.stdout


def _upgrade_script(tmp_path: Path, prefix: str, anchor: str = "") -> str:
    nxt = tmp_path / "next-phase"
    nxt.write_text('#!/bin/sh\necho "phase2 $*"\n', encoding="utf-8")
    nxt.chmod(0o755)
    (tmp_path / "config").mkdir(exist_ok=True)
    return (
        _UPGRADE_HARNESS.replace("@TMP@", tmp_path.as_posix())
        .replace("@LIFECYCLE@", LIFECYCLE.as_posix())
        .replace("@UPGRADE@", UPGRADE.as_posix())
        .replace("@VERIFY@", "0")
        .replace("cmd_upgrade -y @FLAGS@", f"{prefix}\ncmd_upgrade -y")
        .replace("@ANCHOR@", anchor)
        .replace("@CORRELATION@", "0b5a4c84-6f0a-4f36-9a4e-0d0c5a7d1e11")
        .replace("@COMMIT@", "c" * 40)
    )


def test_upgrade_with_the_anchor_needs_no_pinned_release_key_and_hands_it_on(tmp_path):
    if BASH is None:
        pytest.skip("bash is not available")
    script = _upgrade_script(tmp_path, 'TEST_TRUST_ANCHOR="/keys/test.pub"')
    done = subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30,
                          check=False)
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    verify = next(c for c in calls if "image-verify" in c)
    assert "--test-trust-anchor=/keys/test.pub" in verify
    assert "--anchor-fingerprint" not in verify
    # The second phase runs from the target's checkout with the same anchor, nothing else.
    assert "--test-trust-anchor=/keys/test.pub" in calls[-1]
    assert "--resume-anchor" not in calls[-1]


def test_upgrade_without_the_anchor_still_requires_the_release_key(tmp_path):
    if BASH is None:
        pytest.skip("bash is not available")
    done = subprocess.run([BASH, "-c", _upgrade_script(tmp_path, ":")], capture_output=True,
                          text=True, timeout=30, check=False,
                          env={**os.environ, "TEST_TRUST_ANCHOR": "/keys/test.pub"})
    assert done.returncode == 2
    assert "release key" in done.stderr


def test_pairing_hands_the_anchor_to_list_and_confirm(tmp_path):
    if BASH is None:
        pytest.skip("bash is not available")
    script = f"""
set -euo pipefail
DEFAULT_CONFIG_DIR="{tmp_path.as_posix()}"
error() {{ echo "ERROR: $*" >&2; }}
warn() {{ :; }}
usage() {{ :; }}
source "{LIFECYCLE.as_posix()}"
source "{PAIRING_SH.as_posix()}"
_require_setup_done() {{ :; }}
py_cli() {{ echo "py_cli $*"; }}
TEST_TRUST_ANCHOR="/keys/test.pub"
IMAGES_CORRELATION_ID="0b5a4c84-6f0a-4f36-9a4e-0d0c5a7d1e11"
cmd_pairing list
cmd_pairing confirm --approve-pairings=sha256:{"0" * 64}
"""
    done = subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30,
                          check=False)
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    assert len(calls) == 2
    for call in calls:
        assert "--test-trust-anchor=/keys/test.pub" in call
        assert "--correlation-id=0b5a4c84-6f0a-4f36-9a4e-0d0c5a7d1e11" in call


def test_the_entrypoint_dispatches_through_the_anchor_gate():
    ctl = (REPO / "tools" / "papaia-ctl").read_text("utf-8")
    assert 'source "$SH_LIB/trust.sh"' in ctl
    assert '_dispatch_with_test_anchor _dispatch "$cmd" "$@"' in ctl


def test_the_documents_name_the_option():
    assert "--test-trust-anchor" in (REPO / "README.md").read_text("utf-8")
    assert "--test-trust-anchor" in (REPO / "docs/de/betrieb/handbuch.md").read_text("utf-8")
    adr = next((REPO / "docs" / "adr").glob("*-accept-a-test-trust-anchor-*.md"))
    assert "pre-release" in adr.read_text("utf-8")
