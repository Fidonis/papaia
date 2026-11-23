"""Suite bill of materials and compatibility matrix (lib/suite.py).

The bill of materials is checked three ways: its structure (schema), its
signature against a trusted release key, and its inner consistency (tag equals
version, totals equal the entries). The matrix is checked for structure, for
agreement with this checkout (VERSION, ADDON_API, manager pin, public table)
and through `addon check`.
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from lib import cli, compat, envtree, semver, suite
from lib.cli_addon import cmd_addon_check, cmd_addon_install

REPO = Path(__file__).resolve().parents[2]
BOM_SCHEMA = json.loads((REPO / "tools/schemas/suite-bom.schema.json").read_text("utf-8"))
MATRIX_SCHEMA = json.loads((REPO / "tools/schemas/compat-matrix.schema.json").read_text("utf-8"))
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "suite"
# A public key only (real `cosign generate-key-pair` output); its private half is gone.
STATIC_PEM = (FIXTURE / "release.pub").read_text("ascii")

# Only the signature checks call openssl; schema, matrix and `addon check` tests run
# without it. CI sets PAPAIA_REQUIRE_OPENSSL so a missing binary fails instead of
# silently skipping the signature tests.
_NO_OPENSSL = shutil.which("openssl") is None
if _NO_OPENSSL and os.environ.get("PAPAIA_REQUIRE_OPENSSL"):
    raise RuntimeError("PAPAIA_REQUIRE_OPENSSL is set but openssl is not installed")
needs_openssl = pytest.mark.skipif(_NO_OPENSSL, reason="openssl not installed")


def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)


@pytest.fixture
def keypair(tmp_path: Path) -> tuple[Path, Path]:
    """A throwaway P-256 key pair, created per test; nothing is kept on disk."""
    if _NO_OPENSSL:
        pytest.skip("openssl not installed")
    private = tmp_path / "release.key"
    public = tmp_path / "release.pub"
    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(private))
    _openssl("ec", "-in", str(private), "-pubout", "-out", str(public))
    return private, public


def _sign(private: Path, data_path: Path) -> Path:
    """Sign like `cosign sign-blob`: ECDSA over SHA-256, DER, base64 text."""
    raw = data_path.with_suffix(".der")
    _openssl("dgst", "-sha256", "-sign", str(private), "-out", str(raw), str(data_path))
    sig = Path(f"{data_path}.sig")
    sig.write_text(base64.b64encode(raw.read_bytes()).decode("ascii"), encoding="ascii")
    raw.unlink()
    return sig


def _hex(char: str, length: int) -> str:
    return char * length


def _image(name: str, char: str, delivery: str = "shipped") -> dict:
    return {
        "name": name,
        "tag": "1.0.0",
        "digest": "sha256:" + _hex(char, 64),
        "license": "Apache-2.0",
        "license_class": "P",
        "sbom_digest": "sha256:" + _hex("f", 64),
        "delivery": delivery,
    }


def _repo(name: str, role: str, version: str, char: str, images: list[dict]) -> dict:
    entry = {
        "name": name,
        "role": role,
        "version": version,
        "tag": f"v{version}",
        "commit": _hex(char, 40),
        "containers": len(images),
        "images": images,
    }
    return entry


def _bom(public_pem: str = STATIC_PEM) -> dict:
    repos = [
        _repo("papaia", "core", "1.10.0", "a", [_image("ghcr.io/fidonis/papaia-core", "1")]),
        _repo(
            "papaia-manager", "manager", "1.8.0", "b", [_image("ghcr.io/fidonis/manager", "2")]
        ),
        _repo("papaia-flow", "module", "0.1.0", "c", [_image("ghcr.io/fidonis/flow", "3")]),
        _repo("papaia-addons", "addon", "1.4.0", "d", [_image("ghcr.io/fidonis/addon", "4")]),
        _repo("qdrant-mcp-rbac", "mcp", "0.5.0", "e", [_image("ghcr.io/fidonis/qmcp", "5")]),
        _repo("paperless-mcp-rbac", "mcp", "0.2.0", "6", [_image("ghcr.io/fidonis/pmcp", "6")]),
        _repo("papaia-kit", "kit", "0.1.0", "9", []),
    ]
    repos[2]["addon_api"] = 7
    repos[2]["min_core"] = "1.10.0"
    repos[2]["schema_version"] = "3"
    repos[6]["snapshot_sha256"] = _hex("8", 64)
    return {
        "schema": "papaia.suite-bom/1",
        "suite": "1.10.0",
        "scope": "delivery",
        "created": "2026-12-01T10:00:00Z",
        "contract_generation": {"min": 1, "current": 7},
        "signing_key": {
            "algorithm": "ecdsa-p256-sha256",
            "fingerprint": suite.key_fingerprint(public_pem),
            "public_key": public_pem,
        },
        "repos": repos,
        "totals": {"containers": 6, "images": 6},
    }


def _write(tmp_path: Path, doc: dict, name: str = "suite-1.10.0.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return path


# ── schema ───────────────────────────────────────────────────────────────────


def test_valid_bom_passes_both_validators():
    doc = _bom()
    suite.validate_bom(doc)
    assert list(Draft202012Validator(BOM_SCHEMA).iter_errors(doc)) == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(extra=1),
        lambda d: d["repos"][0].update(note="x"),
        lambda d: d["repos"][0]["images"][0].update(pulled=True),
        lambda d: d["signing_key"].update(comment="x"),
        lambda d: d["contract_generation"].update(max=9),
    ],
    ids=["top", "repo", "image", "key", "generation"],
)
def test_unknown_fields_are_rejected(mutate):
    doc = _bom()
    mutate(doc)
    with pytest.raises(suite.SuiteError, match="unknown field"):
        suite.validate_bom(doc)
    assert list(Draft202012Validator(BOM_SCHEMA).iter_errors(doc))


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d["repos"][0]["images"][0].update(digest="sha256:abc"), "digest"),
        (lambda d: d["repos"][0].update(commit="main"), "commit"),
        (lambda d: d["repos"][0].update(tag="v1.9.0"), "tag"),
        (lambda d: d["repos"][0].update(version="latest", tag="vlatest"), "version"),
        (lambda d: d["repos"][0]["images"][0].update(license_class="Z"), "license_class"),
        (lambda d: d["repos"][0]["images"][0].update(delivery="maybe"), "delivery"),
        (lambda d: d["repos"][0].update(containers=-1), "containers"),
        (lambda d: d["repos"][0].update(containers=True), "containers"),
        (lambda d: d.update(schema="papaia.suite-bom/2"), "schema"),
        (lambda d: d["repos"].pop(1), "manager"),
        (lambda d: d["repos"].pop(0), "core"),
        (lambda d: d["repos"].pop(6), "kit"),
        (lambda d: d["repos"][6].pop("snapshot_sha256"), "snapshot_sha256"),
        (lambda d: d["repos"][0].update(snapshot_sha256=_hex("1", 64)), "snapshot_sha256"),
        (lambda d: d["repos"].append(copy.deepcopy(d["repos"][2])), "duplicate"),
        (lambda d: d["contract_generation"].update(min=9), "contract_generation"),
        (lambda d: d["signing_key"].update(algorithm="rsa"), "algorithm"),
        (lambda d: d["signing_key"].update(fingerprint="sha256:" + _hex("0", 64)), "fingerprint"),
    ],
)
def test_malformed_entries_are_rejected(mutate, message):
    doc = _bom()
    mutate(doc)
    with pytest.raises(suite.SuiteError, match=message):
        suite.validate_bom(doc)


def _with_kit(doc: dict) -> dict:
    """Per-repo kit versions (PLT-37-A2, KIT-R4): the core and the MCP servers render
    no kit UI, the manager and the modules do."""
    for repo in doc["repos"]:
        if repo["role"] != "kit":
            repo["kit"] = {"version": "0.1.0", "renders_ui": repo["role"] in ("manager", "module")}
    return doc


def test_per_repo_kit_versions_pass_both_validators():
    doc = _with_kit(_bom())
    del doc["repos"][2]["kit"]["renders_ui"]  # optional: without it the repo renders kit UI
    suite.validate_bom(doc)
    assert list(Draft202012Validator(BOM_SCHEMA).iter_errors(doc)) == []


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d["repos"][0]["kit"].update(colour="x"), "unknown field"),
        (lambda d: d["repos"][0]["kit"].pop("version"), "missing field"),
        (lambda d: d["repos"][0].update(kit="0.1.0"), "must be a mapping"),
        (lambda d: d["repos"][0]["kit"].update(version="0.1"), "kit.version"),
        (lambda d: d["repos"][0]["kit"].update(version="0.1.0-rc.1"), "kit.version"),
        (lambda d: d["repos"][0]["kit"].update(version="01.1.0"), "kit.version"),
        (lambda d: d["repos"][0]["kit"].update(version="1234567.0.0"), "kit.version"),
        (lambda d: d["repos"][0]["kit"].update(version=1), "kit.version"),
        (lambda d: d["repos"][0]["kit"].update(renders_ui="no"), "renders_ui"),
        (lambda d: d["repos"][0]["kit"].update(renders_ui=0), "renders_ui"),
        (lambda d: d["repos"][6].update(kit={"version": "0.1.0"}), "the kit carries no kit"),
    ],
    ids=["unknown", "no-version", "scalar", "short", "prerelease", "leading-zero", "long",
         "number", "flag-text", "flag-int", "kit-repo"],
)
def test_malformed_kit_fields_are_rejected_by_both_validators(mutate, message):
    doc = _with_kit(_bom())
    mutate(doc)
    with pytest.raises(suite.SuiteError, match=message):
        suite.validate_bom(doc)
    if message != "the kit carries no kit":  # a cross-field rule only the validator has
        assert list(Draft202012Validator(BOM_SCHEMA).iter_errors(doc))


def test_totals_must_match_the_entries():
    doc = _bom()
    doc["totals"]["containers"] = 7
    with pytest.raises(suite.SuiteError, match="totals.containers"):
        suite.validate_bom(doc)
    doc = _bom()
    doc["totals"]["images"] = 5
    with pytest.raises(suite.SuiteError, match="totals.images"):
        suite.validate_bom(doc)


def test_test_only_images_are_refused_in_a_delivery_bom():
    doc = _bom()
    doc["repos"][3]["images"].append(_image("mcr.example/sql", "7", delivery="test-only"))
    doc["repos"][3]["containers"] = 2
    doc["totals"] = {"containers": 7, "images": 7}
    with pytest.raises(suite.SuiteError, match="test-only"):
        suite.validate_bom(doc)
    doc["scope"] = "test"
    suite.validate_bom(doc)


def _drop_repo(doc: dict, name: str) -> None:
    gone = next(r for r in doc["repos"] if r["name"] == name)
    doc["repos"].remove(gone)
    doc["totals"]["containers"] -= gone["containers"]
    doc["totals"]["images"] -= len(gone["images"])


@pytest.mark.parametrize(
    ("name", "role"),
    [("papaia-flow", "module"), ("papaia-addons", "addon"), ("paperless-mcp-rbac", "mcp")],
)
def test_delivery_bom_names_modules_addons_and_both_mcp_servers(name, role):
    """PLT-37-A2: a delivery bill of materials names the modules, the add-ons
    (Paperless among them) and both MCP servers; a test one may be partial."""
    doc = _bom()
    _drop_repo(doc, name)
    with pytest.raises(suite.SuiteError, match=f"role {role}"):
        suite.validate_bom(doc)
    doc["scope"] = "test"
    suite.validate_bom(doc)


def test_images_lists_every_pinned_reference():
    doc = _bom()
    refs = suite.image_refs(doc)
    assert refs[0] == "ghcr.io/fidonis/papaia-core:1.0.0@sha256:" + _hex("1", 64)
    assert len(refs) == 6


# ── signature ────────────────────────────────────────────────────────────────


def test_signed_bom_verifies_against_the_trusted_key(tmp_path, keypair):
    private, public = keypair
    path = _write(tmp_path, _bom(public.read_text("ascii")))
    sig = _sign(private, path)

    doc = suite.verify_bom(path, sig, key_path=public)
    assert doc["suite"] == "1.10.0"


def test_signed_bom_verifies_against_a_pinned_fingerprint(tmp_path, keypair):
    private, public = keypair
    pem = public.read_text("ascii")
    path = _write(tmp_path, _bom(pem))
    sig = _sign(private, path)

    assert suite.verify_bom(path, sig, fingerprint=suite.key_fingerprint(pem))["suite"]
    with pytest.raises(suite.SuiteError, match="fingerprint"):
        suite.verify_bom(path, sig, fingerprint="sha256:" + _hex("0", 64))


def test_altered_entry_fails_verification(tmp_path, keypair):
    private, public = keypair
    path = _write(tmp_path, _bom(public.read_text("ascii")))
    sig = _sign(private, path)
    text = path.read_text("utf-8")
    path.write_text(text.replace("sha256:" + _hex("3", 64), "sha256:" + _hex("7", 64)), "utf-8")

    with pytest.raises(suite.SuiteError, match="signature"):
        suite.verify_bom(path, sig, key_path=public)


def test_signature_by_another_key_fails(tmp_path, keypair):
    private, public = keypair
    other = tmp_path / "other"
    other.mkdir()
    other_private = other / "k.key"
    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(other_private))
    path = _write(tmp_path, _bom(public.read_text("ascii")))
    sig = _sign(other_private, path)

    with pytest.raises(suite.SuiteError, match="signature"):
        suite.verify_bom(path, sig, key_path=public)


def test_embedded_key_must_be_the_trusted_key(tmp_path, keypair):
    """A validly signed file that names another release key is refused: image checks
    later trust the embedded key, so it has to be the one the operator trusts."""
    private, public = keypair
    other_pub = tmp_path / "other.pub"
    other_key = tmp_path / "other.key"
    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(other_key))
    _openssl("ec", "-in", str(other_key), "-pubout", "-out", str(other_pub))
    path = _write(tmp_path, _bom(other_pub.read_text("ascii")))
    sig = _sign(private, path)

    with pytest.raises(suite.SuiteError, match="signing_key"):
        suite.verify_bom(path, sig, key_path=public)


def test_malformed_signature_and_oversize_file_are_refused(tmp_path, keypair):
    private, public = keypair
    path = _write(tmp_path, _bom(public.read_text("ascii")))
    sig = tmp_path / "bad.sig"
    sig.write_text("not base64 !!", encoding="ascii")
    with pytest.raises(suite.SuiteError, match="signature"):
        suite.verify_bom(path, sig, key_path=public)

    big = tmp_path / "big.yaml"
    big.write_bytes(b"#" * (suite.MAX_BOM_BYTES + 1))
    with pytest.raises(suite.SuiteError, match="too large"):
        suite.verify_bom(big, _sign(private, big), key_path=public)


def test_verify_needs_exactly_one_trust_anchor(tmp_path, keypair):
    private, public = keypair
    path = _write(tmp_path, _bom(public.read_text("ascii")))
    sig = _sign(private, path)
    with pytest.raises(suite.SuiteError, match="exactly one"):
        suite.verify_bom(path, sig)
    with pytest.raises(suite.SuiteError, match="exactly one"):
        suite.verify_bom(path, sig, key_path=public, fingerprint="sha256:" + _hex("0", 64))


@needs_openssl
def test_real_cosign_sign_blob_output_verifies():
    """The fixture was signed by `cosign sign-blob` itself, not by openssl."""
    bom, sig, pub = (FIXTURE / "suite-1.10.0.yaml", FIXTURE / "suite-1.10.0.yaml.sig",
                     FIXTURE / "release.pub")
    assert suite.verify_bom(bom, sig, key_path=pub)["suite"] == "1.10.0"
    assert suite.verify_bom(bom, sig, fingerprint=suite.key_fingerprint(STATIC_PEM))["suite"]


def test_bom_scope_and_suite_are_bound_to_the_caller(tmp_path, keypair):
    """A validly signed test-scope or older suite file is no delivery of the
    expected suite: no scope confusion, no rollback to an older signed file."""
    private, public = keypair
    doc = _bom(public.read_text("ascii"))
    doc["scope"] = "test"
    path = _write(tmp_path, doc)
    sig = _sign(private, path)

    with pytest.raises(suite.SuiteError, match="scope"):
        suite.verify_bom(path, sig, key_path=public)
    assert suite.verify_bom(path, sig, key_path=public, require_scope="test")["scope"] == "test"
    with pytest.raises(suite.SuiteError, match="suite"):
        suite.verify_bom(path, sig, key_path=public, require_scope="test", expected_suite="1.11.0")
    assert suite.verify_bom(
        path, sig, key_path=public, require_scope="test", expected_suite="1.10.0"
    )


@pytest.mark.parametrize(
    "content",
    [b"[" * 50000, b"- just\n- a list\n", b"\x00\xff" * 100, b""],
    ids=["deep-nesting", "list", "binary", "empty"],
)
def test_fingerprint_mode_refuses_hostile_unsigned_files(tmp_path, content):
    """Before authentication only the embedded key is located, by pattern; a
    hostile file fails cleanly with SuiteError, never with a traceback."""
    path = tmp_path / "hostile.yaml"
    path.write_bytes(content)
    sig = tmp_path / "hostile.yaml.sig"
    sig.write_text(base64.b64encode(b"0" * 70).decode("ascii"), encoding="ascii")

    with pytest.raises(suite.SuiteError):
        suite.verify_bom(path, sig, fingerprint=suite.key_fingerprint(STATIC_PEM))


@needs_openssl
def test_fingerprint_mode_checks_the_signature_before_any_parse(tmp_path, monkeypatch):
    """A file with the trusted key but a bad signature is refused without the
    YAML parser ever seeing it, even when the rest is deeply nested."""
    body = ("signing_key:\n  public_key: |\n    " + STATIC_PEM.replace("\n", "\n    ")).rstrip()
    path = tmp_path / "nested.yaml"
    path.write_text(body + "\nx: " + "[" * 50000 + "\n", encoding="ascii")
    sig = tmp_path / "nested.yaml.sig"
    sig.write_text(base64.b64encode(b"0" * 70).decode("ascii"), encoding="ascii")

    def no_parse(*_args, **_kwargs):
        raise AssertionError("parsed before the signature was checked")

    monkeypatch.setattr(suite.yaml, "safe_load", no_parse)
    with pytest.raises(suite.SuiteError, match="signature"):
        suite.verify_bom(path, sig, fingerprint=suite.key_fingerprint(STATIC_PEM))


def test_fingerprint_mode_refuses_more_than_one_embedded_key(tmp_path):
    path = tmp_path / "two.yaml"
    path.write_text(f"a: |\n{STATIC_PEM}b: |\n{STATIC_PEM}", encoding="ascii")
    sig = tmp_path / "two.yaml.sig"
    sig.write_text(base64.b64encode(b"0" * 70).decode("ascii"), encoding="ascii")
    with pytest.raises(suite.SuiteError, match="exactly one"):
        suite.verify_bom(path, sig, fingerprint=suite.key_fingerprint(STATIC_PEM))


def test_signed_but_hostile_yaml_fails_cleanly(tmp_path, keypair):
    """Even a correctly signed file that the parser cannot handle ends in
    SuiteError, not a traceback."""
    private, public = keypair
    path = tmp_path / "deep.yaml"
    path.write_bytes(b"[" * 50000)
    sig = _sign(private, path)
    with pytest.raises(suite.SuiteError, match="not YAML"):
        suite.verify_bom(path, sig, key_path=public)


def test_only_regular_files_are_read(tmp_path):
    """A FIFO or a device never reaches read(): the size limit would not hold."""
    fifo = tmp_path / "bom.fifo"
    os.mkfifo(fifo)
    with pytest.raises(suite.SuiteError, match="regular file"):
        suite.verify_bom(fifo, fifo, fingerprint=suite.key_fingerprint(STATIC_PEM))
    if Path("/dev/zero").exists():
        with pytest.raises(suite.SuiteError, match="regular file"):
            suite.verify_bom(Path("/dev/zero"), Path("/dev/zero"), key_path=Path("/dev/zero"))


def test_read_stops_at_the_limit_even_when_the_file_grows(tmp_path, monkeypatch):
    """The limit is enforced on what is read, not on what stat() reported."""
    path = tmp_path / "grows.yaml"
    path.write_bytes(b"#" * (suite.MAX_BOM_BYTES + 10))
    real_fstat = os.fstat

    class Small:
        def __init__(self, st):
            self.st_mode, self.st_size = st.st_mode, 1

    monkeypatch.setattr(suite.os, "fstat", lambda fd: Small(real_fstat(fd)))
    with pytest.raises(suite.SuiteError, match="too large"):
        suite.verify_bom(path, path, fingerprint=suite.key_fingerprint(STATIC_PEM))


def _verify_args(**overrides) -> argparse.Namespace:
    values = dict(bom=None, signature=None, key=None, fingerprint=None, json=False,
                  suite=None, scope="delivery", repo_root=str(REPO))
    values.update(overrides)
    return argparse.Namespace(**values)


def test_cli_suite_verify_exit_codes(tmp_path, keypair, capsys):
    private, public = keypair
    path = _write(tmp_path, _bom(public.read_text("ascii")))
    _sign(private, path)

    assert cli.cmd_suite_verify(_verify_args(bom=str(path), key=str(public), json=True)) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verified"] is True
    assert payload["suite"] == "1.10.0"
    assert payload["totals"] == {"containers": 6, "images": 6}

    assert cli.cmd_suite_verify(
        _verify_args(bom=str(path), key=str(public), suite="1.11.0")
    ) == 2
    assert "suite" in capsys.readouterr().err

    path.write_text(path.read_text("utf-8").replace("1.4.0", "1.4.1"), "utf-8")
    assert cli.cmd_suite_verify(_verify_args(bom=str(path), key=str(public))) == 2
    assert "signature" in capsys.readouterr().err


def test_trusted_key_file_with_crlf_line_endings_is_accepted(tmp_path, keypair):
    """A release key copied on Windows has CRLF line endings; it is the same key."""
    private, public = keypair
    path = _write(tmp_path, _bom(public.read_text("ascii")))
    sig = _sign(private, path)
    crlf = tmp_path / "release-crlf.pub"
    crlf.write_bytes(public.read_bytes().replace(b"\n", b"\r\n"))

    assert suite.verify_bom(path, sig, key_path=crlf)["suite"] == "1.10.0"


def test_cli_suite_verify_warns_when_the_suite_is_not_bound(tmp_path, keypair, capsys):
    """Without --suite an older file signed with the same key would pass; the
    command says so on stderr and in the JSON summary."""
    private, public = keypair
    path = _write(tmp_path, _bom(public.read_text("ascii")))
    _sign(private, path)

    assert cli.cmd_suite_verify(_verify_args(bom=str(path), key=str(public), json=True)) == 0
    out = capsys.readouterr()
    assert json.loads(out.out)["suite_bound"] is False
    assert "WARNING" in out.err and "--suite" in out.err

    assert cli.cmd_suite_verify(
        _verify_args(bom=str(path), key=str(public), suite="1.10.0", json=True)
    ) == 0
    out = capsys.readouterr()
    assert json.loads(out.out)["suite_bound"] is True
    assert out.err == ""


def test_cli_suite_verify_defaults_to_the_pinned_release_key(tmp_path, keypair, capsys):
    """Without --key or --fingerprint the release key pinned in the core
    checkout is the anchor; the key inside the file alone is never trusted."""
    private, public = keypair
    path = _write(tmp_path, _bom(public.read_text("ascii")))
    _sign(private, path)
    core = tmp_path / "core"

    (core / "compat").mkdir(parents=True)
    assert cli.cmd_suite_verify(_verify_args(bom=str(path), repo_root=str(core))) == 2
    assert "no trust anchor" in capsys.readouterr().err

    shutil.copy(public, core / suite.RELEASE_KEY_PATH)
    assert cli.cmd_suite_verify(_verify_args(bom=str(path), repo_root=str(core))) == 0


# ── compatibility matrix ─────────────────────────────────────────────────────


def test_shipped_matrix_is_valid():
    doc = yaml.safe_load((REPO / "compat/suite.yaml").read_text("utf-8"))
    suite.validate_matrix(doc)
    assert list(Draft202012Validator(MATRIX_SCHEMA).iter_errors(doc)) == []


def test_shipped_matrix_matches_this_checkout():
    """The row of this core's VERSION exists and names the pinned manager; the
    newest row carries the contract window this checkout serves."""
    matrix = suite.load_matrix(REPO)
    version = envtree.resolve_platform_version(REPO)
    row, _ = suite.matrix_rows(matrix, version)
    assert row is not None, f"compat/suite.yaml has no row for core {version}"

    compose = yaml.safe_load((REPO / "src/manager/docker-compose.yml").read_text("utf-8"))
    image = compose["services"]["papaia-manager"]["image"]
    manager_version = image.split("@", 1)[0].rsplit(":", 1)[1]
    assert semver.satisfies(manager_version, row["versions"]["manager"])

    newest = matrix["suites"][-1]
    window = compat.resolve_addon_api_window(REPO)
    assert (newest["addon_api"]["min"], newest["addon_api"]["current"]) == window


def test_public_table_matches_the_matrix():
    matrix = suite.load_matrix(REPO)
    text = (REPO / "docs/compatibility.md").read_text("utf-8")
    for row in matrix["suites"]:
        assert suite.table_row(matrix, row) in text, f"docs row for {row['suite']} is stale"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d.update(extra=1), "unknown field"),
        (lambda d: d["suites"][0].update(note="x"), "unknown field"),
        (lambda d: d["suites"][0]["versions"].update(unknown=">=1.0.0"), "not a component"),
        (lambda d: d["suites"][0].update(core="soon"), "core"),
        (lambda d: d["suites"][0]["versions"].update(manager="1.x"), "manager"),
        (lambda d: d["suites"].append(copy.deepcopy(d["suites"][0])), "suite"),
        (lambda d: d["suites"][0]["addon_api"].update(min=99), "addon_api"),
        (lambda d: d["suites"][0].update(status="beta"), "status"),
        (lambda d: d.update(components=[{"name": "manager"}]), "components"),
        (lambda d: d.update(components=["manager", 7]), "components"),
        (lambda d: d.update(components="manager"), "components"),
    ],
)
def test_malformed_matrix_is_rejected(mutate, message):
    doc = yaml.safe_load((REPO / "compat/suite.yaml").read_text("utf-8"))
    mutate(doc)
    with pytest.raises(suite.SuiteError, match=message):
        suite.validate_matrix(doc)


# ── addon check evaluates the matrix ─────────────────────────────────────────

MATRIX = {
    "schema": "papaia.compat-matrix/1",
    "components": ["manager", "papaia-flow"],
    "suites": [
        {
            "suite": "0.7.0",
            "status": "released",
            "core": ">=0.7.0,<0.8.0",
            "addon_api": {"min": 1, "current": 1},
            "versions": {"manager": ">=1.0.0,<1.1.0", "papaia-flow": ">=0.1.0,<0.2.0"},
        },
        {
            "suite": "0.8.0",
            "status": "released",
            "core": ">=0.8.0,<0.9.0",
            "addon_api": {"min": 1, "current": 1},
            "versions": {"manager": ">=1.1.0,<1.2.0", "papaia-flow": ">=0.2.0,<0.3.0"},
        },
    ],
}


def _check_args(config_dir: Path, repo_root: Path) -> argparse.Namespace:
    return argparse.Namespace(
        config_dir=str(config_dir),
        repo_root=str(repo_root),
        target_core=None,
        target_version=None,
        target_addon_api=None,
        target_min_addon_api=None,
        json=True,
        force=False,
    )


def _install_flow(repo_root: Path, config_dir: Path, tmp_path: Path, version: str) -> None:
    envtree.init(config_dir, repo_root, env_name="papaia")
    addon = tmp_path / f"flow-{version}"
    addon.mkdir()
    manifest = {"name": "papaia-flow", "version": version, "requires": {"addon_api": 1}}
    (addon / "papaia-app.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    args = argparse.Namespace(
        config_dir=str(config_dir),
        repo_root=str(repo_root),
        name="papaia-flow",
        path=str(addon),
        version=None,
        force=True,
    )
    assert cmd_addon_install(args) == 0


def _with_matrix(repo_root: Path, doc: dict) -> None:
    (repo_root / "compat").mkdir(exist_ok=True)
    (repo_root / "compat/suite.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")


@pytest.mark.parametrize(
    ("version", "expected_exit", "status"),
    [("0.2.3", 0, "OK"), ("0.1.4", 0, "OK"), ("0.3.0", 2, "INCOMPATIBLE")],
    ids=["suite-n", "suite-n-1", "outside"],
)
def test_addon_check_applies_the_matrix(
    repo_root, config_dir, tmp_path, capsys, version, expected_exit, status
):
    _install_flow(repo_root, config_dir, tmp_path, version)
    _with_matrix(repo_root, MATRIX)
    capsys.readouterr()

    assert cmd_addon_check(_check_args(config_dir, repo_root)) == expected_exit
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["status"] == status
    if status == "INCOMPATIBLE":
        assert payload[0]["axis"] == "matrix"
        assert "0.3.0" in payload[0]["reason"]


def _flow(status: str = compat.STATUS_OK) -> compat.CompatResult:
    return compat.CompatResult("papaia-flow", status)


def test_prerelease_core_belongs_to_its_suite_row():
    """1.10.0-rc.1 sorts below 1.10.0, but a release candidate of a suite is
    judged by that suite's row, not let through without one."""
    row, before = suite.matrix_rows(MATRIX, "0.8.0-rc.1")
    assert row["suite"] == "0.8.0"
    assert before["suite"] == "0.7.0"
    verdict = suite.evaluate_matrix(_flow(), "0.3.0", MATRIX, "0.8.0-rc.1")
    assert verdict.status == compat.STATUS_INCOMPATIBLE
    assert verdict.axis == "matrix"


def test_core_without_a_matrix_row_fails_closed():
    """A matrix that has no row for the judged core cannot vouch for any add-on:
    INCOMPATIBLE on the matrix axis, so enforce mode blocks."""
    verdict = suite.evaluate_matrix(_flow(), "0.2.0", MATRIX, "0.9.0")
    assert verdict.status == compat.STATUS_INCOMPATIBLE
    assert verdict.axis == "matrix"
    assert "no row" in verdict.reason


def test_unknown_core_version_is_reported_not_silent():
    """With only --target-addon-api the core version is unknown; the matrix is
    not applied and the result says so."""
    verdict = suite.evaluate_matrix(_flow(), "0.2.0", MATRIX, None)
    assert verdict.status == compat.STATUS_OK
    assert any("matrix not checked" in w for w in verdict.warnings)


@pytest.mark.parametrize(
    ("version", "expected_exit", "status"),
    [("0.3.1", 0, "OK"), ("0.2.0", 0, "OK"), ("0.1.4", 2, "INCOMPATIBLE")],
    ids=["suite-n", "suite-n-1", "two-back"],
)
def test_addon_check_uses_the_candidate_matrix_with_target_core(
    repo_root, config_dir, tmp_path, capsys, version, expected_exit, status
):
    """--target-core judges against the matrix the candidate ships, not this one."""
    _install_flow(repo_root, config_dir, tmp_path, version)
    target = tmp_path / "candidate"
    shutil.copytree(repo_root, target)
    (target / "VERSION").write_text("0.9.0\n", encoding="utf-8")
    candidate = copy.deepcopy(MATRIX)
    candidate["suites"].append({
        "suite": "0.9.0",
        "status": "candidate",
        "core": ">=0.9.0,<0.10.0",
        "addon_api": {"min": 1, "current": 1},
        "versions": {"manager": ">=1.2.0,<1.3.0", "papaia-flow": ">=0.3.0,<0.4.0"},
    })
    _with_matrix(target, candidate)
    capsys.readouterr()

    args = _check_args(config_dir, repo_root)
    args.target_core = str(target)
    assert cmd_addon_check(args) == expected_exit
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["status"] == status
    if status == "INCOMPATIBLE":
        assert payload[0]["axis"] == "matrix"
        assert "0.9.0" in payload[0]["reason"]


def test_addon_check_refuses_a_matrix_with_non_string_components(
    repo_root, config_dir, tmp_path, capsys
):
    _install_flow(repo_root, config_dir, tmp_path, "0.2.0")
    broken = copy.deepcopy(MATRIX)
    broken["components"] = [{"papaia-flow": 1}]
    _with_matrix(repo_root, broken)

    assert cmd_addon_check(_check_args(config_dir, repo_root)) == 2
    assert "components" in capsys.readouterr().err


def test_addon_check_refuses_a_malformed_matrix(repo_root, config_dir, tmp_path, capsys):
    _install_flow(repo_root, config_dir, tmp_path, "0.2.0")
    broken = copy.deepcopy(MATRIX)
    broken["suites"][1]["versions"]["papaia-flow"] = "two"
    _with_matrix(repo_root, broken)

    assert cmd_addon_check(_check_args(config_dir, repo_root)) == 2
    assert "compat/suite.yaml" in capsys.readouterr().err


def test_addon_check_without_matrix_is_unchanged(repo_root, config_dir, tmp_path, capsys):
    _install_flow(repo_root, config_dir, tmp_path, "9.9.9")
    capsys.readouterr()
    assert cmd_addon_check(_check_args(config_dir, repo_root)) == 0
    assert not re.search(r"matrix", capsys.readouterr().out)
