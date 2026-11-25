"""Image pinning and signature checks before `start` and `upgrade` (lib/images.py).

Every compose file names its images as `name:tag@sha256:<digest>`. Before the
containers are started, each image must be listed with that digest in the signed
suite bill of materials and carry a valid cosign signature by the key of that bill
of materials. `--insecure-images` skips the check for one command, prints a banner
and writes an audit row; nothing of it is stored.

The registry is replaced by an in-memory fake serving the same documents a real
registry does; the cosign format itself is covered by real `cosign sign` output in
fixtures/images/.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from lib import cli, doctor, images, status, suite

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "tools"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "images"
SUITE_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "suite"
LIFECYCLE = TOOLS / "lib" / "sh" / "lifecycle.sh"
UPGRADE = TOOLS / "lib" / "sh" / "upgrade.sh"
BASH = shutil.which("bash")

_NO_OPENSSL = shutil.which("openssl") is None
if _NO_OPENSSL and os.environ.get("PAPAIA_REQUIRE_OPENSSL"):
    raise RuntimeError("PAPAIA_REQUIRE_OPENSSL is set but openssl is not installed")

D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
D3 = "sha256:" + "3" * 64

KEYCLOAK = "quay.io/keycloak/keycloak"
POSTGRES = "postgres"


def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def _new_keypair(tmp_path: Path, name: str = "signing") -> tuple[Path, str]:
    """A throwaway P-256 key pair: (private key file, public PEM)."""
    if _NO_OPENSSL:
        pytest.skip("openssl not installed")
    private = tmp_path / f"{name}.key"
    public = tmp_path / f"{name}.pub"
    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(private))
    _openssl("ec", "-in", str(private), "-pubout", "-out", str(public))
    return private, public.read_text("ascii")


@pytest.fixture
def keypair(tmp_path: Path) -> tuple[Path, str]:
    return _new_keypair(tmp_path)


def _sign_bytes(private: Path, data: bytes, tmp: Path) -> str:
    blob, der = tmp / "blob", tmp / "blob.der"
    blob.write_bytes(data)
    _openssl("dgst", "-sha256", "-sign", str(private), "-out", str(der), str(blob))
    return base64.b64encode(der.read_bytes()).decode("ascii")


# ── fake registry ────────────────────────────────────────────────────────────


class FakeRegistry:
    """Serves manifests and blobs like a registry's /v2 API, keyed by host and
    repository as images.parse_ref normalises them."""

    def __init__(self) -> None:
        self.manifests: dict[tuple[str, str, str], bytes] = {}
        self.blobs: dict[tuple[str, str, str], bytes] = {}
        self.requests: list[tuple[str, str, str]] = []

    def manifest(self, host: str, repository: str, reference: str) -> bytes:
        self.requests.append((host, repository, reference))
        try:
            return self.manifests[(host, repository, reference)]
        except KeyError:
            raise images.NotFound(f"{host}/{repository}:{reference}") from None

    def blob(self, host: str, repository: str, digest: str, limit: int) -> bytes:
        try:
            data = self.blobs[(host, repository, digest)]
        except KeyError:
            raise images.NotFound(f"{host}/{repository}@{digest}") from None
        if len(data) > limit:
            raise images.ImageError("blob too large")
        return data

    def add_signature(
        self,
        host: str,
        repository: str,
        digest: str,
        private: Path,
        tmp: Path,
        *,
        signed_digest: str | None = None,
    ) -> None:
        """Store a signature the way `cosign sign` does: a simple signing payload
        as the one layer of a manifest tagged `sha256-<hex>.sig`."""
        payload = json.dumps(
            {
                "critical": {
                    "identity": {"docker-reference": f"{host}/{repository}"},
                    "image": {"docker-manifest-digest": signed_digest or digest},
                    "type": "cosign container image signature",
                },
                "optional": None,
            },
            separators=(",", ":"),
        ).encode()
        layer = "sha256:" + hashlib.sha256(payload).hexdigest()
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": 2,
                "digest": "sha256:" + hashlib.sha256(b"{}").hexdigest(),
            },
            "layers": [
                {
                    "mediaType": images.SIMPLESIGNING_MEDIA_TYPE,
                    "size": len(payload),
                    "digest": layer,
                    "annotations": {
                        images.SIGNATURE_ANNOTATION: _sign_bytes(private, payload, tmp)
                    },
                }
            ],
        }
        tag = digest.replace(":", "-") + ".sig"
        self.manifests[(host, repository, tag)] = json.dumps(manifest).encode()
        self.blobs[(host, repository, layer)] = payload


# ── bill of materials ────────────────────────────────────────────────────────


def _image(name: str, tag: str, digest: str) -> dict:
    return {
        "name": name,
        "tag": tag,
        "digest": digest,
        "license": "Apache-2.0",
        "license_class": "P",
        "sbom_digest": "sha256:" + "f" * 64,
        "delivery": "shipped",
    }


def _repo(name: str, role: str, version: str, char: str, entries: list[dict]) -> dict:
    return {
        "name": name,
        "role": role,
        "version": version,
        "tag": f"v{version}",
        "commit": char * 40,
        "containers": len(entries),
        "images": entries,
    }


def _bom(
    pem: str, entries: list[dict], *, scope: str = "delivery", version: str = "1.10.0"
) -> dict:
    repos = [
        _repo("papaia", "core", version, "a", entries),
        _repo("papaia-manager", "manager", "1.8.0", "b", []),
        _repo("papaia-flow", "module", "0.1.0", "c", []),
        _repo("papaia-addons", "addon", "1.4.0", "d", []),
        _repo("qdrant-mcp-rbac", "mcp", "0.5.0", "e", []),
        _repo("paperless-mcp-rbac", "mcp", "0.2.0", "6", []),
        _repo("papaia-kit", "kit", "0.1.0", "9", []),
    ]
    repos[6]["snapshot_sha256"] = "8" * 64
    return {
        "schema": suite.BOM_SCHEMA,
        "suite": version,
        "scope": scope,
        "created": "2026-12-01T10:00:00Z",
        "contract_generation": {"min": 1, "current": 12},
        "signing_key": {
            "algorithm": "ecdsa-p256-sha256",
            "fingerprint": suite.key_fingerprint(pem),
            "public_key": pem,
        },
        "repos": repos,
        "totals": {
            "containers": len(entries),
            "images": len({e["digest"] for e in entries}),
        },
    }


ENTRIES = [_image(KEYCLOAK, "26.7.0", D1), _image(POSTGRES, "18.3", D2)]


def _core(
    tmp_path: Path,
    keypair: tuple[Path, str],
    *,
    bom: dict | None = None,
    version: str = "1.10.0",
    with_key: bool = True,
) -> Path:
    """A core checkout with VERSION, the pinned release key and a signed bill of
    materials for that version."""
    private, pem = keypair
    root = tmp_path / "core"
    (root / "compat").mkdir(parents=True)
    (root / "VERSION").write_text(f"{version}\n", encoding="utf-8")
    if with_key:
        (root / suite.RELEASE_KEY_PATH).write_text(pem, encoding="ascii")
    doc = bom if bom is not None else _bom(pem, ENTRIES, version=version)
    path = root / "compat" / f"suite-{doc['suite']}.yaml"
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    sig_dir = tmp_path / "sig"
    sig_dir.mkdir(exist_ok=True)
    Path(f"{path}.sig").write_text(_sign_bytes(private, path.read_bytes(), sig_dir), "ascii")
    return root


def _signed_registry(keypair: tuple[Path, str], tmp_path: Path, host: str = "") -> FakeRegistry:
    """Both images of ENTRIES signed in their own repositories (or under `host`, a mirror)."""
    private, _ = keypair
    registry = FakeRegistry()
    for name, digest in ((KEYCLOAK, D1), (POSTGRES, D2)):
        ref = images.parse_ref(f"{host}{name}:x@{digest}")
        registry.add_signature(ref.registry, ref.repository, digest, private, tmp_path)
    return registry


# ── pinning rule (CI) ────────────────────────────────────────────────────────


def test_every_compose_image_is_pinned_by_tag_and_digest():
    refs = images.compose_image_refs(REPO)
    assert len(refs) >= 30, "the scan found too few images; is src/ still where it was?"
    exceptions = images.load_exceptions(REPO)
    problems = [f"{where}: {ref}: {why}" for where, ref in refs
                if (why := images.pin_problem(ref, exceptions)) is not None]
    assert problems == []


def test_every_tag_exception_is_still_in_use():
    used = set()
    for _, ref in images.compose_image_refs(REPO):
        parsed = images.parse_ref(ref)
        used.add((parsed.registry, parsed.repository, parsed.digest))
    assert images.load_exceptions(REPO) <= used


def _exceptions(tmp_path: Path, **entry) -> Path:
    base = {
        "image": "ghcr.io/example/tool",
        "digest": D1,
        "rule": "tag",
        "reason": "upstream keeps no tag for this build",
        "expires": "2027-01-31",
    }
    base.update(entry)
    (tmp_path / "compat").mkdir(exist_ok=True)
    (tmp_path / images.EXCEPTIONS_PATH).write_text(
        yaml.safe_dump({"schema": images.EXCEPTIONS_SCHEMA, "exceptions": [base]}), "utf-8"
    )
    return tmp_path


def test_tag_exception_releases_exactly_that_digest(tmp_path):
    today = images.date(2026, 11, 20)
    allowed = images.load_exceptions(_exceptions(tmp_path), today)
    assert images.pin_problem(f"ghcr.io/example/tool@{D1}", allowed) is None
    assert "tag" in images.pin_problem(f"ghcr.io/example/tool@{D2}", allowed)
    assert "digest" in images.pin_problem("ghcr.io/example/tool", allowed)


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"expires": "2026-11-19"}, "expired"),
        ({"expires": "2027-03-01"}, "90 days"),
        ({"rule": "digest"}, "rule"),
        ({"reason": "none"}, "reason"),
        ({"digest": "sha256:abc"}, "digest"),
        ({"approved": "yes"}, "exactly"),
    ],
)
def test_tag_exceptions_are_bounded(tmp_path, entry, message):
    with pytest.raises(images.ImageError, match=message):
        images.load_exceptions(_exceptions(tmp_path, **entry), images.date(2026, 11, 20))


def test_variant_images_are_pinned_too():
    refs = dict((where, ref) for where, ref in images.compose_image_refs(REPO))
    variants = [w for w in refs if "x-papaia-localai-gpu-images" in w]
    assert len(variants) == 5, refs.keys()
    assert any("x-papaia-voice-tts-gpu-images" in w for w in refs)


def test_localai_variants_are_builds_of_the_cpu_release():
    from lib import gpu_detect

    doc = yaml.safe_load((REPO / "src/ai/localai/docker-compose.yml").read_text("utf-8"))
    cpu = images.parse_ref(doc["services"]["localai"]["image"])
    variants = doc["x-papaia-localai-gpu-images"]
    assert set(variants) == set(gpu_detect.VARIANTS) - {gpu_detect.CPU}
    for variant, ref in variants.items():
        parsed = images.parse_ref(ref)
        assert parsed.repository == cpu.repository
        assert parsed.tag == cpu.tag + gpu_detect.TAG_SUFFIX[variant]


def test_backup_sidecar_image_is_pinned():
    from lib import node_shell

    assert images.pin_problem(node_shell.BACKUP_IMAGE) is None
    backup_sh = (TOOLS / "lib" / "sh" / "backup.sh").read_text("utf-8")
    assert f'BACKUP_IMAGE="{node_shell.BACKUP_IMAGE}"' in backup_sh


@pytest.mark.parametrize(
    ("ref", "reason"),
    [
        ("postgres:18.3", "digest"),
        (f"postgres@{D1}", "tag"),
        (f"curlimages/curl:latest@{D1}", "latest"),
        (f"ghcr.io/fidonis/papaia-me:dev@{D1}", "dev"),
        (f"ghcr.io/fidonis/papaia-me:main@{D1}", "branch"),
        (f"ghcr.io/fidonis/papaia-me:nightly@{D1}", "branch"),
        (f"ghcr.io/fidonis/papaia-me:1.0.0-dev@{D1}", "dev"),
        ("postgres:18.3@sha256:abc", "digest"),
        (f"${{OTHER:-}}postgres:18.3@{D1}", "variable"),
        (f"${{PAPAIA_IMAGE_MIRROR:-}}postgres:18.3@{D1}", "variable"),
        (f"postgres:18.3@{D1} ", "invalid"),
    ],
)
def test_unpinned_or_floating_references_are_named(ref, reason):
    problem = images.pin_problem(ref)
    assert problem is not None and reason in problem


@pytest.mark.parametrize(
    "ref",
    [
        f"postgres:18.3@{D1}",
        f"ghcr.io/devnen/chatterbox-tts-server:sha-915ae28-cpu@{D1}",
        f"127.0.0.1:57500/unpublished/papaia-me:0.1.0@{D1}",
    ],
)
def test_pinned_references_pass(ref):
    assert images.pin_problem(ref) is None


def test_references_are_normalised_like_docker_does():
    hub = images.parse_ref(f"postgres:18.3@{D1}")
    assert (hub.registry, hub.repository, hub.tag, hub.digest) == (
        "docker.io", "library/postgres", "18.3", D1
    )
    quay = images.parse_ref(f"quay.io/keycloak/keycloak:26.7.0@{D1}")
    assert (quay.registry, quay.repository) == ("quay.io", "keycloak/keycloak")
    local = images.parse_ref(f"127.0.0.1:58600/test/busybox:1.37.0@{D1}")
    assert (local.registry, local.repository) == ("127.0.0.1:58600", "test/busybox")


@pytest.mark.parametrize("value", ["", "registry.example.com/", "127.0.0.1:57500/unpublished/"])
def test_mirror_setting_accepts_a_registry_prefix(value):
    assert images.validate_mirror(value) == value


@pytest.mark.parametrize(
    "value", ["registry.example.com", "https://registry.example.com/", "a b/", "../", "x/" * 200]
)
def test_mirror_setting_refuses_anything_else(value):
    with pytest.raises(images.ImageError):
        images.validate_mirror(value)


def test_mirror_override_puts_every_core_image_behind_the_mirror(tmp_path):
    from lib import gen_override

    mirror = "registry.example.com/papaia/"
    config = tmp_path / "config"
    (config / "overrides").mkdir(parents=True)
    gen_override.generate_localai_gpu_override(config, REPO, "vulkan", tmp_path, mirror=mirror)
    gen_override.generate_image_mirror_override(config, REPO, mirror)

    path = config / "overrides" / gen_override.IMAGE_MIRROR_OVERRIDE
    services = yaml.safe_load(path.read_text("utf-8"))["services"]
    assert set(services) == set(images.compose_services(REPO))
    for body in services.values():
        assert body["image"].startswith(mirror)
        assert images.pin_problem(body["image"].removeprefix(mirror),
                                  images.load_exceptions(REPO)) is None
    # The accelerator image, whichever override Compose reads last.
    variant = yaml.safe_load(
        (config / "overrides" / "docker-compose.localai-gpu.override.yml").read_text("utf-8")
    )["services"]["localai"]["image"]
    assert services["localai"]["image"] == variant
    assert variant.startswith(mirror) and "-gpu-vulkan@sha256:" in variant

    gen_override.generate_image_mirror_override(config, REPO, "")
    assert not path.exists()


def test_mirror_override_refuses_a_malformed_mirror(tmp_path):
    from lib import gen_override

    with pytest.raises(images.ImageError):
        gen_override.generate_image_mirror_override(tmp_path, REPO, "registry.example.com")


def test_mirror_override_goes_to_every_node():
    from lib import gen_override, topology

    assert gen_override.IMAGE_MIRROR_OVERRIDE in topology.CORE_OVERRIDES


def test_mirror_variable_is_documented_in_env_example():
    example = (REPO / "src" / ".env.example").read_text("utf-8")
    assert f"\n{images.MIRROR_VAR}=" in example
    assert f"\n{images.SIGNATURES_VAR}=" in example


# ── verification ─────────────────────────────────────────────────────────────


def _refs(host: str = "") -> list[str]:
    return [f"{host}{KEYCLOAK}:26.7.0@{D1}", f"{host}{POSTGRES}:18.3@{D2}"]


def test_signed_images_listed_in_the_bom_pass(tmp_path, keypair):
    registry = _signed_registry(keypair, tmp_path)
    bom = _bom(keypair[1], ENTRIES)
    assert images.verify_images(_refs(), bom, registry=registry) == []


def test_unsigned_image_is_refused(tmp_path, keypair):
    registry = _signed_registry(keypair, tmp_path)
    del registry.manifests[("docker.io", "library/postgres", D2.replace(":", "-") + ".sig")]
    problems = images.verify_images(_refs(), _bom(keypair[1], ENTRIES), registry=registry)
    assert [(p.ref, "no signature" in p.reason) for p in problems] == [(_refs()[1], True)]


def test_tampered_digest_is_refused(tmp_path, keypair):
    """Same name and tag, other content: the digest in the compose file is not the one
    the bill of materials lists. Refused before the registry is asked at all."""
    registry = _signed_registry(keypair, tmp_path)
    private, _ = keypair
    registry.add_signature("quay.io", "keycloak/keycloak", D3, private, tmp_path)
    refs = [f"{KEYCLOAK}:26.7.0@{D3}"]
    problems = images.verify_images(refs, _bom(keypair[1], ENTRIES), registry=registry)
    assert len(problems) == 1
    assert "digest" in problems[0].reason and D1 in problems[0].reason
    assert registry.requests == []


def test_image_missing_from_the_bom_is_refused(tmp_path, keypair):
    registry = _signed_registry(keypair, tmp_path)
    problems = images.verify_images(
        [f"redis:8.8.0-alpine@{D3}"], _bom(keypair[1], ENTRIES), registry=registry
    )
    assert len(problems) == 1 and "not in the bill of materials" in problems[0].reason


def test_unpinned_reference_is_refused_without_asking_the_registry(tmp_path, keypair):
    registry = _signed_registry(keypair, tmp_path)
    problems = images.verify_images(
        [f"{KEYCLOAK}:26.7.0"], _bom(keypair[1], ENTRIES), registry=registry
    )
    assert len(problems) == 1 and "digest" in problems[0].reason
    assert registry.requests == []


def test_signature_by_another_key_is_refused(tmp_path, keypair):
    registry = _signed_registry(keypair, tmp_path)
    other = tmp_path / "other.key"
    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(other))
    registry.add_signature("docker.io", "library/postgres", D2, other, tmp_path)
    problems = images.verify_images(_refs(), _bom(keypair[1], ENTRIES), registry=registry)
    assert [p.ref for p in problems] == [_refs()[1]]
    assert "no valid signature" in problems[0].reason


def test_signature_of_another_image_is_refused(tmp_path, keypair):
    """A valid signature copied over from another digest names that digest."""
    private, pem = keypair
    registry = _signed_registry(keypair, tmp_path)
    registry.add_signature("docker.io", "library/postgres", D2, private, tmp_path,
                           signed_digest=D3)
    problems = images.verify_images(_refs(), _bom(pem, ENTRIES), registry=registry)
    assert [p.ref for p in problems] == [_refs()[1]]


def test_altered_payload_is_refused(tmp_path, keypair):
    registry = _signed_registry(keypair, tmp_path)
    for key, data in list(registry.blobs.items()):
        if key[1] == "library/postgres":
            registry.blobs[key] = data.replace(b"cosign", b"COSIGN")
    problems = images.verify_images(_refs(), _bom(keypair[1], ENTRIES), registry=registry)
    assert [p.ref for p in problems] == [_refs()[1]]


def test_mirror_serves_image_and_signature(tmp_path, keypair):
    mirror = "127.0.0.1:57500/unpublished/"
    registry = _signed_registry(keypair, tmp_path, host=mirror)
    problems = images.verify_images(
        _refs(mirror), _bom(keypair[1], ENTRIES), registry=registry, mirror=mirror
    )
    assert problems == []
    assert {r[0] for r in registry.requests} == {"127.0.0.1:57500"}


def test_signatures_may_live_in_a_separate_repository(tmp_path, keypair):
    private, pem = keypair
    registry = FakeRegistry()
    for digest in (D1, D2):
        registry.add_signature("ghcr.io", "example/signatures", digest, private, tmp_path)
    problems = images.verify_images(
        _refs(), _bom(pem, ENTRIES), registry=registry, signatures="ghcr.io/example/signatures"
    )
    assert problems == []


def test_unreachable_registry_is_a_refusal(tmp_path, keypair):
    class Down(FakeRegistry):
        def manifest(self, host, repository, reference):
            raise images.ImageError("connection refused")

    problems = images.verify_images(_refs(), _bom(keypair[1], ENTRIES), registry=Down())
    assert len(problems) == 2 and all("connection refused" in p.reason for p in problems)


def test_real_cosign_image_signature_verifies():
    """Real `cosign sign` output (cosign 2.4.1) is accepted; see fixtures/images/README.md."""
    if _NO_OPENSSL:
        pytest.skip("openssl not installed")
    manifest = (FIXTURE / "signature-manifest.json").read_bytes()
    payload = (FIXTURE / "payload.json").read_bytes()
    pem = (FIXTURE / "cosign.pub").read_text("ascii")
    digest = json.loads(payload)["critical"]["image"]["docker-manifest-digest"]
    layer = json.loads(manifest)["layers"][0]["digest"]
    registry = FakeRegistry()
    tag = digest.replace(":", "-") + ".sig"
    registry.manifests[("127.0.0.1:58600", "test/busybox", tag)] = manifest
    registry.blobs[("127.0.0.1:58600", "test/busybox", layer)] = payload
    ref = images.parse_ref(f"127.0.0.1:58600/test/busybox:1.37.0@{digest}")

    assert images.signature_problem(registry, ref, pem) is None

    registry.blobs[("127.0.0.1:58600", "test/busybox", layer)] = payload.replace(b"d82c", b"d82d")
    assert images.signature_problem(registry, ref, pem) is not None


# ── trust anchor (CORE-017 review finding) ───────────────────────────────────


def test_trusted_bom_loads_with_the_pinned_release_key(tmp_path, keypair):
    doc = images.load_trusted_bom(_core(tmp_path, keypair))
    assert doc["suite"] == "1.10.0"


def test_missing_release_key_aborts_instead_of_checking_without_anchor(tmp_path, keypair):
    root = _core(tmp_path, keypair, with_key=False)
    with pytest.raises(images.ImageError, match="trust anchor"):
        images.load_trusted_bom(root)


def test_missing_bill_of_materials_aborts(tmp_path, keypair):
    root = _core(tmp_path, keypair)
    (root / "compat" / "suite-1.10.0.yaml").unlink()
    with pytest.raises(images.ImageError, match="bill of materials"):
        images.load_trusted_bom(root)


def test_test_scope_bom_is_refused(tmp_path, keypair):
    root = _core(tmp_path, keypair, bom=_bom(keypair[1], ENTRIES, scope="test"))
    with pytest.raises(images.ImageError, match="scope"):
        images.load_trusted_bom(root)


def test_older_signed_suite_is_refused(tmp_path, keypair):
    """A validly signed bill of materials of an older suite, renamed to the current
    file name: no rollback to the digests of another release."""
    root = _core(tmp_path, keypair, bom=_bom(keypair[1], ENTRIES, version="1.9.0"))
    (root / "VERSION").write_text("1.10.0\n", encoding="utf-8")
    for suffix in ("", ".sig"):
        (root / "compat" / f"suite-1.9.0.yaml{suffix}").rename(
            root / "compat" / f"suite-1.10.0.yaml{suffix}"
        )
    with pytest.raises(images.ImageError, match="suite"):
        images.load_trusted_bom(root)


def test_the_embedded_key_alone_is_not_trusted(tmp_path, keypair):
    """Signed by a key that is not the pinned one, embedding that key itself."""
    other = tmp_path / "other.key"
    other_pub = tmp_path / "other.pub"
    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(other))
    _openssl("ec", "-in", str(other), "-pubout", "-out", str(other_pub))
    root = _core(tmp_path, (other, other_pub.read_text("ascii")))
    (root / suite.RELEASE_KEY_PATH).write_text(keypair[1], encoding="ascii")
    with pytest.raises(images.ImageError, match="signature"):
        images.load_trusted_bom(root)


def test_suite_fixture_key_is_not_a_release_key():
    """The cosign fixture of the suite tests must never become the pinned anchor."""
    pinned = REPO / suite.RELEASE_KEY_PATH
    if pinned.is_file():
        assert pinned.read_text("ascii") != (SUITE_FIXTURE / "release.pub").read_text("ascii")
        assert pinned.read_text("ascii") != (FIXTURE / "cosign.pub").read_text("ascii")


# ── image-verify command ─────────────────────────────────────────────────────


def _config(tmp_path: Path, env: str = "") -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / ".env").write_text(f"COMPOSE_PROJECT_NAME=papaia\n{env}", encoding="utf-8")
    (config / "deployment.yaml").write_text("platform_version: 1.10.0\n", encoding="utf-8")
    return config


def _images_file(tmp_path: Path, refs: list[str]) -> Path:
    path = tmp_path / "images.txt"
    path.write_text("\n".join(refs) + "\n", encoding="utf-8")
    return path


def _verify(root: Path, config: Path, images_file: Path, *extra: str) -> int:
    return cli.main(
        ["--repo-root", str(root), "--config-dir", str(config), "image-verify",
         f"--images-file={images_file}", "--command=start", *extra]
    )


def test_image_verify_passes_signed_images(tmp_path, keypair, monkeypatch, capsys):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(keypair, tmp_path))
    assert _verify(root, config, _images_file(tmp_path, _refs())) == 0
    assert "2 image(s) verified" in capsys.readouterr().out


def test_image_verify_refuses_and_names_each_image(tmp_path, keypair, monkeypatch, capsys):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    registry = _signed_registry(keypair, tmp_path)
    registry.manifests.clear()
    monkeypatch.setattr(images, "Registry", lambda: registry)
    assert _verify(root, config, _images_file(tmp_path, _refs())) == 2
    err = capsys.readouterr().err
    assert _refs()[0] in err and _refs()[1] in err and "--insecure-images" in err


def test_image_verify_without_anchor_refuses(tmp_path, keypair, capsys):
    root, config = _core(tmp_path, keypair, with_key=False), _config(tmp_path)
    assert _verify(root, config, _images_file(tmp_path, _refs())) == 2
    assert "trust anchor" in capsys.readouterr().err


def test_image_verify_uses_the_mirror_setting(tmp_path, keypair, monkeypatch):
    mirror = "127.0.0.1:57500/unpublished/"
    root = _core(tmp_path, keypair)
    config = _config(tmp_path, f"PAPAIA_IMAGE_MIRROR={mirror}\n")
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(keypair, tmp_path, mirror))
    # As the mirror override wrote them, and as an upgrade's pre-check lists them.
    assert _verify(root, config, _images_file(tmp_path, _refs(mirror))) == 0
    assert _verify(root, config, _images_file(tmp_path, _refs())) == 0


def test_image_verify_refuses_a_malformed_mirror_setting(tmp_path, keypair, capsys):
    root = _core(tmp_path, keypair)
    config = _config(tmp_path, "PAPAIA_IMAGE_MIRROR=https://registry.example.com\n")
    assert _verify(root, config, _images_file(tmp_path, _refs())) == 2
    assert images.MIRROR_VAR in capsys.readouterr().err


def test_image_verify_refuses_an_oversized_image_list(tmp_path, keypair, capsys):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    many = [f"{POSTGRES}:18.{i}@{D2}" for i in range(images.MAX_IMAGES + 1)]
    assert _verify(root, config, _images_file(tmp_path, many)) == 2


def _audit_rows(config: Path) -> list[dict]:
    path = config / images.AUDIT_LOG
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line]


def test_insecure_images_shows_a_banner_and_writes_one_audit_row(tmp_path, keypair, capsys):
    root, config = _core(tmp_path, keypair, with_key=False), _config(tmp_path)
    before = {p.name: p.read_bytes() for p in config.iterdir() if p.is_file()}

    assert _verify(root, config, _images_file(tmp_path, _refs()), "--insecure-images") == 0
    err = capsys.readouterr().err
    assert "INSECURE" in err and "not verified" in err

    rows = _audit_rows(config)
    assert len(rows) == 1
    row = rows[0]
    assert row["format"] == "papaia.audit/1"
    assert row["event"] == "image_verification_skipped"
    assert row["operation"] == "start"
    assert row["result"] == "allowed"
    assert row["correlation_id"]
    assert row["detail"] == {"command": "start", "images": 2, "flag": "--insecure-images"}
    assert oct((config / images.AUDIT_LOG).stat().st_mode & 0o777) == "0o600"
    # Nothing but the audit journal changed: the flag is not stored anywhere.
    after = {p.name: p.read_bytes() for p in config.iterdir() if p.is_file()}
    assert after == before


def test_insecure_images_is_not_persisted(tmp_path, keypair, monkeypatch, capsys):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    registry = _signed_registry(keypair, tmp_path)
    registry.manifests.clear()
    monkeypatch.setattr(images, "Registry", lambda: registry)
    refs = _images_file(tmp_path, _refs())
    assert _verify(root, config, refs, "--insecure-images") == 0
    assert _verify(root, config, refs) == 2
    assert len(_audit_rows(config)) == 1


# ── start and upgrade ────────────────────────────────────────────────────────

_START = """
set -euo pipefail
DEFAULT_CONFIG_DIR="@CONFIG@"
REPO_ROOT="@CONFIG@/repo"
COMPOSE_FILE="@CONFIG@/repo/src/docker-compose.yml"
error() { echo "ERROR: $*" >&2; }
warn() { :; }
info() { :; }
success() { :; }
usage() { :; }
source "@LIFECYCLE@"
_require_setup_done() { :; }
_topology_mode() { echo single; }
_require_no_node() { :; }
_stopped_containers_go_stale() { return 1; }
_addon_path() { echo "/addons/$1"; }
_addon_compose_up() { echo "compose-up $1"; }
_addon_image_list() { :; }
docker() {
    case " $* " in
        *" config --images "*) echo "docker $*" >> "@CONFIG@/docker.log"; echo "@REF@" ;;
        *) echo "docker $*" ;;
    esac
}
py_cli() {
    # active-addons answers on stdout, which the caller reads as the list of names.
    [ "$1" = active-addons ] && { echo wiki; return 0; }
    echo "py_cli $*"
    case "$1" in
        image-verify)
            local a
            for a in "$@"; do
                case "$a" in --images-file=*) sed 's/^/listed /' "${a#--images-file=}" ;; esac
            done
            return @VERIFY@ ;;
    esac
}
cmd_start --addons @FLAGS@
"""


def _start(tmp_path: Path, *, verify: int = 0, flags: str = "") -> subprocess.CompletedProcess:
    if BASH is None:
        pytest.skip("bash is not available")
    script = (
        _START.replace("@CONFIG@", tmp_path.as_posix())
        .replace("@LIFECYCLE@", LIFECYCLE.as_posix())
        .replace("@REF@", f"{KEYCLOAK}:26.7.0@{D1}")
        .replace("@VERIFY@", str(verify))
        .replace("@FLAGS@", flags)
    )
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30,
                          check=False)


def test_start_verifies_the_images_before_anything_starts(tmp_path):
    done = _start(tmp_path)
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    verify = next(i for i, c in enumerate(calls) if c.startswith("py_cli image-verify"))
    assert "--command=start" in calls[verify]
    # The list compose printed is what the check gets.
    assert calls[verify + 1] == f"listed {KEYCLOAK}:26.7.0@{D1}"
    assert "config --images" in (tmp_path / "docker.log").read_text("utf-8")
    # The add-on env is materialised first (nothing starts), so the check sees the env
    # `up` interpolates.
    assert calls.index("py_cli addon-start --name=wiki --no-keycloak") < verify
    assert not any(c.startswith("compose-up") for c in calls[:verify])
    up = next(i for i, c in enumerate(calls) if c.startswith("docker compose") and " up " in c)
    assert verify < up


def test_start_aborts_when_verification_fails_and_starts_no_container(tmp_path):
    done = _start(tmp_path, verify=2)
    assert done.returncode != 0
    calls = done.stdout.splitlines()
    assert not any(c.startswith("compose-up") for c in calls)
    assert not any(c.startswith("docker compose") and " up " in c for c in calls)
    # Materialising the add-on env before the check writes files only; no add-on starts.
    assert calls.index("py_cli addon-start --name=wiki --no-keycloak") < next(
        i for i, c in enumerate(calls) if c.startswith("py_cli image-verify"))


def test_start_passes_insecure_images_to_the_check_only(tmp_path):
    done = _start(tmp_path, flags="--insecure-images")
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    flagged = [c for c in calls if "--insecure-images" in c]
    assert len(flagged) == 1 and flagged[0].startswith("py_cli image-verify")


_UPGRADE = """
set -euo pipefail
DEFAULT_CONFIG_DIR="@TMP@/config"
REPO_ROOT="@TMP@/repo"
COMPOSE_FILE="@TMP@/repo/src/docker-compose.yml"
BASH="@TMP@/next-phase"
error() { echo "ERROR: $*" >&2; }
warn() { :; }
info() { :; }
success() { :; }
usage() { :; }
is_tty() { return 1; }
source "@LIFECYCLE@"
source "@UPGRADE@"
_require_setup_done() { :; }
_topology_mode() { echo single; }
cmd_backup() { echo "backup"; LAST_BACKUP_ID=rp1; }
cmd_stop() { echo "stop $*"; }
git() {
    echo "git $*" >&2
    case "$*" in
        *"worktree add"*) mkdir -p "${@: -2:1}" ;;
        *"status --porcelain"*) ;;
        *"rev-parse"*) echo "${@: -1}" | sed 's/\\^{commit}$//' ;;
    esac
    return 0
}
docker() {
    case " $* " in
        *" config --images "*) echo "docker $*" >> "@TMP@/docker.log"; echo "@REF@" ;;
        *) echo "docker $*" ;;
    esac
}
py_cli() {
    case "$1" in
        image-trust-anchor) echo "sha256:@ANCHOR@"; return ;;
        new-correlation-id) echo "0b5a4c84-6f0a-4f36-9a4e-0d0c5a7d1e11"; return ;;
        # No unfinished staged upgrade: no restore point to keep.
        upgrade-stage) [ "$2" = restore-point ] && return 0; echo "py_cli $*"; return ;;
        active-addons) return ;;
    esac
    echo "py_cli $*"
    if [ "$1" = "upgrade-resolve" ]; then
        printf 'CURRENT\\t1.9.0\\nTARGET\\t1.10.0\\nTAG\\tv1.10.0\\nSTATUS\\tupgrade\\n'
    fi
}
# The target's runtime environment (lib/sh/runtime.sh) is not built here.
ctl_runtime_at() { echo "ctl_runtime_at $*"; }
_py_cli_at() {
    echo "py_cli_at $*"
    case "$2" in image-verify) return @VERIFY@ ;; esac
    return 0
}
cmd_upgrade -y @FLAGS@
"""


def _upgrade(tmp_path: Path, *, verify: int = 0, flags: str = "") -> subprocess.CompletedProcess:
    if BASH is None:
        pytest.skip("bash is not available")
    nxt = tmp_path / "next-phase"
    nxt.write_text('#!/bin/sh\necho "phase2 $*"\n', encoding="utf-8")
    nxt.chmod(0o755)
    (tmp_path / "config").mkdir()
    script = (
        _UPGRADE.replace("@TMP@", tmp_path.as_posix())
        .replace("@LIFECYCLE@", LIFECYCLE.as_posix())
        .replace("@UPGRADE@", UPGRADE.as_posix())
        .replace("@REF@", f"{KEYCLOAK}:26.7.0@{D1}")
        .replace("@VERIFY@", str(verify))
        .replace("@FLAGS@", flags)
        .replace("@ANCHOR@", "a" * 64)
    )
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30,
                          check=False)


def test_upgrade_verifies_the_target_images_before_anything_changes(tmp_path):
    done = _upgrade(tmp_path)
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    verify = next(i for i, c in enumerate(calls) if "image-verify" in c)
    assert calls[verify].startswith("py_cli_at ") and "--command=upgrade" in calls[verify]
    # Every image the target pins, all profiles and variants: its env files do not
    # exist yet, so compose cannot narrow the list.
    assert "--from-checkout" in calls[verify]
    assert "/target " in calls[verify] or calls[verify].split()[1].endswith("/target")
    assert verify < calls.index("backup")
    assert "--insecure-images" not in calls[-1]


def test_upgrade_aborts_without_change_when_verification_fails(tmp_path):
    done = _upgrade(tmp_path, verify=2)
    assert done.returncode != 0
    calls = done.stdout.splitlines()
    assert "backup" not in calls
    assert not any(c.startswith("stop") or c.startswith("phase2") for c in calls)
    assert "checkout --detach" not in done.stderr


def test_upgrade_forwards_insecure_images_to_its_own_second_phase_only(tmp_path):
    done = _upgrade(tmp_path, flags="--insecure-images")
    assert done.returncode == 0, done.stderr
    calls = done.stdout.splitlines()
    assert "--insecure-images" in next(c for c in calls if "image-verify" in c)
    assert calls[-1].startswith("phase2 ") and "--insecure-images" in calls[-1]


# ── doctor image_signatures ──────────────────────────────────────────────────


def _doctor_ctx(tmp_path: Path, root: Path, config: Path, containers: dict[str, str]):
    def run(cmd, timeout=0):
        if cmd[:2] == ["docker", "ps"]:
            return status.CommandResult(0, "".join(f"{n}\n" for n in containers))
        if cmd[:2] == ["docker", "inspect"]:
            names = cmd[cmd.index("--format") + 2:]
            return status.CommandResult(
                0, "".join(f"/{n}\t{containers[n]}\tsha256:id-{n}\n" for n in names)
            )
        if cmd[:3] == ["docker", "image", "inspect"]:
            ids = cmd[cmd.index("--format") + 2:]
            lines = []
            for image_id in ids:
                ref = containers[image_id.removeprefix("sha256:id-")]
                name, _, digest = ref.partition("@")
                lines.append(f'{image_id}\t{json.dumps([f"{name}@{digest}"] if digest else [])}\n')
            return status.CommandResult(0, "".join(lines))
        return status.CommandResult(127, "", "unexpected")

    return doctor.Context(config, root, run=run, probes=doctor.Probes(),
                          now=doctor.datetime.now(doctor.timezone.utc))


def test_image_verify_from_checkout_checks_every_pin_of_the_tree(tmp_path, keypair, monkeypatch):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    compose = root / "src" / "docker-compose.yml"
    compose.parent.mkdir(parents=True, exist_ok=True)
    compose.write_text(yaml.safe_dump({"services": {
        "keycloak": {"image": _refs()[0]},
        "postgres": {"image": _refs()[1]},
    }}), "utf-8")
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(keypair, tmp_path, ""))
    assert cli.main(["--repo-root", str(root), "--config-dir", str(config),
                     "image-verify", "--from-checkout", "--command=upgrade"]) == 0
    compose.write_text(yaml.safe_dump({"services": {
        "keycloak": {"image": f"{KEYCLOAK}:26.7.0@{D3}"}}}), "utf-8")
    assert cli.main(["--repo-root", str(root), "--config-dir", str(config),
                     "image-verify", "--from-checkout", "--command=upgrade"]) == 2


def test_image_verify_needs_exactly_one_image_source(tmp_path, keypair):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    assert cli.main(["--repo-root", str(root), "--config-dir", str(config),
                     "image-verify", "--command=start"]) == 2


def test_doctor_registers_image_signatures():
    assert "image_signatures" in doctor.CHECK_NAMES


def test_doctor_passes_signed_running_images(tmp_path, keypair, monkeypatch):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(keypair, tmp_path))
    ctx = _doctor_ctx(tmp_path, root, config,
                      {"papaia-keycloak-1": _refs()[0], "papaia-db-1": _refs()[1]})
    result = doctor.check_image_signatures(ctx)
    assert result.status == doctor.PASS, result.summary


def test_doctor_fails_for_an_unsigned_running_image(tmp_path, keypair, monkeypatch):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    registry = _signed_registry(keypair, tmp_path)
    del registry.manifests[("docker.io", "library/postgres", D2.replace(":", "-") + ".sig")]
    monkeypatch.setattr(images, "Registry", lambda: registry)
    ctx = _doctor_ctx(tmp_path, root, config,
                      {"papaia-keycloak-1": _refs()[0], "papaia-db-1": _refs()[1]})
    result = doctor.check_image_signatures(ctx)
    assert result.status == doctor.FAIL
    assert "papaia-db-1" in result.summary
    assert [i["container"] for i in result.details["images"] if i["status"] == doctor.FAIL] == [
        "papaia-db-1"
    ]


def test_doctor_fails_for_a_running_image_without_digest(tmp_path, keypair, monkeypatch):
    root, config = _core(tmp_path, keypair), _config(tmp_path)
    monkeypatch.setattr(images, "Registry", lambda: _signed_registry(keypair, tmp_path))
    ctx = _doctor_ctx(tmp_path, root, config, {"papaia-redis-1": "redis:8.8.0-alpine"})
    assert doctor.check_image_signatures(ctx).status == doctor.FAIL


def test_doctor_fails_without_trust_anchor_while_images_run(tmp_path, keypair):
    root, config = _core(tmp_path, keypair, with_key=False), _config(tmp_path)
    ctx = _doctor_ctx(tmp_path, root, config, {"papaia-keycloak-1": _refs()[0]})
    result = doctor.check_image_signatures(ctx)
    assert result.status == doctor.FAIL and "trust anchor" in result.summary


def test_doctor_passes_when_nothing_runs(tmp_path, keypair):
    root, config = _core(tmp_path, keypair, with_key=False), _config(tmp_path)
    assert doctor.check_image_signatures(_doctor_ctx(tmp_path, root, config, {})).status == (
        doctor.PASS
    )


def test_doctor_skips_before_setup(tmp_path, keypair):
    root = _core(tmp_path, keypair)
    config = tmp_path / "empty"
    config.mkdir()
    assert doctor.check_image_signatures(_doctor_ctx(tmp_path, root, config, {})).status == (
        doctor.SKIP
    )
