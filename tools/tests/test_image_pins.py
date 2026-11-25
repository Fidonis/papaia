"""Every pinned image resolves in a registry (lib/image_pins.py, tools/check-image-pins).

A pin that no registry serves stops every installation at its start, and a tag that was
moved after the pin was taken names other bytes than the digest. The check resolves
every pin of the compose files, the service-env.json files and the suite bill of
materials against the registry and names file and line of each one that does not
resolve. The fixture registry is a real /v2 HTTP server on the loopback interface,
spoken to by the real client (images.Registry); registries elsewhere are a fake.
"""

from __future__ import annotations

import email.message
import hashlib
import http.server
import json
import subprocess
import threading
import urllib.error
from pathlib import Path

import pytest
import yaml

from lib import (
    compat,
    image_pins,
    images,
    module_offer,
    own_images,
    pairing_approval,
    release_day,
    semver,
)

REPO = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"

D_KNOWN = "sha256:" + hashlib.sha256(b"known index").hexdigest()
D_OTHER = "sha256:" + hashlib.sha256(b"other index").hexdigest()
D_UNKNOWN = "sha256:" + "0" * 64
NO_CI = {"GITHUB_REF": "refs/heads/releases/1.10.0", "GITHUB_REF_TYPE": "branch"}


# ── fixture registry ─────────────────────────────────────────────────────────


class FixtureRegistry:
    """A loopback /v2 registry serving manifests by tag and digest: GET and HEAD, with
    `Docker-Content-Digest` unless `with_digest_header` is off."""

    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}
        self.tags: dict[tuple[str, str], str] = {}
        self.with_digest_header = True
        self.methods: list[str] = []
        registry = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _answer(self, body: bool) -> None:
                registry.methods.append(self.command)
                parts = self.path.split("/manifests/")
                if len(parts) != 2 or not parts[0].startswith("/v2/"):
                    self.send_error(404)
                    return
                repository, reference = parts[0][len("/v2/"):], parts[1]
                digest = reference if reference.startswith("sha256:") else registry.tags.get(
                    (repository, reference))
                data = registry.blobs.get((repository, digest)) if digest else None
                if data is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.oci.image.index.v1+json")
                self.send_header("Content-Length", str(len(data)))
                if registry.with_digest_header:
                    self.send_header("Docker-Content-Digest", digest)
                self.end_headers()
                if body:
                    self.wfile.write(data)

            def do_GET(self) -> None:  # noqa: N802 - http.server API
                self._answer(True)

            def do_HEAD(self) -> None:  # noqa: N802 - http.server API
                self._answer(False)

            def log_message(self, *args) -> None:
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.host = f"127.0.0.1:{self.server.server_address[1]}"
        self.prefix = f"{self.host}/unpublished/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def push(self, repository: str, tag: str, data: bytes) -> str:
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        self.blobs[(repository, digest)] = data
        self.tags[(repository, tag)] = digest
        return digest

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def fixture_registry():
    registry = FixtureRegistry()
    yield registry
    registry.close()


class Upstream:
    """Registries other than the fixture: {(host, repository, reference): digest}."""

    def __init__(self, served: dict[tuple[str, str, str], str] | None = None) -> None:
        self.served = served or {}
        self.asked: list[tuple[str, str, str]] = []

    def resolve(self, host: str, repository: str, reference: str) -> str:
        self.asked.append((host, repository, reference))
        try:
            return self.served[(host, repository, reference)]
        except KeyError:
            raise images.NotFound(f"{host}/{repository}:{reference}") from None


class Routed:
    """The real client for the loopback fixture registry, a fake for the rest."""

    def __init__(self, local_host: str, upstream: Upstream) -> None:
        self.local_host, self.upstream = local_host, upstream
        self.client = images.Registry(credentials=_NoCredentials())

    def resolve(self, host: str, repository: str, reference: str) -> str:
        if host == self.local_host:
            return self.client.resolve(host, repository, reference)
        return self.upstream.resolve(host, repository, reference)


class _NoCredentials:
    def lookup(self, host: str):
        return None


def _served(ref: str) -> dict[tuple[str, str, str], str]:
    """Upstream serving `ref` correctly: by digest and by tag."""
    parsed = images.parse_ref(ref)
    found = {(parsed.registry, parsed.repository, parsed.digest): parsed.digest}
    if parsed.tag:
        found[(parsed.registry, parsed.repository, parsed.tag)] = parsed.digest
    return found


# ── checkouts ────────────────────────────────────────────────────────────────


APP = "ghcr.io/example/app"
DB = "postgres"


def _checkout(tmp_path: Path, app: str, db: str = f"{DB}:18.3@{D_KNOWN}",
              version: str = "1.10.0-rc.1") -> Path:
    root = tmp_path / "core"
    (root / "src" / "app").mkdir(parents=True)
    (root / "compat").mkdir()
    (root / "VERSION").write_text(f"{version}\n", encoding="utf-8")
    (root / "src" / "app" / "docker-compose.yml").write_text(
        "# fixture\n"
        "services:\n"
        "  app:\n"
        f"    image: {app}\n"
        "  app-db:\n"
        f"    image: {db}\n",
        encoding="utf-8",
    )
    (root / "src" / "app" / "service-env.json").write_text(
        json.dumps({"format": "papaia.me-service-env/1", "image": app,
                    "source": {"repository": "app", "commit": "a" * 40}}, indent=2) + "\n",
        encoding="utf-8",
    )
    (root / "compat" / "own-images.yaml").write_text(
        "schema: papaia.own-images/1\nimages: []\n", encoding="utf-8")
    return root


def _check(root: Path, registry, **kwargs):
    kwargs.setdefault("env", NO_CI)
    return image_pins.check(root, registry=registry, **kwargs)


# ── collecting ───────────────────────────────────────────────────────────────


def test_every_pin_is_found_with_file_and_line(tmp_path):
    root = _checkout(tmp_path, f"{APP}:1.0.0@{D_KNOWN}")

    pins = image_pins.collect(root)

    assert [(p.location, p.where) for p in pins] == [
        ("src/app/docker-compose.yml:4", "services.app.image"),
        ("src/app/docker-compose.yml:6", "services.app-db.image"),
        ("src/app/service-env.json:3", "image"),
    ]


def test_the_bill_of_materials_of_the_suite_is_read_too(tmp_path):
    root = _checkout(tmp_path, f"{APP}:1.0.0@{D_KNOWN}")
    (root / "compat" / "suite-1.10.0.yaml").write_text(
        "schema: papaia.suite-bom/1\n"
        "repos:\n"
        "  - name: papaia\n"
        "    images:\n"
        f"      - name: {APP}\n"
        "        tag: 1.0.0\n"
        f"        digest: {D_OTHER}\n",
        encoding="utf-8",
    )

    bom = [p for p in image_pins.collect(root) if p.path == "compat/suite-1.10.0.yaml"]

    assert [(p.line, p.ref) for p in bom] == [(7, f"{APP}:1.0.0@{D_OTHER}")]


def test_the_shipped_tree_names_every_compose_pin_and_the_me_env_list():
    pins = image_pins.collect(REPO)
    found = {(p.path, p.ref) for p in pins}

    for location, ref in images.compose_image_refs(REPO):
        assert (location.split(":", 1)[0], ref) in found, location
    me = [p for p in pins if p.path == "src/infra/me/service-env.json"]
    assert len(me) == 1 and me[0].ref.startswith("ghcr.io/fidonis/papaia-me:")
    for pin in pins:
        lines = (REPO / pin.path).read_text(encoding="utf-8").splitlines()
        assert pin.ref in lines[pin.line - 1], pin.location


# ── candidate mode against the fixture registry ──────────────────────────────


def test_candidate_a_known_digest_passes(tmp_path, fixture_registry):
    digest = fixture_registry.push("unpublished/ghcr.io/example/app", "1.0.0", b"app index")
    db = fixture_registry.push("unpublished/postgres", "18.3", b"db index")
    root = _checkout(tmp_path, f"{APP}:1.0.0@{digest}", f"{DB}:18.3@{db}")
    upstream = Upstream()

    pins, findings = _check(root, Routed(fixture_registry.host, upstream), mode="candidate",
                            candidate_registry=fixture_registry.prefix)

    assert len(pins) == 3 and findings == []
    assert upstream.asked == [], "a pin served by the candidate registry asks nobody else"
    assert "HEAD" in fixture_registry.methods


def test_candidate_an_unknown_digest_fails_with_file_and_line(tmp_path, fixture_registry):
    db = fixture_registry.push("unpublished/postgres", "18.3", b"db index")
    root = _checkout(tmp_path, f"{APP}:1.0.0@{D_UNKNOWN}", f"{DB}:18.3@{db}")

    _, findings = _check(root, Routed(fixture_registry.host, Upstream()), mode="candidate",
                         candidate_registry=fixture_registry.prefix)

    assert [f.pin.location for f in findings] == [
        "src/app/docker-compose.yml:4", "src/app/service-env.json:3"]
    assert all("unknown digest" in f.reason for f in findings)
    assert str(findings[0]).startswith("src/app/docker-compose.yml:4: services.app.image: ")


def test_candidate_a_moved_tag_fails_with_file_and_line(tmp_path, fixture_registry):
    pinned = fixture_registry.push("unpublished/ghcr.io/example/app", "1.0.0", b"first build")
    moved = fixture_registry.push("unpublished/ghcr.io/example/app", "1.0.0", b"second build")
    db = fixture_registry.push("unpublished/postgres", "18.3", b"db index")
    root = _checkout(tmp_path, f"{APP}:1.0.0@{pinned}", f"{DB}:18.3@{db}")

    _, findings = _check(root, Routed(fixture_registry.host, Upstream()), mode="candidate",
                         candidate_registry=fixture_registry.prefix)

    assert [f.pin.location for f in findings] == [
        "src/app/docker-compose.yml:4", "src/app/service-env.json:3"]
    assert f"tag 1.0.0 points to {moved}" in findings[0].reason


def test_candidate_falls_back_to_the_published_image(tmp_path, fixture_registry):
    db = fixture_registry.push("unpublished/postgres", "18.3", b"db index")
    app = f"{APP}:1.0.0@{D_OTHER}"
    root = _checkout(tmp_path, app, f"{DB}:18.3@{db}")

    _, findings = _check(root, Routed(fixture_registry.host, Upstream(_served(app))),
                         mode="candidate", candidate_registry=fixture_registry.prefix)

    assert findings == []


def test_a_registry_without_the_digest_header_is_answered_by_the_manifest_hash(
        tmp_path, fixture_registry):
    fixture_registry.with_digest_header = False
    digest = fixture_registry.push("unpublished/ghcr.io/example/app", "1.0.0", b"app index")
    db = fixture_registry.push("unpublished/postgres", "18.3", b"db index")
    root = _checkout(tmp_path, f"{APP}:1.0.0@{digest}", f"{DB}:18.3@{db}")

    _, findings = _check(root, Routed(fixture_registry.host, Upstream()), mode="candidate",
                         candidate_registry=fixture_registry.prefix)

    assert findings == [] and "GET" in fixture_registry.methods


def test_candidate_needs_a_loopback_test_registry(tmp_path):
    root = _checkout(tmp_path, f"{APP}:1.0.0@{D_KNOWN}")
    for value in ("", "registry.example.org/unpublished/"):
        with pytest.raises(image_pins.PinError):
            _check(root, Upstream(), mode="candidate", candidate_registry=value)


def test_candidate_refuses_to_run_on_a_release_tag_in_ci(tmp_path):
    root = _checkout(tmp_path, f"{APP}:1.0.0@{D_KNOWN}")
    env = {"GITHUB_REF": "refs/tags/v1.10.0", "GITHUB_REF_TYPE": "tag",
           "GITHUB_REF_NAME": "v1.10.0"}

    with pytest.raises(image_pins.PinError, match="release tag v1.10.0"):
        _check(root, Upstream(), mode="candidate", candidate_registry="127.0.0.1:5000/u/",
               env=env)


def test_candidate_refuses_to_run_on_a_tagged_checkout(tmp_path):
    root = _checkout(tmp_path, f"{APP}:1.0.0@{D_KNOWN}")
    git = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.org"]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "fixture"], check=True)
    subprocess.run([*git, "tag", "v1.10.0"], check=True)

    with pytest.raises(image_pins.PinError, match="release tag"):
        _check(root, Upstream(), mode="candidate", candidate_registry="127.0.0.1:5000/u/",
               env={})


# ── release mode ─────────────────────────────────────────────────────────────


def test_release_every_published_pin_passes(tmp_path):
    app, db = f"{APP}:1.0.0@{D_KNOWN}", f"{DB}:18.3@{D_OTHER}"
    root = _checkout(tmp_path, app, db)

    _, findings = _check(root, Upstream(_served(app) | _served(db)), mode="release")

    assert findings == []


def test_release_names_an_unknown_digest_a_moved_and_a_missing_tag(tmp_path):
    app, db = f"{APP}:1.0.0@{D_KNOWN}", f"{DB}:18.3@{D_OTHER}"
    root = _checkout(tmp_path, app, db)
    served = {("ghcr.io", "example/app", D_KNOWN): D_KNOWN,
              ("ghcr.io", "example/app", "1.0.0"): D_OTHER,
              ("docker.io", "library/postgres", D_OTHER): D_OTHER}

    _, findings = _check(root, Upstream(served), mode="release")
    reasons = {f.pin.location: f.reason for f in findings}

    assert reasons["src/app/docker-compose.yml:4"].startswith("tag 1.0.0 points to")
    assert reasons["src/app/docker-compose.yml:6"] == "tag 18.3 does not exist"
    _, findings = _check(root, Upstream({}), mode="release")
    assert {f.reason for f in findings} == {"unknown digest"}


def test_release_refuses_a_test_registry_name(tmp_path):
    root = _checkout(tmp_path, f"127.0.0.1:5000/unpublished/ghcr.io/example/app:1.0.0@{D_KNOWN}")

    _, findings = _check(root, Upstream(), mode="release")

    assert [f.pin.location for f in findings[:1]] == ["src/app/docker-compose.yml:4"]
    assert "loopback test registry" in findings[0].reason
    with pytest.raises(image_pins.PinError, match="candidate mode only"):
        _check(root, Upstream(), mode="release", candidate_registry="127.0.0.1:5000/u/")


def test_an_unpinned_or_floating_reference_fails_without_asking(tmp_path):
    root = _checkout(tmp_path, f"{APP}:latest@{D_KNOWN}", f"{DB}:18.3")
    upstream = Upstream()

    _, findings = _check(root, upstream, mode="release")

    assert all(f.reason.startswith("not pinned") for f in findings) and len(findings) == 3
    assert upstream.asked == []


def test_an_unreachable_registry_is_a_finding_not_a_pass(tmp_path):
    class Down:
        def resolve(self, host, repository, reference):
            raise images.Unreachable(f"{host}: HTTP 429 (rate limited)")

    root = _checkout(tmp_path, f"{APP}:1.0.0@{D_KNOWN}")

    _, findings = _check(root, Down(), mode="release")

    assert findings and all("not reachable" in f.reason for f in findings)


class _AnonymousRefused:
    """The opener of a registry that is not the fixture, as ghcr.io answers an anonymous
    pull of a package it does not publish: every manifest request is answered 401 with a
    bearer challenge, the token request of the challenge 403."""

    def __init__(self) -> None:
        self.urls: list[str] = []

    def open(self, request, timeout):
        url = request.full_url
        self.urls.append(url)
        if url.startswith("https://ghcr.io/token?"):
            raise urllib.error.HTTPError(url, 403, "Forbidden", email.message.Message(), None)
        challenge = email.message.Message()
        challenge["WWW-Authenticate"] = (
            'Bearer realm="https://ghcr.io/token",service="ghcr.io",'
            'scope="repository:example/app:pull"')
        raise urllib.error.HTTPError(url, 401, "Unauthorized", challenge, None)


def _refusing_registry() -> tuple[images.Registry, _AnonymousRefused]:
    client = images.Registry(credentials=_NoCredentials())
    opener = _AnonymousRefused()
    client._opener = opener
    return client, opener


TOKEN_URL = ("https://ghcr.io/token?scope=repository%3Aexample%2Fapp%3Apull"
             "&service=ghcr.io")


def test_a_refused_token_request_is_a_finding_that_names_its_url(tmp_path,
                                                                  fixture_registry):
    # The candidate registry does not have the pin, the published registry refuses the
    # anonymous token: a finding at the pin's file and line naming the refused URL, and
    # the other pins are still checked.
    db = fixture_registry.push("unpublished/postgres", "18.3", b"db index")
    root = _checkout(tmp_path, f"{APP}:1.0.0@{D_OTHER}", f"{DB}:18.3@{db}")
    upstream, opener = _refusing_registry()

    class Split:
        def __init__(self) -> None:
            self.local = images.Registry(credentials=_NoCredentials())

        def resolve(self, host, repository, reference):
            client = self.local if host == fixture_registry.host else upstream
            return client.resolve(host, repository, reference)

    _, findings = _check(root, Split(), mode="candidate",
                         candidate_registry=fixture_registry.prefix)

    assert [f.pin.location for f in findings] == [
        "src/app/docker-compose.yml:4", "src/app/service-env.json:3"]
    for finding in findings:
        assert "registry refused" in finding.reason
        assert f"token request {TOKEN_URL} answered HTTP 403" in finding.reason
    assert TOKEN_URL in opener.urls


def test_the_command_names_the_refused_url_and_exits_1(tmp_path, capsys):
    root = _checkout(tmp_path, f"{APP}:1.0.0@{D_KNOWN}", f"{DB}:18.3@{D_OTHER}")
    upstream, _ = _refusing_registry()

    status = image_pins.main(["--repo-root", str(root), "check", "--mode=release"],
                             registry=upstream)

    err = capsys.readouterr().err
    assert status == 1, err
    assert f"ERROR: src/app/docker-compose.yml:4: services.app.image: {APP}" in err
    assert f"token request {TOKEN_URL} answered HTTP 403" in err
    assert "HTTP Error 403: Forbidden" not in err


def test_a_refused_manifest_request_names_its_url():
    client = images.Registry(credentials=_NoCredentials())

    class Refuses:
        def open(self, request, timeout):
            raise urllib.error.HTTPError(request.full_url, 403, "Forbidden",
                                         email.message.Message(), None)

    client._opener = Refuses()
    with pytest.raises(images.ImageError) as raised:
        client.resolve("ghcr.io", "example/app", "1.0.0")
    assert str(raised.value) == (
        "ghcr.io: https://ghcr.io/v2/example/app/manifests/1.0.0 answered HTTP 403")


def test_release_before_the_tag_takes_the_own_images_from_their_build(tmp_path,
                                                                      fixture_registry):
    own = "ghcr.io/example/own"
    digest = fixture_registry.push("unpublished/ghcr.io/example/own", "1.10.0-rc.1", b"own")
    db = f"{DB}:18.3@{D_OTHER}"
    root = _checkout(tmp_path, f"{own}:1.10.0-rc.1@{digest}", db)
    (root / "compat" / "own-images.yaml").write_text(
        f"schema: papaia.own-images/1\nimages:\n  - name: {own}\n    dockerfile: Dockerfile\n"
        "    inputs: [Dockerfile]\n    services: [app]\n    license: MIT\n"
        "    license_class: P\n", encoding="utf-8")
    (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    builds = tmp_path / "builds.json"
    own_images.write_builds(builds, fixture_registry.prefix, [
        {"name": own, "tag": "1.10.0-rc.1", "digest": digest, "revision": "b" * 40}])
    registry = Routed(fixture_registry.host, Upstream(_served(db)))

    _, findings = _check(root, registry, mode="release", own_builds=builds)
    assert findings == []

    own_images.write_builds(builds, fixture_registry.prefix, [
        {"name": own, "tag": "1.10.0-rc.1", "digest": D_UNKNOWN, "revision": "b" * 40}])
    _, findings = _check(root, registry, mode="release", own_builds=builds)
    assert findings and all("rebuild and pin" in f.reason for f in findings)


# ── command line ─────────────────────────────────────────────────────────────


def test_the_command_exits_0_1_and_2(tmp_path, capsys):
    app, db = f"{APP}:1.0.0@{D_KNOWN}", f"{DB}:18.3@{D_OTHER}"
    root = _checkout(tmp_path, app, db)
    base = ["--repo-root", str(root), "check"]

    assert image_pins.main([*base, "--mode=release"],
                           registry=Upstream(_served(app) | _served(db))) == 0
    assert "3 pin(s) resolve" in capsys.readouterr().out
    assert image_pins.main([*base, "--mode=release"], registry=Upstream(_served(db))) == 1
    err = capsys.readouterr().err
    assert "ERROR: src/app/docker-compose.yml:4: services.app.image:" in err
    assert "unknown digest" in err
    assert image_pins.main([*base, "--mode=candidate"], registry=Upstream()) == 2


def test_the_wrapper_is_executable_and_documented():
    wrapper = REPO / "tools" / "check-image-pins"
    assert wrapper.stat().st_mode & 0o111
    assert "lib.image_pins" in wrapper.read_text(encoding="utf-8")


# ── re-pinning ───────────────────────────────────────────────────────────────


def test_repin_moves_every_compose_and_service_env_pin_of_the_image(tmp_path):
    root = _checkout(tmp_path, f"{APP}:1.0.0@{D_KNOWN}")
    new = f"{APP}:1.0.1@{D_OTHER}"

    changed = image_pins.repin(root, new)

    assert changed == ["src/app/docker-compose.yml:4: services.app.image",
                       "src/app/service-env.json:3: image"]
    assert [p.ref for p in image_pins.collect(root)] == [new, f"{DB}:18.3@{D_KNOWN}", new]
    doc = json.loads((root / "src/app/service-env.json").read_text(encoding="utf-8"))
    assert doc["image"] == new
    assert yaml.safe_load((root / "src/app/docker-compose.yml").read_text(
        encoding="utf-8"))["services"]["app"]["image"] == new
    assert image_pins.repin(root, new) == []


@pytest.mark.parametrize("ref, match", [
    (f"{APP}:1.0.1", "no digest"),
    (f"{APP}:latest@{D_OTHER}", "latest"),
    (f"127.0.0.1:5000/u/ghcr.io/example/app:1.0.1@{D_OTHER}", "loopback"),
    (f"ghcr.io/example/nothing:1.0.1@{D_OTHER}", "pinned nowhere"),
])
def test_repin_refuses(tmp_path, ref, match):
    root = _checkout(tmp_path, f"{APP}:1.0.0@{D_KNOWN}")
    before = (root / "src/app/docker-compose.yml").read_text(encoding="utf-8")

    with pytest.raises(image_pins.PinError, match=match):
        image_pins.repin(root, ref)

    assert (root / "src/app/docker-compose.yml").read_text(encoding="utf-8") == before


def test_repin_leaves_the_own_images_to_build_images(tmp_path):
    with pytest.raises(image_pins.PinError, match="build-images pin"):
        image_pins.repin(REPO, f"ghcr.io/fidonis/papaia-egress:0.0.1@{D_OTHER}")


# ── the candidate suite ──────────────────────────────────────────────────────


def test_a_candidate_core_belongs_to_the_suite_of_its_release():
    assert images.suite_version("1.10.0-rc.1") == "1.10.0"
    assert images.suite_version("1.10.0") == "1.10.0"
    assert images.is_candidate("1.10.0-rc.1") and not images.is_candidate("1.10.0")
    assert images.bom_path(Path("/x"), "1.10.0-rc.1") == Path("/x/compat/suite-1.10.0.yaml")
    with pytest.raises(images.ImageError):
        images.suite_version("1.10")


def test_the_start_check_reads_suite_1_10_0_in_candidate_mode(tmp_path):
    from test_images import _core, _new_keypair

    keypair = _new_keypair(tmp_path)
    root = _core(tmp_path, keypair, version="1.10.0")
    (root / "VERSION").write_text("1.10.0-rc.1\n", encoding="utf-8")

    assert images.load_trusted_bom(root)["suite"] == "1.10.0"
    assert module_offer.load(root)["suite"] == "1.10.0"
    assert pairing_approval._trusted_bom(root)["suite"] == "1.10.0"


def test_a_candidate_core_refuses_an_older_suite(tmp_path):
    from test_images import _bom, _core, _new_keypair

    keypair = _new_keypair(tmp_path)
    root = _core(tmp_path, keypair, bom=_bom(keypair[1], [], version="1.9.0"))
    (root / "VERSION").write_text("1.10.0-rc.1\n", encoding="utf-8")
    for suffix in ("", ".sig"):
        (root / "compat" / f"suite-1.9.0.yaml{suffix}").rename(
            root / "compat" / f"suite-1.10.0.yaml{suffix}")

    with pytest.raises(images.ImageError, match="expected 1.10.0"):
        images.load_trusted_bom(root)


def test_a_candidate_core_serves_the_addons_of_its_release():
    assert semver.release_of("1.10.0-rc.1") == semver.parse_version("1.10.0")
    core = compat.CoreTarget(platform_version="1.10.0-rc.1")
    manifest = {"name": "docs", "papaia_compat": ">=0.1.0"}

    result = compat.evaluate_addon("docs", manifest, core)

    assert result.status == compat.STATUS_OK, result.reason


# ── CI and docs ──────────────────────────────────────────────────────────────


def _workflow() -> dict:
    return yaml.safe_load((WORKFLOWS / "images.yml").read_text(encoding="utf-8"))


def test_ci_checks_the_pins_on_the_milestone_before_and_on_a_tag():
    jobs = _workflow()["jobs"]
    steps = {step.get("name"): step for step in jobs["build-scan"]["steps"]}

    candidate = steps["Every pin resolves (candidate mode)"]
    assert "--mode=candidate" in candidate["run"] and "${SCAN_REGISTRY}" in candidate["run"]
    assert "refs/heads/releases/" in candidate["if"] and "push" in candidate["if"]
    before = steps["Every pin resolves (release mode, before the tag)"]
    assert "--mode=release" in before["run"] and "--own-builds" in before["run"]
    tag = jobs["release-pins"]
    assert tag["needs"] == "publish" and "permissions" not in tag
    assert not any("login" in step.get("uses", "") for step in tag["steps"])
    assert any("--mode=release" in step.get("run", "") for step in tag["steps"])


def test_the_repin_procedure_is_documented():
    text = (REPO / "docs" / "compatibility.md").read_text(encoding="utf-8")

    assert "### Pinned images resolve" in text
    for needle in ("check-image-pins repin --ref=", "--mode=candidate", "--mode=release",
                   "lib.me_profile generate"):
        assert needle in text, needle


# ── module images published only on the release day ──────────────────────────
#
# A module image (papaia-me, papaia-connections, the manager) is published by its own
# release on the release day; until then the core pins the candidate built from the
# module milestone and lists it in compat/release-day-images.yaml. Candidate mode
# reports such a pin as a notice instead of asking the published registry; release
# mode ignores the list and refuses to pass while it still has an entry.

MOD = "ghcr.io/fidonis/papaia-mod"
MOD_SOURCE = "c" * 40
REFUSED = "token request https://ghcr.io/token?scope=repository%3Afidonis%2Fpapaia-mod" \
          "%3Apull&service=ghcr.io answered HTTP 403"


class Refusing(Upstream):
    """ghcr.io as it answers an anonymous pull of a package it does not publish; every
    other registry as `Upstream`."""

    def resolve(self, host: str, repository: str, reference: str) -> str:
        if (host, repository) == ("ghcr.io", "fidonis/papaia-mod"):
            self.asked.append((host, repository, reference))
            raise images.ImageError(f"ghcr.io: {REFUSED}")
        return super().resolve(host, repository, reference)


def _entry(image: str = MOD, tag: str = "0.1.0", digest: str = D_KNOWN, **extra) -> dict:
    entry = {"image": image, "tag": tag, "digest": digest, "module": "papaia-mod",
             "source": MOD_SOURCE, "built": "2026-11-25"}
    entry.update(extra)
    return entry


def _release_day(root: Path, entries: list[dict]) -> Path:
    path = root / "compat" / "release-day-images.yaml"
    path.write_text(
        "# fixture\n" + yaml.safe_dump({"schema": "papaia.release-day-images/1",
                                        "images": entries}, sort_keys=False),
        encoding="utf-8")
    return path


def _module_checkout(tmp_path: Path, mod: str = f"{MOD}:0.1.0@{D_KNOWN}",
                     db: str = f"{DB}:18.3@{D_OTHER}") -> Path:
    return _checkout(tmp_path, mod, db)


def _db_served_locally(fixture_registry) -> str:
    return f"{DB}:18.3@" + fixture_registry.push("unpublished/postgres", "18.3", b"db index")


def test_candidate_a_listed_unpublished_module_image_is_a_notice(tmp_path, fixture_registry):
    root = _module_checkout(tmp_path, db=_db_served_locally(fixture_registry))
    _release_day(root, [_entry()])
    upstream = Refusing()

    result = image_pins.evaluate(root, registry=Routed(fixture_registry.host, upstream),
                                 mode="candidate", candidate_registry=fixture_registry.prefix,
                                 env=NO_CI)

    assert result.findings == []
    assert [str(n) for n in result.notices] == [
        f"published only on release day: {MOD}:0.1.0@{D_KNOWN} "
        f"(candidate of papaia-mod @ {MOD_SOURCE})"]
    assert [p.location for p in result.notices[0].pins] == [
        "src/app/docker-compose.yml:4", "src/app/service-env.json:3"]
    assert not any(host == "ghcr.io" for host, _, _ in upstream.asked), (
        "candidate mode never asks ghcr.io for a listed image")


def test_the_command_reports_release_day_notices_and_exits_0(tmp_path, fixture_registry,
                                                             capsys, monkeypatch):
    root = _module_checkout(tmp_path, db=_db_served_locally(fixture_registry))
    _release_day(root, [_entry()])
    base = ["--repo-root", str(root), "check", "--mode=candidate",
            f"--registry={fixture_registry.prefix}"]
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    for name in ("GITHUB_REF", "GITHUB_REF_TYPE", "GITHUB_REF_NAME"):
        monkeypatch.delenv(name, raising=False)

    assert image_pins.main(base, registry=Routed(fixture_registry.host, Refusing())) == 0
    out = capsys.readouterr().out
    assert f"published only on release day: {MOD}:0.1.0@{D_KNOWN}" in out
    assert "1 pin(s) resolve" in out
    assert "2 pin(s) of 1 image(s) published only on release day" in out
    assert "::notice::" not in out

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert image_pins.main(base, registry=Routed(fixture_registry.host, Refusing())) == 0
    out = capsys.readouterr().out
    assert out.count("::notice::published only on release day: ") == 1


def test_candidate_a_listed_image_served_by_the_candidate_registry_passes(
        tmp_path, fixture_registry):
    digest = fixture_registry.push(f"unpublished/{MOD}", "0.1.0", b"module candidate")
    root = _module_checkout(tmp_path, f"{MOD}:0.1.0@{digest}",
                            _db_served_locally(fixture_registry))
    _release_day(root, [_entry(digest=digest)])
    upstream = Refusing()

    result = image_pins.evaluate(root, registry=Routed(fixture_registry.host, upstream),
                                 mode="candidate", candidate_registry=fixture_registry.prefix,
                                 env=NO_CI)

    assert result.findings == [] and result.notices == []
    assert upstream.asked == []


def test_candidate_a_listed_image_with_another_digest_at_the_candidate_registry_fails(
        tmp_path, fixture_registry):
    other = fixture_registry.push(f"unpublished/{MOD}", "0.1.0", b"another build")
    root = _module_checkout(tmp_path, db=_db_served_locally(fixture_registry))
    _release_day(root, [_entry()])

    result = image_pins.evaluate(root, registry=Routed(fixture_registry.host, Refusing()),
                                 mode="candidate", candidate_registry=fixture_registry.prefix,
                                 env=NO_CI)

    assert [f.pin.location for f in result.findings] == [
        "src/app/docker-compose.yml:4", "src/app/service-env.json:3"]
    assert all(other in f.reason and "candidate registry" in f.reason
               for f in result.findings)
    assert result.notices == []


def test_candidate_a_listed_image_with_a_moved_tag_at_the_candidate_registry_fails(
        tmp_path, fixture_registry):
    pinned = fixture_registry.push(f"unpublished/{MOD}", "0.1.0", b"first build")
    moved = fixture_registry.push(f"unpublished/{MOD}", "0.1.0", b"second build")
    root = _module_checkout(tmp_path, f"{MOD}:0.1.0@{pinned}",
                            _db_served_locally(fixture_registry))
    _release_day(root, [_entry(digest=pinned)])

    result = image_pins.evaluate(root, registry=Routed(fixture_registry.host, Refusing()),
                                 mode="candidate", candidate_registry=fixture_registry.prefix,
                                 env=NO_CI)

    assert [f.pin.location for f in result.findings] == [
        "src/app/docker-compose.yml:4", "src/app/service-env.json:3"]
    assert f"tag 0.1.0 points to {moved}" in result.findings[0].reason


@pytest.mark.parametrize("entry", [
    _entry(digest=D_OTHER),
    _entry(tag="0.1.1"),
], ids=["digest", "tag"])
def test_candidate_a_pin_that_differs_from_its_entry_fails(tmp_path, fixture_registry, entry):
    root = _module_checkout(tmp_path, db=_db_served_locally(fixture_registry))
    _release_day(root, [entry])

    result = image_pins.evaluate(root, registry=Routed(fixture_registry.host, Refusing()),
                                 mode="candidate", candidate_registry=fixture_registry.prefix,
                                 env=NO_CI)

    assert [f.pin.location for f in result.findings] == [
        "src/app/docker-compose.yml:4", "src/app/service-env.json:3"]
    assert all("release-day entry" in f.reason and entry["digest"] in f.reason
               for f in result.findings)
    assert result.notices == []


def test_candidate_an_entry_no_pin_uses_fails(tmp_path, fixture_registry):
    root = _module_checkout(tmp_path, db=_db_served_locally(fixture_registry))
    _release_day(root, [_entry(), _entry(image="ghcr.io/fidonis/papaia-gone",
                                         module="papaia-gone")])

    result = image_pins.evaluate(root, registry=Routed(fixture_registry.host, Refusing()),
                                 mode="candidate", candidate_registry=fixture_registry.prefix,
                                 env=NO_CI)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.pin.path == "compat/release-day-images.yaml"
    lines = (root / finding.pin.path).read_text(encoding="utf-8").splitlines()
    assert "ghcr.io/fidonis/papaia-gone" in lines[finding.pin.line - 1]
    assert "used by no pin" in finding.reason


def test_candidate_an_unlisted_unpublished_image_still_fails_with_its_url(
        tmp_path, fixture_registry):
    root = _module_checkout(tmp_path, db=_db_served_locally(fixture_registry))
    upstream = Refusing()

    result = image_pins.evaluate(root, registry=Routed(fixture_registry.host, upstream),
                                 mode="candidate", candidate_registry=fixture_registry.prefix,
                                 env=NO_CI)

    assert [f.pin.location for f in result.findings] == [
        "src/app/docker-compose.yml:4", "src/app/service-env.json:3"]
    assert all(REFUSED in f.reason for f in result.findings)
    assert result.notices == []


def test_candidate_a_moved_third_party_tag_is_still_a_finding(tmp_path, fixture_registry):
    # As python:3.12.16-slim-trixie: the tag now names another build than the pin.
    pinned, moved = D_KNOWN, D_OTHER
    base = f"python:3.12.16-slim-trixie@{pinned}"
    root = _checkout(tmp_path, f"{MOD}:0.1.0@{D_KNOWN}", base)
    _release_day(root, [_entry()])
    upstream = Refusing({("docker.io", "library/python", pinned): pinned,
                         ("docker.io", "library/python", "3.12.16-slim-trixie"): moved})

    result = image_pins.evaluate(root, registry=Routed(fixture_registry.host, upstream),
                                 mode="candidate", candidate_registry=fixture_registry.prefix,
                                 env=NO_CI)

    assert [f.pin.location for f in result.findings] == ["src/app/docker-compose.yml:6"]
    assert f"tag 3.12.16-slim-trixie points to {moved}" in result.findings[0].reason


# ── release mode with the release-day list ───────────────────────────────────


def test_release_fails_while_the_release_day_list_has_an_entry(tmp_path):
    second = "ghcr.io/fidonis/papaia-two"
    root = _module_checkout(tmp_path)
    (root / "src" / "two").mkdir()
    (root / "src" / "two" / "docker-compose.yml").write_text(
        f"services:\n  two:\n    image: {second}:1.8.0@{D_OTHER}\n", encoding="utf-8")
    _release_day(root, [_entry(), _entry(image=second, tag="1.8.0", digest=D_OTHER,
                                         module="papaia-two")])
    served = (_served(f"{MOD}:0.1.0@{D_KNOWN}") | _served(f"{second}:1.8.0@{D_OTHER}")
              | _served(f"{DB}:18.3@{D_OTHER}"))

    result = image_pins.evaluate(root, registry=Upstream(served), mode="release", env=NO_CI)

    assert len(result.findings) == 1 and result.notices == []
    reason = result.findings[0].reason
    assert reason.startswith("release-day list not empty: ")
    assert f"{MOD}:0.1.0" in reason and f"{second}:1.8.0" in reason
    assert "re-pin after the module release" in reason
    assert result.findings[0].pin.path == "compat/release-day-images.yaml"


def test_release_passes_with_an_empty_list_and_every_module_image_served(tmp_path):
    root = _module_checkout(tmp_path)
    _release_day(root, [])
    served = _served(f"{MOD}:0.1.0@{D_KNOWN}") | _served(f"{DB}:18.3@{D_OTHER}")

    result = image_pins.evaluate(root, registry=Upstream(served), mode="release", env=NO_CI)

    assert result.findings == [] and result.notices == []


def test_release_a_listed_image_the_registry_refuses_is_a_finding_never_a_notice(tmp_path):
    root = _module_checkout(tmp_path)
    _release_day(root, [_entry()])
    upstream = Refusing(_served(f"{DB}:18.3@{D_OTHER}"))

    result = image_pins.evaluate(root, registry=upstream, mode="release", env=NO_CI)

    assert result.notices == []
    refused = [f for f in result.findings if REFUSED in f.reason]
    assert [f.pin.location for f in refused] == [
        "src/app/docker-compose.yml:4", "src/app/service-env.json:3"]
    assert ("ghcr.io", "fidonis/papaia-mod", D_KNOWN) in upstream.asked
    assert any(f.reason.startswith("release-day list not empty") for f in result.findings)


def test_release_with_own_builds_still_blocks_on_the_release_day_list(tmp_path,
                                                                     fixture_registry):
    own = "ghcr.io/fidonis/papaia-own"
    digest = fixture_registry.push(f"unpublished/{own}", "1.10.0-rc.1", b"own")
    root = _module_checkout(tmp_path)
    (root / "src" / "own").mkdir()
    (root / "src" / "own" / "docker-compose.yml").write_text(
        f"services:\n  own:\n    image: {own}:1.10.0-rc.1@{digest}\n", encoding="utf-8")
    (root / "compat" / "own-images.yaml").write_text(
        f"schema: papaia.own-images/1\nimages:\n  - name: {own}\n    dockerfile: Dockerfile\n"
        "    inputs: [Dockerfile]\n    services: [own]\n    license: MIT\n"
        "    license_class: P\n", encoding="utf-8")
    (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    builds = tmp_path / "builds.json"
    own_images.write_builds(builds, fixture_registry.prefix, [
        {"name": own, "tag": "1.10.0-rc.1", "digest": digest, "revision": "b" * 40}])
    served = _served(f"{MOD}:0.1.0@{D_KNOWN}") | _served(f"{DB}:18.3@{D_OTHER}")
    registry = Routed(fixture_registry.host, Upstream(served))

    _release_day(root, [])
    assert image_pins.evaluate(root, registry=registry, mode="release", own_builds=builds,
                               env=NO_CI).findings == []
    _release_day(root, [_entry()])
    findings = image_pins.evaluate(root, registry=registry, mode="release",
                                   own_builds=builds, env=NO_CI).findings
    assert [f.reason.split(":")[0] for f in findings] == ["release-day list not empty"]


def test_the_release_command_names_every_listed_image_and_exits_1(tmp_path, capsys):
    root = _module_checkout(tmp_path)
    _release_day(root, [_entry()])
    served = _served(f"{MOD}:0.1.0@{D_KNOWN}") | _served(f"{DB}:18.3@{D_OTHER}")

    status = image_pins.main(["--repo-root", str(root), "check", "--mode=release"],
                             registry=Upstream(served))

    err = capsys.readouterr().err
    assert status == 1
    assert f"release-day list not empty: {MOD}:0.1.0" in err


# ── the release-day list ─────────────────────────────────────────────────────


@pytest.mark.parametrize("entries, match", [
    ([_entry(extra="x")], "unknown"),
    ([_entry(digest="sha256:abc")], "digest"),
    ([_entry(digest="sha512:" + "a" * 128)], "digest"),
    ([_entry(source="c" * 12)], "source"),
    ([_entry(), _entry(tag="0.2.0")], "twice"),
    ([_entry(image="127.0.0.1:5000/fidonis/papaia-mod")], "loopback"),
    ([_entry(image="localhost:5000/unpublished/ghcr.io/fidonis/papaia-mod")], "loopback"),
    ([_entry(image="ghcr.io/example/app")], "ghcr.io/fidonis/"),
    ([_entry(image="docker.io/library/python")], "ghcr.io/fidonis/"),
    ([_entry(image="python")], "ghcr.io/fidonis/"),
    ([_entry(image="ghcr.io/fidonis/papaia-own")], "own image"),
    ([_entry(image=f"{MOD}:0.1.0")], "repository"),
    ([_entry(tag="latest")], "tag"),
    ([_entry(module="Papaia Mod")], "module"),
    ([_entry(built="yesterday")], "built"),
    ([{k: v for k, v in _entry().items() if k != "source"}], "source"),
], ids=["unknown-key", "short-digest", "sha512", "short-commit", "duplicate", "loopback",
        "localhost", "other-owner", "docker-hub", "short-name", "own-image", "with-tag",
        "latest", "module-name", "built-date", "missing-key"])
def test_the_release_day_list_refuses(tmp_path, entries, match):
    root = _module_checkout(tmp_path)
    (root / "compat" / "own-images.yaml").write_text(
        "schema: papaia.own-images/1\nimages:\n  - name: ghcr.io/fidonis/papaia-own\n"
        "    dockerfile: Dockerfile\n    inputs: [Dockerfile]\n    services: [own]\n"
        "    license: MIT\n    license_class: P\n", encoding="utf-8")
    (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    _release_day(root, entries)

    with pytest.raises(release_day.ReleaseDayError, match=match):
        release_day.load(root)
    status = image_pins.main(["--repo-root", str(root), "check", "--mode=release"],
                             registry=Upstream())
    assert status == 2


@pytest.mark.parametrize("text, match", [
    ("schema: papaia.release-day-images/2\nimages: []\n", "schema"),
    ("schema: papaia.release-day-images/1\nimages: []\nextra: 1\n", "schema"),
    ("schema: papaia.release-day-images/1\nimages: {}\n", "list"),
    ("- not a mapping\n", "schema"),
    ("schema: papaia.release-day-images/1\nimages: []\n" + "#" * (64 * 1024), "large"),
], ids=["schema-version", "unknown-top-key", "not-a-list", "not-a-mapping", "oversized"])
def test_the_release_day_file_refuses(tmp_path, capsys, text, match):
    root = _module_checkout(tmp_path)
    (root / "compat" / "release-day-images.yaml").write_text(text, encoding="utf-8")

    with pytest.raises(release_day.ReleaseDayError, match=match):
        release_day.load(root)
    assert image_pins.main(["--repo-root", str(root), "check", "--mode=release"],
                           registry=Upstream()) == 2
    assert "ERROR: compat/release-day-images.yaml" in capsys.readouterr().err


def test_the_release_day_list_reads_its_entries_with_their_lines(tmp_path):
    root = _module_checkout(tmp_path)
    _release_day(root, [_entry(), _entry(image="ghcr.io/fidonis/papaia-two",
                                         module="papaia-two")])

    entries = release_day.load(root)

    assert [(e.image, e.tag, e.digest, e.module, e.source, e.built) for e in entries] == [
        (MOD, "0.1.0", D_KNOWN, "papaia-mod", MOD_SOURCE, "2026-11-25"),
        ("ghcr.io/fidonis/papaia-two", "0.1.0", D_KNOWN, "papaia-two", MOD_SOURCE,
         "2026-11-25")]
    lines = (root / "compat" / "release-day-images.yaml").read_text(
        encoding="utf-8").splitlines()
    assert [lines[e.line - 1] for e in entries] == [
        f"- image: {MOD}", "- image: ghcr.io/fidonis/papaia-two"]
    assert entries[0].ref == f"{MOD}:0.1.0@{D_KNOWN}"
    assert release_day.load(tmp_path / "nothing") == []


# ── --candidate-digests ──────────────────────────────────────────────────────


def _candidate_digests(tmp_path: Path, entries: list[dict], as_json: bool = True) -> Path:
    path = tmp_path / ("digests.json" if as_json else "digests.yaml")
    path.write_text(json.dumps(entries) if as_json else yaml.safe_dump(entries),
                    encoding="utf-8")
    return path


@pytest.mark.parametrize("as_json", [True, False], ids=["json", "yaml"])
def test_candidate_digests_equal_to_the_entry_pass(tmp_path, fixture_registry, as_json):
    root = _module_checkout(tmp_path, db=_db_served_locally(fixture_registry))
    _release_day(root, [_entry()])
    digests = _candidate_digests(tmp_path, [{"image": MOD, "tag": "0.1.0",
                                             "digest": D_KNOWN}], as_json)

    result = image_pins.evaluate(root, registry=Routed(fixture_registry.host, Refusing()),
                                 mode="candidate", candidate_registry=fixture_registry.prefix,
                                 candidate_digests=digests, env=NO_CI)

    assert result.findings == [] and len(result.notices) == 1


def test_a_differing_candidate_digest_is_a_finding_naming_both(tmp_path, fixture_registry):
    root = _module_checkout(tmp_path, db=_db_served_locally(fixture_registry))
    _release_day(root, [_entry()])
    digests = _candidate_digests(tmp_path, [{"image": MOD, "tag": "0.1.0",
                                             "digest": D_OTHER}])

    result = image_pins.evaluate(root, registry=Routed(fixture_registry.host, Refusing()),
                                 mode="candidate", candidate_registry=fixture_registry.prefix,
                                 candidate_digests=digests, env=NO_CI)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.pin.path == "compat/release-day-images.yaml"
    assert D_KNOWN in finding.reason and D_OTHER in finding.reason


@pytest.mark.parametrize("entries, match", [
    ([{"image": MOD, "tag": "0.1.0", "digest": D_KNOWN, "extra": 1}], "unknown"),
    ([{"image": MOD, "tag": "0.1.0", "digest": "sha256:x"}], "digest"),
    ([{"image": "ghcr.io/fidonis/papaia-else", "tag": "0.1.0", "digest": D_KNOWN}],
     "not on the release-day list"),
    ({"image": MOD}, "list"),
], ids=["unknown-key", "digest", "unlisted", "not-a-list"])
def test_candidate_digests_refuse(tmp_path, fixture_registry, entries, match):
    root = _module_checkout(tmp_path, db=_db_served_locally(fixture_registry))
    _release_day(root, [_entry()])
    digests = _candidate_digests(tmp_path, entries)

    with pytest.raises(image_pins.PinError, match=match):
        image_pins.evaluate(root, registry=Routed(fixture_registry.host, Refusing()),
                            mode="candidate", candidate_registry=fixture_registry.prefix,
                            candidate_digests=digests, env=NO_CI)
    with pytest.raises(image_pins.PinError, match="candidate mode only"):
        image_pins.evaluate(root, registry=Upstream(), mode="release",
                            candidate_digests=digests, env=NO_CI)


# ── the shipped tree ─────────────────────────────────────────────────────────


RELEASE_DAY_MODULES = {"ghcr.io/fidonis/papaia-me", "ghcr.io/fidonis/papaia-connections",
                       "ghcr.io/fidonis/papaia-manager"}


def test_every_module_pin_of_the_shipped_tree_matches_its_release_day_entry():
    entries = {entry.image: entry for entry in release_day.load(REPO)}
    assert set(entries) == RELEASE_DAY_MODULES
    seen: set[str] = set()
    for pin in image_pins.collect(REPO):
        ref = images.parse_ref(pin.ref)
        name = f"{ref.registry}/{ref.repository}"
        if name in RELEASE_DAY_MODULES and pin.path.startswith("src/"):
            seen.add(name)
            assert pin.ref == entries[name].ref, pin.location
    assert seen == RELEASE_DAY_MODULES
    me = json.loads((REPO / "src/infra/me/service-env.json").read_text(encoding="utf-8"))
    assert me["source"]["commit"] == entries["ghcr.io/fidonis/papaia-me"].source


def test_ci_runs_release_mode_strictly_and_names_the_release_day_list():
    text = (WORKFLOWS / "images.yml").read_text(encoding="utf-8")
    jobs = _workflow()["jobs"]
    pin_steps = [step for job in jobs.values() for step in job.get("steps", [])
                 if "lib.image_pins" in step.get("run", "")]

    assert len(pin_steps) == 3
    assert not any("continue-on-error" in step for step in pin_steps)
    assert not any("continue-on-error" in job for job in jobs.values())
    steps = {step.get("name"): step for step in jobs["build-scan"]["steps"]}
    assert "--mode=release" in steps["Every pin resolves (release mode, before the tag)"]["run"]
    assert any("--mode=release" in step.get("run", "") and "--own-builds" not in step["run"]
               for step in jobs["release-pins"]["steps"])
    lines = text.splitlines()
    at = next(i for i, line in enumerate(lines)
              if line.strip() == "- name: Every pin resolves (candidate mode)")
    comment = []
    while lines[at - 1 - len(comment)].strip().startswith("#"):
        comment.append(lines[at - 1 - len(comment)])
    assert "compat/release-day-images.yaml" in " ".join(comment)


def test_the_release_day_procedure_is_documented():
    text = (REPO / "docs" / "compatibility.md").read_text(encoding="utf-8")

    assert "compat/release-day-images.yaml" in text
    assert "published only on release day" in text
    assert "release-day list not empty" in text
    assert "the candidate run on the milestone branch fails and names it" not in text
    gate = text[text.index("### Release gate"):text.index("### Pinned images resolve")]
    assert "release-day-images.yaml" in gate and "--mode=release" in gate
    assert "papaia-manager" in text[text.index("**Re-pin after a module release.**"):]
