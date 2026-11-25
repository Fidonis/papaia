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

from lib import compat, image_pins, images, module_offer, own_images, pairing_approval, semver

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
