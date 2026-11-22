"""The core profile `me`: Mein Bereich (`me-web`) and the preference store (`prefs`, `prefs-db`).

One list of environment variables, `src/infra/me/service-env.json`, is shared by the
profile and the services: it is generated from the configuration modules of the pinned
image's source (`python -m lib.me_profile generate`), and `me_profile.check` passes only
when the compose file sets exactly those variables and the profile's `.env.example`
documents exactly the variables the compose file interpolates beyond the root file.
The checks read the real checkout, so a drift fails CI; the drift cases run against
copies.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

from lib import common, compat, envtree, ingress, me_profile, resolve, topology
from lib.compat import CoreTarget

REPO = Path(__file__).resolve().parents[2]
ME_DIR = REPO / "src" / "infra" / "me"
REQUIRE_COMPOSE = os.environ.get("PAPAIA_REQUIRE_GOLDEN_COMPOSE") == "1"


def _compose(root: Path = REPO) -> dict:
    return yaml.safe_load((root / me_profile.COMPOSE_REL).read_text(encoding="utf-8"))


def _env_list(root: Path = REPO) -> dict:
    return json.loads((root / me_profile.ENV_LIST_REL).read_text(encoding="utf-8"))


def _copy(tmp_path: Path) -> Path:
    """The files `check` reads, copied so a test can change them."""
    root = tmp_path / "repo"
    for rel in (
        me_profile.COMPOSE_REL,
        me_profile.ENV_EXAMPLE_REL,
        me_profile.ENV_LIST_REL,
        Path("src/.env.example"),
    ):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / rel, root / rel)
    return root


def _rewrite_compose(root: Path, change) -> None:
    doc = _compose(root)
    change(doc)
    (root / me_profile.COMPOSE_REL).write_text(yaml.safe_dump(doc, sort_keys=False), "utf-8")


# ── the real checkout ────────────────────────────────────────────────────────


def test_the_checkout_passes_the_check():
    assert me_profile.check(REPO) == []


def test_the_profile_has_three_services_from_one_pinned_image():
    services = _compose()["services"]
    assert set(services) == {"me-web", "prefs", "prefs-db"}
    for service in services.values():
        assert service["profiles"] == [me_profile.PROFILE]
    image = _env_list()["image"]
    assert services["me-web"]["image"] == services["prefs"]["image"] == image
    assert me_profile.PINNED_IMAGE_RE.fullmatch(image)
    assert me_profile.PINNED_IMAGE_RE.fullmatch(services["prefs-db"]["image"])


def test_no_service_publishes_a_host_port():
    for name, service in _compose()["services"].items():
        assert "ports" not in service, name
        assert service.get("network_mode") is None, name


def test_the_env_of_each_service_equals_what_the_service_reads():
    listed = _env_list()["services"]
    services = _compose()["services"]
    for name in me_profile.SERVICES:
        expected = me_profile.expected_names(listed[name], set(services[name]["environment"]))
        assert set(services[name]["environment"]) == expected, name
        # Values only through `environment:`: an env_file next to it would be a second
        # source that may carry names the service does not read (ME-26-A2).
        assert "env_file" not in services[name], name


def test_the_env_example_documents_exactly_the_own_interpolated_variables():
    own = me_profile.interpolated(ME_DIR / "docker-compose.yml") - set(
        common.parse_env_file(REPO / "src" / ".env.example")
    )
    assert set(common.parse_env_file(ME_DIR / ".env.example")) == own


def test_secrets_are_generated_and_never_shipped():
    example = common.parse_env_file(ME_DIR / ".env.example")
    for key in ("ME_OIDC_CLIENT_SECRET", "ME_SESSION_SECRET", "PREFS_DB_PASSWORD"):
        assert example[key] == f"GENERATE_{key}", key
    # The database password reaches prefs as a file, never as a variable of prefs.
    prefs = _compose()["services"]["prefs"]
    assert "PREFS_DB_PASSWORD" not in prefs["environment"]
    assert prefs["environment"]["PREFS_DB_PASSWORD_FILE"] == "/run/secrets/prefs-db-password"


def test_the_database_is_reachable_by_prefs_only():
    doc = _compose()
    networks = doc["networks"]
    db_networks = doc["services"]["prefs-db"]["networks"]
    assert db_networks == [me_profile.DB_NETWORK]
    assert networks[me_profile.DB_NETWORK]["internal"] is True
    members = [
        name for name, s in doc["services"].items() if me_profile.DB_NETWORK in s["networks"]
    ]
    assert sorted(members) == ["prefs", "prefs-db"]
    assert "prefs-db" in compat.NEVER_ATTACHABLE


def test_the_core_wiring_names_the_profile():
    root = yaml.safe_load((REPO / "src/docker-compose.yml").read_text(encoding="utf-8"))
    assert {"path": "./infra/me/docker-compose.yml"} in root["include"]
    spec = topology.CATALOGUE["me"]
    assert spec.profiles == ("me",)
    assert spec.env_dirs == ("infra/me",)
    assert spec.public_url == ("", "ME_PUBLIC_URL")
    assert "me" in topology.CONTROLLER_ONLY
    rows = [row for row in ingress.CORE_PROXY_HOSTS if row[0] == "me"]
    assert rows == [("me", "", "ME_PUBLIC_URL", "me", "me-web", 8000, "http", True, False)]


# ── the address: a host name only ────────────────────────────────────────────

EDGE = "57143"


def _setup(repo_root, *, stored=None, **kwargs):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["INGRESS_HTTPS_EXT_PORT"] = EDGE
    for key, value in (stored or {}).items():
        tree[""][key] = value
    args = resolve.SetupArgs(
        config_dir=repo_root,
        env_name="itest",
        app_host=kwargs.pop("app_host", "http://host.docker.internal"),
        non_interactive=True,
        fresh_init=not stored,
        **kwargs,
    )
    tree = resolve.resolve_multi_env(tree, args)
    return resolve.resolve_hostnames(tree, args)[""]


def test_on_the_edge_me_web_gets_its_host_name(repo_root):
    assert _setup(repo_root)["ME_PUBLIC_URL"] == f"https://me.itest.papaia.localhost:{EDGE}"


def test_behind_an_external_proxy_me_web_gets_its_host_name(repo_root):
    root = _setup(
        repo_root, app_host="https://example.org", reverse_proxy_provider="external_proxy"
    )
    assert root["ME_PUBLIC_URL"] == "https://me.example.org"


@pytest.mark.parametrize(
    "kwargs",
    [{"reverse_proxy_provider": "no_proxy"}, {"allow_direct_port_access": True}],
)
def test_without_a_proxy_no_port_address_is_derived(repo_root, kwargs):
    # me-web never publishes a port (A-02), so a port address would lead nowhere.
    assert _setup(repo_root, **kwargs)["ME_PUBLIC_URL"] == ""


def test_an_address_the_operator_chose_is_kept(repo_root):
    stored = {
        "PAPAIA_HOST": "http://host.docker.internal",
        "REVERSE_PROXY_PROVIDER": "internal_nginx",
        "ME_PUBLIC_URL": "https://mein-bereich.customer.example",
    }
    assert _setup(repo_root, stored=stored)["ME_PUBLIC_URL"] == stored["ME_PUBLIC_URL"]


# ── attachable at generation 8 ───────────────────────────────────────────────


def _target(window: tuple[int, int]) -> CoreTarget:
    return CoreTarget(
        platform_version="1.10.0",
        addon_api=window,
        services=compat.resolve_core_services(REPO),
    )


def _manifest(attach: list[str], generation: int) -> dict:
    return {
        "requires": {"addon_api": [generation]},
        "networks": {"attach": attach},
    }


def test_prefs_and_me_web_are_attachable_at_generation_8():
    result = compat.evaluate_addon("probe", _manifest(["prefs", "me-web"], 8), _target((1, 8)))
    assert result.status == compat.STATUS_OK, result.reason


def test_the_preference_database_is_never_attachable():
    result = compat.evaluate_addon("probe", _manifest(["prefs-db"], 8), _target((1, 8)))
    assert result.status == compat.STATUS_INCOMPATIBLE
    assert "prefs-db" in result.reason


# ── the check fails on every drift ───────────────────────────────────────────


def test_a_variable_the_service_reads_but_the_profile_does_not_set_fails(tmp_path):
    root = _copy(tmp_path)
    _rewrite_compose(root, lambda d: d["services"]["prefs"]["environment"].pop("PREFS_LANG"))
    problems = me_profile.check(root)
    assert any("prefs" in p and "PREFS_LANG" in p and "missing" in p for p in problems)


def test_a_variable_the_service_does_not_read_fails(tmp_path):
    root = _copy(tmp_path)

    def add(doc):
        doc["services"]["me-web"]["environment"]["ME_UNKNOWN_SETTING"] = "1"

    _rewrite_compose(root, add)
    problems = me_profile.check(root)
    assert any("me-web" in p and "ME_UNKNOWN_SETTING" in p for p in problems)


def test_two_names_of_one_alias_group_fail(tmp_path):
    root = _copy(tmp_path)

    def add(doc):
        doc["services"]["me-web"]["environment"]["ME_OIDC_ISSUER"] = "${OIDC_ISSUER}"

    _rewrite_compose(root, add)
    assert any("ME_OIDC_ISSUER" in p for p in me_profile.check(root))


def test_an_undocumented_interpolation_fails(tmp_path):
    root = _copy(tmp_path)
    path = root / me_profile.ENV_EXAMPLE_REL
    lines = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if not line.startswith("PREFS_LANG=")
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert any("PREFS_LANG" in p and ".env.example" in p for p in me_profile.check(root))


def test_a_stale_entry_of_the_env_example_fails(tmp_path):
    root = _copy(tmp_path)
    path = root / me_profile.ENV_EXAMPLE_REL
    path.write_text(path.read_text(encoding="utf-8") + "ME_GONE=1\n", encoding="utf-8")
    assert any("ME_GONE" in p for p in me_profile.check(root))


def test_a_published_port_fails(tmp_path):
    root = _copy(tmp_path)
    _rewrite_compose(root, lambda d: d["services"]["me-web"].update(ports=["8130:8000"]))
    assert any("me-web" in p and "port" in p for p in me_profile.check(root))


def test_a_second_image_fails(tmp_path):
    root = _copy(tmp_path)

    def change(doc):
        doc["services"]["prefs"]["image"] = "ghcr.io/fidonis/papaia-me:0.1.1"

    _rewrite_compose(root, change)
    assert any("prefs" in p and "image" in p for p in me_profile.check(root))


# ── the list is generated, not written by hand ───────────────────────────────

_ME_CONFIG = '''
class Settings:
    @classmethod
    def from_env(cls, env=None):
        e = dict(env)

        def req(name):
            return e[name]

        def opt(*names):
            return None

        issuer = opt("ME_OIDC_ISSUER", "OIDC_ISSUER")
        return cls(
            secret=req("ME_SESSION_SECRET"),
            port=int(e.get("ME_MODULE_PORT", "8080")),
            lang=e.get("ME_DEFAULT_LANG", "de"),
        )
'''

_PREFS_CONFIG = '''
class PrefsSettings:
    @classmethod
    def from_env(cls, env=None):
        def get(name, default=""):
            return env.get(name, default)

        def path(name):
            return get(name)

        return cls(
            issuer=get("OIDC_ISSUER"),
            dialect=get("PREFS_DB_DIALECT", "postgres"),
            password=path("PREFS_DB_PASSWORD_FILE"),
        )
'''


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "papaia-me"
    (source / "src/app").mkdir(parents=True)
    (source / "src/prefs").mkdir(parents=True)
    (source / "src/app/config.py").write_text(textwrap.dedent(_ME_CONFIG), "utf-8")
    (source / "src/prefs/config.py").write_text(textwrap.dedent(_PREFS_CONFIG), "utf-8")
    return source


def test_the_generator_reads_the_names_from_the_configuration_modules(tmp_path):
    image = "ghcr.io/fidonis/papaia-me:0.1.0@sha256:" + "a" * 64
    listed = me_profile.generate(_source(tmp_path), image=image, commit="0" * 40)
    assert listed["format"] == me_profile.FORMAT
    assert listed["image"] == image
    assert listed["source"] == {"repository": "papaia-me", "commit": "0" * 40}
    me_web = listed["services"]["me-web"]
    assert me_web["reads"] == ["ME_DEFAULT_LANG", "ME_MODULE_PORT", "ME_SESSION_SECRET"]
    assert me_web["one_of"] == [["ME_OIDC_ISSUER", "OIDC_ISSUER"]]
    prefs = listed["services"]["prefs"]
    # Defaults ("postgres") are values, not names.
    assert prefs["reads"] == ["OIDC_ISSUER", "PREFS_DB_DIALECT", "PREFS_DB_PASSWORD_FILE"]
    assert prefs["one_of"] == []
    assert me_web["runtime"] == prefs["runtime"] == list(me_profile.RUNTIME_READS)


def test_the_generator_refuses_a_name_outside_the_variable_grammar(tmp_path):
    source = _source(tmp_path)
    path = source / "src/prefs/config.py"
    text = path.read_text("utf-8").replace("PREFS_DB_DIALECT", "prefs-db dialect")
    path.write_text(text, "utf-8")
    with pytest.raises(me_profile.MeProfileError, match="variable name"):
        me_profile.generate(source, image="x:1@sha256:" + "a" * 64, commit="0" * 40)


def test_the_generator_refuses_a_floating_image(tmp_path):
    with pytest.raises(me_profile.MeProfileError, match="digest"):
        me_profile.generate(
            _source(tmp_path), image="ghcr.io/fidonis/papaia-me:0.1.0", commit="0" * 40
        )


def test_the_cli_check_exits_non_zero_on_drift(tmp_path, capsys):
    root = _copy(tmp_path)
    assert me_profile.main(["check", "--repo", str(root)]) == 0
    _rewrite_compose(root, lambda d: d["services"]["prefs"]["environment"].pop("PREFS_LANG"))
    assert me_profile.main(["check", "--repo", str(root)]) == 1
    assert "PREFS_LANG" in capsys.readouterr().err


# ── rendered by Compose ──────────────────────────────────────────────────────


def _compose_cli() -> list[str] | None:
    docker = shutil.which("docker")
    if docker is None:
        return None
    probe = subprocess.run([docker, "compose", "version"], capture_output=True, check=False)
    return [docker, "compose"] if probe.returncode == 0 else None


def test_the_rendered_profile_sets_the_listed_variables_and_no_host_port(tmp_path):
    cli = _compose_cli()
    if cli is None:
        if REQUIRE_COMPOSE:
            pytest.fail("PAPAIA_REQUIRE_GOLDEN_COMPOSE is set but Docker Compose is missing")
        pytest.skip("Docker Compose not installed")
    env = {
        **common.parse_env_file(REPO / "src" / ".env.example"),
        **common.parse_env_file(ME_DIR / ".env.example"),
        "PAPAIA_CONFIG_DIR": str(tmp_path / "config"),
        "DOCKER_NETWORK": "itk-core-027-net",
    }
    env_file = tmp_path / "render.env"
    env_file.write_text("".join(f"{k}={v}\n" for k, v in env.items()), encoding="utf-8")
    # `config` only renders the model; it starts nothing and needs no daemon.
    rendered = subprocess.run(
        [
            *cli,
            "--project-name", "itk-core-027",
            "--project-directory", str(ME_DIR),
            "--env-file", str(env_file),
            "-f", str(ME_DIR / "docker-compose.yml"),
            "-f", str(Path(__file__).parent / "fixtures" / "me" / "networks.yml"),
            "--profile", "me",
            "config", "--format", "json",
        ],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": os.environ.get("PATH", "")},
    )
    assert rendered.returncode == 0, rendered.stderr
    services = json.loads(rendered.stdout)["services"]
    listed = _env_list()["services"]
    for name in me_profile.SERVICES:
        environment = services[name]["environment"]
        assert set(environment) == me_profile.expected_names(listed[name], set(environment))
        assert all(value is not None for value in environment.values()), name
    for name, service in services.items():
        assert not service.get("ports"), name
