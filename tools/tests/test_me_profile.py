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
from urllib.parse import urlsplit

import pytest
import yaml

from lib import audit, common, compat, envtree, ingress, me_profile, resolve, smtp, topology
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
    assert set(common.parse_env_file(ME_DIR / ".env.example")) == own | set(
        me_profile.FILE_SECRETS
    )


def test_the_database_password_reaches_both_containers_as_a_file_secret():
    # A read-only service takes no secret from an environment variable (Compose writes
    # such a secret into the container and refuses a read-only one); the file is written
    # from PREFS_DB_PASSWORD of infra/me/.env before every start.
    doc = _compose()
    assert doc["secrets"]["prefs-db-password"] == {
        "file": "${PAPAIA_CONFIG_DIR}/infra/me/secrets/prefs-db-password"
    }
    assert doc["services"]["prefs"]["read_only"] is True
    for name in ("prefs", "prefs-db"):
        assert doc["services"][name]["secrets"] == ["prefs-db-password"]
    assert "PREFS_DB_PASSWORD" in me_profile.FILE_SECRETS


def _installation(tmp_path: Path, profiles: str, password: str) -> Path:
    config = tmp_path / "config"
    (config / "infra" / "me").mkdir(parents=True)
    (config / ".env").write_text(f"COMPOSE_PROFILES={profiles}\n", encoding="utf-8")
    (config / "infra" / "me" / ".env").write_text(
        f"PREFS_DB_PASSWORD={password}\n", encoding="utf-8"
    )
    return config


def test_the_password_file_is_written_from_the_profile_env_while_me_is_on(tmp_path):
    from lib import render_core

    config = _installation(tmp_path, "keycloak,audit,me", "s3cret-value-of-prefs")
    render_core.ensure_me_secrets(config)
    path = config / "infra" / "me" / "secrets" / "prefs-db-password"
    assert path.read_text(encoding="utf-8") == "s3cret-value-of-prefs"
    # prefs (10001) and the database (postgres) read it through the bind mount; the
    # folder keeps every other account of the host out.
    assert path.stat().st_mode & 0o777 == 0o644
    assert path.parent.stat().st_mode & 0o777 == 0o700
    # A changed value replaces the file.
    (config / "infra" / "me" / ".env").write_text("PREFS_DB_PASSWORD=other\n", "utf-8")
    render_core.ensure_me_secrets(config)
    assert path.read_text(encoding="utf-8") == "other"


def test_no_password_file_while_me_is_off(tmp_path):
    from lib import render_core

    config = _installation(tmp_path, "keycloak,audit", "s3cret-value-of-prefs")
    render_core.ensure_me_secrets(config)
    assert not (config / "infra" / "me" / "secrets").exists()


@pytest.mark.parametrize("value", ["", "GENERATE_PREFS_DB_PASSWORD"])
def test_a_password_setup_has_not_generated_stops_the_render(tmp_path, value):
    from lib import render_core

    config = _installation(tmp_path, "me", value)
    with pytest.raises(render_core.RenderError, match="PREFS_DB_PASSWORD"):
        render_core.ensure_me_secrets(config)
    assert not (config / "infra" / "me" / "secrets" / "prefs-db-password").exists()


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


# ── the settings the core owns (candidate of papaia-me releases/0.1.0) ──────────


def test_the_list_names_a_full_source_commit_and_the_pinned_image():
    listed = _env_list()
    assert listed["source"]["repository"] == "papaia-me"
    assert len(listed["source"]["commit"]) == 40
    assert int(listed["source"]["commit"], 16) >= 0
    services = _compose()["services"]
    assert services["me-web"]["image"] == services["prefs"]["image"] == listed["image"]


def test_me_web_reads_its_audit_tickets_from_papaia_audit_over_mutual_tls():
    me_web = _compose()["services"]["me-web"]
    env = me_web["environment"]
    url = urlsplit(env["ME_AUDIT_URL"])
    assert (url.scheme, url.hostname, url.port, url.path) == ("https", "papaia-audit", 8443, "")
    # The source certificate of papaia-me from the ingest CA (`papaia-ctl audit cert
    # papaia-me`), the one prefs delivers with: papaia-audit knows its sources by it.
    assert "papaia-me" in audit.SOURCES
    assert env["ME_AUDIT_CLIENT_DIR"] == "/run/papaia/audit"
    assert (
        "${PAPAIA_CONFIG_DIR}/infra/audit/clients/papaia-me:/run/papaia/audit:ro"
        in me_web["volumes"]
    )
    prefs = _compose()["services"]["prefs"]
    assert (
        "${PAPAIA_CONFIG_DIR}/infra/audit/clients/papaia-me:/run/papaia/audit:ro"
        in prefs["volumes"]
    )
    assert "papaia-audit-ingest-net" in me_web["networks"]


def test_prefs_checks_me_webs_rows_with_the_certificate_me_web_signs_with():
    # One audit source, one outbox: me-web signs its rows with the key in its folder and
    # hands them to prefs, which checks the signature with the certificate it delivers
    # with. Both must be the same certificate of papaia-me, and they must share a network.
    services = _compose()["services"]
    me_web, prefs = services["me-web"], services["prefs"]
    folder = me_web["environment"]["ME_AUDIT_CLIENT_DIR"]
    assert prefs["environment"]["PREFS_AUDIT_CERT_FILE"] == f"{folder}/client.crt"
    assert prefs["environment"]["PREFS_AUDIT_KEY_FILE"] == f"{folder}/client.key"
    mounts = {v.split(":")[1]: v.split(":")[0] for v in me_web["volumes"]}
    prefs_mounts = {v.split(":")[1]: v.split(":")[0] for v in prefs["volumes"]}
    assert mounts[folder] == prefs_mounts[folder]
    host = urlsplit(me_web["environment"]["ME_PREFS_URL"]).hostname
    assert host == "prefs"
    assert set(me_web["networks"]) & set(prefs["networks"]) >= {"papaia-net"}


def test_me_web_and_prefs_take_the_default_time_zone_from_one_setting():
    services = _compose()["services"]
    me_web = services["me-web"]["environment"]["ME_DEFAULT_TIME_ZONE"]
    prefs = services["prefs"]["environment"]["PREFS_DEFAULT_TIME_ZONE"]
    assert me_web == prefs == "${PREFS_DEFAULT_TIME_ZONE:-Europe/Berlin}"
    assert "PREFS_DEFAULT_TIME_ZONE" not in services["me-web"]["environment"]
    assert common.parse_env_file(ME_DIR / ".env.example")["PREFS_DEFAULT_TIME_ZONE"] == (
        "Europe/Berlin"
    )


def test_me_web_calls_prefs_by_its_compose_name_and_port():
    services = _compose()["services"]
    url = urlsplit(services["me-web"]["environment"]["ME_PREFS_URL"])
    assert (url.scheme, url.hostname, url.port, url.path) == ("http", "prefs", 8080, "")
    shared = set(services["me-web"]["networks"]) & set(services["prefs"]["networks"])
    assert "papaia-net" in shared
    assert "127.0.0.1:8080/healthz" in " ".join(services["prefs"]["healthcheck"]["test"])


def test_the_log_level_of_me_web_is_one_setting_with_default_info():
    env = _compose()["services"]["me-web"]["environment"]
    assert env["LOG_LEVEL"] == "${ME_LOG_LEVEL:-INFO}"
    assert common.parse_env_file(ME_DIR / ".env.example")["ME_LOG_LEVEL"] == "INFO"


def test_disabled_channels_are_set_and_name_only_channels_of_the_store():
    env = _compose()["services"]["prefs"]["environment"]
    assert env["PREFS_DISABLED_CHANNELS"] == "${PREFS_DISABLED_CHANNELS:-}"
    channels = _env_list()["services"]["prefs"]["channels"]
    assert sorted(channels) == ["chat_window", "mail"]
    example = common.parse_env_file(ME_DIR / ".env.example")
    assert example["PREFS_DISABLED_CHANNELS"] == ""
    assert example["PREFS_DEFAULT_CHANNEL"] in channels


def test_a_disabled_channel_the_store_does_not_know_fails(tmp_path):
    root = _copy(tmp_path)
    path = root / me_profile.ENV_EXAMPLE_REL
    text = path.read_text(encoding="utf-8").replace(
        "PREFS_DISABLED_CHANNELS=", "PREFS_DISABLED_CHANNELS=mail,sms"
    )
    path.write_text(text, encoding="utf-8")
    problems = me_profile.check(root)
    assert any("PREFS_DISABLED_CHANNELS" in p and "sms" in p for p in problems)


def test_a_channel_named_twice_fails(tmp_path):
    root = _copy(tmp_path)
    _rewrite_compose(
        root,
        lambda d: d["services"]["prefs"]["environment"].update(
            PREFS_DISABLED_CHANNELS="${PREFS_DISABLED_CHANNELS:-mail,mail}"
        ),
    )
    problems = me_profile.check(root)
    assert any("PREFS_DISABLED_CHANNELS" in p and "mail" in p for p in problems)


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


_PREFS_MODEL = '''
CHANNELS = ("chat_window", "mail")
DEFAULT_CHANNELS = CHANNELS
'''


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "papaia-me"
    (source / "src/app").mkdir(parents=True)
    (source / "src/prefs").mkdir(parents=True)
    (source / "src/app/config.py").write_text(textwrap.dedent(_ME_CONFIG), "utf-8")
    (source / "src/prefs/config.py").write_text(textwrap.dedent(_PREFS_CONFIG), "utf-8")
    (source / "src/prefs/model.py").write_text(textwrap.dedent(_PREFS_MODEL), "utf-8")
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
    # The channels the store knows, for the operator's PREFS_DISABLED_CHANNELS.
    assert prefs["channels"] == ["chat_window", "mail"]
    assert "channels" not in me_web


def test_the_generator_refuses_a_store_without_a_literal_channel_list(tmp_path):
    source = _source(tmp_path)
    (source / "src/prefs/model.py").write_text("CHANNELS = tuple(load())\n", "utf-8")
    with pytest.raises(me_profile.MeProfileError, match="CHANNELS"):
        me_profile.generate(source, image="x:1@sha256:" + "a" * 64, commit="0" * 40)


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


# ── the mail exit of prefs: the test message by mail (ME-07-A8, KE-25) ──────

MAIL = ("PREFS_SMTP_HOST", "PREFS_SMTP_PORT", "PREFS_MAIL_FROM", "PREFS_INSTALLATION_NAME",
        "PREFS_NOTIFICATIONS_URL")  # fmt: skip
RELAY = {smtp.KEY_FROM: "noreply@example.org", smtp.KEY_SENDER_DOMAINS: "example.org"}


def _mail(**overrides):
    kwargs = {
        "profiles": {"keycloak", "audit", "me", "smtp"},
        "public_url": "https://me.example.org",
        "relay": dict(RELAY),
        "installation_name": "Muster GmbH",
        **overrides,
    }
    return me_profile.mail_env(**kwargs)


def test_prefs_reads_the_five_mail_settings_and_the_compose_file_sets_them():
    listed = _env_list()["services"]["prefs"]
    assert set(MAIL) <= set(listed["reads"])
    env = _compose()["services"]["prefs"]["environment"]
    # The relay's fixed name and port (lib/smtp.py); the rest derived into infra/me/.env.
    assert env["PREFS_SMTP_HOST"] == "${PREFS_SMTP_HOST:-}"
    assert env["PREFS_SMTP_PORT"] == str(smtp.RELAY_PORT)
    for name in ("PREFS_MAIL_FROM", "PREFS_INSTALLATION_NAME", "PREFS_NOTIFICATIONS_URL"):
        assert env[name] == f"${{{name}:-}}", name
    # Derived, never set by hand: documented empty in the profile's .env.example.
    example = common.parse_env_file(ME_DIR / ".env.example")
    for name in me_profile.MAIL_DERIVED:
        assert example[name] == "", name


def test_prefs_reaches_only_the_internal_relay_and_holds_no_upstream_credential():
    prefs = _compose()["services"]["prefs"]
    assert "papaia-net" in prefs["networks"]
    relay = yaml.safe_load(
        (REPO / "src/infra/smtp-relay/docker-compose.yml").read_text(encoding="utf-8")
    )["services"][smtp.SERVICE]
    assert "papaia-net" in relay["networks"]
    assert not any(name.startswith("SMTP_RELAY_") for name in prefs["environment"])
    assert not any("smtp-relay" in str(volume) for volume in prefs["volumes"])
    assert not any("PASSWORD" in name for name in me_profile.MAIL_DERIVED)


def test_with_smtp_prefs_gets_the_relay_its_sender_the_name_and_the_https_link():
    assert _mail() == {
        "PREFS_SMTP_HOST": smtp.RELAY_HOST,
        "PREFS_MAIL_FROM": "noreply@example.org",
        "PREFS_INSTALLATION_NAME": "Muster GmbH",
        "PREFS_NOTIFICATIONS_URL": "https://me.example.org/notifications",
    }
    # A trailing slash of the address does not double.
    url = _mail(public_url="https://me.example.org:57143/")["PREFS_NOTIFICATIONS_URL"]
    assert url == "https://me.example.org:57143/notifications"


@pytest.mark.parametrize("profiles", [{"keycloak", "me"}, {"keycloak", "smtp"}, set()])
def test_without_smtp_or_me_the_host_is_empty(profiles):
    # The mail test of Me then answers "unavailable"; prefs starts as before.
    values = _mail(profiles=profiles, public_url="http://me.example.org", relay={})
    assert values == dict.fromkeys(me_profile.MAIL_DERIVED, "")


@pytest.mark.parametrize(
    "relay",
    [
        {smtp.KEY_FROM: "noreply@other.example", smtp.KEY_SENDER_DOMAINS: "example.org"},
        {smtp.KEY_FROM: "noreply@sub.example.org", smtp.KEY_SENDER_DOMAINS: "example.org"},
        {smtp.KEY_FROM: "", smtp.KEY_SENDER_DOMAINS: "example.org"},
        {smtp.KEY_FROM: "Muster <noreply@example.org>", smtp.KEY_SENDER_DOMAINS: "example.org"},
        {smtp.KEY_FROM: "noreply@example.org", smtp.KEY_SENDER_DOMAINS: ""},
    ],
)
def test_a_sender_outside_the_relays_sender_domains_is_refused(relay):
    with pytest.raises(me_profile.MeProfileError, match="PREFS_MAIL_FROM"):
        _mail(relay=relay)


def test_the_sender_domain_compares_without_case():
    relay = {smtp.KEY_FROM: "NoReply@Example.ORG", smtp.KEY_SENDER_DOMAINS: "example.org"}
    assert _mail(relay=relay)["PREFS_MAIL_FROM"] == "NoReply@Example.ORG"


@pytest.mark.parametrize(
    "public_url",
    ["", "http://me.example.org", "https://", "https://me.example.org/a b", "ftp://me.x"],
)
def test_a_link_that_is_not_https_is_refused(public_url):
    with pytest.raises(me_profile.MeProfileError, match="PREFS_NOTIFICATIONS_URL"):
        _mail(public_url=public_url)


@pytest.mark.parametrize("name", ["", "   ", "x" * 61, "Zeile\nzwei"])
def test_an_installation_name_prefs_cannot_send_under_is_refused(name):
    with pytest.raises(me_profile.MeProfileError, match="PREFS_INSTALLATION_NAME"):
        _mail(installation_name=name)


def test_the_installation_name_is_handed_on_without_surrounding_spaces():
    # The branding schema allows them; the relay strips the name it writes into From.
    assert _mail(installation_name="  Muster GmbH ")["PREFS_INSTALLATION_NAME"] == "Muster GmbH"


def _start_config(tmp_path: Path, *, profiles: str, me_url: str, relay: dict) -> Path:
    config = tmp_path / "config"
    (config / "infra" / "me").mkdir(parents=True)
    (config / "infra" / "smtp-relay").mkdir(parents=True)
    (config / ".env").write_text(
        f"COMPOSE_PROFILES={profiles}\nME_PUBLIC_URL={me_url}\n", encoding="utf-8"
    )
    shutil.copyfile(ME_DIR / ".env.example", config / "infra" / "me" / ".env")
    (config / "infra" / "smtp-relay" / ".env").write_text(
        "".join(f"{k}={v}\n" for k, v in relay.items()), encoding="utf-8"
    )
    return config


def _mail_rows(config: Path) -> list[dict]:
    from lib import realm_sync as rs

    path = rs.audit_path(config)
    if not path.is_file():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    return [r for r in rows if r.get("writer") == "papaia-ctl/me-mail"]


def test_start_derives_the_mail_settings_into_the_profile_env_and_the_checkout(tmp_path):
    from lib import render_core

    config = _start_config(
        tmp_path, profiles="keycloak,audit,me,smtp", me_url="https://me.example.org",
        relay=RELAY,
    )  # fmt: skip
    checkout = tmp_path / "checkout"
    (checkout / "src" / "infra" / "me").mkdir(parents=True)
    shutil.copyfile(config / "infra" / "me" / ".env", checkout / "src/infra/me/.env")
    render_core.ensure_me_mail(config, checkout, installation_name="Muster GmbH")
    for path in (config / "infra/me/.env", checkout / "src/infra/me/.env"):
        values = common.parse_env_file(path)
        assert values["PREFS_SMTP_HOST"] == "smtp-relay"
        assert values["PREFS_MAIL_FROM"] == "noreply@example.org"
        assert values["PREFS_INSTALLATION_NAME"] == "Muster GmbH"
        assert values["PREFS_NOTIFICATIONS_URL"] == "https://me.example.org/notifications"
        # The generated secrets of the file stay as they were.
        assert values["PREFS_DB_PASSWORD"] == "GENERATE_PREFS_DB_PASSWORD"
    rows = _mail_rows(config)
    assert len(rows) == 1
    row = rows[0]
    assert row["result"] == "allowed" and row["correlation_id"]
    # Field names, never values.
    text = json.dumps(row)
    assert "PREFS_MAIL_FROM" in text
    assert "noreply@example.org" not in text and "Muster GmbH" not in text
    # A second start changes nothing and writes no row.
    before = (config / "infra/me/.env").read_bytes()
    render_core.ensure_me_mail(config, checkout, installation_name="Muster GmbH")
    assert (config / "infra/me/.env").read_bytes() == before
    assert len(_mail_rows(config)) == 1


def test_a_name_with_surrounding_spaces_is_written_once(tmp_path):
    from lib import render_core

    config = _start_config(
        tmp_path, profiles="keycloak,me,smtp", me_url="https://me.example.org", relay=RELAY
    )
    render_core.ensure_me_mail(config, tmp_path / "none", installation_name=" Muster GmbH  ")
    values = common.parse_env_file(config / "infra/me/.env")
    assert values["PREFS_INSTALLATION_NAME"] == "Muster GmbH"
    before = (config / "infra/me/.env").read_bytes()
    # The second start finds the stored value equal: no write, no audit row.
    assert render_core.ensure_me_mail(
        config, tmp_path / "none", installation_name=" Muster GmbH  "
    ) == []
    assert (config / "infra/me/.env").read_bytes() == before
    assert len(_mail_rows(config)) == 1


def test_start_empties_the_host_once_smtp_is_switched_off(tmp_path):
    from lib import render_core

    config = _start_config(
        tmp_path, profiles="keycloak,me,smtp", me_url="https://me.example.org", relay=RELAY
    )
    render_core.ensure_me_mail(config, tmp_path / "none", installation_name="Muster GmbH")
    (config / ".env").write_text(
        "COMPOSE_PROFILES=keycloak,me\nME_PUBLIC_URL=https://me.example.org\n", "utf-8"
    )
    render_core.ensure_me_mail(config, tmp_path / "none", installation_name="Muster GmbH")
    values = common.parse_env_file(config / "infra/me/.env")
    assert {name: values[name] for name in me_profile.MAIL_DERIVED} == dict.fromkeys(
        me_profile.MAIL_DERIVED, ""
    )
    assert len(_mail_rows(config)) == 2


@pytest.mark.parametrize(
    ("me_url", "relay", "variable"),
    [
        ("http://me.example.org", RELAY, "PREFS_NOTIFICATIONS_URL"),
        (
            "https://me.example.org",
            {smtp.KEY_FROM: "noreply@other.example", smtp.KEY_SENDER_DOMAINS: "example.org"},
            "PREFS_MAIL_FROM",
        ),
    ],
)
def test_start_refuses_a_setting_prefs_cannot_send_with(tmp_path, me_url, relay, variable):
    from lib import render_core

    config = _start_config(tmp_path, profiles="keycloak,me,smtp", me_url=me_url, relay=relay)
    before = (config / "infra/me/.env").read_bytes()
    with pytest.raises(render_core.RenderError, match=variable):
        render_core.ensure_me_mail(config, tmp_path / "none", installation_name="Muster GmbH")
    assert (config / "infra/me/.env").read_bytes() == before
    assert _mail_rows(config) == []


def test_the_render_of_start_derives_the_mail_settings():
    import inspect

    from lib import render_core

    # `start` and `addon start` render before `up`; the name is the catalog's, the one
    # the relay writes into From.
    source = inspect.getsource(render_core.render)
    assert "ensure_me_mail(" in source
    assert "installation_name(" in inspect.getsource(render_core.ensure_me_mail)


def test_setup_derives_the_mail_settings(repo_root):
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,audit,me,smtp"
    tree[""]["ME_PUBLIC_URL"] = "https://me.example.org"
    tree.setdefault("infra/smtp-relay", {}).update(RELAY)
    args = resolve.SetupArgs(
        config_dir=repo_root, env_name="itest", installation_name="Muster GmbH",
        non_interactive=True,
    )  # fmt: skip
    me = resolve.resolve_me_mail(tree, args)["infra/me"]
    assert me["PREFS_SMTP_HOST"] == "smtp-relay"
    assert me["PREFS_NOTIFICATIONS_URL"] == "https://me.example.org/notifications"
    tree[""]["ME_PUBLIC_URL"] = "http://me.example.org"
    with pytest.raises(resolve.SetupError, match="PREFS_NOTIFICATIONS_URL"):
        resolve.resolve_me_mail(tree, args)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,audit,me"
    assert resolve.resolve_me_mail(tree, args)["infra/me"]["PREFS_SMTP_HOST"] == ""


def test_the_rendered_prefs_carries_the_derived_mail_settings(tmp_path):
    cli = _compose_cli()
    if cli is None:
        if REQUIRE_COMPOSE:
            pytest.fail("PAPAIA_REQUIRE_GOLDEN_COMPOSE is set but Docker Compose is missing")
        pytest.skip("Docker Compose not installed")
    env = {
        **common.parse_env_file(REPO / "src" / ".env.example"),
        **common.parse_env_file(ME_DIR / ".env.example"),
        **_mail(),
        "PAPAIA_CONFIG_DIR": str(tmp_path / "config"),
        "DOCKER_NETWORK": "papaia-me-render-net",
    }
    env_file = tmp_path / "render.env"
    env_file.write_text("".join(f"{k}={v}\n" for k, v in env.items()), encoding="utf-8")
    rendered = subprocess.run(
        [
            *cli,
            "--project-name", "papaia-me-render",
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
    )  # fmt: skip
    assert rendered.returncode == 0, rendered.stderr
    environment = json.loads(rendered.stdout)["services"]["prefs"]["environment"]
    assert {name: environment[name] for name in MAIL} == {
        "PREFS_SMTP_HOST": "smtp-relay",
        "PREFS_SMTP_PORT": "587",
        "PREFS_MAIL_FROM": "noreply@example.org",
        "PREFS_INSTALLATION_NAME": "Muster GmbH",
        "PREFS_NOTIFICATIONS_URL": "https://me.example.org/notifications",
    }
