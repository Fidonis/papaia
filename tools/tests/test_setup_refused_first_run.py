"""A refused `setup` writes nothing, so nothing has to be taken back, and a first one
leaves nothing the next run would take for an existing installation (#400, #402).

Everything is resolved and checked before the first write. The root .env is written last:
until it is there, the next setup is a first one. Because setup never deletes to clean up,
what other processes do in the config directory meanwhile is safe."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from install_helpers import checkout
from test_topology import FULL

from lib import cli, common, defaults, envtree, resolve, secrets, smtp, topology

APP_HOST = "https://papaia.example.test"
# Every derived address is the app host or a name below its domain (`litellm.` + domain).
APP_DOMAIN = "papaia.example.test"
TWO_NODES = [
    "--topology=distributed",
    "--node=internal=10.0.2.10",
    "--node=edge=10.0.1.10,ssh=papaia@10.0.1.10",
]

# Every value the app host derives that a seeded template would have pinned to
# http://host.docker.internal:<port>.
DERIVED = {
    "": ("LITELLM_PUBLIC_URL", "LOCALAI_PUBLIC_URL", "MANAGER_PUBLIC_URL", "NPM_ADMIN_HOST"),
    "ai/librechat": ("DOMAIN_CLIENT", "DOMAIN_SERVER"),
    "ai/litellm": ("GENERIC_REDIRECT_URI", "PROXY_LOGOUT_URL"),
}

# One refusal per stage of a first setup: a value resolve rejects, a value it rejects
# only after looking at the stored password, and a topology refused after the relay's
# password has been settled.
REFUSALS = {
    "smtp-without-host": (
        ["--enable-smtp=true", "--smtp-from=noreply@example.org"],
        3,
        "--smtp-host is required",
    ),
    "smtp-login-without-password": (
        [
            "--enable-smtp=true",
            "--smtp-host=smtp.example.org",
            "--smtp-from=noreply@example.org",
            "--smtp-user=mailer",
        ],
        3,
        "PAPAIA_SMTP_PASSWORD",
    ),
    "placement-after-the-password": (
        [*FULL[1:], *TWO_NODES, "--place=manager=edge"],
        cli.SETUP_REFUSED,
        "'manager' must run on the controller",
    ),
}
LATE_REFUSAL = REFUSALS["placement-after-the-password"][0]


@pytest.fixture(autouse=True)
def _no_password_in_the_environment(monkeypatch):
    monkeypatch.delenv("PAPAIA_SMTP_PASSWORD", raising=False)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return checkout(tmp_path)


def _setup(repo: Path, config: Path, *flags: str) -> int:
    return cli.main(
        ["--repo-root", str(repo), "--config-dir", str(config), "setup", "--env=papaia", *flags]
    )


def _files(root: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()
    }


def _entries(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*")}


def _template_hosts(config: Path, repo: Path) -> set[tuple[str, str]]:
    tree = envtree.load_config_dir_tree(config, repo)
    return {
        (rel_dir, key)
        for rel_dir, values in tree.items()
        for key, value in values.items()
        if "host.docker.internal" in value
    }


def _assert_like_reference(config: Path, reference: Path, repo: Path) -> None:
    for rel_dir, keys in DERIVED.items():
        stored = common.parse_env_file(config / rel_dir / ".env")
        expected = common.parse_env_file(reference / rel_dir / ".env")
        for key in keys:
            assert APP_DOMAIN in stored[key], (rel_dir, key, stored[key])
            assert "host.docker.internal" not in stored[key], (rel_dir, key, stored[key])
            assert stored[key] == expected[key], (rel_dir, key)
    # Nothing else kept a template host either.
    assert _template_hosts(config, repo) == _template_hosts(reference, repo)


@pytest.fixture
def reference(repo: Path, tmp_path: Path) -> Path:
    """The same setup on a config directory nothing has touched before."""
    config = tmp_path / "reference-config"
    assert _setup(repo, config, f"--app-host={APP_HOST}") == 0
    return config


# ─────────────────────────────────────────────────────────────────────────
# a refused setup writes nothing
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("state", ["empty", "missing"])
@pytest.mark.parametrize("refusal", sorted(REFUSALS))
def test_a_refused_first_setup_leaves_nothing_and_the_next_one_derives_every_url(
    repo, reference, tmp_path, capsys, state, refusal
):
    flags, code, message = REFUSALS[refusal]
    # Nested: the parents of a missing config directory are not created either.
    config = tmp_path / "not" / "there" / "papaia-config"
    if state == "empty":
        config.mkdir(parents=True)

    assert _setup(repo, config, f"--app-host={APP_HOST}", *flags) == code
    assert message in capsys.readouterr().err
    if state == "empty":
        assert list(config.iterdir()) == []
    else:
        assert not (tmp_path / "not").exists()

    assert _setup(repo, config, f"--app-host={APP_HOST}") == 0
    _assert_like_reference(config, reference, repo)


@pytest.mark.parametrize("refusal", sorted(REFUSALS))
def test_a_refused_setup_calls_no_writer(repo, tmp_path, monkeypatch, capsys, refusal):
    # Not just "the same files afterwards": nothing written and taken back either.
    written: list[Path] = []
    for writer in ("atomic_write", "atomic_write_private", "ensure_dir"):
        monkeypatch.setattr(common, writer, lambda path, *_a, **_k: written.append(path))

    flags, code, _ = REFUSALS[refusal]
    assert _setup(repo, tmp_path / "cfg", f"--app-host={APP_HOST}", *flags) == code
    capsys.readouterr()
    assert written == []


def test_files_that_were_there_before_a_refused_first_setup_stay(repo, tmp_path, capsys):
    config = tmp_path / "papaia-config"
    (config / "overlay" / "ai" / "librechat").mkdir(parents=True)
    (config / "overlay" / "ai" / "librechat" / "librechat.yaml").write_text("version: 1\n")
    (config / "overrides").mkdir()
    (config / "notes.txt").write_text("kept\n")
    before = _files(config), _entries(config)

    assert _setup(repo, config, *FULL[:1], *LATE_REFUSAL) == cli.SETUP_REFUSED
    capsys.readouterr()

    assert (_files(config), _entries(config)) == before


@pytest.mark.parametrize("refusal", sorted(REFUSALS))
def test_what_others_change_during_a_refused_setup_is_never_deleted(
    repo, tmp_path, monkeypatch, capsys, refusal
):
    config = tmp_path / "papaia-config"
    (config / "data").mkdir(parents=True)
    (config / "data" / "document.txt").write_text("kept\n")
    original = resolve.resolve_smtp

    def meanwhile(tree, args):
        # A rename and a new file by another process, while setup is still checking.
        (config / "data").rename(config / "archive")
        (config / "incoming.txt").write_text("new\n")
        return original(tree, args)

    monkeypatch.setattr(resolve, "resolve_smtp", meanwhile)
    flags, code, _ = REFUSALS[refusal]
    assert _setup(repo, config, f"--app-host={APP_HOST}", *flags) == code
    capsys.readouterr()

    assert _files(config) == {
        str(Path("archive", "document.txt")): (config / "archive" / "document.txt").read_bytes(),
        "incoming.txt": (config / "incoming.txt").read_bytes(),
    }


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_a_refused_setup_writes_nothing_through_a_symlinked_directory(repo, tmp_path, capsys):
    config, elsewhere = tmp_path / "papaia-config", tmp_path / "elsewhere"
    config.mkdir()
    elsewhere.mkdir()
    (config / "infra").symlink_to(elsewhere, target_is_directory=True)

    assert _setup(repo, config, f"--app-host={APP_HOST}", *LATE_REFUSAL) == cli.SETUP_REFUSED
    capsys.readouterr()

    assert list(elsewhere.iterdir()) == []
    assert (config / "infra").is_symlink()


@pytest.mark.parametrize("exception", [RuntimeError, KeyboardInterrupt])
def test_an_exception_during_the_checks_changes_nothing(repo, tmp_path, monkeypatch, exception):
    config = tmp_path / "papaia-config"
    (config / "data").mkdir(parents=True)
    before = _entries(config)

    def fail(*_args, **_kwargs):
        raise exception

    monkeypatch.setattr(topology, "validate", fail)
    with pytest.raises(exception):
        _setup(repo, config, f"--app-host={APP_HOST}", *LATE_REFUSAL)

    assert _entries(config) == before


@pytest.mark.parametrize(
    ("login", "password"),
    [(["--smtp-no-auth"], None), (["--smtp-user=mailer"], "new-password")],
    ids=["no-auth", "new-password"],
)
def test_a_refused_first_setup_keeps_a_password_that_was_there(
    repo, tmp_path, monkeypatch, capsys, login, password
):
    config = tmp_path / "papaia-config"
    smtp.write_password(config, "old-password")
    if password:
        monkeypatch.setenv("PAPAIA_SMTP_PASSWORD", password)
    flags = [flag for flag in LATE_REFUSAL if flag != "--smtp-no-auth"]

    assert _setup(repo, config, f"--app-host={APP_HOST}", *flags, *login) == cli.SETUP_REFUSED
    capsys.readouterr()

    assert smtp.read_password(config) == "old-password"


def test_a_refused_setup_of_an_existing_installation_changes_nothing(repo, tmp_path, capsys):
    config = tmp_path / "papaia-config"
    assert _setup(repo, config, f"--app-host={APP_HOST}") == 0
    before = _files(config)
    capsys.readouterr()

    flags, code, _ = REFUSALS["smtp-without-host"]
    assert _setup(repo, config, *flags) == code
    assert _files(config) == before


def test_a_refused_password_change_of_a_distributed_installation_changes_nothing(
    repo, tmp_path, monkeypatch, capsys
):
    config = tmp_path / "papaia-config"
    install = [flag for flag in FULL if flag != "--smtp-no-auth"]
    monkeypatch.setenv("PAPAIA_SMTP_PASSWORD", "old-password")
    install += ["--smtp-user=mailer", *TWO_NODES, "--preset=dmz-split"]
    assert _setup(repo, config, *install) == 0
    before = _files(config)

    monkeypatch.setenv("PAPAIA_SMTP_PASSWORD", "new-password")
    bad_url = "--librechat-host=https://chat.example.org:8000"
    assert _setup(repo, config, bad_url, "--smtp-user=mailer") == cli.SETUP_REFUSED
    capsys.readouterr()

    assert _files(config) == before


# ─────────────────────────────────────────────────────────────────────────
# a setup cut short while it writes
# ─────────────────────────────────────────────────────────────────────────


class _Killed(BaseException):
    """Stands for a SIGKILL: setup has no handler that could clean up after it."""


def _record_writes(monkeypatch, stop_at: int | None = None) -> list[Path]:
    """Record every file write; the one numbered `stop_at` does not happen any more."""
    writes: list[Path] = []
    for name in ("atomic_write", "atomic_write_private"):
        original = getattr(common, name)

        def writer(path, content, _original=original):
            if len(writes) == stop_at:
                raise _Killed
            writes.append(path)
            return _original(path, content)

        monkeypatch.setattr(common, name, writer)
    return writes


def test_the_root_env_is_the_last_one_written_and_never_holds_the_template(
    repo, tmp_path, monkeypatch
):
    config = tmp_path / "papaia-config"
    writes = _record_writes(monkeypatch)
    assert _setup(repo, config, *FULL) == 0

    root = writes.index(config / ".env")
    assert writes.count(config / ".env") == 1, "written once, resolved, without a template first"
    modules = [i for i, p in enumerate(writes) if p.name == ".env" and config in p.parents]
    assert root == max(modules)
    revision = writes.index(config / smtp.MODULE_DIR / ".env")
    assert revision < writes.index(smtp.password_path(config)) < root


def test_cut_short_before_the_root_env_the_next_setup_is_still_a_first_one(
    repo, reference, tmp_path, monkeypatch
):
    mail = ["--enable-smtp=true", "--smtp-host=smtp.example.org", "--smtp-from=a@example.org"]
    with monkeypatch.context() as patch:
        writes = _record_writes(patch)
        probe = tmp_path / "probe"
        assert _setup(repo, probe, f"--app-host={APP_HOST}", *mail) == 0
        until_root = writes.index(probe / ".env") + 1

    for stop_at in range(until_root):
        config = tmp_path / f"cut-{stop_at}"
        with monkeypatch.context() as patch:
            _record_writes(patch, stop_at)
            with pytest.raises(_Killed):
                _setup(repo, config, "--app-host=https://typo.example.test", *mail)
        assert not (config / ".env").exists(), stop_at

        assert _setup(repo, config, f"--app-host={APP_HOST}") == 0
        _assert_like_reference(config, reference, repo)
        tree = envtree.load_config_dir_tree(config, repo)
        for (canon_dir, key), aliases in secrets.SECRET_ALIASES.items():
            for alias_dir, alias in aliases:
                assert tree[alias_dir][alias] == tree[canon_dir][key], (stop_at, alias_dir, alias)


@pytest.mark.parametrize("cut", ["password", "root"])
def test_a_password_change_cut_short_still_recreates_the_relay(repo, tmp_path, monkeypatch, cut):
    config = tmp_path / "papaia-config"
    flags = [flag for flag in FULL if flag != "--smtp-no-auth"] + ["--smtp-user=mailer"]
    monkeypatch.setenv("PAPAIA_SMTP_PASSWORD", "old-password")
    assert _setup(repo, config, *flags) == 0
    module = config / smtp.MODULE_DIR / ".env"
    installed = common.parse_env_file(module)[smtp.KEY_PASSWORD_REV]

    stop = smtp.password_path(config) if cut == "password" else config / ".env"
    with monkeypatch.context() as patch:
        for name in ("atomic_write", "atomic_write_private"):
            original = getattr(common, name)

            def writer(path, content, _original=original):
                if path == stop:
                    raise _Killed
                return _original(path, content)

            patch.setattr(common, name, writer)
        patch.setenv("PAPAIA_SMTP_PASSWORD", "new-password")
        with pytest.raises(_Killed):
            _setup(repo, config, *flags)
    between = common.parse_env_file(module)[smtp.KEY_PASSWORD_REV]
    assert between != installed

    monkeypatch.setenv("PAPAIA_SMTP_PASSWORD", "new-password")
    assert _setup(repo, config, *flags) == 0
    assert smtp.read_password(config) == "new-password"
    final = common.parse_env_file(module)[smtp.KEY_PASSWORD_REV]
    # A relay recreated in between read the old password if that write was the one cut off.
    assert (final != between) == (cut == "password")


def test_a_failure_after_the_configuration_is_written_keeps_it(repo, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_project_bundles", lambda config_dir, repo_root: 3)
    config = tmp_path / "papaia-config"
    assert _setup(repo, config, f"--app-host={APP_HOST}") == 3
    root = common.parse_env_file(config / ".env")
    assert root["PAPAIA_VERSION"]
    assert APP_DOMAIN in root["LITELLM_PUBLIC_URL"]


# ─────────────────────────────────────────────────────────────────────────
# a root .env that is no configuration yet
# ─────────────────────────────────────────────────────────────────────────


def _prepared(repo: Path, config: Path, state: str) -> None:
    if state == "template":  # what a refused first setup of an older release left
        envtree.init(config, repo)
    else:
        config.mkdir(parents=True)
        lines = {"workspace": f"PAPAIA_WORKSPACE_DIR={repo.parent}\n", "blank": ""}
        (config / ".env").write_text(lines[state])


@pytest.mark.parametrize("state", ["template", "workspace", "blank"])
def test_a_root_env_without_a_configuration_is_still_a_first_setup(
    repo, reference, tmp_path, state
):
    config = tmp_path / "papaia-config"
    _prepared(repo, config, state)

    assert _setup(repo, config, f"--app-host={APP_HOST}") == 0

    _assert_like_reference(config, reference, repo)
    root, expected = (common.parse_env_file(d / ".env") for d in (config, reference))
    for key in ("COMPOSE_PROFILES", "REVERSE_PROXY_PROVIDER", "PAPAIA_WORKSPACE_DIR"):
        assert root[key] == expected[key], key


@pytest.mark.parametrize("state", ["template", "workspace", "blank"])
def test_the_wizard_prefills_it_like_an_empty_directory(repo, tmp_path, state):
    config = tmp_path / "papaia-config"
    _prepared(repo, config, state)
    empty = defaults.compute_defaults(tmp_path / "empty", repo)

    assert defaults.compute_defaults(config, repo) == empty


def test_a_first_setup_still_needs_the_app_host(repo, tmp_path, capsys):
    config = tmp_path / "papaia-config"
    _prepared(repo, config, "template")
    before = _files(config)

    assert _setup(repo, config) == 3
    assert "--app-host is required" in capsys.readouterr().err
    assert _files(config) == before


def test_the_advice_of_the_native_refusal_leads_to_derived_urls(tmp_path, capsys):
    # Only a checkout named `papaia` lets setup derive the workspace.
    repo = checkout(tmp_path).rename(tmp_path / "papaia-core")
    config = tmp_path / "papaia-config"
    native = [f"--app-host={APP_HOST}", "--enable-local-ai=true", "--localai-runtime=native"]
    assert _setup(repo, config, *native) == 3
    assert "set it in the root .env" in capsys.readouterr().err

    config.mkdir()
    (config / ".env").write_text(f"PAPAIA_WORKSPACE_DIR={tmp_path}\n")
    assert _setup(repo, config, *native) == 0

    root = common.parse_env_file(config / ".env")
    assert root["PAPAIA_WORKSPACE_DIR"] == str(tmp_path)
    for key in ("LITELLM_PUBLIC_URL", "MANAGER_PUBLIC_URL", "NPM_ADMIN_HOST"):
        assert APP_DOMAIN in root[key], key
        assert "host.docker.internal" not in root[key], key
    librechat = common.parse_env_file(config / "ai" / "librechat" / ".env")
    assert librechat["DOMAIN_CLIENT"] == librechat["DOMAIN_SERVER"]
    assert APP_DOMAIN in librechat["DOMAIN_SERVER"]


def test_a_prepared_port_goes_into_the_derived_url(repo, tmp_path):
    config = tmp_path / "papaia-config"
    config.mkdir()
    (config / ".env").write_text("LITELLM_EXT_PORT=9200\n")

    # Only with direct port access does a service URL carry its own port; behind the
    # bundled proxy every service has a host name of its own.
    assert _setup(repo, config, f"--app-host={APP_HOST}", "--allow-direct-port-access") == 0

    root = common.parse_env_file(config / ".env")
    assert root["LITELLM_EXT_PORT"] == "9200"
    assert root["LITELLM_PUBLIC_URL"] == f"{APP_HOST}:9200"


@pytest.mark.parametrize(
    ("rel_dir", "key", "value"),
    [
        ("", "PAPAIA_HOST", "https://chosen.example.net"),
        ("", "LITELLM_PUBLIC_URL", "https://llm.example.net"),
        ("", "MANAGER_PUBLIC_URL", "https://manager.example.net"),
        ("", "NPM_ADMIN_HOST", "https://npm.example.net"),
        ("ai/librechat", "DOMAIN_SERVER", "https://chat.example.net"),
    ],
)
def test_a_choice_in_a_root_env_no_setup_wrote_is_kept(repo, tmp_path, rel_dir, key, value):
    config = tmp_path / "papaia-config"
    envtree.init(config, repo)
    env = config / rel_dir / ".env"
    common.write_env_file(env, {**common.parse_env_file(env), key: value})

    flags = [] if key == "PAPAIA_HOST" else [f"--app-host={APP_HOST}"]
    assert _setup(repo, config, *flags) == 0

    assert common.parse_env_file(env)[key] == value


@pytest.mark.parametrize(
    "lines",
    [
        "PAPAIA_HOST={app}\n",
        "LOCALAI_IMAGE_VARIANT=hipblas\n",
        "COMPOSE_PROFILES=keycloak,nginx,oauth2-proxy,librechat,litellm,localai\n",
    ],
    ids=["app-host", "variant", "profiles"],
)
@pytest.mark.parametrize("template", [False, True], ids=["partial", "copied-template"])
def test_next_to_a_choice_a_template_address_is_still_derived(
    repo, reference, tmp_path, lines, template
):
    config = tmp_path / "papaia-config"
    key, value = lines.format(app=APP_HOST).strip().split("=", 1)
    if template:
        envtree.init(config, repo)
        root = {**common.parse_env_file(config / ".env"), key: value}
        common.write_env_file(config / ".env", root)
    else:
        config.mkdir()
        (config / ".env").write_text(f"{key}={value}\n")

    assert _setup(repo, config, f"--app-host={APP_HOST}") == 0

    for rel_dir, keys in DERIVED.items():
        stored = common.parse_env_file(config / rel_dir / ".env")
        expected = common.parse_env_file(reference / rel_dir / ".env")
        for derived in keys:
            assert stored[derived] == expected[derived], (rel_dir, derived)
    # Compared as a list: setup moves the nginx profile to the end.
    kept = common.parse_env_file(config / ".env")[key]
    assert set(value.split(",")) <= set(kept.split(","))


@pytest.mark.parametrize("template", [False, True], ids=["partial", "copied-template"])
def test_a_switch_to_external_oidc_next_to_a_choice_blanks_no_address(repo, tmp_path, template):
    # Setup does not derive AUTH_HOST for an external provider, so it has to stay.
    flags = [
        f"--app-host={APP_HOST}",
        "--auth-provider=external_oidc",
        "--oidc-issuer=https://idp.example.net/realms/x",
    ]
    empty, config = tmp_path / "empty-config", tmp_path / "papaia-config"
    assert _setup(repo, empty, *flags) == 0
    if template:
        envtree.init(config, repo)
        root = {**common.parse_env_file(config / ".env"), "PAPAIA_HOST": APP_HOST}
        common.write_env_file(config / ".env", root)
    else:
        config.mkdir()
        (config / ".env").write_text(f"PAPAIA_HOST={APP_HOST}\n")

    assert _setup(repo, config, *flags) == 0

    stored, expected = (common.parse_env_file(d / ".env") for d in (config, empty))
    assert stored["AUTH_HOST"] == expected["AUTH_HOST"] != ""
    chat, chat_expected = (
        common.parse_env_file(d / "ai" / "librechat" / ".env") for d in (config, empty)
    )
    assert chat["DOMAIN_SERVER"] == chat_expected["DOMAIN_SERVER"]
    assert APP_DOMAIN in chat["DOMAIN_SERVER"]


def test_a_completed_local_installation_keeps_the_template_addresses(repo, tmp_path):
    config = tmp_path / "papaia-config"
    envtree.init(config, repo)
    root = {**common.parse_env_file(config / ".env"), "PAPAIA_VERSION": "1.9.0"}
    common.write_env_file(config / ".env", root)

    assert _setup(repo, config) == 0

    stored = common.parse_env_file(config / "ai" / "librechat" / ".env")
    assert stored["DOMAIN_SERVER"] == "http://host.docker.internal:8000"


# ─────────────────────────────────────────────────────────────────────────
# through papaia-ctl
# ─────────────────────────────────────────────────────────────────────────

BASH = shutil.which("bash")


@pytest.mark.skipif(BASH is None, reason="bash is not available")
@pytest.mark.parametrize("state", [None, "template", "workspace"])
def test_the_reproduction_through_papaia_ctl(repo, tmp_path, state):
    tools = Path(__file__).resolve().parents[1]
    shutil.copytree(
        tools,
        repo / "tools",
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("tests", "__pycache__", ".venv", ".runtime"),
    )
    config = tmp_path / "cfg"
    if state:
        _prepared(repo, config, state)
    before = _files(config) if state else {}
    base = [
        BASH,
        str(repo / "tools" / "papaia-ctl"),
        "setup",
        "-y",
        f"--config-dir={config}",
        "--host-ip=127.0.0.1",
        f"--app-host={APP_HOST}",
    ]
    refused = subprocess.run(
        [*base, "--smtp"], capture_output=True, text=True, timeout=180, check=False
    )
    assert refused.returncode == 3, refused.stderr
    assert "--smtp-host is required" in refused.stderr
    if state:
        assert _files(config) == before
    else:
        assert not config.exists()

    done = subprocess.run(base, capture_output=True, text=True, timeout=180, check=False)
    assert done.returncode == 0, done.stderr
    root = common.parse_env_file(config / ".env")
    for key in DERIVED[""]:
        assert APP_DOMAIN in root[key], (key, root[key])
        assert "host.docker.internal" not in root[key], (key, root[key])
    librechat = common.parse_env_file(config / "ai" / "librechat" / ".env")
    assert APP_DOMAIN in librechat["DOMAIN_CLIENT"]
