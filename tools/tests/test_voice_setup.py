"""The `voice` choice in `papaia-ctl setup`: the profile toggle, its sticky
default, the secret fan-out to LiteLLM, and the CLI path from the flag to the
stored environment."""

from __future__ import annotations

import pytest

from lib import cli, common, defaults, envtree, resolve


def _args(repo_root, **kwargs) -> resolve.SetupArgs:
    kwargs.setdefault("non_interactive", True)
    return resolve.SetupArgs(config_dir=repo_root, **kwargs)


def _tree(repo_root, host="https://papaia.example.com") -> dict:
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["PAPAIA_HOST"] = host
    return tree


def test_enabling_adds_the_profile_once_and_keeps_the_others(repo_root):
    tree = _tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,librechat,manager"

    tree = resolve.resolve_voice(tree, _args(repo_root, enable_voice=True))
    tree = resolve.resolve_voice(tree, _args(repo_root, enable_voice=True))

    assert tree[""]["COMPOSE_PROFILES"] == "keycloak,librechat,manager,voice"


def test_disabling_removes_only_the_profile(repo_root):
    tree = _tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,voice,librechat"

    tree = resolve.resolve_voice(tree, _args(repo_root, enable_voice=False))

    assert tree[""]["COMPOSE_PROFILES"] == "keycloak,librechat"


@pytest.mark.parametrize("profiles", ["keycloak,librechat", "keycloak,voice,librechat"])
def test_no_flag_leaves_the_profiles_alone(repo_root, profiles):
    tree = _tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = profiles

    tree = resolve.resolve_voice(tree, _args(repo_root))

    assert tree[""]["COMPOSE_PROFILES"] == profiles


def test_defaults_report_the_stored_choice_for_the_wizard(repo_root, config_dir):
    envtree.init(config_dir, repo_root, env_name="papaia")
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    tree[""]["COMPOSE_PROFILES"] = "keycloak,librechat,voice"
    envtree.persist_tree(tree, config_dir, repo_root)

    assert defaults.compute_defaults(config_dir, repo_root)["VOICE_STICKY"] == "true"


def test_defaults_are_empty_before_the_config_dir_exists(repo_root, config_dir):
    assert defaults.compute_defaults(config_dir, repo_root)["VOICE_STICKY"] == ""


def _setup(repo_root, config_dir, *flags: str) -> int:
    return cli.main(
        [
            "--repo-root",
            str(repo_root),
            "--config-dir",
            str(config_dir),
            "setup",
            "--app-host=https://papaia.example.com",
            *flags,
        ]
    )


def _stored(config_dir, relative: str = "") -> dict[str, str]:
    path = config_dir / relative / ".env" if relative else config_dir / ".env"
    return common.parse_env_file(path)


def test_setup_flag_reaches_the_stored_environment(repo_root, config_dir):
    assert _setup(repo_root, config_dir, "--enable-voice=true") == 0

    assert "voice" in _stored(config_dir)["COMPOSE_PROFILES"].split(",")


def test_setup_without_a_voice_flag_leaves_the_profile_off(repo_root, config_dir):
    assert _setup(repo_root, config_dir) == 0

    assert "voice" not in _stored(config_dir)["COMPOSE_PROFILES"].split(",")


def test_the_engine_key_is_generated_and_fanned_out_to_litellm(repo_root, config_dir):
    assert _setup(repo_root, config_dir, "--enable-voice=true") == 0

    canonical = _stored(config_dir, "ai/voice")["VOICE_API_KEY"]
    assert canonical and not canonical.startswith("GENERATE_")
    assert _stored(config_dir, "ai/litellm")["VOICE_API_KEY"] == canonical


def test_voice_variant_is_sticky_until_a_new_choice(repo_root):
    tree = _tree(repo_root)

    tree = resolve.resolve_voice_variant(tree, _args(repo_root, voice_variant="nvidia"))
    assert tree[""]["VOICE_TTS_IMAGE_VARIANT"] == "nvidia"

    # None = no flag given: the stored choice survives the re-run.
    tree = resolve.resolve_voice_variant(tree, _args(repo_root))
    assert tree[""]["VOICE_TTS_IMAGE_VARIANT"] == "nvidia"

    tree = resolve.resolve_voice_variant(tree, _args(repo_root, voice_variant="cpu"))
    assert tree[""]["VOICE_TTS_IMAGE_VARIANT"] == "cpu"


def test_setup_voice_variant_writes_the_override_and_cpu_removes_it(repo_root, config_dir):
    override = config_dir / "overrides" / "docker-compose.voice-gpu.override.yml"

    assert _setup(repo_root, config_dir, "--enable-voice=true", "--voice-variant=nvidia") == 0
    assert _stored(config_dir)["VOICE_TTS_IMAGE_VARIANT"] == "nvidia"
    assert override.is_file()

    # A re-run without the flag keeps both the stored variant and the override.
    assert _setup(repo_root, config_dir) == 0
    assert _stored(config_dir)["VOICE_TTS_IMAGE_VARIANT"] == "nvidia"
    assert override.is_file()

    assert _setup(repo_root, config_dir, "--voice-variant=cpu") == 0
    assert not override.exists()


def test_the_override_only_materializes_while_voice_is_active(repo_root, config_dir):
    override = config_dir / "overrides" / "docker-compose.voice-gpu.override.yml"

    # A host that does not run the engine stores the choice but gets no
    # override: nothing may feed an accelerator fragment to compose here.
    assert _setup(repo_root, config_dir, "--voice-variant=nvidia") == 0
    assert _stored(config_dir)["VOICE_TTS_IMAGE_VARIANT"] == "nvidia"
    assert not override.exists()

    # Enabling the profile later materializes the stored choice ...
    assert _setup(repo_root, config_dir, "--enable-voice=true") == 0
    assert override.is_file()

    # ... and disabling it cleans the override up again.
    assert _setup(repo_root, config_dir, "--enable-voice=false") == 0
    assert not override.exists()


def test_defaults_report_the_stored_variant_for_the_wizard(repo_root, config_dir):
    assert _setup(repo_root, config_dir, "--enable-voice=true", "--voice-variant=hipblas") == 0

    assert defaults.compute_defaults(config_dir, repo_root)["VOICE_VARIANT_STICKY"] == "hipblas"


def test_the_template_seed_is_not_reported_as_a_sticky_choice(repo_root, config_dir):
    # Every install materializes VOICE_TTS_IMAGE_VARIANT=cpu from the template.
    # While voice is off that is a seed, not a choice — reporting it as sticky
    # would keep the variant prompt from defaulting to the detection
    # recommendation on the run that first enables voice.
    assert _setup(repo_root, config_dir) == 0

    assert _stored(config_dir)["VOICE_TTS_IMAGE_VARIANT"] == "cpu"
    assert defaults.compute_defaults(config_dir, repo_root)["VOICE_VARIANT_STICKY"] == ""
