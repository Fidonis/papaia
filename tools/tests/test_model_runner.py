"""Docker Model Runner: the model list, detection and model removal (lib/model_runner.py)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from lib import model_runner

REAL_REPO = Path(__file__).resolve().parents[2]


# -- model list ---------------------------------------------------------------------------


def test_the_shipped_list_has_a_chat_model_and_the_embedding_alias_rag_expects() -> None:
    text = (REAL_REPO / "src" / model_runner.MODELS_FILE).read_text(encoding="utf-8")
    parsed = model_runner.parse_models(text)
    assert parsed.errors == []
    aliases = {m.alias for m in parsed.models}
    assert "nomic-embed-text" in aliases
    rag_env = (REAL_REPO / "src" / "ai" / "librechat" / ".env.example").read_text()
    assert "RAG_EMBEDDINGS_MODEL=nomic-embed-text" in rag_env
    # Only GGUF models by default: they run without the vllm engine.
    assert not any(m.is_mlx for m in parsed.models)


def test_comments_blank_lines_and_aliases() -> None:
    parsed = model_runner.parse_models(
        "# comment\n\n  ai/qwen3:4b  chat\nhf.co/mlx-community/Qwen3-4B-4bit\n   # indented\n"
    )
    assert parsed.errors == []
    assert [(m.reference, m.alias) for m in parsed.models] == [
        ("ai/qwen3:4b", "chat"),
        ("hf.co/mlx-community/Qwen3-4B-4bit", "Qwen3-4B-4bit"),
    ]


def test_a_reference_with_shell_or_url_characters_is_reported_and_left_out() -> None:
    parsed = model_runner.parse_models('ai/x;rm -rf /\nai/y"z\nai/ok\n')
    assert [m.reference for m in parsed.models] == ["ai/ok"]
    assert len(parsed.errors) == 2
    assert parsed.errors[0].startswith("line 1:")


def test_a_repeated_alias_is_reported() -> None:
    parsed = model_runner.parse_models("ai/a:1 chat\nai/b:1 chat\n")
    assert [m.reference for m in parsed.models] == ["ai/a:1"]
    assert parsed.errors == ["line 2: the name 'chat' is already used on line 1"]


def test_more_than_an_alias_on_a_line_is_reported_but_the_model_kept() -> None:
    parsed = model_runner.parse_models("ai/a:1 chat extra\n")
    assert [m.alias for m in parsed.models] == ["chat"]
    assert "only a reference and an alias" in parsed.errors[0]


@pytest.mark.parametrize(
    ("reference", "mlx"),
    [
        ("ai/qwen3:4b-instruct-2507-q4_K_M", False),
        ("ai/qwen3:4b-instruct-2507-mlx-4bit", True),
        ("hf.co/mlx-community/Qwen3-4B-Instruct-2507-4bit", True),
        ("hf.co/bartowski/Qwen3-4B-GGUF", False),
    ],
)
def test_mlx_models_are_recognised(reference: str, mlx: bool) -> None:
    assert model_runner.Model(reference, "x").is_mlx is mlx


@pytest.mark.parametrize(
    ("reference", "listed"),
    [
        # As the runner lists them (checked against Docker Desktop 4.95, ADR 0011).
        ("ai/smollm2:360M-Q4_K_M", "docker.io/ai/smollm2:360M-Q4_K_M"),
        ("ai/nomic-embed-text-v1.5", "docker.io/ai/nomic-embed-text-v1.5:latest"),
        (
            "hf.co/mlx-community/Qwen2.5-0.5B-Instruct-4bit",
            "huggingface.co/mlx-community/qwen2.5-0.5b-instruct-4bit:latest",
        ),
        ("registry.example.org/team/model:1", "registry.example.org/team/model:1"),
    ],
)
def test_references_are_normalised_the_way_the_runner_lists_them(
    reference: str, listed: str
) -> None:
    assert model_runner.normalise(reference) == listed


def test_a_model_path_keeps_its_slashes() -> None:
    assert model_runner.model_path("hf.co/org/repo:tag") == "/models/hf.co/org/repo:tag"


# -- detection ----------------------------------------------------------------------------

_STATUS_RUNNING = json.dumps(
    {
        "running": True,
        "backends": {
            "llama.cpp": "Running: llama.cpp b9879-metal",
            "mlx": "Not Installed: package not installed",
            "vllm": "Running: vllm-metal v0.2.0",
            "diffusers": "Not Installed",
        },
        "kind": "Docker Desktop",
    }
)


class _Probe:
    """Answers the two commands `detect` runs."""

    def __init__(self, platform_name: str | None, status: str | None, status_rc: int = 0):
        self.platform_name = platform_name
        self.status = status
        self.status_rc = status_rc
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], timeout: float = 10.0):
        self.calls.append(argv)
        if argv[:2] == ["docker", "version"]:
            if self.platform_name is None:
                return None
            return subprocess.CompletedProcess(argv, 0, self.platform_name + "\n", "")
        if argv[:3] == ["docker", "model", "status"]:
            if self.status is None:
                return None
            return subprocess.CompletedProcess(argv, self.status_rc, self.status, "")
        raise AssertionError(argv)


@pytest.mark.parametrize(("system", "machine"), [("Linux", "x86_64"), ("Linux", "aarch64")])
def test_linux_is_not_offered_and_docker_is_not_asked(system: str, machine: str) -> None:
    probe = _Probe("Docker Engine - Community", _STATUS_RUNNING)
    found = model_runner.detect(system=system, machine=machine, run=probe)
    assert not found.available
    assert probe.calls == []


def test_an_intel_mac_is_not_offered() -> None:
    probe = _Probe("Docker Desktop 4.95.0 (242831)", _STATUS_RUNNING)
    found = model_runner.detect(system="Darwin", machine="x86_64", run=probe)
    assert not found.available
    assert "Apple Silicon" in found.label
    assert probe.calls == []


def test_apple_silicon_without_docker_desktop() -> None:
    found = model_runner.detect(system="Darwin", machine="arm64", run=_Probe(None, None))
    assert not found.available
    assert "Docker Desktop not found" in found.label


def test_apple_silicon_without_the_model_plugin() -> None:
    probe = _Probe("Docker Desktop 4.95.0 (242831)", None)
    found = model_runner.detect(system="Darwin", machine="arm64", run=probe)
    assert not found.available
    assert found.desktop_version == "4.95.0"
    assert "Settings > AI" in found.label


def test_a_switched_off_runner_names_the_setting() -> None:
    status = json.dumps({"running": False, "backends": {}})
    found = model_runner.detect(
        system="Darwin", machine="arm64", run=_Probe("Docker Desktop 4.95.0", status, 1)
    )
    assert not found.available
    assert "switched off" in found.label and "Settings > AI" in found.label


def test_a_running_runner_lists_its_engines() -> None:
    found = model_runner.detect(
        system="Darwin", machine="arm64", run=_Probe("Docker Desktop 4.95.0", _STATUS_RUNNING)
    )
    assert found.available
    assert found.running_engines == ["llama.cpp", "vllm"]
    assert found.warning == ""
    assert model_runner.detection_vars(found) == {
        "MODEL_RUNNER_AVAILABLE": "true",
        "MODEL_RUNNER_LABEL": "Docker Desktop 4.95.0, engines: llama.cpp, vllm",
        "MODEL_RUNNER_WARN": "",
        "MODEL_RUNNER_DESKTOP_VERSION": "4.95.0",
        "MODEL_RUNNER_ENGINES": "llama.cpp,vllm",
    }


def test_without_vllm_the_wizard_says_how_to_install_it() -> None:
    status = json.dumps({"running": True, "backends": {"llama.cpp": "Running: b1"}})
    found = model_runner.detect(
        system="Darwin", machine="arm64", run=_Probe("Docker Desktop 4.95.0", status)
    )
    assert found.available
    assert "install-runner --backend vllm" in found.warning


def test_an_old_docker_desktop_is_told_mlx_needs_4_62() -> None:
    status = json.dumps({"running": True, "backends": {"llama.cpp": "Running: b1"}})
    found = model_runner.detect(
        system="Darwin", machine="arm64", run=_Probe("Docker Desktop 4.40.0 (1)", status)
    )
    assert found.available
    assert "4.62" in found.warning


def test_unreadable_status_counts_as_not_running() -> None:
    assert model_runner.parse_status("Docker Model Runner is running") == (False, {})
    assert model_runner.parse_status("[]") == (False, {})


# -- removing a model ---------------------------------------------------------------------


def _request(status: int, body: str = ""):
    calls: list[tuple[str, str]] = []

    def request(method: str, path: str, **_kwargs):
        calls.append((method, path))
        return status, body

    request.calls = calls  # type: ignore[attr-defined]
    return request


def test_in_a_container_a_model_is_removed_through_the_api() -> None:
    request = _request(200)
    assert model_runner.remove_model("hf.co/org/repo", in_container=True, request=request)
    assert request.calls == [("DELETE", "/models/hf.co/org/repo")]


def test_in_a_container_a_missing_model_is_not_an_error() -> None:
    assert not model_runner.remove_model("ai/x", in_container=True, request=_request(404))


def test_in_a_container_a_refusal_is_an_error() -> None:
    with pytest.raises(model_runner.RunnerError, match="busy"):
        model_runner.remove_model("ai/x", in_container=True, request=_request(500, "busy"))


def _cli(rc: int, out: str = "", err: str = ""):
    calls: list[list[str]] = []

    def run(argv: list[str], timeout: float = 10.0):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, rc, out, err)

    run.calls = calls  # type: ignore[attr-defined]
    return run


def test_on_the_host_a_model_is_removed_with_the_cli() -> None:
    run = _cli(0, "Untagged: ai/x\n")
    assert model_runner.remove_model("ai/x", in_container=False, run=run)
    assert run.calls == [["docker", "model", "rm", "ai/x"]]


def test_on_the_host_a_missing_model_is_not_an_error() -> None:
    run = _cli(1, err="Failed to remove model: no such model: ai/x\n")
    assert not model_runner.remove_model("ai/x", in_container=False, run=run)


def test_on_the_host_without_the_plugin_is_an_error() -> None:
    with pytest.raises(model_runner.RunnerError, match="did not answer"):
        model_runner.remove_model("ai/x", in_container=False, run=lambda argv, timeout: None)
