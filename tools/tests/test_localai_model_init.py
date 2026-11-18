"""The `localai-model-init` job against a temporary models directory.

The script is taken from the compose file as compose hands it to `sh -c` (`$$` is a
literal `$`), with its fixed paths moved into a temporary directory and a fake `curl` on
the PATH, so the copy, the download and the removal of model YAMLs that are no longer
rendered can be checked over several runs. The same script fills the `localai-models`
volume and, for the native runtime, the bind-mounted models directory of the host.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "src" / "ai" / "localai" / "docker-compose.yml"
RECORD = ".papaia-model-configs"

_FAKE_CURL = """#!/bin/sh
# Writes the URL into the file named by -o, as a stand-in for the download.
out=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\\n' "$url" > "$out"
"""


def _script(root: Path) -> str:
    service = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"][
        "localai-model-init"
    ]
    assert service["entrypoint"] == "sh"
    assert service["command"][0] == "-c"
    script = service["command"][1].replace("$$", "$")
    script = script.replace("/models-config/", "\0CONFIG\0")
    script = script.replace("/models/", f"{root}/models/")
    return script.replace("\0CONFIG\0", f"{root}/models-config/")


def _run(root: Path) -> str:
    bin_dir = root / "bin"
    bin_dir.mkdir(exist_ok=True)
    curl = bin_dir / "curl"
    curl.write_text(_FAKE_CURL, encoding="utf-8")
    curl.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    result = subprocess.run(
        ["sh", "-c", _script(root)],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
        env=env,
    )
    return result.stdout + result.stderr


def _rendered(root: Path, models: dict[str, str], urls: str = "") -> None:
    configs = root / "models-config" / "configs"
    configs.mkdir(parents=True, exist_ok=True)
    for path in configs.iterdir():
        path.unlink()
    for name, text in models.items():
        (configs / name).write_text(text, encoding="utf-8")
    (root / "models-config" / "models.txt").write_text(urls, encoding="utf-8")


def _volume(root: Path) -> Path:
    path = root / "models"
    path.mkdir(exist_ok=True)
    return path


def test_the_rendered_yamls_are_copied_and_the_models_downloaded(tmp_path):
    volume = _volume(tmp_path)
    _rendered(tmp_path, {"a.yaml": "name: a\n"}, "# comment\nhttps://example.org/x/a.gguf\n")
    _run(tmp_path)
    assert (volume / "a.yaml").read_text() == "name: a\n"
    assert (volume / "a.gguf").read_text() == "https://example.org/x/a.gguf\n"
    assert not (volume / "a.gguf.part").exists()


def test_a_yaml_that_is_no_longer_rendered_is_removed(tmp_path):
    volume = _volume(tmp_path)
    _rendered(
        tmp_path,
        {"shipped.yaml": "name: shipped\n", "own.yaml": "name: own\n"},
        "https://example.org/x/own.gguf\n",
    )
    _run(tmp_path)
    assert (volume / "own.yaml").is_file()

    _rendered(tmp_path, {"shipped.yaml": "name: shipped\n"})
    log = _run(tmp_path)

    assert not (volume / "own.yaml").exists()
    assert "removed own.yaml" in log
    assert (volume / "shipped.yaml").read_text() == "name: shipped\n"
    # The weights are never the job's to delete.
    assert (volume / "own.gguf").is_file()
    assert (volume / RECORD).read_text() == "shipped.yaml\n"


def test_yamls_the_job_did_not_install_are_kept(tmp_path):
    """LocalAI writes YAMLs of its own (a model installed from its gallery); only what an
    earlier run recorded is removed."""
    volume = _volume(tmp_path)
    (volume / "gallery.yaml").write_text("name: gallery\n", encoding="utf-8")
    (volume / "weights.bin").write_text("x", encoding="utf-8")
    _rendered(tmp_path, {"a.yaml": "name: a\n"})
    _run(tmp_path)
    _rendered(tmp_path, {})
    _run(tmp_path)

    assert not (volume / "a.yaml").exists()
    assert (volume / "gallery.yaml").is_file()
    assert (volume / "weights.bin").is_file()
    assert (volume / RECORD).read_text() == ""


def test_the_record_never_reaches_beyond_the_model_yamls(tmp_path):
    """A record that names a model file, a path or a dotfile removes nothing."""
    volume = _volume(tmp_path)
    outside = tmp_path / "outside.yaml"
    outside.write_text("x", encoding="utf-8")
    for name in ("m.gguf", ".hidden.yaml"):
        (volume / name).write_text("x", encoding="utf-8")
    (volume / RECORD).write_text(
        f"m.gguf\n.hidden.yaml\n../outside.yaml\n{outside}\n\n", encoding="utf-8"
    )
    _rendered(tmp_path, {})
    _run(tmp_path)

    assert (volume / "m.gguf").is_file()
    assert (volume / ".hidden.yaml").is_file()
    assert outside.is_file()


def test_a_rerun_with_the_same_set_changes_nothing(tmp_path):
    volume = _volume(tmp_path)
    _rendered(tmp_path, {"a.yaml": "name: a\n", "b.yaml": "name: b\n"})
    _run(tmp_path)
    log = _run(tmp_path)

    assert "removed" not in log
    assert sorted(p.name for p in volume.iterdir()) == [RECORD, "a.yaml", "b.yaml"]
    assert (volume / RECORD).read_text() == "a.yaml\nb.yaml\n"
