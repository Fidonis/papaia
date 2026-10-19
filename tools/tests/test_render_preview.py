"""The preview of a draft overlay, and the way a layer that does not parse is reported.

The preview shares its merge with `render`, so the first group of tests pins that the two cannot
disagree: what `preview` says a target renders to is what `render` writes. The rest is what the
papaia-manager's overlay editor relies on: nothing is written, a draft that does not parse is an
answer with a position, and the command prints a JSON document whose keys are a contract.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml
from test_render_core import (
    FIXTURES_DIR,
    _install_rag_fragment,
    _set_profiles,
    _setup_minimal,
)

from lib import cli, render_core

LIBRECHAT = "ai/librechat/librechat.yaml"
SEARXNG = "services/searxng/settings.yml"
KEYCLOAK_CONF = "infra/keycloak/keycloak.conf"

DRAFT = (
    "mcpSettings:\n  allowedDomains:\n    - http://customer.example:9000\n"
    "endpoints:\n  custom: []\n"
)


def _file_targets(repo_root: Path) -> list[str]:
    return [t for t in render_core.BASE_RENDER_TARGETS if (repo_root / "src" / t).is_file()]


def _overlay(config_dir: Path, rel: str, text: str) -> Path:
    path = config_dir / "overlay" / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _addon(repo_root: Path, config_dir: Path) -> None:
    shutil.copytree(
        FIXTURES_DIR / "addon-paperless", repo_root / "addons" / "papaia-addon-paperless"
    )
    path = config_dir / "deployment.yaml"
    manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
    manifest["addons"] = [
        {
            "name": "paperless",
            "path": "addons/papaia-addon-paperless",
            "version": "1.0.0",
            "active": True,
        }
    ]
    path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")


def _snapshot(*roots: Path) -> dict[str, tuple[bytes, int]]:
    found: dict[str, tuple[bytes, int]] = {}
    for root in roots:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                found[str(path)] = (path.read_bytes(), path.stat().st_mtime_ns)
    return found


# -- the preview cannot disagree with the render ---------------------------------------------


@pytest.mark.parametrize("scenario", ["bare", "overlay", "rag-fragment", "addon-fragment"])
def test_the_current_text_is_what_render_writes_for_every_file_target(
    repo_root: Path, config_dir: Path, scenario: str
) -> None:
    if scenario == "rag-fragment":
        _install_rag_fragment(repo_root)
    _setup_minimal(repo_root, config_dir)
    if scenario in ("overlay", "rag-fragment"):
        _overlay(config_dir, LIBRECHAT, DRAFT)
        _overlay(config_dir, SEARXNG, "general:\n  instance_name: Ours\n")
        _overlay(config_dir, KEYCLOAK_CONF, "# replaced as a whole\n")
    if scenario == "rag-fragment":
        _set_profiles(config_dir, "librechat,rag")
    if scenario == "addon-fragment":
        _addon(repo_root, config_dir)

    render_core.render(config_dir, repo_root)

    targets = _file_targets(repo_root)
    assert LIBRECHAT in targets and SEARXNG in targets and KEYCLOAK_CONF in targets
    for target in targets:
        result = render_core.preview(config_dir, repo_root, target, None)
        assert result["current"].encode() == (config_dir / target).read_bytes(), target


def test_a_draft_previews_to_exactly_what_it_renders_to_once_it_is_the_overlay(
    repo_root: Path, config_dir: Path
) -> None:
    _install_rag_fragment(repo_root)
    _setup_minimal(repo_root, config_dir)
    _set_profiles(config_dir, "librechat,rag")

    for target, draft in (
        (LIBRECHAT, DRAFT),
        (SEARXNG, "general:\n  instance_name: Ours\nsearch:\n  default_lang: de\n"),
        (KEYCLOAK_CONF, "# replaced as a whole\n"),
    ):
        shown = render_core.preview(config_dir, repo_root, target, draft)["preview"]
        _overlay(config_dir, target, draft)
        render_core.render(config_dir, repo_root)
        assert (config_dir / target).read_text(encoding="utf-8") == shown, target


def test_no_overlay_and_an_empty_overlay_both_leave_the_base_alone(
    repo_root: Path, config_dir: Path
) -> None:
    _setup_minimal(repo_root, config_dir)
    base = render_core.preview(config_dir, repo_root, LIBRECHAT, None)
    assert render_core.preview(config_dir, repo_root, LIBRECHAT, "")["preview"] == base["preview"]
    assert (
        render_core.preview(config_dir, repo_root, LIBRECHAT, "# only a comment\n")["preview"]
        == base["preview"]
    )
    assert base["changed"] is False


def test_a_draft_is_compared_with_the_overlay_on_disk_not_with_nothing(
    repo_root: Path, config_dir: Path
) -> None:
    _setup_minimal(repo_root, config_dir)
    _overlay(config_dir, SEARXNG, "general:\n  instance_name: On disk\n")
    result = render_core.preview(
        config_dir, repo_root, SEARXNG, "general:\n  instance_name: Draft\n"
    )
    assert "On disk" in result["current"] and "Draft" not in result["current"]
    assert "Draft" in result["preview"] and "On disk" not in result["preview"]
    assert result["changed"] is True
    # `None` drops the overlay on disk from the preview.
    dropped = render_core.preview(config_dir, repo_root, SEARXNG, None)
    assert "On disk" not in dropped["preview"]


def test_lists_are_appended_and_scalars_replaced_as_in_a_render(
    repo_root: Path, config_dir: Path
) -> None:
    _setup_minimal(repo_root, config_dir)
    base = yaml.safe_load(render_core.preview(config_dir, repo_root, LIBRECHAT, None)["preview"])
    shown = yaml.safe_load(render_core.preview(config_dir, repo_root, LIBRECHAT, DRAFT)["preview"])
    domains = shown["mcpSettings"]["allowedDomains"]
    assert (
        domains[: len(base["mcpSettings"]["allowedDomains"])]
        == base["mcpSettings"]["allowedDomains"]
    )
    assert domains[-1] == "http://customer.example:9000"
    again = render_core.preview(config_dir, repo_root, LIBRECHAT, DRAFT)["preview"]
    assert (
        yaml.safe_load(again)["mcpSettings"]["allowedDomains"].count("http://customer.example:9000")
        == 1
    )


def test_a_text_target_is_replaced_as_a_whole(repo_root: Path, config_dir: Path) -> None:
    _setup_minimal(repo_root, config_dir)
    result = render_core.preview(config_dir, repo_root, KEYCLOAK_CONF, "# mine\n")
    assert result["structured"] is False
    assert result["preview"] == "# mine\n"
    assert render_core.preview(config_dir, repo_root, LIBRECHAT, None)["structured"] is True


# -- nothing is written ------------------------------------------------------------------------


def test_a_preview_changes_nothing_in_the_configuration_or_the_checkout(
    repo_root: Path, config_dir: Path
) -> None:
    _setup_minimal(repo_root, config_dir)
    _overlay(config_dir, LIBRECHAT, DRAFT)
    render_core.render(config_dir, repo_root)
    before = _snapshot(config_dir, repo_root)

    for target in _file_targets(repo_root):
        render_core.preview(
            config_dir, repo_root, target, "a: 1\n" if target.endswith("yml") else "# x\n"
        )
    with pytest.raises(render_core.RenderError):
        render_core.preview(config_dir, repo_root, LIBRECHAT, "a: [\n")

    assert _snapshot(config_dir, repo_root) == before


# -- what is refused ---------------------------------------------------------------------------


def test_a_draft_with_a_syntax_error_names_the_overlay_and_the_line(
    repo_root: Path, config_dir: Path
) -> None:
    _setup_minimal(repo_root, config_dir)
    with pytest.raises(render_core.RenderError) as caught:
        render_core.preview(config_dir, repo_root, LIBRECHAT, "a: 1\nb: [\n")
    error = caught.value
    assert str(error).startswith(f"overlay/{LIBRECHAT}: invalid YAML at line ")
    assert error.line is not None and error.line >= 2
    assert error.column is not None


@pytest.mark.parametrize("draft", ["- a\n- b\n", "just text\n", "42\n"])
def test_a_draft_that_is_not_a_mapping_would_replace_the_whole_file_so_it_is_refused(
    repo_root: Path, config_dir: Path, draft: str
) -> None:
    _setup_minimal(repo_root, config_dir)
    with pytest.raises(render_core.RenderError, match="top level must be a mapping"):
        render_core.preview(config_dir, repo_root, LIBRECHAT, draft)


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("ai/librechat/other.yaml", "not a render target"),
        ("../etc/passwd", "not a render target"),
        ("ai/localai/models", "is a directory"),
        ("ai/localai/models/stub.yaml", "not a render target"),
    ],
)
def test_only_the_file_targets_of_the_render_list_are_previewed(
    repo_root: Path, config_dir: Path, target: str, message: str
) -> None:
    _setup_minimal(repo_root, config_dir)
    with pytest.raises(render_core.RenderError, match=message):
        render_core.preview(config_dir, repo_root, target, "a: 1\n")


def test_a_target_the_repository_does_not_have_is_refused(
    repo_root: Path, config_dir: Path
) -> None:
    _setup_minimal(repo_root, config_dir)
    (repo_root / "src" / SEARXNG).unlink()
    with pytest.raises(render_core.RenderError, match="no such file"):
        render_core.preview(config_dir, repo_root, SEARXNG, "a: 1\n")


def test_json_that_does_not_parse_is_reported_with_its_position() -> None:
    with pytest.raises(render_core.RenderError) as caught:
        render_core._parse_structured(".json", '{"a": 1,\n "b": }', "overlay/x.json")
    assert str(caught.value).startswith("overlay/x.json: invalid JSON at line 2")
    assert (caught.value.line, caught.value.column) == (2, 7)


# -- a broken layer on disk ---------------------------------------------------------------------


def test_render_with_a_broken_overlay_says_which_file_and_where(
    repo_root: Path, config_dir: Path
) -> None:
    _setup_minimal(repo_root, config_dir)
    _overlay(config_dir, LIBRECHAT, "ok: 1\nbroken: [\n")
    with pytest.raises(render_core.RenderError, match=f"overlay/{LIBRECHAT}: invalid YAML at line"):
        render_core.render(config_dir, repo_root)


def test_the_command_prints_one_error_line_and_exits_3_for_a_broken_overlay(
    repo_root: Path, config_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _setup_minimal(repo_root, config_dir)
    _overlay(config_dir, LIBRECHAT, "ok: 1\nbroken: [\n")

    code = cli.main(["--repo-root", str(repo_root), "--config-dir", str(config_dir), "render"])

    err = capsys.readouterr().err.strip().splitlines()
    assert code == 3
    assert len(err) == 1
    assert err[0].startswith(f"ERROR: overlay/{LIBRECHAT}: invalid YAML at line ")
    assert "Traceback" not in err[0]


def test_a_broken_overlay_does_not_stop_an_unrelated_layer_from_being_named(
    repo_root: Path, config_dir: Path
) -> None:
    """The first layer that fails is the one reported, and it is named: the base is `src/...`."""
    _setup_minimal(repo_root, config_dir)
    (repo_root / "src" / SEARXNG).write_text("a: [\n", encoding="utf-8")
    with pytest.raises(render_core.RenderError, match=f"^src/{SEARXNG}: invalid YAML"):
        render_core.render(config_dir, repo_root)


# -- the command ------------------------------------------------------------------------------


def _preview_command(
    repo_root: Path, config_dir: Path, tmp_path: Path, target: str, draft: str | None
) -> int:
    flags = ["--target", target, "--overlay-file", str(tmp_path / "draft.tmp")]
    if draft is not None:
        (tmp_path / "draft.tmp").write_text(draft, encoding="utf-8")
    args = [
        "--repo-root",
        str(repo_root),
        "--config-dir",
        str(config_dir),
        "render-preview",
        *flags,
    ]
    return cli.main(args)


def test_the_command_prints_the_documented_json(
    repo_root: Path, config_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _setup_minimal(repo_root, config_dir)
    code = _preview_command(
        repo_root, config_dir, tmp_path, SEARXNG, "search:\n  default_lang: de\n"
    )
    out = capsys.readouterr().out
    assert code == 0
    document = json.loads(out)
    assert sorted(document) == ["changed", "current", "ok", "preview", "structured", "target"]
    assert document["ok"] is True and document["changed"] is True
    assert document["target"] == SEARXNG and document["structured"] is True
    assert "default_lang: de" in document["preview"]
    assert out.count("\n") == 1, "exactly one document on stdout"


def test_a_draft_that_does_not_parse_is_an_answer_not_a_failure(
    repo_root: Path, config_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _setup_minimal(repo_root, config_dir)
    code = _preview_command(repo_root, config_dir, tmp_path, SEARXNG, "a: 1\nb: [\n")
    document = json.loads(capsys.readouterr().out)
    assert code == 0
    assert sorted(document) == ["column", "error", "line", "ok"]
    assert document["ok"] is False
    assert document["error"].startswith(f"overlay/{SEARXNG}: invalid YAML at line ")
    assert isinstance(document["line"], int) and isinstance(document["column"], int)


def test_a_draft_that_is_not_a_mapping_has_no_column_to_point_at(
    repo_root: Path, config_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _setup_minimal(repo_root, config_dir)
    _preview_command(repo_root, config_dir, tmp_path, SEARXNG, "- a\n")
    document = json.loads(capsys.readouterr().out)
    assert document["ok"] is False and "mapping" in document["error"]


def test_the_command_writes_nothing(repo_root: Path, config_dir: Path, tmp_path: Path) -> None:
    _setup_minimal(repo_root, config_dir)
    render_core.render(config_dir, repo_root)
    before = _snapshot(config_dir, repo_root)
    _preview_command(repo_root, config_dir, tmp_path, LIBRECHAT, DRAFT)
    assert _snapshot(config_dir, repo_root) == before


@pytest.mark.parametrize("target", ["nope.yaml", "ai/localai/models", "../x"])
def test_a_target_that_is_not_a_file_of_the_render_is_a_usage_error(
    repo_root: Path,
    config_dir: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    target: str,
) -> None:
    _setup_minimal(repo_root, config_dir)
    code = _preview_command(repo_root, config_dir, tmp_path, target, "a: 1\n")
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert captured.err.startswith("ERROR: ")


def test_a_draft_file_that_is_not_there_is_a_usage_error(
    repo_root: Path, config_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _setup_minimal(repo_root, config_dir)
    code = _preview_command(repo_root, config_dir, tmp_path, SEARXNG, None)
    assert code == 2
    assert "cannot read" in capsys.readouterr().err
