"""Keeps the repository root limited to the published project documents.

The root of the checkout is the first thing a reader of the public repository
sees. Only the documents below belong there; long-form documentation lives
under docs/. Any other Markdown file at the root fails this check, so a stray
note cannot reach a release unnoticed. Adding a document to the root is a
deliberate change of ALLOWED_ROOT_DOCUMENTS in the same pull request.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

ALLOWED_ROOT_DOCUMENTS = frozenset({
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "README.md",
    "SECURITY.md",
    "THIRD_PARTY_LICENSES.md",
    "TRADEMARK.md",
})

# Case-insensitive, so README.MD or notes.markdown cannot slip past the list.
_MARKDOWN_SUFFIXES = (".md", ".markdown")


def unexpected_root_documents(root: Path) -> list[str]:
    """Names of Markdown files directly in `root` that are not on the allow-list."""
    return sorted(
        entry.name
        for entry in root.iterdir()
        if entry.name.lower().endswith(_MARKDOWN_SUFFIXES)
        and not entry.is_dir()
        and entry.name not in ALLOWED_ROOT_DOCUMENTS
    )


def _seed_root(root: Path, names: list[str]) -> Path:
    root.mkdir()
    for name in names:
        (root / name).write_text("# placeholder\n", encoding="utf-8")
    return root


def test_repository_root_holds_only_the_allowed_documents():
    unexpected = unexpected_root_documents(REPO)
    assert unexpected == [], (
        f"Markdown files at the repository root that are not allowed: {unexpected}. "
        "Move them under docs/ or remove them."
    )


def test_every_allowed_document_is_present():
    # A missing entry means the list is stale and would silently allow a new file of that name.
    missing = sorted(name for name in ALLOWED_ROOT_DOCUMENTS if not (REPO / name).is_file())
    assert missing == []


def test_an_extra_root_document_fails_the_check(tmp_path: Path):
    root = _seed_root(tmp_path / "repo", [*ALLOWED_ROOT_DOCUMENTS, "NOTES.md"])
    assert unexpected_root_documents(root) == ["NOTES.md"]


def test_the_check_ignores_case_and_the_long_suffix(tmp_path: Path):
    # Distinct names on purpose: a case-insensitive file system would merge README.md/readme.MD.
    root = _seed_root(tmp_path / "repo", ["README.md", "Notes.MD", "guide.markdown"])
    assert unexpected_root_documents(root) == ["Notes.MD", "guide.markdown"]


def test_the_check_ignores_directories_and_other_files(tmp_path: Path):
    root = _seed_root(tmp_path / "repo", ["README.md", "LICENSE", "VERSION"])
    (root / "docs.md").mkdir()
    (root / "docs.md" / "index.md").write_text("# nested\n", encoding="utf-8")
    assert unexpected_root_documents(root) == []
