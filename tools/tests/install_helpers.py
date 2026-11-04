"""A real installation in a temporary directory: `setup` run against a copy of this
checkout's `src/`, the way an operator's host has it. Shared by the golden tests and the
topology tests."""

from __future__ import annotations

import shutil
from pathlib import Path

from lib import cli, common, envtree

REPO = Path(__file__).resolve().parents[2]

# What `setup` reads from the checkout. Copied from the working tree, not from git, so
# an uncommitted change to a compose fragment or a template is what gets tested.
_CHECKOUT_FILES = ("tools/deployment.template.yaml", "VERSION", "ADDON_API", "CHANGELOG.md")
_IGNORED = shutil.ignore_patterns(
    ".env", "papaia-realm.json", "__pycache__", ".pytest_cache", "*.pyc", "*.tmp"
)

# Keys of the root .env that describe the machine and the user running the test.
_HOST_KEYS = ("UID", "GID", "DOCKER_GID")


def checkout(tmp_path: Path) -> Path:
    """A copy of what `setup` reads, under `<tmp>/workspace/papaia` so the workspace
    and backup paths it derives from the checkout's name are the real ones."""
    dest = tmp_path / "workspace" / "papaia"
    shutil.copytree(REPO / "src", dest / "src", ignore=_IGNORED)
    for rel in _CHECKOUT_FILES:
        source = REPO / rel
        if source.is_file():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, dest / rel)
    return dest


def run_cli(repo: Path, config: Path, *args: str) -> None:
    code = cli.main(["--repo-root", str(repo), "--config-dir", str(config), *args])
    assert code == 0, f"lib.cli {' '.join(args)} exited {code}"


class Installation:
    def __init__(self, tmp_path: Path, flags: list[str]):
        self.repo = checkout(tmp_path)
        self.workspace = self.repo.parent
        self.config = self.workspace / "papaia-config"
        self.flags = flags

    def setup(self, *flags: str) -> None:
        run_cli(self.repo, self.config, "setup", "--env=papaia", *flags)

    def secrets(self) -> list[str]:
        """Every generated secret of this installation, longest first so that no
        secret is replaced inside a longer one."""
        seed = envtree.load_seed_tree(self.repo)
        tree = envtree.load_config_dir_tree(self.config, self.repo)
        found: set[str] = set()
        for rel_dir, values in seed.items():
            for key, seed_value in values.items():
                if common.marks_generated_secret(seed_value):
                    value = tree.get(rel_dir, {}).get(key, "")
                    if value and not common.is_placeholder(value):
                        found.add(value)
        return sorted(found, key=len, reverse=True)

    def normalise(self, text: str) -> str:
        for secret in self.secrets():
            text = text.replace(secret, "<SECRET>")
        # Longest path first: the config dir and the checkout sit inside the workspace.
        for path, label in (
            (self.config, "<CONFIG>"),
            (self.repo, "<REPO>"),
            (self.workspace, "<WORKSPACE>"),
        ):
            text = text.replace(str(path), label)
        lines = []
        for line in text.split("\n"):
            key = line.partition("=")[0]
            if key in _HOST_KEYS and "=" in line:
                line = f"{key}=<HOST>"
            lines.append(line)
        return "\n".join(lines)
