"""Addon env-bundle handling: seeding, CHANGE_ME prompts, materialization.

The canonical addon .env lives in $PAPAIA_CONFIG_DIR/addons/<name>/ so the
addon repo checkout stays git-pristine (read-only at deploy time); before
containers start, the bundle .env is copied back into the checkout.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import yaml

from . import common


def seed_addon_env(addon_path: Path, config_dir: Path) -> None:
    """Non-destructively seed an addon's .env.example into <config>/addons/<name>/.env.

    The canonical .env lives in the config bundle so the addon repo checkout
    stays git-pristine (read-only at deploy time). Before starting containers,
    materialize_addon_env copies the bundle .env into the checkout.

    Rules:
    - Keys already present in the bundle .env are never touched (sticky).
    - Values marked GENERATE_* get a fresh random secret.
    - All other values (CHANGE_ME markers, literals) are copied verbatim.
    """
    example_path = addon_path / ".env.example"
    if not example_path.is_file():
        return

    try:
        manifest = yaml.safe_load((addon_path / "papaia-app.yaml").read_text(encoding="utf-8")) or {}
        addon_name = manifest.get("name", addon_path.name)
    except Exception:
        addon_name = addon_path.name

    bundle_dir = config_dir / "addons" / addon_name
    common.ensure_dir(bundle_dir)
    env_path = bundle_dir / ".env"

    example_values = common.parse_env_file(example_path)
    existing_keys = set(common.parse_env_file(env_path).keys())

    new_pairs: list[tuple[str, str]] = []
    for key, template_value in example_values.items():
        if key in existing_keys:
            continue
        if common.marks_generated_secret(template_value):
            new_pairs.append((key, common.generate_secret(key)))
        else:
            new_pairs.append((key, template_value))

    if not new_pairs:
        return

    existing_content = env_path.read_text(encoding="utf-8") if env_path.is_file() else ""
    lines: list[str] = []
    if existing_content and not existing_content.endswith("\n"):
        lines.append("")
    lines.append(f"# --- Addon: {addon_name} (seeded by papaia-ctl) ---")
    for k, v in new_pairs:
        lines.append(f"{k}={v}")

    common.atomic_write(env_path, existing_content + "\n".join(lines) + "\n")


_CHANGE_ME = "CHANGE_ME"


def prompt_change_me_vars(env_path: Path, manifest: dict, config_dir: Path) -> dict[str, str]:
    """Prompt interactively for CHANGE_ME values in the seeded bundle env.

    Returns a dict of key→value pairs the caller should write back.
    Non-interactive stdin → warns on stderr and returns {} (values stay CHANGE_ME).
    """
    env_vals = common.parse_env_file(env_path)
    change_me_keys = [k for k, v in env_vals.items() if v == _CHANGE_ME]
    if not change_me_keys:
        return {}

    prompts_cfg = manifest.get("env_prompts") or {}

    if not sys.stdin.isatty():
        print(
            "\nWARNING: Non-interactive mode — the following keys still contain CHANGE_ME in\n"
            f"  {env_path}\n"
            "  Set them before running 'papaia-ctl addon start':\n",
            file=sys.stderr,
        )
        for key in change_me_keys:
            print(f"  {key}", file=sys.stderr)
        print(file=sys.stderr)
        return {}

    print("\nFill in environment-specific values (press Enter to accept the default):\n")
    updates: dict[str, str] = {}
    core_env: dict[str, str] | None = None

    for key in change_me_keys:
        cfg = prompts_cfg.get(key) or {}
        label = cfg.get("label") or key
        default = cfg.get("default", "")

        if "default_from_core" in cfg:
            if core_env is None:
                core_env = common.parse_env_file(config_dir / ".env")
            default = core_env.get(cfg["default_from_core"], default)

        suffix = f" [{default}]" if default else ""
        answer = input(f"  {label}{suffix}: ").strip() or default
        updates[key] = answer

    print()
    return updates


def materialize_addon_env(config_dir: Path, addon_path: Path, addon_name: str) -> None:
    """Copy the canonical bundle .env into the addon checkout before compose up.

    The addon's docker-compose.yml uses `env_file: ./.env`. This function
    ensures the checkout .env is always in sync with the config bundle.
    """
    bundle_env = config_dir / "addons" / addon_name / ".env"
    target_env = addon_path / ".env"
    if bundle_env.is_file():
        shutil.copy2(bundle_env, target_env)
