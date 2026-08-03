"""Freezes the lib.* contract surface the papaia-manager imports.

The manager imports a small set of lib.* functions directly from the mounted
checkout (arch doc §2: PAPAIA_WORKSPACE_DIR/papaia/tools) rather than from a
bundled copy.  This file pins the signatures of those functions so that a PR
breaking them fails core CI and must update this snapshot deliberately.

When an assert here fails there are exactly two legitimate paths:

  * the change is breaking for the manager -> add a SUPPORTED_CORE bump note
    to the PR description and update the snapshot, OR
  * the change is additive / backwards-compatible -> update the snapshot.

Silence (green test via deletion of the assertion) is never acceptable.
"""

from __future__ import annotations

import inspect
from pathlib import Path

from lib import common, compat, deployment, semver  # noqa: F401

REPO = Path(__file__).resolve().parents[2]

_SURFACE_CHANGED = (
    "Manager-facing lib.* contract surface changed. Update this snapshot"
    " deliberately and add a note to the PR description. See"
    " papaia-manager-1.0.0.md §2 (Kopplungsrisiko und Absicherung)."
)


# ---------------------------------------------------------------------------
# compat surface
# ---------------------------------------------------------------------------

def test_resolve_core_target_signature():
    sig = inspect.signature(compat.resolve_core_target)
    params = list(sig.parameters)
    assert params == ["repo_root"], _SURFACE_CHANGED


def test_evaluate_addon_signature():
    sig = inspect.signature(compat.evaluate_addon)
    params = list(sig.parameters)
    assert params == ["name", "manifest", "core", "active_profiles"], _SURFACE_CHANGED


def test_resolve_core_services_signature():
    sig = inspect.signature(compat.resolve_core_services)
    params = list(sig.parameters)
    assert params == ["repo_root"], _SURFACE_CHANGED


# ---------------------------------------------------------------------------
# common surface
# ---------------------------------------------------------------------------

def test_parse_env_file_signature():
    sig = inspect.signature(common.parse_env_file)
    params = list(sig.parameters)
    assert params == ["path"], _SURFACE_CHANGED


def test_write_env_file_signature():
    sig = inspect.signature(common.write_env_file)
    params = list(sig.parameters)
    assert params == ["path", "values", "template_path"], _SURFACE_CHANGED


def test_generate_secret_signature():
    sig = inspect.signature(common.generate_secret)
    params = list(sig.parameters)
    assert params == ["key"], _SURFACE_CHANGED


# ---------------------------------------------------------------------------
# deployment surface
# ---------------------------------------------------------------------------

def test_deployment_load_signature():
    sig = inspect.signature(deployment.load)
    params = list(sig.parameters)
    assert params == ["config_dir"], _SURFACE_CHANGED


def test_load_addon_manifest_signature():
    sig = inspect.signature(deployment.load_addon_manifest)
    params = list(sig.parameters)
    assert params == ["addon_path"], _SURFACE_CHANGED


def test_resolve_addon_path_signature():
    sig = inspect.signature(deployment.resolve_addon_path)
    params = list(sig.parameters)
    assert params == ["addon", "repo_root"], _SURFACE_CHANGED


# ---------------------------------------------------------------------------
# semver surface
# ---------------------------------------------------------------------------

def test_semver_satisfies_signature():
    sig = inspect.signature(semver.satisfies)
    params = list(sig.parameters)
    assert params == ["version", "constraint"], _SURFACE_CHANGED


def test_semver_parse_version_signature():
    sig = inspect.signature(semver.parse_version)
    params = list(sig.parameters)
    assert params == ["text"], _SURFACE_CHANGED


def test_semver_parse_constraint_signature():
    sig = inspect.signature(semver.parse_constraint)
    params = list(sig.parameters)
    assert params == ["text"], _SURFACE_CHANGED
