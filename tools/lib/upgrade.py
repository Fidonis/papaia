"""Release selection for `papaia-ctl upgrade`.

The bash side owns every git invocation; this module owns the question
"which release is the target, and is moving there allowed at all". Keeping
the version arithmetic here rather than in `sort -V` pipelines is what makes
pre-releases behave: `git tag --sort=-v:refname` happily ranks `v1.0.0-rc.1`
above `v1.0.0`, while `semver.compare` implements SemVer precedence.

Upgrades are deliberately one-directional. A downgrade would have to undo
migrations that only exist in the newer tree, which is not a thing the
migration contract can express -- so it is refused rather than half-supported.
"""

from __future__ import annotations

from pathlib import Path

from . import semver


class UpgradeError(Exception):
    """Anything that makes the requested upgrade impossible. The CLI turns
    this into exit code 3 with the message shown verbatim."""


def normalize_version(text: str) -> str:
    """Accept `1.5.0` and `v1.5.0` alike, return the bare SemVer string."""
    candidate = text.strip()
    if candidate.startswith(("v", "V")):
        candidate = candidate[1:]
    try:
        semver.parse_version(candidate)
    except ValueError as exc:
        raise UpgradeError(f"Not a valid version: {text!r} ({exc})") from exc
    return candidate


def tag_for(version: str) -> str:
    """The git tag carrying a release, per the Playbook's `vX.Y.Z` rule."""
    return f"v{version}"


def parse_tags(lines: list[str]) -> list[str]:
    """Extract release versions from `git ls-remote --tags` / `git tag` output.

    Both forms are accepted so the caller can fall back to local tags when the
    remote is unreachable:

        <sha>\trefs/tags/v1.2.0
        <sha>\trefs/tags/v1.2.0^{}     (peeled annotated tag -- same release)
        v1.2.0

    Anything that is not a `vX.Y.Z` tag is ignored rather than rejected: a repo
    may carry unrelated tags, and they are none of this command's business.
    """
    versions: list[str] = []
    for raw_line in lines:
        ref = raw_line.strip()
        if not ref:
            continue
        if "\t" in ref:
            ref = ref.split("\t", 1)[1].strip()
        if ref.startswith("refs/tags/"):
            ref = ref[len("refs/tags/") :]
        if ref.endswith("^{}"):
            ref = ref[:-3]
        if not ref.startswith("v"):
            continue
        try:
            semver.parse_version(ref[1:])
        except ValueError:
            continue
        if ref[1:] not in versions:
            versions.append(ref[1:])
    return versions


def latest_release(versions: list[str]) -> str | None:
    """Highest non-pre-release version, or None when there is none.

    Pre-releases are never picked implicitly -- `--version=1.1.0-rc.1` is the
    only way onto one, which keeps `upgrade` without flags a production move."""
    best: str | None = None
    for version in versions:
        if semver.parse_version(version).prerelease:
            continue
        if best is None or semver.compare(version, best) > 0:
            best = version
    return best


def select_target(versions: list[str], requested: str | None) -> str:
    """Resolve the target release from the available tags.

    `requested` must exist as a tag: silently upgrading to something else than
    the operator asked for is worse than failing."""
    if requested is not None:
        target = normalize_version(requested)
        if target not in versions:
            raise UpgradeError(
                f"No release tag {tag_for(target)} found. Check the available"
                " releases with 'git tag --list' (or 'git ls-remote --tags origin')."
            )
        return target
    target = latest_release(versions)
    if target is None:
        raise UpgradeError(
            "No release tag (vX.Y.Z) found in this checkout or on its remote."
            " Pass --version=X.Y.Z to name the target explicitly."
        )
    return target


def resolve_current_version(config_dir: Path, repo_root: Path) -> str:
    """The version this installation is *at*, which is the version its config
    bundle was last migrated and rendered to -- `platform_version` in
    deployment.yaml, stamped by every `papaia-ctl setup` run.

    Deliberately not the checkout's VERSION file: an operator who moved the
    checkout by hand (`git pull`) without re-running setup has a bundle that
    still carries the old shape, and that shape is what the migrations have to
    start from. The VERSION file is only the fallback for a bundle too old to
    carry the field."""
    # Local import: deployment imports compat -> envtree, and this module is
    # imported by cli.py alongside all three.
    from . import deployment, envtree

    recorded = str(deployment.load(config_dir).get("platform_version") or "").strip()
    if recorded:
        try:
            semver.parse_version(recorded)
        except ValueError:
            recorded = ""
    return recorded or envtree.resolve_platform_version(repo_root)


STATUS_OK = "ok"
STATUS_UP_TO_DATE = "up-to-date"


def resolve_status(current: str, target: str, *, explicit: bool) -> str:
    """Whether this upgrade has anything to do -- and whether it is allowed.

    Without `--version` the command means "go to the newest release if there is
    one", so a target that is not ahead is simply nothing to do: `upgrade` stays
    safe to run unattended, from a cron job or a fleet loop, and a checkout that
    is temporarily ahead of the newest tag (a milestone branch before its
    release is cut) does not read as a broken installation.

    With an explicit `--version` the operator named a release, so anything but a
    move forward is answered instead of silently ignored."""
    ordering = semver.compare(target, current)
    if ordering > 0:
        return STATUS_OK
    if ordering == 0 or not explicit:
        return STATUS_UP_TO_DATE
    check_direction(current, target)
    return STATUS_OK  # unreachable: check_direction raises for ordering < 0


def check_direction(current: str, target: str) -> None:
    """Refuse a move backwards."""
    if semver.compare(target, current) >= 0:
        return
    raise UpgradeError(
        f"Refusing to move from {current} down to {target}. Downgrades are not"
        " supported: migrations only ever move a config bundle forward. Restore"
        " a backup taken before the upgrade instead ('papaia-ctl restore --list')."
    )
