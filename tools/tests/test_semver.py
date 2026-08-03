from __future__ import annotations

import pytest

from lib import semver

# ── parsing ───────────────────────────────────────────────────────────────────


def test_parse_version_basic():
    v = semver.parse_version("1.2.3")
    assert (v.major, v.minor, v.patch, v.prerelease) == (1, 2, 3, ())


def test_parse_version_prerelease():
    v = semver.parse_version("1.0.0-rc.1")
    assert v.prerelease == ("rc", "1")


def test_parse_version_ignores_build_metadata():
    assert semver.compare("1.0.0+build.5", "1.0.0") == 0


@pytest.mark.parametrize("text", ["1.2", "1", "abc", "1.2.3.4", "1.2.3-", "", "v1.2.3"])
def test_parse_version_malformed_raises(text):
    with pytest.raises(ValueError):
        semver.parse_version(text)


@pytest.mark.parametrize("text", ["", " , ", ">=1.2", ">>1.0.0", "^x.y.z", ">=0.8.0,"])
def test_parse_constraint_malformed_raises(text):
    with pytest.raises(ValueError):
        semver.parse_constraint(text)


# ── ordering ──────────────────────────────────────────────────────────────────


def test_prerelease_ordering_chain():
    # The canonical SemVer 2.0.0 precedence chain.
    chain = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0-rc.2",
        "1.0.0",
    ]
    for lower, higher in zip(chain, chain[1:], strict=False):
        assert semver.compare(lower, higher) == -1
        assert semver.compare(higher, lower) == 1


def test_compare_triples():
    assert semver.compare("0.7.0", "0.8.0") == -1
    assert semver.compare("1.0.0", "0.9.9") == 1
    assert semver.compare("1.2.3", "1.2.3") == 0


# ── satisfies ─────────────────────────────────────────────────────────────────


def test_satisfies_the_bug_direction():
    # The defect this module exists for: a core reporting 0.7.0 must not
    # satisfy the shipped addon's ">=0.8.0", while 0.8.0 must.
    assert semver.satisfies("0.8.0", ">=0.8.0")
    assert not semver.satisfies("0.7.0", ">=0.8.0")


def test_satisfies_operators():
    assert semver.satisfies("0.9.0", ">0.8.0")
    assert not semver.satisfies("0.8.0", ">0.8.0")
    assert semver.satisfies("0.8.0", "<=0.8.0")
    assert semver.satisfies("0.7.9", "<0.8.0")
    assert semver.satisfies("0.8.0", "==0.8.0")
    assert semver.satisfies("0.8.0", "0.8.0")  # bare version == equality
    assert semver.satisfies("0.8.1", "!=0.8.0")
    assert not semver.satisfies("0.8.0", "!=0.8.0")


def test_prerelease_does_not_satisfy_release_range():
    # 1.0.0-rc precedes 1.0.0 but must not leak through a plain range.
    assert not semver.satisfies("1.0.0-rc", ">=0.8.0")
    assert not semver.satisfies("1.0.0-rc.1", ">=0.8.0,<2.0.0")


def test_prerelease_satisfies_when_bound_is_prerelease_on_same_triple():
    assert semver.satisfies("1.0.0-rc.2", ">=1.0.0-rc.1")
    assert not semver.satisfies("1.0.0-rc.1", ">=1.0.0-rc.2")
    # Different triple: the opt-in does not transfer.
    assert not semver.satisfies("1.1.0-rc.1", ">=1.0.0-rc.1")


def test_release_satisfies_prerelease_bound():
    assert semver.satisfies("1.0.0", ">=1.0.0-rc.1")


def test_caret_zero_major_locks_minor():
    assert semver.satisfies("0.8.5", "^0.8.0")
    assert not semver.satisfies("0.9.0", "^0.8.0")
    assert not semver.satisfies("0.7.9", "^0.8.0")


def test_caret_nonzero_major_locks_major():
    assert semver.satisfies("1.9.9", "^1.2.3")
    assert not semver.satisfies("2.0.0", "^1.2.3")
    assert not semver.satisfies("1.2.2", "^1.2.3")


def test_caret_zero_zero_locks_patch():
    assert semver.satisfies("0.0.3", "^0.0.3")
    assert not semver.satisfies("0.0.4", "^0.0.3")


def test_tilde_locks_minor():
    assert semver.satisfies("1.2.9", "~1.2.3")
    assert not semver.satisfies("1.3.0", "~1.2.3")
    assert not semver.satisfies("1.2.2", "~1.2.3")


def test_comma_means_and():
    assert semver.satisfies("1.5.0", ">=0.8.0,<2.0.0")
    assert not semver.satisfies("2.1.0", ">=0.8.0,<2.0.0")
    assert not semver.satisfies("0.7.0", ">=0.8.0,<2.0.0")


def test_satisfies_malformed_raises():
    with pytest.raises(ValueError):
        semver.satisfies("1.0.0", ">=not.a.version")
    with pytest.raises(ValueError):
        semver.satisfies("garbage", ">=1.0.0")
