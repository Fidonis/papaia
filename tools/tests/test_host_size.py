"""Size profiles and the host check before `setup` (lib/host_size.py, doctor
`profile_size`; OPS-01, PLT-58-A5).

A host below the chosen profile stops `setup` before anything is written, with the size
that is missing; `doctor` reports the same before `setup` against the smallest profile.
Hermetic: the runner and the probes are stubs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lib import cli, doctor, host_size
from lib.doctor import FAIL, PASS, SKIP, WARN, MemInfo, Probes
from lib.status import CommandResult

GB = 10**9
REPO = Path(__file__).resolve().parents[2]


def runner(*, cpus: int | None = None, memory: int | None = None, gpu_mib: int | None = None):
    calls: list[list[str]] = []

    def run(argv, timeout):
        calls.append(list(argv))
        if argv[:2] == ["docker", "info"] and "{{.NCPU}} {{.MemTotal}}" in argv:
            if cpus is None:
                return CommandResult(1, "", "no daemon")
            return CommandResult(0, f"{cpus} {memory}\n")
        if argv[:2] == ["docker", "info"]:
            return CommandResult(1, "", "no daemon")
        if argv[0] == "nvidia-smi":
            if gpu_mib is None:
                return CommandResult(127, "", "not found")
            return CommandResult(0, f"0, NVIDIA L4, 550.1, {gpu_mib}, 10, 0, 40\n")
        return CommandResult(1, "", "unexpected")

    run.calls = calls
    return run


def probes(*, cores=8, memory=64 * GB, free=400 * GB) -> Probes:
    return Probes(
        disk_usage=lambda path: (1000 * GB, free),
        cpu_count=lambda: cores,
        meminfo=lambda: MemInfo(memory, memory // 2, 0, 0) if memory else None,
    )


def check(tmp_path: Path, profile: str, **kwargs) -> doctor.CheckResult:
    run = kwargs.pop("run", runner())
    return doctor.check_size(tmp_path, REPO, profile, run=run, probes=probes(**kwargs))


# ── the profiles ─────────────────────────────────────────────────────────────


def test_the_profiles_carry_the_documented_sizes():
    small_no_model = host_size.PROFILES["small-no-model"]
    assert (small_no_model.cores, small_no_model.memory, small_no_model.disk) == (
        8, 32 * GB, 200 * GB)
    small = host_size.PROFILES["small"]
    assert (small.cores, small.memory, small.disk) == (8, 64 * GB, 300 * GB)
    assert small.gpu_alternative == (32 * GB, 16 * GB) and small.local_model
    large = host_size.PROFILES["large"]
    assert (large.cores, large.memory, large.disk) == (16, 64 * GB, 500 * GB)
    assert host_size.SMALLEST == "small-no-model"


def test_a_host_that_fits_passes(tmp_path):
    assert check(tmp_path, "small").status == PASS


def test_half_the_memory_fails_and_names_the_missing_size(tmp_path):
    result = check(tmp_path, "small-no-model", memory=16 * GB)

    assert result.status == FAIL
    assert "memory: 32 GB needed, 16 GB found" in result.summary
    assert result.details["missing"] and result.details["profile"] == "small-no-model"


def test_every_missing_size_is_named(tmp_path):
    result = check(tmp_path, "large", cores=8, memory=32 * GB, free=100 * GB)

    assert result.status == FAIL
    for part in ("CPU: 16 cores needed, 8 found", "memory: 64 GB needed",
                 "disk: 500 GB free needed"):
        assert part in result.summary


def test_the_kernel_share_of_the_memory_is_tolerated(tmp_path):
    # A host sold with 32 GB reports a little less as its total.
    assert check(tmp_path, "small-no-model", memory=31 * GB).status == PASS
    assert check(tmp_path, "small-no-model", memory=29 * GB).status == FAIL


def test_small_takes_32_gb_with_a_16_gb_gpu(tmp_path):
    with_gpu = check(tmp_path, "small", memory=32 * GB, run=runner(gpu_mib=24576))
    assert with_gpu.status == PASS

    small_gpu = check(tmp_path, "small", memory=32 * GB, run=runner(gpu_mib=8192))
    assert small_gpu.status == FAIL
    assert "or 32 GB with a GPU of 16 GB video memory" in small_gpu.summary

    no_gpu = check(tmp_path, "small", memory=32 * GB, run=runner())
    assert no_gpu.status == FAIL


def test_the_gpu_is_not_asked_when_memory_suffices(tmp_path):
    run = runner(gpu_mib=24576)
    check(tmp_path, "small", memory=64 * GB, run=run)
    assert not any(call[0] == "nvidia-smi" for call in run.calls)


def test_docker_desktop_counts_the_vm_not_the_host(tmp_path):
    # The containers get what the daemon has: 4 CPUs of a 16-core Mac are 4.
    result = check(tmp_path, "small-no-model", cores=16, run=runner(cpus=4, memory=64 * GB))
    assert result.status == FAIL
    assert "CPU: 8 cores needed, 4 found" in result.summary


def test_a_size_that_cannot_be_read_warns(tmp_path):
    result = doctor.check_size(
        tmp_path, REPO, "small-no-model", run=runner(),
        probes=Probes(disk_usage=lambda p: (1, 400 * GB), cpu_count=lambda: None,
                      meminfo=lambda: MemInfo(64 * GB, 1, 0, 0)),
    )
    assert result.status == WARN
    assert "CPU cores cannot be read" in result.summary


def test_an_unknown_profile_fails(tmp_path):
    assert check(tmp_path, "huge").status == FAIL


# ── doctor ───────────────────────────────────────────────────────────────────


def _ctx(config: Path, **kwargs) -> doctor.Context:
    from datetime import datetime, timezone

    return doctor.Context(config, REPO, run=runner(), probes=probes(**kwargs),
                          now=datetime.now(timezone.utc))


def test_doctor_before_setup_measures_the_smallest_profile(tmp_path):
    result = doctor.check_profile_size(_ctx(tmp_path / "papaia-config", memory=16 * GB))

    assert result.status == FAIL
    assert "small-no-model" in result.summary and "memory" in result.summary
    assert result.details["before_setup"] is True


def _configured(tmp_path: Path, **env: str) -> Path:
    config = tmp_path / "papaia-config"
    config.mkdir()
    (config / ".env").write_text("".join(f"{k}={v}\n" for k, v in env.items()))
    (config / "deployment.yaml").write_text("addons: []\n")
    return config


def test_doctor_measures_the_chosen_profile(tmp_path):
    config = _configured(tmp_path, PAPAIA_SIZE_PROFILE="large")
    result = doctor.check_profile_size(_ctx(config, cores=8))

    assert result.status == FAIL
    assert "'large'" in result.summary


def test_doctor_skips_an_installation_without_a_profile(tmp_path):
    config = _configured(tmp_path)
    assert doctor.check_profile_size(_ctx(config)).status == SKIP


def test_profile_size_is_registered_after_cpu():
    names = list(doctor.CHECK_NAMES)
    assert names[names.index("cpu") + 1] == "profile_size"


def test_setup_size_check_exits_3_and_names_the_size(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        doctor, "check_size",
        lambda config, repo, name, **kw: doctor.size_result(
            _ctx(config, memory=16 * GB), name),
    )
    rc = cli.main(["--repo-root", str(REPO), "--config-dir", str(tmp_path / "c"),
                   "size-check", "--profile=small-no-model"])

    assert rc == 3
    err = capsys.readouterr().err
    assert "memory: 32 GB needed, 16 GB found" in err and "Nothing was changed" in err


@pytest.mark.parametrize("memory,expected", [(64 * GB, 0), (16 * GB, 3)])
def test_setup_size_check_exit_codes(tmp_path, monkeypatch, memory, expected):
    monkeypatch.setattr(
        doctor, "check_size",
        lambda config, repo, name, **kw: doctor.size_result(_ctx(config, memory=memory), name),
    )
    assert cli.main(["--repo-root", str(REPO), "--config-dir", str(tmp_path / "c"),
                     "size-check", "--profile=small-no-model"]) == expected
