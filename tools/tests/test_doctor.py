"""`papaia-ctl doctor`: preflight and diagnostics.

Nothing outside the process is touched. Docker is `FakeDocker`; the disk, the
network, the name resolver and the certificates are stubbed through `Probes`.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from stack_helpers import (
    NOW,
    RUNTIMES_WITH_NVIDIA,
    FakeDocker,
    healthy_addon,
    healthy_core,
    not_found,
)

from lib import cli, doctor, status
from lib.doctor import FAIL, PASS, SKIP, WARN, CertReadError, MemInfo, Probes
from lib.status import CommandResult

REPO = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((REPO / "tools" / "schemas" / "doctor.schema.json").read_text("utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)

GIB = 1024**3


# ─────────────────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────────────────


def probes(**overrides) -> Probes:
    values = {
        "disk_usage": lambda path: (500 * GIB, 400 * GIB),
        "connect": lambda host, port: False,
        "resolve": lambda host: doctor.RESOLVED,
        "cert_enddate": lambda path, run: NOW + timedelta(days=365),
        "meminfo": lambda: MemInfo(16 * GIB, 12 * GIB, 0, 0),
        "loadavg": lambda: (0.3, 0.2, 0.1),
        "cpu_count": lambda: 8,
        "in_container": lambda: False,
        "dev_root": Path("/papaia-test-has-no-devices"),
    }
    values.update(overrides)
    return Probes(**values)


def healthy_docker(**kwargs) -> FakeDocker:
    return FakeDocker(healthy_core() + healthy_addon(), **kwargs)


def run_doctor(stack, docker=None, *, skip=None, **probe_overrides) -> doctor.DoctorReport:
    return doctor.run_checks(
        stack["config"],
        stack["repo"],
        skip=skip,
        run=docker or healthy_docker(),
        probes=probes(**probe_overrides),
        now=NOW,
    )


def result(report: doctor.DoctorReport, name: str) -> doctor.CheckResult:
    return next(c for c in report.checks if c.name == name)


def add_certs(stack, *names: str) -> None:
    certs = stack["config"] / "certs"
    certs.mkdir(exist_ok=True)
    for name in names:
        (certs / name).write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")


def set_env(stack, **values: str) -> None:
    env = stack["config"] / ".env"
    with env.open("a", encoding="utf-8", newline="\n") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


PROFILES = "keycloak,oauth2-proxy,librechat-websearch"

# One GPU as `nvidia-smi --query-gpu=... --format=csv,noheader,nounits` prints it.
NVIDIA_ONE = "0, NVIDIA GeForce RTX 4090, 560.35.03, 24564, 3012, 12, 54\n"

# `rocm-smi --showmeminfo vram --showuse --showtemp --json`, trimmed to the
# fields that matter; the temperature keys are listed junction-first on purpose.
ROCM_ONE = json.dumps(
    {
        "card0": {
            "VRAM Total Memory (B)": "17163091968",
            "VRAM Total Used Memory (B)": "1073741824",
            "GPU use (%)": "7",
            "Temperature (Sensor junction) (C)": "43.0",
            "Temperature (Sensor edge) (C)": "41.0",
        },
        "system": {"Driver version": "6.2.4"},
    }
)


def enable_localai(stack, variant: str | None = None) -> None:
    values = {"COMPOSE_PROFILES": f"{PROFILES},localai"}
    if variant is not None:
        values["LOCALAI_IMAGE_VARIANT"] = variant
    set_env(stack, **values)


def fake_dev(tmp_path: Path, *, kfd: bool = False, render_node: bool = False) -> Path:
    """A stand-in for /dev with the device nodes a GPU host would have."""
    dev = tmp_path / "dev"
    (dev / "dri").mkdir(parents=True, exist_ok=True)
    if kfd:
        (dev / "kfd").write_text("", encoding="utf-8")
    if render_node:
        (dev / "dri" / "renderD128").write_text("", encoding="utf-8")
    return dev


def nvidia_docker(
    smi: CommandResult | str = NVIDIA_ONE, *, runtimes: str = RUNTIMES_WITH_NVIDIA, **kwargs
) -> FakeDocker:
    """A host whose `nvidia-smi` answers and whose Docker has the nvidia runtime."""
    answer = CommandResult(0, smi, "") if isinstance(smi, str) else smi
    return healthy_docker(
        tools={"nvidia-smi": answer, "rocm-smi": CommandResult(0, ROCM_ONE, "")},
        runtimes=CommandResult(0, runtimes + "\n", ""),
        **kwargs,
    )


# ─────────────────────────────────────────────────────────────────────────
# the report as a whole
# ─────────────────────────────────────────────────────────────────────────


def test_healthy_installation_passes_and_validates(stack):
    add_certs(stack, "local-ca.crt")
    report = run_doctor(stack)

    assert [c.status for c in report.checks] == [
        PASS,  # docker_version
        PASS,  # disk_space
        PASS,  # memory
        PASS,  # cpu
        SKIP,  # gpu: LocalAI is not enabled
        PASS,  # ports
        SKIP,  # dns: only local hostnames configured
        PASS,  # time_sync
        PASS,  # certs
        PASS,  # addon_compat
        PASS,  # container_health
    ]
    assert report.ok
    assert report.exit_code == 0
    assert not list(VALIDATOR.iter_errors(json.loads(doctor.to_json(report))))


def test_registry_names_are_unique_and_in_the_documented_order():
    assert doctor.CHECK_NAMES == (
        "docker_version",
        "disk_space",
        "memory",
        "cpu",
        "gpu",
        "ports",
        "dns",
        "time_sync",
        "certs",
        "addon_compat",
        "container_health",
    )


def test_any_fail_means_exit_2_warnings_and_skips_do_not(stack):
    failing = run_doctor(stack, docker=healthy_docker(engine=CommandResult(1, "", "no daemon")))
    assert failing.exit_code == 2
    assert not failing.ok

    warning_only = run_doctor(stack, disk_usage=lambda path: (500 * GIB, 5 * GIB))  # warn, not fail
    assert result(warning_only, "disk_space").status == WARN
    assert warning_only.exit_code == 0


def test_summary_counts_every_status(stack):
    report = run_doctor(stack, docker=healthy_docker(engine=CommandResult(1, "", "x")))

    counts = report.summary
    assert sum(counts.values()) == len(doctor.CHECKS)
    assert counts[FAIL] >= 1


def test_a_crashing_check_is_reported_not_raised(stack):
    def explode(path):
        raise RuntimeError("boom")

    report = run_doctor(stack, disk_usage=explode)

    crashed = result(report, "disk_space")
    assert crashed.status == FAIL
    assert crashed.summary == "check crashed: RuntimeError: boom"
    # the other checks still ran
    assert result(report, "docker_version").status == PASS
    assert report.exit_code == 2


# ─────────────────────────────────────────────────────────────────────────
# --skip
# ─────────────────────────────────────────────────────────────────────────


def test_skip_marks_checks_without_running_them(stack):
    docker = healthy_docker()
    report = run_doctor(stack, docker=docker, skip=["docker_version", "container_health"])

    assert result(report, "docker_version").status == SKIP
    assert result(report, "docker_version").summary == "skipped (--skip)"
    assert result(report, "container_health").status == SKIP
    assert not any(c[:2] == ["docker", "version"] for c in docker.calls)


def test_skip_rejects_unknown_names_and_lists_the_valid_ones(stack):
    with pytest.raises(doctor.DoctorError, match="nope.*Valid: docker_version"):
        run_doctor(stack, skip=["dns", "nope"])


def test_skip_accepts_comma_free_names_with_whitespace():
    assert doctor.parse_skip([" dns ", "certs"]) == ["dns", "certs"]
    assert doctor.parse_skip(None) == []


# ─────────────────────────────────────────────────────────────────────────
# docker_version
# ─────────────────────────────────────────────────────────────────────────


def test_docker_version_reports_engine_and_compose(stack):
    check = result(run_doctor(stack), "docker_version")

    assert check.status == PASS
    assert check.summary == "Docker Engine 27.0.3, Compose 2.29.1"
    assert check.details == {"engine": "27.0.3", "compose": "2.29.1", "min_compose": "2.20.0"}


def test_compose_older_than_the_minimum_fails(stack):
    docker = healthy_docker(compose=CommandResult(0, "2.19.1\n", ""))
    check = result(run_doctor(stack, docker=docker), "docker_version")

    assert check.status == FAIL
    assert "2.19.1" in check.summary and "2.20.0" in check.summary


@pytest.mark.parametrize("output", ["v2.29.1\n", "v2.29.1-desktop.1\n", "2.20.0\n"])
def test_compose_version_spellings_are_accepted(stack, output):
    docker = healthy_docker(compose=CommandResult(0, output, ""))

    assert result(run_doctor(stack, docker=docker), "docker_version").status == PASS


def test_unreadable_compose_version_is_a_warning(stack):
    docker = healthy_docker(compose=CommandResult(0, "dev\n", ""))

    assert result(run_doctor(stack, docker=docker), "docker_version").status == WARN


def test_missing_compose_plugin_fails(stack):
    docker = healthy_docker(compose=CommandResult(1, "", "unknown command"))
    check = result(run_doctor(stack, docker=docker), "docker_version")

    assert check.status == FAIL
    assert "Compose" in check.summary


def test_unreachable_daemon_and_missing_binary_fail_differently(stack):
    daemon = healthy_docker(engine=CommandResult(1, "", "Cannot connect to the Docker daemon"))
    missing = healthy_docker(engine=CommandResult(127, "", "docker: command not found"))

    assert "not reachable" in result(run_doctor(stack, docker=daemon), "docker_version").summary
    assert "not found" in result(run_doctor(stack, docker=missing), "docker_version").summary


# ─────────────────────────────────────────────────────────────────────────
# disk_space
# ─────────────────────────────────────────────────────────────────────────


def test_disk_space_measures_config_dir_and_backup_dir_in_bytes(stack, tmp_path):
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    set_env(stack, PAPAIA_BACKUP_DIR=str(backup_dir))
    seen: list[Path] = []

    def usage(path):
        seen.append(path)
        return (500 * GIB, 123 * GIB)

    check = result(run_doctor(stack, disk_usage=usage), "disk_space")

    assert check.status == PASS
    assert {Path(p["path"]) for p in check.details["paths"]} == {stack["config"], backup_dir}
    assert all(p["free_bytes"] == 123 * GIB for p in check.details["paths"])
    assert all(p["total_bytes"] == 500 * GIB for p in check.details["paths"])


@pytest.mark.parametrize(
    ("free_gib", "expected"),
    [(400, PASS), (10, PASS), (9, WARN), (2, WARN), (1, FAIL), (0, FAIL)],
)
def test_disk_space_thresholds(stack, free_gib, expected):
    check = result(
        run_doctor(stack, disk_usage=lambda p: (500 * GIB, free_gib * GIB)), "disk_space"
    )

    assert check.status == expected


def test_disk_space_reports_the_worst_path(stack, tmp_path):
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    set_env(stack, PAPAIA_BACKUP_DIR=str(backup_dir))

    def usage(path):
        return (500 * GIB, 1 * GIB if path == backup_dir else 300 * GIB)

    check = result(run_doctor(stack, disk_usage=usage), "disk_space")

    assert check.status == FAIL
    assert "backup_dir" in check.summary


def test_disk_space_uses_the_nearest_existing_parent_before_setup(tmp_path, stack):
    missing = tmp_path / "not" / "yet" / "there"
    measured: list[Path] = []

    def usage(path):
        measured.append(path)
        return (500 * GIB, 400 * GIB)

    doctor.run_checks(
        missing, stack["repo"], run=healthy_docker(), probes=probes(disk_usage=usage), now=NOW
    )

    assert tmp_path in measured


def test_docker_data_root_is_measured_when_the_host_can_see_it(stack, tmp_path):
    root = tmp_path / "docker-root"
    root.mkdir()
    docker = healthy_docker(root_dir=str(root))
    check = result(run_doctor(stack, docker=docker), "disk_space")

    assert "docker_root" in {p["label"] for p in check.details["paths"]}


def test_docker_data_root_inside_a_vm_is_skipped_with_a_note(stack):
    docker = healthy_docker(root_dir="/var/lib/docker-in-a-vm-that-is-not-here")
    check = result(run_doctor(stack, docker=docker), "disk_space")

    assert "docker_root" not in {p["label"] for p in check.details["paths"]}
    assert any("docker_root" in note for note in check.details["notes"])


# ─────────────────────────────────────────────────────────────────────────
# memory
# ─────────────────────────────────────────────────────────────────────────


def meminfo(total_gib: float, available_gib: float, swap_gib: float = 0, swap_free_gib: float = 0):
    def read():
        return MemInfo(
            int(total_gib * GIB),
            int(available_gib * GIB),
            int(swap_gib * GIB),
            int(swap_free_gib * GIB),
        )

    return read


def test_memory_reports_total_available_and_swap_in_bytes(stack):
    check = result(run_doctor(stack, meminfo=meminfo(16, 12, 4, 3)), "memory")

    assert check.status == PASS
    assert check.details == {
        "source": "proc",
        "total_bytes": 16 * GIB,
        "available_bytes": 12 * GIB,
        "used_percent": 25.0,
        "swap_total_bytes": 4 * GIB,
        "swap_used_bytes": 1 * GIB,
    }
    assert check.summary == "16.0 GiB total, 12.0 GiB available (25 % used)"


@pytest.mark.parametrize(
    ("total_gib", "available_gib", "expected"),
    [
        (16, 12, PASS),
        (8, 5, PASS),  # the documented minimum, as a host reports it
        (7, 5, WARN),  # total below the recommended 8 GB
        (16, 0.9, WARN),  # less than 1 GiB available
        (64, 3, WARN),  # more than 1 GiB, but under 10 % of the total
        (16, 0.2, WARN),
    ],
)
def test_memory_thresholds(stack, total_gib, available_gib, expected):
    check = result(run_doctor(stack, meminfo=meminfo(total_gib, available_gib)), "memory")

    assert check.status == expected


def test_memory_pressure_is_a_warning_and_never_fails_the_run(stack):
    report = run_doctor(stack, meminfo=meminfo(1, 0.01))

    assert result(report, "memory").status == WARN
    assert report.exit_code == 0


def test_memory_falls_back_to_the_docker_daemon_without_proc(stack):
    check = result(run_doctor(stack, meminfo=lambda: None), "memory")

    assert check.status == PASS  # the default FakeDocker daemon reports 16 GiB
    assert check.details["source"] == "docker_info"
    assert check.details["total_bytes"] == 16 * GIB
    assert check.details["available_bytes"] is None
    assert "cannot be read" in check.summary


def test_memory_total_from_the_daemon_is_still_compared_with_the_recommendation(stack):
    docker = healthy_docker(totals=CommandResult(0, f"2 {4 * GIB}\n", ""))
    check = result(run_doctor(stack, docker=docker, meminfo=lambda: None), "memory")

    assert check.status == WARN
    assert "recommended 8 GB" in check.summary


def test_memory_is_skipped_when_nothing_can_be_read(stack):
    docker = healthy_docker(totals=CommandResult(1, "", "daemon down"))
    check = result(run_doctor(stack, docker=docker, meminfo=lambda: None), "memory")

    assert check.status == SKIP


def test_memory_asks_the_daemon_only_when_proc_is_missing(stack):
    docker = healthy_docker()
    run_doctor(stack, docker=docker)

    assert ["docker", "info", "--format", "{{.NCPU}} {{.MemTotal}}"] not in docker.calls


def test_parse_meminfo_reads_kib_and_swap():
    text = (
        "MemTotal:       16384000 kB\nMemFree:         1000000 kB\n"
        "MemAvailable:    8192000 kB\nSwapTotal:       2048000 kB\n"
        "SwapFree:        1024000 kB\nHugePages_Total:       0\n"
    )

    assert doctor.parse_meminfo(text) == MemInfo(
        total=16384000 * 1024,
        available=8192000 * 1024,
        swap_total=2048000 * 1024,
        swap_free=1024000 * 1024,
    )


def test_parse_meminfo_estimates_availability_on_kernels_without_memavailable():
    info = doctor.parse_meminfo(
        "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 150 kB\n"
    )

    assert info is not None
    assert info.available == 300 * 1024
    assert info.swap_total == 0


@pytest.mark.parametrize("text", ["", "garbage\n", "MemFree: 5 kB\n", "MemTotal: lots kB\n"])
def test_parse_meminfo_without_a_total_is_none(text):
    assert doctor.parse_meminfo(text) is None


# ─────────────────────────────────────────────────────────────────────────
# cpu
# ─────────────────────────────────────────────────────────────────────────


def test_cpu_reports_cores_and_load_per_core(stack):
    check = result(run_doctor(stack, cpu_count=lambda: 8, loadavg=lambda: (1.0, 2.0, 3.0)), "cpu")

    assert check.status == PASS
    assert check.details == {
        "source": "os",
        "cores": 8,
        "load1": 1.0,
        "load5": 2.0,
        "load15": 3.0,
        "load_per_core": 0.25,
    }
    assert check.summary == "8 core(s), load 1.00 2.00 3.00 (5 min: 0.25 per core)"


@pytest.mark.parametrize(
    ("cores", "load5", "expected"),
    [(8, 2.0, PASS), (8, 7.9, PASS), (8, 8.0, WARN), (4, 9.0, WARN), (1, 0.4, PASS)],
)
def test_cpu_thresholds_use_the_five_minute_load_per_core(stack, cores, load5, expected):
    check = result(
        run_doctor(stack, cpu_count=lambda: cores, loadavg=lambda: (0.0, load5, 0.0)), "cpu"
    )

    assert check.status == expected


def test_cpu_load_is_a_warning_and_never_fails_the_run(stack):
    report = run_doctor(stack, cpu_count=lambda: 2, loadavg=lambda: (40.0, 40.0, 40.0))

    assert result(report, "cpu").status == WARN
    assert report.exit_code == 0


def test_cpu_without_a_load_average_is_skipped_but_still_names_the_cores(stack):
    check = result(run_doctor(stack, loadavg=lambda: None), "cpu")

    assert check.status == SKIP
    assert check.details["cores"] == 8


def test_cpu_cores_fall_back_to_the_docker_daemon(stack):
    docker = healthy_docker(totals=CommandResult(0, f"4 {16 * GIB}\n", ""))
    check = result(run_doctor(stack, docker=docker, cpu_count=lambda: None), "cpu")

    assert check.status == PASS
    assert check.details["source"] == "docker_info"
    assert check.details["cores"] == 4


def test_cpu_is_skipped_when_the_core_count_is_unknown(stack):
    docker = healthy_docker(totals=CommandResult(1, "", "daemon down"))
    check = result(run_doctor(stack, docker=docker, cpu_count=lambda: None), "cpu")

    assert check.status == SKIP


# ─────────────────────────────────────────────────────────────────────────
# gpu
# ─────────────────────────────────────────────────────────────────────────


def test_gpu_is_skipped_before_setup(tmp_path, stack):
    report = doctor.run_checks(
        tmp_path / "never-set-up", stack["repo"], run=healthy_docker(), probes=probes(), now=NOW
    )

    assert result(report, "gpu").status == SKIP
    assert "not set up" in result(report, "gpu").summary


def test_gpu_is_skipped_when_localai_is_not_enabled(stack):
    set_env(stack, LOCALAI_IMAGE_VARIANT="nvidia-cuda-13")  # a leftover from an earlier setup
    docker = nvidia_docker()
    check = result(run_doctor(stack, docker=docker), "gpu")

    assert check.status == SKIP
    assert "not enabled" in check.summary
    assert not any(c[0] == "nvidia-smi" for c in docker.calls)


@pytest.mark.parametrize("variant", ["cpu", None])
def test_gpu_is_skipped_for_the_cpu_image(stack, variant):
    enable_localai(stack, variant)
    check = result(run_doctor(stack, docker=nvidia_docker()), "gpu")

    assert check.status == SKIP
    assert "CPU image" in check.summary


def test_gpu_unknown_variant_is_a_warning_naming_the_valid_ones(stack):
    enable_localai(stack, "tpu")
    check = result(run_doctor(stack), "gpu")

    assert check.status == WARN
    assert "tpu" in check.summary and "nvidia-cuda-13" in check.summary


def test_gpu_is_skipped_inside_a_container_without_calling_host_tools(stack):
    enable_localai(stack, "nvidia-cuda-13")
    docker = nvidia_docker()
    check = result(run_doctor(stack, docker=docker, in_container=lambda: True), "gpu")

    assert check.status == SKIP
    assert "inside a container" in check.summary
    assert check.details["variant"] == "nvidia-cuda-13"
    assert not any(c[0] == "nvidia-smi" for c in docker.calls)


@pytest.mark.parametrize("variant", ["nvidia-cuda-12", "nvidia-cuda-13"])
def test_gpu_nvidia_reports_the_card_and_validates(stack, variant):
    enable_localai(stack, variant)
    report = run_doctor(stack, docker=nvidia_docker())
    check = result(report, "gpu")

    assert check.status == PASS
    assert check.summary == "NVIDIA GeForce RTX 4090: 2.9/24.0 GiB VRAM, 12 % util, 54C"
    assert check.details["variant"] == variant
    assert check.details["nvidia_runtime"] is True
    assert check.details["override_present"] is False
    assert check.details["gpus"] == [
        {
            "index": 0,
            "name": "NVIDIA GeForce RTX 4090",
            "driver": "560.35.03",
            "memory_total_mib": 24564,
            "memory_used_mib": 3012,
            "vram_percent": 12.3,
            "utilization_percent": 12,
            "temperature_c": 54,
        }
    ]
    assert not list(VALIDATOR.iter_errors(json.loads(doctor.to_json(report))))


def test_gpu_notes_whether_the_generated_override_exists(stack):
    enable_localai(stack, "nvidia-cuda-13")
    override = stack["config"] / "overrides" / "docker-compose.localai-gpu.override.yml"
    override.parent.mkdir(exist_ok=True)
    override.write_text("services: {}\n", encoding="utf-8")

    check = result(run_doctor(stack, docker=nvidia_docker()), "gpu")

    assert check.details["override_present"] is True


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("0, RTX 4090, 560.35, 24000, 21600, 3, 50", WARN),  # 90 % VRAM
        ("0, RTX 4090, 560.35, 24000, 21599, 3, 50", PASS),
        ("0, RTX 4090, 560.35, 24000, 1000, 3, 85", WARN),  # 85 C
        ("0, RTX 4090, 560.35, 24000, 1000, 3, 84", PASS),
        ("0, RTX 4090, 560.35, 24000, 1000, 100, 50", PASS),  # busy is not a problem
    ],
)
def test_gpu_vram_and_temperature_warn_but_utilization_does_not(stack, line, expected):
    enable_localai(stack, "nvidia-cuda-13")
    report = run_doctor(stack, docker=nvidia_docker(line + "\n"))

    assert result(report, "gpu").status == expected
    assert report.exit_code == 0


def test_gpu_not_applicable_fields_are_left_empty_not_guessed(stack):
    enable_localai(stack, "nvidia-cuda-13")
    check = result(
        run_doctor(stack, docker=nvidia_docker("0, Tesla T4, 535.1, [N/A], [N/A], [N/A], [N/A]\n")),
        "gpu",
    )

    assert check.status == PASS
    gpu = check.details["gpus"][0]
    assert gpu["memory_total_mib"] is None and gpu["vram_percent"] is None
    assert gpu["utilization_percent"] is None and gpu["temperature_c"] is None
    assert check.summary == "Tesla T4"


def test_gpu_several_cards_are_listed_and_the_hot_one_is_named(stack):
    enable_localai(stack, "nvidia-cuda-13")
    smi = "0, RTX A6000, 560.35, 49140, 1000, 2, 40\n1, RTX A6000, 560.35, 49140, 48000, 99, 70\n"
    check = result(run_doctor(stack, docker=nvidia_docker(smi)), "gpu")

    assert check.status == WARN
    assert [g["index"] for g in check.details["gpus"]] == [0, 1]
    assert "GPU 1 VRAM 98 % used" in check.summary
    assert "GPU 0 VRAM" not in check.summary


def test_gpu_nvidia_without_the_driver_fails(stack):
    enable_localai(stack, "nvidia-cuda-13")
    docker = healthy_docker()  # no nvidia-smi on this host
    report = run_doctor(stack, docker=docker)
    check = result(report, "gpu")

    assert check.status == FAIL
    assert "driver is not installed" in check.summary
    assert report.exit_code == 2


@pytest.mark.parametrize(
    ("smi", "reason"),
    [
        (CommandResult(9, "No devices were found\n", ""), "No devices were found"),
        (CommandResult(1, "", "Failed to initialize NVML\n"), "Failed to initialize NVML"),
    ],
)
def test_gpu_nvidia_that_cannot_talk_to_the_driver_fails_with_its_message(stack, smi, reason):
    enable_localai(stack, "nvidia-cuda-13")
    check = result(run_doctor(stack, docker=nvidia_docker(smi)), "gpu")

    assert check.status == FAIL
    assert reason in check.summary


def test_gpu_nvidia_that_hangs_is_a_warning(stack):
    enable_localai(stack, "nvidia-cuda-13")
    check = result(
        run_doctor(stack, docker=nvidia_docker(CommandResult(124, "", "timed out"))), "gpu"
    )

    assert check.status == WARN
    assert "timed out" in check.summary


def test_gpu_nvidia_output_that_cannot_be_read_is_a_warning(stack):
    enable_localai(stack, "nvidia-cuda-13")
    check = result(run_doctor(stack, docker=nvidia_docker("a different format\n")), "gpu")

    assert check.status == WARN


@pytest.mark.parametrize(
    "runtimes",
    [
        '{"runc":{"path":"runc"}}',
        # `nvidia` only inside a value: Docker's runtime entries carry long annotations.
        '{"runc":{"path":"runc","status":{"note":"works with nvidia hardware"}}}',
    ],
)
def test_gpu_nvidia_runtime_missing_from_docker_fails(stack, runtimes):
    enable_localai(stack, "nvidia-cuda-13")
    docker = nvidia_docker(runtimes=runtimes)
    check = result(run_doctor(stack, docker=docker), "gpu")

    assert check.status == FAIL
    assert "Container Toolkit" in check.summary
    assert check.details["nvidia_runtime"] is False
    assert check.details["gpus"]  # what was measured is not thrown away


def test_gpu_nvidia_runtime_that_cannot_be_asked_is_not_held_against_the_host(stack):
    enable_localai(stack, "nvidia-cuda-13")
    docker = nvidia_docker()
    docker.runtimes = CommandResult(1, "", "daemon down")
    check = result(run_doctor(stack, docker=docker), "gpu")

    assert check.status == PASS
    assert check.details["nvidia_runtime"] is None


def test_gpu_nvidia_runtime_output_that_is_not_json_is_not_held_against_the_host(stack):
    enable_localai(stack, "nvidia-cuda-13")
    check = result(run_doctor(stack, docker=nvidia_docker(runtimes="not json")), "gpu")

    assert check.status == PASS
    assert check.details["nvidia_runtime"] is None


def test_gpu_amd_without_the_rocm_driver_fails(stack, tmp_path):
    enable_localai(stack, "hipblas")
    check = result(run_doctor(stack, docker=nvidia_docker(), dev_root=fake_dev(tmp_path)), "gpu")

    assert check.status == FAIL
    assert "/dev/kfd" in check.summary


def test_gpu_amd_reports_vram_use_and_prefers_the_edge_temperature(stack, tmp_path):
    enable_localai(stack, "hipblas")
    check = result(
        run_doctor(stack, docker=nvidia_docker(), dev_root=fake_dev(tmp_path, kfd=True)), "gpu"
    )

    assert check.status == PASS
    assert check.details["gpus"] == [
        {
            "index": 0,
            "name": None,
            "driver": None,
            "memory_total_mib": 16368,
            "memory_used_mib": 1024,
            "vram_percent": 6.3,
            "utilization_percent": 7,
            "temperature_c": 41,
        }
    ]
    assert check.summary == "GPU 0: 1.0/16.0 GiB VRAM, 7 % util, 41C"


@pytest.mark.parametrize(
    ("smi", "reason"),
    [
        (not_found("rocm-smi"), "not installed"),
        (CommandResult(0, "not json", ""), "unreadable"),
        (CommandResult(0, '{"card0": {"Something else": "1"}}', ""), "unreadable"),
        (CommandResult(1, "", "ROCm error"), "unreadable"),
    ],
)
def test_gpu_amd_without_readable_figures_passes_with_a_note(stack, tmp_path, smi, reason):
    enable_localai(stack, "hipblas")
    docker = healthy_docker(tools={"rocm-smi": smi})
    check = result(run_doctor(stack, docker=docker, dev_root=fake_dev(tmp_path, kfd=True)), "gpu")

    assert check.status == PASS
    assert check.details["utilization_measured"] is False
    assert reason in check.summary


def test_gpu_amd_that_hangs_is_a_warning(stack, tmp_path):
    enable_localai(stack, "hipblas")
    docker = healthy_docker(tools={"rocm-smi": CommandResult(124, "", "timed out")})
    check = result(run_doctor(stack, docker=docker, dev_root=fake_dev(tmp_path, kfd=True)), "gpu")

    assert check.status == WARN


def test_gpu_intel_needs_a_render_node(stack, tmp_path):
    enable_localai(stack, "intel")

    present = result(run_doctor(stack, dev_root=fake_dev(tmp_path, render_node=True)), "gpu")
    missing = result(run_doctor(stack, dev_root=fake_dev(tmp_path / "other")), "gpu")

    assert present.status == PASS
    assert "not measured" in present.summary
    assert missing.status == FAIL
    assert "/dev/dri" in missing.summary


def test_gpu_vulkan_without_a_render_node_falls_back_to_the_cpu_with_a_warning(stack, tmp_path):
    enable_localai(stack, "vulkan")

    present = result(run_doctor(stack, dev_root=fake_dev(tmp_path, render_node=True)), "gpu")
    missing = result(run_doctor(stack, dev_root=fake_dev(tmp_path / "other")), "gpu")

    assert present.status == PASS
    assert missing.status == WARN
    assert "falls back to the CPU" in missing.summary


def test_parse_nvidia_smi_keeps_a_comma_inside_the_name():
    gpus = doctor.parse_nvidia_smi("2, Odd, Card Name, 535.1, 8192, 100, 5, 33\n")

    assert gpus[0]["name"] == "Odd, Card Name"
    assert gpus[0]["driver"] == "535.1"
    assert gpus[0]["memory_total_mib"] == 8192
    assert gpus[0]["index"] == 2


def test_parse_nvidia_smi_drops_lines_that_do_not_fit():
    assert doctor.parse_nvidia_smi("\nNVIDIA-SMI has failed\nx, y, z\n") == []


@pytest.mark.parametrize("value", ["nan", "inf", "-inf"])
def test_parse_nvidia_smi_treats_non_finite_numbers_as_unavailable(value):
    gpus = doctor.parse_nvidia_smi(f"0, Card, 535.1, 8192, 100, {value}, 50\n")

    assert gpus[0]["utilization_percent"] is None


def test_parse_rocm_smi_orders_cards_numerically():
    card = {"VRAM Total Memory (B)": "1048576", "VRAM Total Used Memory (B)": "0"}
    gpus = doctor.parse_rocm_smi(json.dumps({"card10": card, "card2": card, "system": {}}))

    assert [g["index"] for g in gpus] == [2, 10]


# ─────────────────────────────────────────────────────────────────────────
# time_sync
# ─────────────────────────────────────────────────────────────────────────


def test_time_sync_passes_when_the_clock_is_synchronized(stack):
    check = result(run_doctor(stack), "time_sync")

    assert check.status == PASS
    assert check.details == {"ntp_synchronized": True}


def test_time_sync_warns_when_the_clock_drifts_but_does_not_fail_the_run(stack):
    docker = healthy_docker(tools={"timedatectl": CommandResult(0, "no\n", "")})
    report = run_doctor(stack, docker=docker)

    assert result(report, "time_sync").status == WARN
    assert result(report, "time_sync").details == {"ntp_synchronized": False}
    assert report.exit_code == 0


@pytest.mark.parametrize(
    "answer",
    [
        not_found("timedatectl"),
        CommandResult(1, "", "System has not been booted with systemd"),
        CommandResult(0, "maybe\n", ""),
    ],
)
def test_time_sync_is_skipped_where_the_clock_state_cannot_be_read(stack, answer):
    docker = healthy_docker(tools={"timedatectl": answer})

    assert result(run_doctor(stack, docker=docker), "time_sync").status == SKIP


def test_time_sync_is_skipped_inside_a_container_without_asking(stack):
    docker = healthy_docker()
    check = result(run_doctor(stack, docker=docker, in_container=lambda: True), "time_sync")

    assert check.status == SKIP
    assert not any(c[0] == "timedatectl" for c in docker.calls)


# ─────────────────────────────────────────────────────────────────────────
# ports
# ─────────────────────────────────────────────────────────────────────────


def test_ports_are_taken_from_the_compose_files_and_the_env(stack):
    set_env(stack, KEYCLOAK_EXT_PORT="8110", HOST_IP="0.0.0.0")
    probed: list[tuple[str, int]] = []

    def connect(host, port):
        probed.append((host, port))
        return False

    check = result(run_doctor(stack, connect=connect), "ports")

    assert check.status == PASS
    assert probed == [("127.0.0.1", 8110)]
    assert check.details["ports"][0]["services"] == ["keycloak"]


def test_a_port_held_by_this_installation_is_fine(stack):
    set_env(stack, KEYCLOAK_EXT_PORT="8110")
    check = result(run_doctor(stack, connect=lambda host, port: port == 8110), "ports")

    assert check.status == PASS
    assert check.details["ports"][0]["holder"] == "papaia-keycloak-1"
    assert "held" in check.summary


def test_a_port_held_by_something_else_fails(stack):
    set_env(stack, KEYCLOAK_EXT_PORT="9999")  # not the port our container publishes
    check = result(run_doctor(stack, connect=lambda host, port: port == 9999), "ports")

    assert check.status == FAIL
    assert "9999" in check.summary and "keycloak" in check.summary


def test_a_busy_port_is_only_a_warning_when_docker_cannot_say_whose_it_is(stack):
    set_env(stack, KEYCLOAK_EXT_PORT="8110")
    docker = healthy_docker(ps_result=CommandResult(1, "", "no daemon"))
    check = result(run_doctor(stack, docker=docker, connect=lambda host, port: True), "ports")

    assert check.status == WARN


def test_a_fixed_bind_address_in_the_compose_file_is_the_one_probed(stack):
    set_env(stack, KEYCLOAK_EXT_PORT="8110", HOST_IP="192.0.2.10")
    stack_repo_compose = stack["repo"] / "src" / "infra" / "keycloak" / "docker-compose.yml"
    stack_repo_compose.write_text(
        stack_repo_compose.read_text(encoding="utf-8").replace("${HOST_IP:-0.0.0.0}", "127.0.0.1"),
        encoding="utf-8",
    )
    probed: list[str] = []
    result(run_doctor(stack, connect=lambda host, port: probed.append(host) or False), "ports")

    assert probed == ["127.0.0.1"]


def test_unresolvable_port_variables_are_ignored(stack):
    # KEYCLOAK_EXT_PORT is not set anywhere: the entry cannot be resolved.
    (stack["config"] / ".env").write_text(
        "COMPOSE_PROJECT_NAME=papaia\nCOMPOSE_PROFILES=keycloak\n", encoding="utf-8"
    )
    check = result(run_doctor(stack), "ports")

    assert check.status == SKIP
    assert "no published ports" in check.summary


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ("80:80", ("", 80)),
        ("0.0.0.0:8110:8443", ("0.0.0.0", 8110)),
        ("127.0.0.1:8181:81", ("127.0.0.1", 8181)),
        ("${HOST_IP:-0.0.0.0}:${P}:3080", ("0.0.0.0", 8000)),
        ("8000:8000/udp", ("", 8000)),
        ("8080", None),  # ephemeral host port
        ("8000-8002:8000-8002", None),  # range
        ("${UNSET}:3080", None),
    ],
)
def test_published_host_port_parsing(entry, expected):
    assert doctor._published_host_port(entry, {"P": "8000"}) == expected


# ─────────────────────────────────────────────────────────────────────────
# dns
# ─────────────────────────────────────────────────────────────────────────


def test_public_hostnames_are_looked_up(stack):
    set_env(
        stack, PAPAIA_HOST="https://papaia.example.org", AUTH_HOST="https://auth.example.org:8110"
    )
    asked: list[str] = []

    def resolve(host):
        asked.append(host)
        return doctor.RESOLVED

    check = result(run_doctor(stack, resolve=resolve), "dns")

    assert check.status == PASS
    assert asked == ["papaia.example.org", "auth.example.org"]


def test_a_name_that_does_not_resolve_is_a_warning(stack):
    set_env(stack, PAPAIA_HOST="https://gone.example.org")
    check = result(run_doctor(stack, resolve=lambda host: doctor.NOT_FOUND), "dns")

    assert check.status == WARN
    assert "gone.example.org" in check.summary


def test_an_unreachable_resolver_skips_instead_of_warning(stack):
    set_env(stack, PAPAIA_HOST="https://papaia.example.org")
    check = result(run_doctor(stack, resolve=lambda host: doctor.UNAVAILABLE), "dns")

    assert check.status == SKIP
    assert "offline" in check.summary


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000",
        "http://host.docker.internal",
        "http://127.0.0.1:8080",
        "http://192.168.1.10",
        "http://papaia",  # single label
        "http://[::1]:8000",
        "",
    ],
)
def test_local_names_are_not_looked_up(url):
    assert doctor._public_hostname(url) is None


def test_only_hostnames_of_active_profiles_are_checked(stack):
    set_env(stack, LITELLM_PUBLIC_URL="https://litellm.example.org")  # litellm is not active
    asked: list[str] = []
    run_doctor(stack, resolve=lambda host: asked.append(host) or doctor.RESOLVED)

    assert "litellm.example.org" not in asked


def test_the_external_oidc_issuer_is_checked_for_external_oidc(stack):
    set_env(stack, AUTH_PROVIDER="external_oidc", OIDC_ISSUER="https://idp.example.org/realms/x")
    asked: list[str] = []
    run_doctor(stack, resolve=lambda host: asked.append(host) or doctor.RESOLVED)

    assert asked == ["idp.example.org"]


# ─────────────────────────────────────────────────────────────────────────
# certs
# ─────────────────────────────────────────────────────────────────────────


def _cert_days(days_by_name: dict[str, int]):
    def enddate(path, run):
        return NOW + timedelta(days=days_by_name[path.name], hours=1)

    return enddate


def test_certs_report_days_until_expiry(stack):
    add_certs(stack, "local-ca.crt", "keycloak.crt")
    check = result(
        run_doctor(stack, cert_enddate=_cert_days({"local-ca.crt": 3000, "keycloak.crt": 200})),
        "certs",
    )

    assert check.status == PASS
    assert "certs/keycloak.crt expires in 200 day(s)" in check.summary
    days = {c["path"]: c["days_left"] for c in check.details["certificates"]}
    assert days == {"certs/keycloak.crt": 200, "certs/local-ca.crt": 3000}


@pytest.mark.parametrize(
    ("days", "expected"),
    [(365, PASS), (30, PASS), (29, WARN), (7, WARN), (6, FAIL), (0, FAIL), (-3, FAIL)],
)
def test_cert_thresholds(stack, days, expected):
    add_certs(stack, "keycloak.crt")
    check = result(run_doctor(stack, cert_enddate=_cert_days({"keycloak.crt": days})), "certs")

    assert check.status == expected


def test_an_expired_certificate_says_so(stack):
    add_certs(stack, "keycloak.crt")
    check = result(run_doctor(stack, cert_enddate=_cert_days({"keycloak.crt": -3})), "certs")

    assert "expired 3 day(s) ago" in check.summary


def test_lets_encrypt_certificates_on_disk_are_included(stack):
    live = stack["config"] / "infra" / "nginx" / "nginx-letsencrypt" / "live" / "npm-1"
    live.mkdir(parents=True)
    (live / "fullchain.pem").write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    check = result(
        run_doctor(stack, cert_enddate=lambda path, run: NOW + timedelta(days=12)), "certs"
    )

    assert check.status == WARN
    assert check.details["certificates"][0]["path"].endswith("live/npm-1/fullchain.pem")


def test_no_certificates_means_skip(stack):
    assert result(run_doctor(stack), "certs").status == SKIP


def test_unreadable_certificates_skip_the_check_with_the_reason(stack):
    add_certs(stack, "keycloak.crt")

    def broken(path, run):
        raise CertReadError("openssl not found")

    check = result(run_doctor(stack, cert_enddate=broken), "certs")

    assert check.status == SKIP
    assert "openssl not found" in check.summary


def test_cert_enddate_parses_openssl_output():
    def run(cmd, timeout):
        assert cmd[:2] == ["openssl", "x509"]
        return CommandResult(0, "notAfter=Sep  7 10:15:00 2036 GMT\n", "")

    assert doctor._cert_enddate(Path("x.crt"), run) == datetime(
        2036, 9, 7, 10, 15, tzinfo=NOW.tzinfo
    )


def test_cert_enddate_reports_missing_openssl_and_bad_files():
    with pytest.raises(CertReadError, match="openssl not found"):
        doctor._cert_enddate(Path("x"), lambda cmd, t: CommandResult(127, "", "not found"))
    with pytest.raises(CertReadError, match="unable to load certificate"):
        doctor._cert_enddate(
            Path("x"), lambda cmd, t: CommandResult(1, "", "unable to load certificate\n")
        )
    with pytest.raises(CertReadError, match="unexpected date format"):
        doctor._cert_enddate(
            Path("x"), lambda cmd, t: CommandResult(0, "notAfter=tomorrow-ish\n", "")
        )


# ─────────────────────────────────────────────────────────────────────────
# addon_compat
# ─────────────────────────────────────────────────────────────────────────


def test_compatible_addons_pass(stack):
    check = result(run_doctor(stack), "addon_compat")

    assert check.status == PASS
    assert check.details["addons"][0]["compat_status"] == "OK"


def test_incompatible_addon_fails_in_enforce_mode(stack):
    (stack["addon"] / "papaia-app.yaml").write_text(
        'name: paperless\npapaia_compat: ">=99.0.0"\n', encoding="utf-8"
    )
    check = result(run_doctor(stack), "addon_compat")

    assert check.status == FAIL
    assert "paperless: INCOMPATIBLE" in check.summary


def test_incompatible_addon_is_a_warning_in_warn_mode(stack, monkeypatch):
    (stack["addon"] / "papaia-app.yaml").write_text(
        'name: paperless\npapaia_compat: ">=99.0.0"\n', encoding="utf-8"
    )
    monkeypatch.setenv("PAPAIA_COMPAT_MODE", "warn")
    check = result(run_doctor(stack), "addon_compat")

    assert check.status == WARN
    assert check.details["mode"] == "warn"


def test_addon_without_a_requirement_is_unknown_and_warns(stack):
    (stack["addon"] / "papaia-app.yaml").write_text("name: paperless\n", encoding="utf-8")

    assert result(run_doctor(stack), "addon_compat").status == WARN


def test_addon_with_a_missing_manifest_is_an_error_and_fails(stack):
    (stack["addon"] / "papaia-app.yaml").unlink()
    check = result(run_doctor(stack), "addon_compat")

    assert check.status == FAIL
    assert "ERROR" in check.summary


def test_addon_compat_gives_the_verdict_addon_check_gives(stack, capsys):
    """Folded in, not duplicated: both go through evaluate_active_addons."""
    (stack["addon"] / "papaia-app.yaml").write_text(
        'name: paperless\npapaia_compat: ">=99.0.0"\n', encoding="utf-8"
    )
    code = cli.main(
        [
            "--repo-root",
            str(stack["repo"]),
            "--config-dir",
            str(stack["config"]),
            "addon-check",
            "--json",
        ]
    )
    verdict = json.loads(capsys.readouterr().out)[0]

    check = result(run_doctor(stack), "addon_compat")
    assert (code, verdict["status"]) == (2, "INCOMPATIBLE")
    assert check.details["addons"][0]["compat_status"] == verdict["status"]
    assert check.details["addons"][0]["reason"] == verdict["reason"]


def test_no_active_addons_passes(stack):
    deployment_file = stack["config"] / "deployment.yaml"
    deployment_file.write_text("addons: []\n", encoding="utf-8")

    assert result(run_doctor(stack), "addon_compat").status == PASS


# ─────────────────────────────────────────────────────────────────────────
# container_health
# ─────────────────────────────────────────────────────────────────────────


def test_unhealthy_and_stopped_modules_fail(stack):
    live = [
        line.replace("Up 2 hours (healthy)", "Up 2 hours (unhealthy)", 1) for line in healthy_core()
    ]
    check = result(run_doctor(stack, docker=FakeDocker(live + healthy_addon())), "container_health")

    assert check.status == FAIL
    assert "keycloak (unhealthy)" in check.summary


def test_a_never_started_module_is_only_a_warning(stack):
    live = [line for line in healthy_core() if "oauth2-proxy" not in line]
    check = result(run_doctor(stack, docker=FakeDocker(live + healthy_addon())), "container_health")

    assert check.status == WARN
    assert "auth (missing)" in check.summary


def test_docker_unreachable_is_a_warning_not_an_outage(stack):
    docker = healthy_docker(ps_result=CommandResult(1, "", "Cannot connect to the Docker daemon"))
    check = result(run_doctor(stack, docker=docker), "container_health")

    assert check.status == WARN
    assert "unknown" in check.summary


def test_container_health_reuses_one_status_reading(stack):
    docker = healthy_docker()
    run_doctor(stack, docker=docker)

    assert sum(1 for c in docker.calls if c[:3] == ["docker", "ps", "-a"]) == 1


# ─────────────────────────────────────────────────────────────────────────
# before setup, and read-only
# ─────────────────────────────────────────────────────────────────────────


def test_doctor_works_before_setup(tmp_path, stack):
    nowhere = tmp_path / "never-set-up"
    report = doctor.run_checks(
        nowhere, stack["repo"], run=healthy_docker(), probes=probes(), now=NOW
    )

    by_name = {c.name: c.status for c in report.checks}
    assert by_name["docker_version"] == PASS
    assert by_name["disk_space"] == PASS
    # The host checks do not depend on the installation's configuration, except
    # the GPU one, which needs to know the configured LocalAI variant.
    assert by_name["memory"] == PASS
    assert by_name["cpu"] == PASS
    assert by_name["time_sync"] == PASS
    assert by_name["gpu"] == SKIP
    assert by_name["ports"] == SKIP
    assert by_name["dns"] == SKIP
    assert by_name["certs"] == SKIP
    assert by_name["addon_compat"] == SKIP
    assert by_name["container_health"] == SKIP
    assert report.exit_code == 0
    assert not nowhere.exists()


def _tree_state(root: Path) -> dict[str, tuple[int, int]]:
    return {
        str(p.relative_to(root)): (p.stat().st_size, p.stat().st_mtime_ns)
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


@pytest.mark.parametrize("variant", ["nvidia-cuda-13", "hipblas"])
def test_doctor_writes_nothing(stack, tmp_path, variant):
    set_env(stack, KEYCLOAK_EXT_PORT="8110", PAPAIA_HOST="https://papaia.example.org")
    add_certs(stack, "local-ca.crt")
    enable_localai(stack, variant)
    dev = fake_dev(tmp_path, kfd=True)
    before = _tree_state(tmp_path)
    docker = nvidia_docker()
    run_doctor(stack, docker=docker, dev_root=dev)

    assert _tree_state(tmp_path) == before
    # Reads only: `docker` queries and the three host tools, each asked a question.
    allowed = {
        ("docker", "ps"),
        ("docker", "inspect"),
        ("docker", "version"),
        ("docker", "compose"),
        ("docker", "info"),
        ("nvidia-smi", "--query-gpu=" + doctor._NVIDIA_QUERY),
        ("rocm-smi", "--showmeminfo"),
        ("timedatectl", "show"),
    }
    assert {tuple(c[:2]) for c in docker.calls} <= allowed


# ─────────────────────────────────────────────────────────────────────────
# output and CLI
# ─────────────────────────────────────────────────────────────────────────


def test_table_lists_every_check_and_a_summary_line(stack):
    table = doctor.format_table(run_doctor(stack))

    for name in doctor.CHECK_NAMES:
        assert name in table
    assert table.splitlines()[-1].endswith("skip")
    assert "pass," in table.splitlines()[-1]


def test_json_carries_what_the_table_shows(stack):
    report = run_doctor(stack)
    document = json.loads(doctor.to_json(report))

    assert [c["name"] for c in document["checks"]] == list(doctor.CHECK_NAMES)
    assert document["summary"] == report.summary
    assert document["ok"] is True
    table = doctor.format_table(report)
    for check in document["checks"]:
        assert check["summary"] in table


def _run_cli(stack, monkeypatch, docker, *args):
    monkeypatch.setattr(status, "run_command", docker)
    monkeypatch.setattr(doctor, "Probes", lambda: probes())
    return cli.main(
        ["--repo-root", str(stack["repo"]), "--config-dir", str(stack["config"]), "doctor", *args]
    )


def test_cli_exit_code_and_json_for_a_healthy_installation(stack, monkeypatch, capsys):
    code = _run_cli(stack, monkeypatch, healthy_docker(), "--json")

    document = json.loads(capsys.readouterr().out)
    assert code == 0
    assert document["ok"] is True


def test_cli_exits_2_when_a_check_fails(stack, monkeypatch, capsys):
    docker = healthy_docker(engine=CommandResult(1, "", "no daemon"))
    code = _run_cli(stack, monkeypatch, docker, "--json")

    document = json.loads(capsys.readouterr().out)
    assert code == 2
    assert document["ok"] is False
    assert document["summary"]["fail"] >= 1


def test_cli_skip_flag_accepts_repeated_and_comma_separated_values(stack, monkeypatch, capsys):
    code = _run_cli(
        stack, monkeypatch, healthy_docker(), "--json", "--skip=dns,certs", "--skip=ports"
    )

    statuses = {c["name"]: c["summary"] for c in json.loads(capsys.readouterr().out)["checks"]}
    assert code == 0
    assert [n for n, s in statuses.items() if s == "skipped (--skip)"] == ["ports", "dns", "certs"]


def test_cli_unknown_skip_name_exits_2_with_the_valid_names_on_stderr(stack, monkeypatch, capsys):
    code = _run_cli(stack, monkeypatch, healthy_docker(), "--skip=nope")

    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert "nope" in captured.err and "docker_version" in captured.err
