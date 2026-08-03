from __future__ import annotations

from pathlib import Path

import pytest

from lib import gpu_detect


def _fake_drm(tmp_path: Path, *vendors: str) -> Path:
    """A stand-in for /sys/class/drm with one card per vendor id."""
    drm = tmp_path / "drm"
    for index, vendor in enumerate(vendors):
        device = drm / f"card{index}" / "device"
        device.mkdir(parents=True)
        (device / "vendor").write_text(f"{vendor}\n", encoding="utf-8")
    drm.mkdir(parents=True, exist_ok=True)
    return drm


def _fake_dev(tmp_path: Path, *nodes: str) -> Path:
    """A stand-in for /dev. `nodes` are paths relative to it, e.g. "dri/renderD128"."""
    dev = tmp_path / "dev"
    dev.mkdir(parents=True, exist_ok=True)
    for node in nodes:
        path = dev / node
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    return dev


@pytest.fixture
def no_nvidia(monkeypatch):
    monkeypatch.setattr(gpu_detect.shutil, "which", lambda _name: None)
    monkeypatch.setattr(gpu_detect, "_run", lambda *_a, **_k: None)


def _nvidia_probe(banner: str | None, query: str | None):
    def _run(cmd, timeout=5.0):  # noqa: ARG001 - signature mirrors the real probe
        if cmd[:1] == ["nvidia-smi"] and len(cmd) == 1:
            return banner
        if cmd[:1] == ["nvidia-smi"]:
            return query
        if cmd[:1] == ["docker"]:
            return '{"nvidia":{}}'
        return None

    return _run


# ─────────────────────────────────────────────────────────────────────────
# Tag catalogue


def test_every_variant_has_a_tag_suffix():
    assert set(gpu_detect.VARIANTS) == set(gpu_detect.TAG_SUFFIX)
    assert gpu_detect.TAG_SUFFIX[gpu_detect.CPU] == ""
    # CPU is the only variant that maps to the plain pinned tag.
    assert all(suffix for name, suffix in gpu_detect.TAG_SUFFIX.items() if name != gpu_detect.CPU)


# ─────────────────────────────────────────────────────────────────────────
# Compose fragments


def test_compose_fragment_cpu_is_empty():
    assert gpu_detect.compose_fragment(gpu_detect.CPU) == {}


def test_compose_fragment_unknown_variant_is_empty():
    assert gpu_detect.compose_fragment("does-not-exist") == {}


@pytest.mark.parametrize("variant", [gpu_detect.NVIDIA_CUDA_12, gpu_detect.NVIDIA_CUDA_13])
def test_compose_fragment_nvidia_reserves_a_gpu(variant):
    fragment = gpu_detect.compose_fragment(variant)
    device = fragment["deploy"]["resources"]["reservations"]["devices"][0]
    assert device == {"driver": "nvidia", "count": "all", "capabilities": ["gpu"]}
    assert "devices" not in fragment


def test_compose_fragment_intel_passes_dri_only():
    assert gpu_detect.compose_fragment(gpu_detect.INTEL) == {"devices": ["/dev/dri:/dev/dri"]}


def test_compose_fragment_hipblas_passes_kfd_and_video_group():
    fragment = gpu_detect.compose_fragment(gpu_detect.HIPBLAS)
    assert fragment["devices"] == ["/dev/dri:/dev/dri", "/dev/kfd:/dev/kfd"]
    assert fragment["group_add"] == ["video"]


def test_compose_fragment_vulkan_follows_present_device_nodes(tmp_path):
    dev = _fake_dev(tmp_path, "dri/renderD128")
    assert gpu_detect.compose_fragment(gpu_detect.VULKAN, dev) == {
        "devices": ["/dev/dri:/dev/dri"]
    }


def test_compose_fragment_vulkan_adds_rocm_and_nvidia_when_present(tmp_path):
    dev = _fake_dev(tmp_path, "dri/renderD128", "kfd", "nvidiactl")
    fragment = gpu_detect.compose_fragment(gpu_detect.VULKAN, dev)
    assert fragment["devices"] == ["/dev/dri:/dev/dri", "/dev/kfd:/dev/kfd"]
    assert fragment["group_add"] == ["video"]
    assert fragment["deploy"]["resources"]["reservations"]["devices"][0]["driver"] == "nvidia"


def test_compose_fragment_vulkan_on_bare_host_is_empty(tmp_path):
    assert gpu_detect.compose_fragment(gpu_detect.VULKAN, _fake_dev(tmp_path)) == {}


# ─────────────────────────────────────────────────────────────────────────
# NVIDIA detection


def test_nvidia_detected_from_banner_cuda_version(monkeypatch):
    monkeypatch.setattr(gpu_detect.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(
        gpu_detect,
        "_run",
        _nvidia_probe(
            banner="| NVIDIA-SMI 580.65.06   Driver Version: 580.65.06   CUDA Version: 13.0 |",
            query="NVIDIA GeForce RTX 4090, 580.65.06\n",
        ),
    )
    info = gpu_detect._detect_nvidia()
    assert info.variant == gpu_detect.NVIDIA_CUDA_13
    assert "RTX 4090" in info.label
    assert info.warning == ""


def test_nvidia_falls_back_to_cuda_12_on_older_driver(monkeypatch):
    monkeypatch.setattr(gpu_detect.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(
        gpu_detect,
        "_run",
        _nvidia_probe(
            banner="| NVIDIA-SMI 550.54.14   Driver Version: 550.54.14   CUDA Version: 12.4 |",
            query="NVIDIA A100, 550.54.14\n",
        ),
    )
    assert gpu_detect._detect_nvidia().variant == gpu_detect.NVIDIA_CUDA_12


def test_nvidia_derives_cuda_major_from_driver_when_banner_is_unusable(monkeypatch):
    monkeypatch.setattr(gpu_detect.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(
        gpu_detect, "_run", _nvidia_probe(banner="unparseable", query="NVIDIA L40S, 580.82.07\n")
    )
    assert gpu_detect._detect_nvidia().variant == gpu_detect.NVIDIA_CUDA_13


def test_nvidia_future_cuda_major_maps_to_the_newest_published_image(monkeypatch):
    monkeypatch.setattr(gpu_detect.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(
        gpu_detect,
        "_run",
        _nvidia_probe(banner="CUDA Version: 14.0", query="NVIDIA Future, 999.0\n"),
    )
    info = gpu_detect._detect_nvidia()
    assert info.variant == gpu_detect.NVIDIA_CUDA_13
    assert "CUDA 13" in info.label


def test_nvidia_driver_too_old_is_not_offered(monkeypatch):
    monkeypatch.setattr(gpu_detect.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(
        gpu_detect,
        "_run",
        _nvidia_probe(banner="no cuda line here", query="NVIDIA GTX 970, 470.10\n"),
    )
    info = gpu_detect._detect_nvidia()
    assert not info.available
    assert "CUDA 12" in info.label


def test_nvidia_absent_without_nvidia_smi(no_nvidia):
    info = gpu_detect._detect_nvidia()
    assert not info.available
    assert info.label == "no NVIDIA GPU detected"


def test_nvidia_smi_present_but_reporting_nothing(monkeypatch):
    monkeypatch.setattr(gpu_detect.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(gpu_detect, "_run", lambda *_a, **_k: "")
    assert not gpu_detect._detect_nvidia().available


def test_nvidia_warns_when_container_runtime_is_missing(monkeypatch):
    monkeypatch.setattr(
        gpu_detect.shutil,
        "which",
        lambda name: None if name == "nvidia-ctk" else "/usr/bin/" + name,
    )

    def _run(cmd, timeout=5.0):  # noqa: ARG001
        if cmd[:1] == ["docker"]:
            return '{"runc":{}}'
        if len(cmd) == 1:
            return "CUDA Version: 13.0"
        return "NVIDIA RTX 4090, 580.65.06\n"

    monkeypatch.setattr(gpu_detect, "_run", _run)
    info = gpu_detect._detect_nvidia()
    # Still selectable — the operator may install the toolkit afterwards.
    assert info.variant == gpu_detect.NVIDIA_CUDA_13
    assert "Container Toolkit" in info.warning


# ─────────────────────────────────────────────────────────────────────────
# Vendor detection


def test_intel_detected_from_vendor_and_render_node(tmp_path, no_nvidia):
    detection = gpu_detect.detect(
        _fake_drm(tmp_path, gpu_detect._VENDOR_INTEL), _fake_dev(tmp_path, "dri/renderD128")
    )
    assert detection.slots["intel"].variant == gpu_detect.INTEL
    assert detection.recommended == gpu_detect.INTEL


def test_intel_card_without_render_node_is_not_offered(tmp_path, no_nvidia):
    detection = gpu_detect.detect(
        _fake_drm(tmp_path, gpu_detect._VENDOR_INTEL), _fake_dev(tmp_path)
    )
    assert not detection.slots["intel"].available
    assert detection.recommended == gpu_detect.CPU


def test_amd_with_rocm_is_recommended_over_vulkan(tmp_path, no_nvidia):
    detection = gpu_detect.detect(
        _fake_drm(tmp_path, gpu_detect._VENDOR_AMD),
        _fake_dev(tmp_path, "dri/renderD128", "kfd"),
    )
    assert detection.slots["amd"].variant == gpu_detect.HIPBLAS
    assert detection.slots["vulkan"].variant == gpu_detect.VULKAN
    assert detection.recommended == gpu_detect.HIPBLAS


def test_amd_without_rocm_falls_back_to_vulkan(tmp_path, no_nvidia):
    detection = gpu_detect.detect(
        _fake_drm(tmp_path, gpu_detect._VENDOR_AMD), _fake_dev(tmp_path, "dri/renderD128")
    )
    assert not detection.slots["amd"].available
    assert "ROCm" in detection.slots["amd"].label
    assert detection.recommended == gpu_detect.VULKAN


def test_unknown_vendor_with_render_node_gets_vulkan(tmp_path, no_nvidia):
    detection = gpu_detect.detect(
        _fake_drm(tmp_path, "0xdead"), _fake_dev(tmp_path, "dri/renderD128")
    )
    assert not detection.slots["intel"].available
    assert not detection.slots["amd"].available
    assert detection.recommended == gpu_detect.VULKAN


def test_bare_host_falls_back_to_cpu(tmp_path, no_nvidia):
    detection = gpu_detect.detect(_fake_drm(tmp_path), _fake_dev(tmp_path))
    assert detection.recommended == gpu_detect.CPU
    assert detection.slots["cpu"].available
    assert not any(detection.slots[slot].available for slot in ("nvidia", "amd", "intel", "vulkan"))


def test_missing_sysfs_and_dev_do_not_raise(tmp_path, no_nvidia):
    detection = gpu_detect.detect(tmp_path / "nope", tmp_path / "also-nope")
    assert detection.recommended == gpu_detect.CPU


def test_nvidia_outranks_every_other_accelerator(tmp_path, monkeypatch):
    monkeypatch.setattr(gpu_detect.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(
        gpu_detect,
        "_run",
        _nvidia_probe(banner="CUDA Version: 13.0", query="NVIDIA RTX 4090, 580.65.06\n"),
    )
    detection = gpu_detect.detect(
        _fake_drm(tmp_path, gpu_detect._VENDOR_AMD, gpu_detect._VENDOR_INTEL),
        _fake_dev(tmp_path, "dri/renderD128", "kfd"),
    )
    assert detection.recommended == gpu_detect.NVIDIA_CUDA_13


# ─────────────────────────────────────────────────────────────────────────
# Shell handoff


def test_detection_vars_cover_every_slot(tmp_path, no_nvidia):
    out = gpu_detect.detection_vars(gpu_detect.detect(_fake_drm(tmp_path), _fake_dev(tmp_path)))
    for slot in gpu_detect.SLOTS:
        prefix = f"LOCALAI_VARIANT_{slot.upper()}"
        assert prefix in out
        assert f"{prefix}_LABEL" in out
        assert f"{prefix}_WARN" in out
    assert out["LOCALAI_VARIANT_RECOMMENDED"] == gpu_detect.CPU
    assert out["LOCALAI_VARIANT_CPU"] == gpu_detect.CPU
    assert out["LOCALAI_VARIANT_NVIDIA"] == ""


def test_detection_vars_stay_single_line(tmp_path, no_nvidia):
    """The bash side parses these with a line-oriented read loop."""
    out = gpu_detect.detection_vars(
        gpu_detect.detect(_fake_drm(tmp_path, gpu_detect._VENDOR_AMD), _fake_dev(tmp_path))
    )
    for key, value in out.items():
        assert "\n" not in value, key
        assert "=" not in key
