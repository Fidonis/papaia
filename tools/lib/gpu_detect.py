"""LocalAI image-variant catalogue and host capability detection.

Upstream publishes one image per accelerator for every LocalAI release: a
plain CPU tag plus `-gpu-nvidia-cuda-12`, `-gpu-nvidia-cuda-13`, `-gpu-intel`,
`-gpu-hipblas` and `-gpu-vulkan`. This module owns two things:

  * the catalogue -- which variants exist, what tag suffix each one carries
    and which Compose keys it needs to reach the device;
  * detection -- which of them this host can actually run.

Detection and Compose emission are deliberately split. `detect()` runs once,
during `papaia-ctl setup`, and may fork `nvidia-smi`. `compose_fragment()`
runs on every render (and therefore on every `papaia-ctl start`) and is
subprocess-free: it derives everything from the chosen variant plus plain
device-node checks, so a render never blocks on GPU tooling.

Only the x86_64 variants are catalogued. The `nvidia-l4t-arm64` (Jetson) tags
target a different architecture and host stack and are out of scope.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────
# Catalogue

CPU = "cpu"
NVIDIA_CUDA_12 = "nvidia-cuda-12"
NVIDIA_CUDA_13 = "nvidia-cuda-13"
INTEL = "intel"
HIPBLAS = "hipblas"
VULKAN = "vulkan"

# variant id -> tag suffix appended to the version pinned in the compose file
TAG_SUFFIX: dict[str, str] = {
    CPU: "",
    NVIDIA_CUDA_12: "-gpu-nvidia-cuda-12",
    NVIDIA_CUDA_13: "-gpu-nvidia-cuda-13",
    INTEL: "-gpu-intel",
    HIPBLAS: "-gpu-hipblas",
    VULKAN: "-gpu-vulkan",
}

VARIANTS: tuple[str, ...] = tuple(TAG_SUFFIX)

# Menu slots. The slot set is fixed so the wizard's numbering stays stable
# regardless of what was detected; the concrete variant behind the "nvidia"
# slot varies with the installed driver (CUDA 12 vs 13).
SLOTS: tuple[str, ...] = ("nvidia", "amd", "intel", "vulkan", "cpu")

# Preference order used to pick the recommended slot. Vendor-specific
# backends outrank Vulkan, which is the generic fallback for GPUs whose
# vendor path is unavailable (e.g. an AMD card without the ROCm driver).
_PREFERENCE: tuple[str, ...] = ("nvidia", "amd", "intel", "vulkan", "cpu")

# PCI vendor IDs as exposed by /sys/class/drm/card*/device/vendor
_VENDOR_INTEL = "0x8086"
_VENDOR_AMD = "0x1002"

_CUDA_VERSION_RE = re.compile(r"CUDA Version:\s*(\d+)\.(\d+)")

# The NVIDIA accelerator image of the voice TTS engine (the -cu128 pin in
# src/ai/voice/docker-compose.yml) declares NVIDIA_REQUIRE_CUDA=cuda>=12.8,
# with brand exceptions that do not cover GeForce cards — on a driver below
# this the NVIDIA runtime refuses the container. Keep in step with the pin.
VOICE_NVIDIA_MIN_CUDA = (12, 8)
_LEADING_INT_RE = re.compile(r"^\d+")

# Minimum NVIDIA driver branches per CUDA major, used only when the
# `nvidia-smi` banner does not carry a "CUDA Version:" line.
_DRIVER_MIN_CUDA_13 = 580
_DRIVER_MIN_CUDA_12 = 525

# Newest CUDA major an image is published for. A driver reporting anything
# above this still gets the newest image rather than no image at all.
_MAX_CUDA_MAJOR = 13


@dataclass
class SlotInfo:
    """One menu slot: which variant it resolves to and what to tell the operator."""

    variant: str = ""  # "" when this slot is not usable on the host
    label: str = ""  # detection result, shown next to the menu entry
    warning: str = ""  # unmet host prerequisite, shown but not disqualifying

    @property
    def available(self) -> bool:
        return bool(self.variant)


@dataclass
class Detection:
    slots: dict[str, SlotInfo] = field(default_factory=dict)
    recommended: str = CPU  # variant id
    # The voice TTS engine speaks a shorter vocabulary (cpu/nvidia/hipblas)
    # and its nvidia image has a CUDA floor, so its recommendation is derived
    # here, from the same probe, rather than re-mapped in the wizard.
    voice_recommended: str = CPU
    voice_nvidia_warning: str = ""  # set when a found NVIDIA GPU misses the CUDA floor


def cuda_version(banner: str) -> tuple[int, int] | None:
    """major.minor of the "CUDA Version:" line of a plain `nvidia-smi` banner."""
    match = _CUDA_VERSION_RE.search(banner or "")
    return (int(match.group(1)), int(match.group(2))) if match else None


# ─────────────────────────────────────────────────────────────────────────
# Compose emission (subprocess-free, safe to run on every render)


def _nvidia_reservation() -> dict:
    """The Compose spelling of `docker run --gpus all`."""
    return {
        "deploy": {
            "resources": {
                "reservations": {
                    "devices": [{"driver": "nvidia", "count": "all", "capabilities": ["gpu"]}]
                }
            }
        }
    }


def _vulkan_fragment(dev_root: Path) -> dict:
    """Vulkan runs on whatever GPU is present, so its device set is not fixed
    by the variant -- upstream documents a different set per vendor. Emit the
    union of the device nodes that actually exist on this host, which is what
    upstream's mixed-hardware example does."""
    devices: list[str] = []
    group_add: list[str] = []
    if (dev_root / "dri").exists():
        devices.append("/dev/dri:/dev/dri")
    if (dev_root / "kfd").exists():
        devices.append("/dev/kfd:/dev/kfd")
        group_add.append("video")

    fragment: dict = {}
    if devices:
        fragment["devices"] = devices
    if group_add:
        fragment["group_add"] = group_add
    if (dev_root / "nvidiactl").exists():
        fragment.update(_nvidia_reservation())
    return fragment


def compose_fragment(variant: str, dev_root: Path = Path("/dev")) -> dict:
    """The `services.localai` keys the given variant needs on top of the image.

    Returns {} for CPU and for unknown variants -- callers treat an empty
    fragment plus an unchanged image as "no override needed".
    """
    if variant in (NVIDIA_CUDA_12, NVIDIA_CUDA_13):
        return _nvidia_reservation()
    if variant == INTEL:
        return {"devices": ["/dev/dri:/dev/dri"]}
    if variant == HIPBLAS:
        # /dev/kfd is the ROCm kernel interface; the video group owns the
        # render nodes on most distributions.
        return {
            "devices": ["/dev/dri:/dev/dri", "/dev/kfd:/dev/kfd"],
            "group_add": ["video"],
        }
    if variant == VULKAN:
        return _vulkan_fragment(dev_root)
    return {}


# ─────────────────────────────────────────────────────────────────────────
# Detection (setup-time only)


def _run(cmd: list[str], timeout: float = 5.0) -> str | None:
    """Run a probe command, returning stdout or None on any failure.

    Every probe is best-effort: a missing binary, a timeout or a non-zero
    exit means "not detected", never a failed setup.
    """
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def _drm_vendors(sys_class_drm: Path) -> set[str]:
    """PCI vendor IDs of the DRM cards on this host."""
    vendors: set[str] = set()
    try:
        cards = sorted(sys_class_drm.glob("card*"))
    except OSError:
        return vendors
    for card in cards:
        try:
            vendors.add((card / "device" / "vendor").read_text(encoding="utf-8").strip().lower())
        except OSError:
            continue
    return vendors


def has_render_node(dev_root: Path) -> bool:
    try:
        return any((dev_root / "dri").glob("renderD*"))
    except OSError:
        return False


def _cuda_major_from_driver(driver_version: str) -> int | None:
    match = _LEADING_INT_RE.match(driver_version)
    if not match:
        return None
    branch = int(match.group())
    if branch >= _DRIVER_MIN_CUDA_13:
        return 13
    if branch >= _DRIVER_MIN_CUDA_12:
        return 12
    return None


def _detect_nvidia() -> tuple[SlotInfo, tuple[int, int] | None]:
    """The NVIDIA menu slot, plus the full CUDA version when it is known.

    The second value feeds the voice recommendation's CUDA floor. It comes
    from the banner's "CUDA Version:" line; when only the driver branch is
    readable, a 580+ branch proves CUDA 13 while a 12-branch driver's minor
    stays unknown (None), which the caller treats as below the floor."""
    if shutil.which("nvidia-smi") is None:
        return SlotInfo(label="no NVIDIA GPU detected"), None

    query = _run(["nvidia-smi", "--query-gpu=name,driver_version", "--format=csv,noheader"])
    if not query or not query.strip():
        return SlotInfo(label="nvidia-smi present but reported no GPU"), None

    name, _, driver = query.strip().splitlines()[0].partition(",")
    name = name.strip()
    driver = driver.strip()

    # The banner's "CUDA Version:" is the highest CUDA the installed driver
    # supports, which is exactly what picks the image. Fall back to the
    # driver branch when the banner is unavailable or reshaped.
    cuda: tuple[int, int] | None = None
    banner = _run(["nvidia-smi"])
    if banner:
        cuda = cuda_version(banner)
    cuda_major = cuda[0] if cuda is not None else _cuda_major_from_driver(driver)
    if cuda is None and cuda_major is not None and cuda_major >= 13:
        cuda = (cuda_major, 0)

    if cuda_major is None or cuda_major < 12:
        return SlotInfo(
            label=f"{name} detected, but the driver is older than CUDA 12 (driver {driver})"
        ), None

    variant = NVIDIA_CUDA_13 if cuda_major >= _MAX_CUDA_MAJOR else NVIDIA_CUDA_12
    label = f"{name}, driver {driver}, CUDA {min(cuda_major, _MAX_CUDA_MAJOR)}"
    warning = ""
    if not _nvidia_runtime_available():
        warning = "NVIDIA Container Toolkit not found - install it before starting the stack"
    return SlotInfo(variant=variant, label=label, warning=warning), cuda


def _nvidia_runtime_available() -> bool:
    """Whether Docker can hand a GPU to a container. Advisory only: setup may
    legitimately run before the toolkit is installed."""
    if shutil.which("nvidia-ctk") is not None:
        return True
    runtimes = _run(["docker", "info", "--format", "{{json .Runtimes}}"], timeout=10.0)
    return bool(runtimes) and "nvidia" in runtimes


def _detect_amd(vendors: set[str], dev_root: Path) -> SlotInfo:
    if _VENDOR_AMD not in vendors:
        return SlotInfo(label="no AMD GPU detected")
    if not (dev_root / "kfd").exists():
        # The card is there but ROCm's kernel interface is not, so the
        # hipBLAS image would start without an accelerator. Vulkan is the
        # working path for these hosts.
        return SlotInfo(label="AMD GPU detected, but the ROCm driver (/dev/kfd) is missing")
    return SlotInfo(variant=HIPBLAS, label="AMD GPU with ROCm driver detected")


def _detect_intel(vendors: set[str], dev_root: Path) -> SlotInfo:
    if _VENDOR_INTEL not in vendors:
        return SlotInfo(label="no Intel GPU detected")
    if not has_render_node(dev_root):
        return SlotInfo(label="Intel GPU detected, but no render node under /dev/dri")
    return SlotInfo(variant=INTEL, label="Intel GPU detected")


def _detect_vulkan(dev_root: Path) -> SlotInfo:
    if not has_render_node(dev_root):
        return SlotInfo(label="no render node under /dev/dri")
    return SlotInfo(variant=VULKAN, label="render node under /dev/dri available")


def detect(
    sys_class_drm: Path = Path("/sys/class/drm"), dev_root: Path = Path("/dev")
) -> Detection:
    """Probe the host for usable LocalAI image variants.

    Never raises: anything that cannot be probed counts as "not detected",
    and CPU is always available as the floor.
    """
    vendors = _drm_vendors(sys_class_drm)
    nvidia, nvidia_cuda = _detect_nvidia()
    slots = {
        "nvidia": nvidia,
        "amd": _detect_amd(vendors, dev_root),
        "intel": _detect_intel(vendors, dev_root),
        "vulkan": _detect_vulkan(dev_root),
        "cpu": SlotInfo(variant=CPU, label="runs on any hardware"),
    }

    recommended = CPU
    for slot in _PREFERENCE:
        if slots[slot].available:
            recommended = slots[slot].variant
            break

    # The voice recommendation applies the CUDA floor of the TTS engine's
    # nvidia image: a usable-for-LocalAI GPU below it gets a warning and no
    # recommendation, because the runtime would refuse that container.
    voice_recommended = CPU
    voice_nvidia_warning = ""
    if nvidia.available:
        if nvidia_cuda is not None and nvidia_cuda >= VOICE_NVIDIA_MIN_CUDA:
            voice_recommended = "nvidia"
        else:
            floor = ".".join(str(part) for part in VOICE_NVIDIA_MIN_CUDA)
            seen = (
                f"this driver reports CUDA {nvidia_cuda[0]}.{nvidia_cuda[1]}"
                if nvidia_cuda is not None
                else "this driver's CUDA minor version could not be read"
            )
            voice_nvidia_warning = (
                f"the TTS accelerator image needs CUDA >= {floor} and {seen}"
                " - the NVIDIA runtime would refuse the container"
            )
    if voice_recommended == CPU and slots["amd"].available:
        voice_recommended = HIPBLAS

    return Detection(
        slots=slots,
        recommended=recommended,
        voice_recommended=voice_recommended,
        voice_nvidia_warning=voice_nvidia_warning,
    )


def detection_vars(detection: Detection) -> dict[str, str]:
    """Flatten a Detection into the KEY=VALUE map the bash wizard reads.

    Mirrors the `defaults` seam: one line per key, no newlines in values.
    """
    out: dict[str, str] = {}
    for slot in SLOTS:
        info = detection.slots.get(slot, SlotInfo())
        prefix = f"LOCALAI_VARIANT_{slot.upper()}"
        out[prefix] = info.variant
        out[f"{prefix}_LABEL"] = info.label
        out[f"{prefix}_WARN"] = info.warning
    out["LOCALAI_VARIANT_RECOMMENDED"] = detection.recommended
    out["VOICE_VARIANT_RECOMMENDED"] = detection.voice_recommended
    out["VOICE_VARIANT_NVIDIA_WARN"] = detection.voice_nvidia_warning
    return out
