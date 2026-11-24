"""Size profiles of an installation and the host they need (operation BE-02, OPS-01).

The question round of `setup` asks for one profile (BE-03 No. 7); `doctor` measures the
host against it in its check `profile_size`, and `setup` runs the same measurement before
it writes anything: a host below the profile stops it with the size that is missing
(PLT-58-A5). Before the first `setup` the host is measured against the smallest profile.

| Profile          | CPU      | Memory                               | Free disk |
|------------------|----------|--------------------------------------|-----------|
| `small-no-model` | 8 cores  | 32 GB                                | 200 GB    |
| `small`          | 8 cores  | 64 GB, or 32 GB and a GPU with 16 GB | 300 GB    |
| `large`          | 16 cores | 64 GB                                | 500 GB    |

The values are decimal gigabytes, as the profiles are written. Memory gets a tolerance of
five per cent: the kernel keeps part of the installed memory for itself, so a host sold
with 32 GB reports a little less as its total. CPU cores and free disk get none.

`small` runs the default model in LocalAI on this host; `small-no-model` and `large` use
a model server of their own (the question round then asks for its URL, BE-03 No. 8; the
answer is checked and recorded, the model gateway does not take it as its upstream yet).
"""

from __future__ import annotations

from dataclasses import dataclass

GB = 10**9
MEMORY_TOLERANCE = 0.05


@dataclass(frozen=True)
class Profile:
    name: str
    cores: int
    memory: int
    disk: int
    # (memory, video memory of one GPU) that also satisfy the profile, or None.
    gpu_alternative: tuple[int, int] | None = None
    local_model: bool = False


PROFILES: dict[str, Profile] = {
    "small-no-model": Profile("small-no-model", 8, 32 * GB, 200 * GB),
    "small": Profile("small", 8, 64 * GB, 300 * GB, (32 * GB, 16 * GB), local_model=True),
    "large": Profile("large", 16, 64 * GB, 500 * GB),
}
SMALLEST = "small-no-model"
# The root .env key setup stores the chosen profile under.
ENV_KEY = "PAPAIA_SIZE_PROFILE"


@dataclass(frozen=True)
class Measured:
    """What the host offers. None where it cannot be read on this platform."""

    cores: int | None
    memory: int | None
    disk_free: int | None
    disk_path: str = ""
    # The largest video memory of one GPU, in bytes; None without a readable GPU.
    gpu_memory: int | None = None


def _gb(value: int) -> str:
    return f"{value / GB:.0f} GB" if value >= 10 * GB else f"{value / GB:.1f} GB"


def _enough_memory(found: int, needed: int) -> bool:
    return found >= needed * (1 - MEMORY_TOLERANCE)


def shortfall(profile: Profile, host: Measured) -> tuple[list[str], list[str]]:
    """(what is missing, what could not be measured), each as sentences naming the size.

    An empty first list means the host fits the profile as far as it could be read."""
    missing: list[str] = []
    unknown: list[str] = []
    if host.cores is None:
        unknown.append("the number of CPU cores cannot be read")
    elif host.cores < profile.cores:
        missing.append(f"CPU: {profile.cores} cores needed, {host.cores} found")
    if host.memory is None:
        unknown.append("the memory cannot be read")
    elif not _enough_memory(host.memory, profile.memory):
        alternative = profile.gpu_alternative
        if not (
            alternative is not None
            and _enough_memory(host.memory, alternative[0])
            and host.gpu_memory is not None
            and host.gpu_memory >= alternative[1]
        ):
            text = f"memory: {_gb(profile.memory)} needed, {_gb(host.memory)} found"
            if alternative is not None:
                text += (
                    f" (or {_gb(alternative[0])} with a GPU of"
                    f" {_gb(alternative[1])} video memory)"
                )
            missing.append(text)
    if host.disk_free is None:
        unknown.append("the free disk space cannot be read")
    elif host.disk_free < profile.disk:
        where = f" at {host.disk_path}" if host.disk_path else ""
        missing.append(
            f"disk: {_gb(profile.disk)} free needed{where}, {_gb(host.disk_free)} free"
        )
    return missing, unknown


def profile(name: str) -> Profile:
    try:
        return PROFILES[name]
    except KeyError:
        raise ValueError(
            f"unknown size profile {name!r}; known: {', '.join(PROFILES)}"
        ) from None
