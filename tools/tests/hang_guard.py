"""One deadline for the subprocesses and waits of the tests that start real processes.

The deadline only stops a hang: a test never passes or fails because something took long
but finished in time. A slow host raises it with PAPAIA_TEST_HANG_GUARD_SECONDS, for
example during a load run (see CONTRIBUTING.md, "Load runs").
"""

from __future__ import annotations

import math
import os

ENV = "PAPAIA_TEST_HANG_GUARD_SECONDS"
DEFAULT_SECONDS = 900.0
MAX_SECONDS = 4 * 3600.0


def seconds() -> float:
    """The deadline in seconds: DEFAULT_SECONDS, or the value of ENV (above 0 and at most
    MAX_SECONDS). A malformed value is an error, never a silent default."""
    raw = os.environ.get(ENV, "").strip()
    if not raw:
        return DEFAULT_SECONDS
    if len(raw) > 32:
        raise ValueError(f"{ENV} is too long")
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{ENV} must be a number of seconds, not {raw!r}") from None
    if not math.isfinite(value) or not 0 < value <= MAX_SECONDS:
        raise ValueError(f"{ENV} must be above 0 and at most {MAX_SECONDS:.0f}, not {raw}")
    return value
