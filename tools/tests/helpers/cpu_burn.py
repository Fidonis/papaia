"""Keep half of the host's cores busy while a test run is in progress.

A load run of a test file shows whether a pass depends on how fast the host is:

    nice -n 19 python3 tests/helpers/cpu_burn.py --seconds=1500 &
    uv run --locked --extra dev --with pytest-xdist==3.6.1 python -m pytest -n auto <files>

Bounds, checked before anything starts:

- at most half of the cores (`os.cpu_count() // 2`, at least 1) busy processes; that is
  also the default;
- every process of the helper runs at niceness 19, so the host stays usable;
- at most MAX_SECONDS (30 minutes) per call; every busy process also stops by itself at
  the deadline, even if the helper was killed.

The helper stops its busy processes when it ends, on SIGINT and on SIGTERM, and touches
nothing outside its own processes. Its first line on standard error names the process
ids it started.
"""

from __future__ import annotations

import argparse
import math
import multiprocessing
import os
import signal
import sys
import time

MAX_SECONDS = 30 * 60
NICENESS = 19
DEFAULT_SECONDS = 600.0


def max_processes() -> int:
    """Half of the cores, at least one."""
    return max(1, (os.cpu_count() or 1) // 2)


def _spin(deadline: float) -> None:
    value = 0
    while time.monotonic() < deadline:
        for _ in range(100_000):
            value = (value * 31 + 7) % 1_000_003


def _lower_priority() -> None:
    """Raise the niceness of this process to NICENESS; children inherit it."""
    current = os.nice(0)
    if current < NICENESS:
        os.nice(NICENESS - current)


def _check(processes: int, seconds: float) -> None:
    if isinstance(processes, bool) or not isinstance(processes, int):
        raise ValueError("processes must be a whole number")
    if not 1 <= processes <= max_processes():
        raise ValueError(f"processes must be between 1 and {max_processes()} "
                         "(at most half of the cores)")
    if (not isinstance(seconds, (int, float)) or not math.isfinite(seconds)
            or not 0 < seconds <= MAX_SECONDS):
        raise ValueError(f"seconds must be above 0 and at most {MAX_SECONDS}")


def burn(processes: int, seconds: float) -> int:
    """Run `processes` busy processes for at most `seconds`; return how many were started."""
    _check(processes, seconds)
    _lower_priority()
    deadline = time.monotonic() + seconds
    context = multiprocessing.get_context("spawn")
    workers = [context.Process(target=_spin, args=(deadline,), daemon=True)
               for _ in range(processes)]

    def _stop_all() -> None:
        for worker in workers:
            if worker.pid is not None and worker.is_alive():
                worker.terminate()
        for worker in workers:
            if worker.pid is not None:
                worker.join(timeout=10)
                if worker.is_alive():
                    worker.kill()
                    worker.join()

    def _on_signal(signum, _frame):
        _stop_all()
        raise SystemExit(128 + signum)

    previous = {sig: signal.signal(sig, _on_signal) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        for worker in workers:
            worker.start()
        pids = " ".join(str(worker.pid) for worker in workers)
        print(f"cpu_burn: started {len(workers)} process(es) at niceness {os.nice(0)} "
              f"for at most {seconds:g} s: {pids}", file=sys.stderr, flush=True)
        for worker in workers:
            worker.join()
    finally:
        _stop_all()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return len(workers)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--processes", type=int, default=max_processes(),
                        help="busy processes to start (default and maximum: half of the "
                             f"cores, here {max_processes()})")
    parser.add_argument("--seconds", type=float, default=DEFAULT_SECONDS,
                        help=f"stop after this many seconds (default: {DEFAULT_SECONDS:g}, "
                             f"at most {MAX_SECONDS})")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        _check(args.processes, args.seconds)
    except ValueError as exc:
        print(f"cpu_burn: {exc}", file=sys.stderr)
        return 2
    started = burn(args.processes, args.seconds)
    print(f"cpu_burn: {started} process(es) done", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
