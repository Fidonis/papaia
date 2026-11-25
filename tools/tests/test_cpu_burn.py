"""The CPU-burn helper of a load run (`tests/helpers/cpu_burn.py`) keeps its bounds: at most
half of the cores, every burn process at niceness 19, at most 30 minutes, and no process
left behind when it stops by its deadline or on SIGTERM.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import hang_guard
import pytest
from helpers import cpu_burn

HELPER = Path(__file__).resolve().parent / "helpers" / "cpu_burn.py"

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX process handling")


def _alive(pid: int) -> bool:
    """Whether `pid` is a running process (a zombie counts as gone)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True,
                           text=True, check=False, timeout=hang_guard.seconds())
    return state.returncode == 0 and not state.stdout.strip().startswith("Z")


def _niceness(pid: int) -> int:
    out = subprocess.run(["ps", "-o", "ni=", "-p", str(pid)], capture_output=True, text=True,
                         check=True, timeout=hang_guard.seconds())
    return int(out.stdout.strip())


def _start(*args: str) -> tuple[subprocess.Popen, list[int]]:
    """Start the helper and read the worker pids from its first line."""
    proc = subprocess.Popen([sys.executable, str(HELPER), *args], stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, text=True)
    assert proc.stderr is not None
    line = proc.stderr.readline()
    assert line.startswith("cpu_burn: started "), line
    pids = [int(p) for p in line.rsplit(":", 1)[1].split()]
    return proc, pids


def _cleanup(proc: subprocess.Popen, pids: list[int]) -> None:
    """Never leave a burner behind, also when an assertion failed."""
    if proc.poll() is None:
        proc.kill()
        proc.wait(timeout=hang_guard.seconds())
    for pid in pids:
        if _alive(pid):
            os.kill(pid, signal.SIGKILL)
    if proc.stderr is not None:
        proc.stderr.close()


def _gone_within(pids: list[int], seconds: float) -> bool:
    end = time.monotonic() + seconds
    while any(_alive(pid) for pid in pids):
        if time.monotonic() >= end:
            return False
        time.sleep(0.1)
    return True


def test_the_default_is_half_the_cores_and_at_least_one():
    assert cpu_burn.max_processes() == max(1, (os.cpu_count() or 1) // 2)
    assert cpu_burn.parse_args([]).processes == cpu_burn.max_processes()


def test_more_than_half_the_cores_is_refused(capsys):
    too_many = cpu_burn.max_processes() + 1
    assert cpu_burn.main([f"--processes={too_many}", "--seconds=1"]) == 2
    assert "at most half of the cores" in capsys.readouterr().err
    with pytest.raises(ValueError, match="at most half of the cores"):
        cpu_burn.burn(too_many, 1)


def test_more_than_30_minutes_is_refused(capsys):
    assert cpu_burn.MAX_SECONDS == 30 * 60
    assert cpu_burn.main(["--processes=1", f"--seconds={cpu_burn.MAX_SECONDS + 1}"]) == 2
    assert "at most 1800" in capsys.readouterr().err
    for seconds in (0, -1, float("nan"), float("inf")):
        with pytest.raises(ValueError):
            cpu_burn.burn(1, seconds)


def test_every_burn_process_runs_at_niceness_19_and_stops_by_its_deadline():
    proc, pids = _start("--processes=1", "--seconds=2")
    try:
        assert len(pids) == 1
        assert [_niceness(pid) for pid in pids] == [19]
        assert _niceness(proc.pid) == 19
        assert proc.wait(timeout=hang_guard.seconds()) == 0
        assert _gone_within(pids, 5), "a burn process outlived the helper"
    finally:
        _cleanup(proc, pids)


def test_sigterm_stops_the_helper_and_every_burn_process():
    workers = min(2, cpu_burn.max_processes())
    proc, pids = _start(f"--processes={workers}", "--seconds=600")
    try:
        assert len(pids) == workers
        assert all(_alive(pid) for pid in pids)
        started = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=hang_guard.seconds()) == 128 + signal.SIGTERM
        assert time.monotonic() - started < 60
        assert _gone_within(pids, 5), "a burn process outlived SIGTERM"
    finally:
        _cleanup(proc, pids)
