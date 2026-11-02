"""Headless-browser render check for the Agent Observatory viewer.

Playwright is not a project dependency, so the check runs as a node script
(observatory/tests/render_check.mjs). The test is skipped if node, Playwright or
Chromium are unavailable.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from observatory import compact
from observatory.sample.make_sample_events import write_all

SCRIPT = Path(__file__).resolve().parent.parent / "observatory" / "tests" / "render_check.mjs"
SKIPPED_EXIT = 77


def test_viewer_renders_and_responds(tmp_path: Path) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    events, replays = tmp_path / "events", tmp_path / "replays"
    write_all(events)
    assert compact.main(["--events", str(events), "--out", str(replays)]) == 0
    shot = tmp_path / "observatory.png"
    proc = subprocess.run(
        [node, str(SCRIPT), str(replays), str(shot)],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if proc.returncode == SKIPPED_EXIT:
        pytest.skip(f"Playwright/Chromium unavailable: {proc.stderr.strip()}")
    print(proc.stdout)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert shot.exists() and shot.stat().st_size > 5000
    # Keep a copy where a human can look at it.
    keep = Path(__file__).resolve().parent.parent / ".pytest_cache" / "observatory.png"
    keep.parent.mkdir(exist_ok=True)
    shutil.copy(shot, keep)
