"""The Dagster graph runs end to end on the fixture and the schedule is off by default."""

from __future__ import annotations

from pathlib import Path

import dagster as dg
import pytest

from pipeline import definitions as d


def test_schedule_is_stopped_by_default() -> None:
    assert d.daily_schedule.default_status == dg.DefaultScheduleStatus.STOPPED


def test_materialise_graph(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fixtures.make_fixture import generate

    out = tmp_path / "fx" / "data"
    generate("tiny", seed=7, out=out)
    monkeypatch.setenv("SLEEPER_SNAPSHOT", str(out.parent / "snapshot.yaml"))
    monkeypatch.setenv("SLEEPER_WAREHOUSE", str(tmp_path / "wh"))
    r = dg.materialize([d.raw_landing, d.staging, d.enriched, d.gold])
    assert r.success
    from pipeline.warehouse import Warehouse

    assert Warehouse(tmp_path / "wh").exists("gold_triage_cases")
