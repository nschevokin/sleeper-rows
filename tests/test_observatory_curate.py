"""Curating traces from a run: ranking, family spread and the end-to-end compaction."""

from __future__ import annotations

import json
from pathlib import Path

from observatory import curate

TID_A = "instruction_override.fabrication.blackbox.triage.0.narrative.d5.s0.GRP.aaaa"
TID_B = "laundering.suppression.blackbox.triage.0.narrative.d5.s0.GRP.bbbb"
TID_C = "tool_hijack.unauthorized_action.blackbox.analyst.0.narrative.d5.s0.q001.cccc"


def _rows() -> list[dict[str, object]]:
    return [
        {"trial_id": TID_A, "family": "instruction_override", "defense": "none", "goal_met": True,
         "survived_agent_input": True},
        {"trial_id": TID_A, "family": "instruction_override", "defense": "taintguard",
         "goal_met": False, "blocked_calls": 2},
        {"trial_id": TID_B, "family": "laundering", "defense": "none", "goal_met": False,
         "survived_agent_input": True},
        {"trial_id": TID_C, "family": "tool_hijack", "defense": "none", "goal_met": False},
    ]  # fmt: skip


def test_trial_id_is_recovered_from_a_dotted_file_name() -> None:
    assert curate.trial_of(f"{TID_A}.detector.attack.jsonl") == TID_A


def test_rank_prefers_goal_met_and_blocked_and_spreads_families() -> None:
    ranked = curate.rank(_rows(), {TID_A, TID_B, TID_C})
    assert ranked[0][2] == TID_A and ranked[0][0] == 7  # exposed (2) + goal met (3) + blocked (2)
    assert curate.spread(ranked, 2) == [TID_A, TID_B]  # TID_C scores 0 and is left out
    assert curate.rank(_rows(), {TID_C})[0][0] == 0  # an uninteresting trial still ranks last


def test_curate_end_to_end_on_the_sample_events(tmp_path: Path) -> None:
    run = tmp_path / "run"
    (run / "events").mkdir(parents=True)
    src = Path("observatory/sample/events")
    # reuse a sample trace under a matrix-style name so the compaction has real events to read
    first = sorted(src.glob("*.attacked.jsonl"))[0]
    (run / "events" / f"{TID_A}.none.attack.jsonl").write_text(first.read_text())
    (run / "trials.jsonl").write_text(json.dumps(_rows()[0]) + "\n")
    out = tmp_path / "replays"
    assert curate.main(["--run", str(run), "--out", str(out), "--max", "3"]) == 0
    assert (out / "index.json").exists()


def test_retime_spreads_short_traces_and_keeps_real_time():
    from observatory.compact import retime

    steps = [{"t": 0}, {"t": 3}, {"t": 7}]
    assert retime(steps) is True
    assert [s["t"] for s in steps] == [0, 1200, 2400]
    assert [s["t_real"] for s in steps] == [0, 3, 7]
    long = [{"t": 0}, {"t": 20_000}]
    assert retime(long) is False and "t_real" not in long[0]


def test_compact_banner_is_written(tmp_path):
    import json

    from observatory import compact

    ev = {
        "ts": "2026-01-01T00:00:00", "run_id": "r", "scenario": "attacked", "scenario_id": "s",
        "actor": "ingest", "action": "read", "inputs": [], "trust": "trusted",
    }  # fmt: skip
    compact.compact([compact.validate_event(ev)], tmp_path, banner="stub run")
    assert json.loads((tmp_path / "index.json").read_text())["banner"] == "stub run"
    assert json.loads((tmp_path / "s.json").read_text())["banner"] == "stub run"
