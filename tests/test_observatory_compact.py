"""Tests for observatory.compact."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from observatory import compact
from observatory.sample.make_sample_events import write_all

T0 = datetime(2026, 3, 1, 10, 0, 0, tzinfo=UTC)


def ev(i: int, scenario_id: str = "s1", scenario: str = "attacked", **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "ts": (T0 + timedelta(milliseconds=i * 10)).isoformat(),
        "run_id": f"{scenario_id}-{scenario}",
        "scenario": scenario,
        "scenario_id": scenario_id,
        "actor": "ingest",
        "action": "read",
        "inputs": [f"raw_complaints:ODINO={i}/CDESCR"],
        "trust": "untrusted",
        "poisoned": False,
        "tool": None,
        "args_digest": None,
        "output_ref": f"raw_complaints:ODINO={i}",
        "latency_ms": 1.5,
        "tokens": 0,
    }
    base.update(kw)
    return base


def write_jsonl(path: Path, events: list[dict[str, Any]], extra: list[str] | None = None) -> Path:
    lines = [json.dumps(e) for e in events] + (extra or [])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def load(out: Path, name: str) -> Any:
    return json.loads((out / name).read_text(encoding="utf-8"))


def run_cli(events: Path, out: Path) -> int:
    return compact.main(["--events", str(events), "--out", str(out)])


def test_grouping_and_index(tmp_path: Path) -> None:
    events = (
        [ev(i, "a", "attacked", poisoned=(i == 2)) for i in range(5)]
        + [ev(i, "a", "defended") for i in range(4)]
        + [ev(i, "b", "clean") for i in range(3)]
    )
    src = write_jsonl(tmp_path / "e.jsonl", events)
    out = tmp_path / "out"
    assert run_cli(src, out) == 0
    index = load(out, "index.json")
    by_id = {s["id"]: s for s in index["scenarios"]}
    assert list(by_id) == ["a", "b"]
    assert by_id["a"]["runs"] == ["attacked", "defended"]
    assert by_id["a"]["steps"] == {"attacked": 5, "defended": 4}
    assert by_id["a"]["has_poisoned"] is True
    assert by_id["b"]["runs"] == ["clean"]
    assert by_id["b"]["has_poisoned"] is False
    assert by_id["a"]["file"] == "a.json"
    replay = load(out, "a.json")
    assert replay["lanes"] == list(compact.LANES)
    assert set(replay["runs"]) == {"attacked", "defended"}


def test_times_are_offsets_sorted_and_unknown_fields_dropped(tmp_path: Path) -> None:
    events = [ev(3, huge="x" * 100000), ev(1), ev(2, excerpt="y" * 1000, tainted_spans=[[0, 999]])]
    src = write_jsonl(tmp_path / "e.jsonl", events)
    out = tmp_path / "out"
    assert run_cli(src, out) == 0
    steps = load(out, "s1.json")["runs"]["attacked"]["steps"]
    assert [s["t_real"] for s in steps] == [0, 10, 20]  # short traces are re-timed for viewing
    assert all("huge" not in s and "ts" not in s for s in steps)
    excerpt_step = steps[1]
    assert len(excerpt_step["excerpt"]) == compact.MAX_EXCERPT
    assert excerpt_step["tainted_spans"] == [[0, compact.MAX_EXCERPT]]


def test_deterministic_byte_identical(tmp_path: Path) -> None:
    src = tmp_path / "events"
    src.mkdir()
    write_all(src)
    outs = []
    for name in ("one", "two"):
        out = tmp_path / name
        assert run_cli(src, out) == 0
        outs.append(out)
    names = sorted(p.name for p in outs[0].iterdir())
    assert names == sorted(p.name for p in outs[1].iterdir())
    for name in names:
        assert (outs[0] / name).read_bytes() == (outs[1] / name).read_bytes()


def test_capping_keeps_critical_events(tmp_path: Path) -> None:
    n, limit = 3000, 100
    events = [ev(i) for i in range(n)]
    critical: dict[int, dict[str, Any]] = {
        7: {"poisoned": True},
        500: {"action": "blocked"},
        1500: {"action": "tool_call"},
    }
    critical |= {2900: {"action": "decide"}, 2999: {"poisoned": True, "action": "decide"}}
    for i, kw in critical.items():
        events[i] = ev(i, **kw)
    src = write_jsonl(tmp_path / "e.jsonl", events)
    out = tmp_path / "out"
    assert compact.main(["--events", str(src), "--out", str(out), "--max-events", str(limit)]) == 0
    run = load(out, "s1.json")["runs"]["attacked"]
    assert run["raw_steps"] == n
    assert len(run["steps"]) == limit
    kept = {s["t"] // 10 for s in run["steps"]}
    assert set(critical) <= kept
    assert [s["t"] for s in run["steps"]] == sorted(s["t"] for s in run["steps"])


def test_critical_events_exceeding_limit_are_all_kept() -> None:
    events = [{**ev(i), "ts_ms": float(i), "poisoned": True} for i in range(50)]
    assert len(compact.sample_events(events, 10)) == 50


def test_default_cap_is_2000(tmp_path: Path) -> None:
    src = write_jsonl(tmp_path / "e.jsonl", [ev(i) for i in range(2500)])
    out = tmp_path / "out"
    assert run_cli(src, out) == 0
    assert len(load(out, "s1.json")["runs"]["attacked"]["steps"]) == 2000


def test_malformed_lines_skipped_and_counted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = [
        "not json at all",
        "[1, 2, 3]",
        json.dumps(ev(1, actor="nobody")),
        json.dumps(ev(1, action="explode")),
        json.dumps(ev(1, scenario="weird")),
        json.dumps(ev(1, ts="yesterday")),
        json.dumps({k: v for k, v in ev(1).items() if k != "scenario_id"}),
        json.dumps(ev(1, inputs="oops")),
    ]
    src = write_jsonl(tmp_path / "e.jsonl", [ev(0), ev(1)], extra=bad)
    out = tmp_path / "out"
    assert run_cli(src, out) == 0
    text = capsys.readouterr().out
    assert "2 valid, 8 malformed" in text
    assert len(load(out, "s1.json")["runs"]["attacked"]["steps"]) == 2


def test_nothing_valid_exits_nonzero(tmp_path: Path) -> None:
    src = tmp_path / "e.jsonl"
    src.write_text("garbage\n{}\n", encoding="utf-8")
    assert run_cli(src, tmp_path / "out") == 1
    assert run_cli(tmp_path / "missing", tmp_path / "out") != 0
    empty = tmp_path / "empty"
    empty.mkdir()
    assert run_cli(empty, tmp_path / "out") == 1


def test_reads_directory_recursively(tmp_path: Path) -> None:
    (tmp_path / "ev" / "sub").mkdir(parents=True)
    write_jsonl(tmp_path / "ev" / "a.jsonl", [ev(0, "a")])
    write_jsonl(tmp_path / "ev" / "sub" / "b.jsonl", [ev(0, "b")])
    out = tmp_path / "out"
    assert run_cli(tmp_path / "ev", out) == 0
    assert [s["id"] for s in load(out, "index.json")["scenarios"]] == ["a", "b"]


def test_scenario_id_is_sanitised_for_file_names(tmp_path: Path) -> None:
    src = write_jsonl(tmp_path / "e.jsonl", [ev(0, "../evil/id")])
    out = tmp_path / "out"
    assert run_cli(src, out) == 0
    entry = load(out, "index.json")["scenarios"][0]
    assert entry["id"] == "../evil/id"
    assert "/" not in entry["file"]
    assert (out / entry["file"]).exists()
