"""Compact raw JSONL event logs into small, static replay files for the viewer.

Usage::

    python -m observatory.compact --events <dir-or-file> --out <dir>

Output: ``<out>/<scenario_id>.json`` (one per scenario, holding every available run) and
``<out>/index.json`` (the list of scenarios the viewer's picker shows).

The output is deterministic: the same input always yields byte-identical files.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

LANES: tuple[str, ...] = (
    "ingest",
    "transform",
    "enrich",
    "guard",
    "triage",
    "analyst",
    "data_quality",
)
ACTIONS = frozenset({"read", "transform", "tag", "query", "tool_call", "decide", "blocked"})
SCENARIOS: tuple[str, ...] = ("clean", "attacked", "defended")
TRUST = frozenset({"trusted", "structured", "untrusted"})
ALWAYS_KEEP_ACTIONS = frozenset({"blocked", "tool_call", "decide"})

MAX_EVENTS = 2000
MAX_EXCERPT = 240
MAX_SHORT = 200
MAX_INPUTS = 12
MAX_SPANS = 32
_SAFE_ID = re.compile(r"[^A-Za-z0-9._-]")


class BadEventError(ValueError):
    """Raised when one input line is not a valid event."""


@dataclass
class ReadStats:
    """Counters reported at the end of a compaction run."""

    files: int = 0
    lines: int = 0
    valid: int = 0
    malformed: int = 0
    reasons: Counter[str] = field(default_factory=Counter)


def _short(value: Any, limit: int = MAX_SHORT) -> str | None:
    if value is None:
        return None
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    return text[:limit]


def _number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return 0
    return round(float(value), 3)


def _parse_ts(value: Any) -> float:
    """Return epoch milliseconds for an ISO-8601 string (naive means UTC)."""
    if not isinstance(value, str):
        raise BadEventError("ts is not a string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise BadEventError("ts is not ISO-8601") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.timestamp() * 1000.0


def _spans(value: Any, text_len: int) -> list[list[int]]:
    spans: list[list[int]] = []
    if not isinstance(value, list):
        return spans
    for pair in value[:MAX_SPANS]:
        if (
            isinstance(pair, list | tuple)
            and len(pair) == 2
            and all(isinstance(x, int) and not isinstance(x, bool) for x in pair)
        ):
            start, end = max(0, pair[0]), min(text_len, pair[1])
            if start < end:
                spans.append([start, end])
    return spans


def validate_event(raw: Any) -> dict[str, Any]:
    """Validate one decoded event and return its normalised form (``t`` not yet set).

    Unknown fields are dropped. ``ts_ms`` holds the absolute time for later normalisation.
    """
    if not isinstance(raw, dict):
        raise BadEventError("not a JSON object")
    scenario, actor, action = raw.get("scenario"), raw.get("actor"), raw.get("action")
    if scenario not in SCENARIOS:
        raise BadEventError("bad scenario")
    if actor not in LANES:
        raise BadEventError("unknown actor")
    if action not in ACTIONS:
        raise BadEventError("unknown action")
    for key in ("run_id", "scenario_id"):
        if not isinstance(raw.get(key), str) or not raw[key]:
            raise BadEventError(f"missing {key}")
    inputs = raw.get("inputs", [])
    if not isinstance(inputs, list) or not all(isinstance(x, str) for x in inputs):
        raise BadEventError("inputs is not a list of strings")
    trust = raw.get("trust", "trusted")
    if trust not in TRUST:
        raise BadEventError("bad trust")
    event: dict[str, Any] = {
        "ts_ms": _parse_ts(raw.get("ts")),
        "run_id": raw["run_id"],
        "scenario": scenario,
        "scenario_id": raw["scenario_id"],
        "actor": actor,
        "action": action,
        "inputs": [s[:MAX_SHORT] for s in inputs[:MAX_INPUTS]],
        "trust": trust,
        "poisoned": bool(raw.get("poisoned", False)),
        "tool": _short(raw.get("tool"), 80),
        "args_digest": _short(raw.get("args_digest")),
        "output_ref": _short(raw.get("output_ref")),
        "latency_ms": _number(raw.get("latency_ms")),
        "tokens": _number(raw.get("tokens")),
    }
    excerpt = raw.get("excerpt")
    if isinstance(excerpt, str):
        event["excerpt"] = excerpt[:MAX_EXCERPT]
        event["tainted_spans"] = _spans(raw.get("tainted_spans"), len(event["excerpt"]))
    for key in ("decision", "blocked_reason"):
        if raw.get(key) is not None:
            event[key] = _short(raw[key])
    return event


def iter_event_files(source: Path) -> list[Path]:
    """Return ``source`` itself, or every ``*.jsonl`` below it in sorted order."""
    if source.is_file():
        return [source]
    return sorted(p for p in source.rglob("*.jsonl") if p.is_file())


def read_events(source: Path, stats: ReadStats) -> list[dict[str, Any]]:
    """Read and validate every line, counting malformed ones instead of raising."""
    events: list[dict[str, Any]] = []
    for path in iter_event_files(source):
        stats.files += 1
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                stats.lines += 1
                try:
                    events.append(validate_event(json.loads(line)))
                except (json.JSONDecodeError, BadEventError, RecursionError) as exc:
                    stats.malformed += 1
                    stats.reasons[type(exc).__name__ + ": " + str(exc)[:60]] += 1
                    continue
                stats.valid += 1
    return events


def sample_events(events: list[dict[str, Any]], limit: int = MAX_EVENTS) -> list[dict[str, Any]]:
    """Cap ``events`` (already time-sorted) to ``limit`` by uniform sampling.

    Poisoned, blocked, tool_call and decide events are always kept, even if that
    exceeds ``limit``. The remaining budget is spread uniformly over the other events.
    """
    if len(events) <= limit:
        return events
    forced = [e["poisoned"] or e["action"] in ALWAYS_KEEP_ACTIONS for e in events]
    others = [i for i, f in enumerate(forced) if not f]
    budget = max(0, limit - (len(events) - len(others)))
    keep = {i for i, f in enumerate(forced) if f}
    if budget and others:
        count = min(budget, len(others))
        keep.update(others[(k * len(others)) // count] for k in range(count))
    return [e for i, e in enumerate(events) if i in keep]


def _public_step(event: dict[str, Any], t0: float) -> dict[str, Any]:
    step = {k: v for k, v in event.items() if k not in ("ts_ms", "run_id", "scenario")}
    step.pop("scenario_id", None)
    step["t"] = round(event["ts_ms"] - t0)
    return dict(sorted(step.items()))


RETIME_BELOW_MS = 10_000
RETIME_STEP_MS = 1200


def retime(steps: list[dict[str, Any]]) -> bool:
    """Spread the steps of a very short trace evenly so a person can follow it.

    Model-less (stub) runs finish in milliseconds. Only the order is kept, and the real time of
    every step stays in ``t_real``. Returns True when the trace was changed.
    """
    if len(steps) < 2 or steps[-1]["t"] >= RETIME_BELOW_MS:
        return False
    gap = max(150, min(RETIME_STEP_MS, 40_000 // len(steps)))
    for i, step in enumerate(steps):
        step["t_real"] = step["t"]
        step["t"] = i * gap
    return True


def build_run(events: list[dict[str, Any]], limit: int) -> dict[str, Any]:
    """Build the compacted replay object for one run (events in input order)."""
    ordered = [e for _, e in sorted(enumerate(events), key=lambda p: (p[1]["ts_ms"], p[0]))]
    t0 = ordered[0]["ts_ms"]
    kept = sample_events(ordered, limit)
    steps = [_public_step(e, t0) for e in kept]
    retimed = retime(steps)
    return {
        "retimed": retimed,
        "run_id": ordered[0]["run_id"],
        "start": datetime.fromtimestamp(t0 / 1000.0, UTC).isoformat(timespec="milliseconds"),
        "duration_ms": steps[-1]["t"] if steps else 0,
        "raw_steps": len(ordered),
        "steps": steps,
    }


def _dump(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"


def _file_stem(scenario_id: str) -> str:
    return _SAFE_ID.sub("_", scenario_id)[:120] or "scenario"


def compact(
    events: Iterable[dict[str, Any]], out_dir: Path, limit: int = MAX_EVENTS, banner: str = ""
) -> list[dict[str, Any]]:
    """Write replay files and ``index.json``; return the index entries."""
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for event in events:
        grouped.setdefault(event["scenario_id"], {}).setdefault(event["scenario"], []).append(event)
    out_dir.mkdir(parents=True, exist_ok=True)
    index: list[dict[str, Any]] = []
    for scenario_id in sorted(grouped):
        runs = {kind: build_run(grouped[scenario_id][kind], limit) for kind in grouped[scenario_id]}
        ordered_kinds = [k for k in SCENARIOS if k in runs]
        stem = _file_stem(scenario_id)
        replay = {
            "scenario_id": scenario_id,
            "lanes": list(LANES),
            "runs": {k: runs[k] for k in ordered_kinds},
        }
        if banner:
            replay["banner"] = banner
        (out_dir / f"{stem}.json").write_text(_dump(replay), encoding="utf-8")
        index.append(
            {
                "id": scenario_id,
                "file": f"{stem}.json",
                "runs": ordered_kinds,
                "steps": {k: len(runs[k]["steps"]) for k in ordered_kinds},
                "raw_steps": {k: runs[k]["raw_steps"] for k in ordered_kinds},
                "duration_ms": max(runs[k]["duration_ms"] for k in ordered_kinds),
                "has_poisoned": any(s["poisoned"] for k in ordered_kinds for s in runs[k]["steps"]),
            }
        )
    (out_dir / "index.json").write_text(
        _dump({"version": 1, "banner": banner, "scenarios": index}), encoding="utf-8"
    )
    return index


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="observatory.compact", description=__doc__)
    parser.add_argument("--events", type=Path, required=True, help="JSONL file or directory")
    parser.add_argument("--out", type=Path, required=True, help="output replays directory")
    parser.add_argument("--max-events", type=int, default=MAX_EVENTS, help="cap per run")
    parser.add_argument(
        "--banner", default="", help="note shown above every replay (e.g. that it is a stub run)"
    )
    args = parser.parse_args(argv)

    if not args.events.exists():
        print(f"error: {args.events} does not exist", file=sys.stderr)
        return 2
    stats = ReadStats()
    events = read_events(args.events, stats)
    print(
        f"read {stats.files} file(s), {stats.lines} line(s): "
        f"{stats.valid} valid, {stats.malformed} malformed"
    )
    for reason, count in sorted(stats.reasons.items()):
        print(f"  skipped {count} x {reason}")
    if not events:
        print("error: no valid events read; nothing written", file=sys.stderr)
        return 1
    index = compact(events, args.out, args.max_events, args.banner)
    for entry in index:
        steps = ", ".join(f"{k}={n}/{entry['raw_steps'][k]}" for k, n in entry["steps"].items())
        print(f"  {entry['id']}: {steps}")
    print(f"wrote {len(index)} scenario(s) to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
