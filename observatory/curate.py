"""Pick the most informative traces from a finished run and compact them for the viewer.

A matrix run writes one trace per (trial, defense, attack|control) for a subset of trials, which
is too many for a picker. This ranks the traced trials by what a reader wants to see and keeps a
few, spread over attack families:

* a payload that reached an agent's input            (+2)
* an attack that met its goal under some defense      (+3)
* a defense that blocked a call or flagged an answer  (+2)

Usage::

    python -m observatory.curate --run results_real3/real3 --out observatory/replays --max 8

The ranking reads ``trials.jsonl`` (outcomes) and ``events/`` (traces); it never calls a model.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from observatory import compact


def load_trials(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not r.get("error"):
            rows.append(r)
    return rows


def trial_of(name: str) -> str:
    """``<trial>.<defense>.<attack|control>.jsonl`` -> ``<trial>`` (trial ids contain dots)."""
    return name.removesuffix(".jsonl").rsplit(".", 2)[0]


def traced_ids(events: Path) -> set[str]:
    """Trial ids that have at least one trace file."""
    return {trial_of(f.name) for f in events.glob("*.jsonl")}


def rank(rows: list[dict[str, Any]], traced: set[str]) -> list[tuple[int, str, str]]:
    """(score, family, trial_id), best first, only for trials that have traces."""
    by_trial: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        if r["trial_id"] in traced:
            by_trial[r["trial_id"]].append(r)
    out = []
    for tid, rs in by_trial.items():
        score = 0
        if any(r.get("defense") == "none" and r.get("survived_agent_input") for r in rs):
            score += 2
        if any(r.get("goal_met") for r in rs):
            score += 3
        if any(
            r.get("defense") != "none" and (r.get("blocked_calls") or r.get("flagged")) for r in rs
        ):
            score += 2
        out.append((score, rs[0].get("family", ""), tid))
    return sorted(out, key=lambda t: (-t[0], t[1], t[2]))


def spread(ranked: list[tuple[int, str, str]], n: int) -> list[str]:
    """Take the best trials but at most one per family per round, so families are all shown."""
    chosen: list[str] = []
    pool = [t for t in ranked if t[0] > 0] or ranked
    while pool and len(chosen) < n:
        seen: set[str] = set()
        rest = []
        for t in pool:
            if t[1] not in seen and len(chosen) < n:
                seen.add(t[1])
                chosen.append(t[2])
            else:
                rest.append(t)
        pool = rest
    return chosen


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="observatory.curate", description=__doc__)
    ap.add_argument(
        "--run", type=Path, required=True, help="run folder with trials.jsonl and events/"
    )
    ap.add_argument("--out", type=Path, required=True, help="output replays directory")
    ap.add_argument("--max", type=int, default=8)
    ap.add_argument("--banner", default="", help="note shown above every replay")
    args = ap.parse_args(argv)
    trials, events = args.run / "trials.jsonl", args.run / "events"
    if not trials.exists() or not events.is_dir():
        print(f"error: {args.run} needs trials.jsonl and an events/ folder", file=sys.stderr)
        return 2
    ranked = rank(load_trials(trials), traced_ids(events))
    keep = spread(ranked, args.max)
    if not keep:
        print("error: no traced trials found", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        wanted = set(keep)
        for f in events.glob("*.jsonl"):
            if trial_of(f.name) in wanted:
                shutil.copy(f, Path(tmp) / f.name)
        score = {t: s for s, _, t in ranked}
        for tid in keep:
            print(f"  selected {tid} (score {score[tid]})")
        cargs = ["--events", tmp, "--out", str(args.out)]
        if args.banner:
            cargs += ["--banner", args.banner]
        return compact.main(cargs)


if __name__ == "__main__":
    raise SystemExit(main())
