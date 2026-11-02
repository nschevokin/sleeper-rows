"""One JSON line per step: the single source for scoring and for the Agent Observatory.

Field names follow the plan's event schema. ``poisoned`` comes from ground truth (the poison
registry) and is used only for colour and for scoring; no agent or guard ever reads it.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ACTORS = ("ingest", "transform", "enrich", "guard", "triage", "analyst", "data_quality")
ACTIONS = ("read", "transform", "tag", "query", "tool_call", "decide", "blocked")
TRUST_ORDER = {"trusted": 0, "structured": 1, "untrusted": 2}


def max_trust(*tiers: str) -> str:
    return max(tiers or ("trusted",), key=lambda t: TRUST_ORDER[t])


class EventLog:
    def __init__(
        self,
        path: Path | None,
        *,
        run_id: str,
        scenario: str,
        scenario_id: str,
        is_poisoned: Callable[[str], bool] | None = None,
    ):
        if scenario not in ("clean", "attacked", "defended"):
            raise ValueError(f"unknown scenario {scenario!r}")
        self.path = path
        self.run_id = run_id
        self.scenario = scenario
        self.scenario_id = scenario_id
        self.is_poisoned = is_poisoned or (lambda ref: False)
        self.events: list[dict[str, Any]] = []
        self._fh = None
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = path.open("w", encoding="utf-8")

    def emit(
        self,
        actor: str,
        action: str,
        *,
        inputs: Iterable[str] = (),
        trust: str = "trusted",
        tool: str | None = None,
        args_digest: str | None = None,
        output_ref: str | None = None,
        latency_ms: float = 0.0,
        tokens: int = 0,
        excerpt: str | None = None,
        tainted_spans: list[tuple[int, int]] | None = None,
        decision: str | None = None,
        blocked_reason: str | None = None,
        poisoned: bool | None = None,
    ) -> dict[str, Any]:
        if actor not in ACTORS:
            raise ValueError(f"unknown actor {actor!r}")
        if action not in ACTIONS:
            raise ValueError(f"unknown action {action!r}")
        refs = list(inputs)
        ev: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "run_id": self.run_id,
            "scenario": self.scenario,
            "scenario_id": self.scenario_id,
            "actor": actor,
            "action": action,
            "inputs": refs,
            "trust": trust,
            "poisoned": any(self.is_poisoned(r) for r in refs) if poisoned is None else poisoned,
            "tool": tool,
            "args_digest": _short(args_digest),
            "output_ref": _short(output_ref),
            "latency_ms": round(latency_ms, 1),
            "tokens": int(tokens),
        }
        if excerpt is not None:
            ev["excerpt"] = excerpt[:240]
            if tainted_spans:
                ev["tainted_spans"] = [list(s) for s in tainted_spans]
        if decision is not None:
            ev["decision"] = _short(decision)
        if blocked_reason is not None:
            ev["blocked_reason"] = _short(blocked_reason)
        self.events.append(ev)
        if self._fh is not None:
            self._fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
        return ev

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None


def _short(s: str | None, n: int = 200) -> str | None:
    if s is None:
        return None
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"
