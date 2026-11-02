"""Generic tool-loop runtime shared by the triage, analyst and data-quality agents.

The loop is deliberately small and deterministic: one model call per step, a typed ``Action``
back, a hard step budget, no retries on malformed output. A ``Defense`` can intervene at three
points: how untrusted text is presented, whether a tool call may run, and whether a final
answer may be returned.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from typing import Any

from agents.events import EventLog, max_trust
from agents.llm import MalformedOutput, ModelClient
from agents.schemas import Action
from agents.tools import Sinks, SqlResult, SqlSandbox, ToolCall

# Fallback name-based trust map. The experiment harness installs lineage-derived tiers for every
# defense (taintguard.lineage), so the baselines are not undercut by plumbing leaks (ADR 0004 s8.1).
DEFAULT_UNTRUSTED_COLUMNS = frozenset(
    {"top_summary", "sample_summary", "summary_llm", "summary", "cdescr", "row_json"}
)


@dataclass
class Verdict:
    allow: bool = True
    reason: str | None = None
    flagged: bool = False
    needs_confirmation: bool = False


def _default_tiers(sql: str, columns: list[str]) -> list[str]:
    return ["untrusted" if c in DEFAULT_UNTRUSTED_COLUMNS else "structured" for c in columns]


@dataclass
class RunState:
    agent: str
    task_text: str  # what the user/operator asked: trusted
    trusted_context: str = ""  # every trusted string shown to the model
    candidate_ids: set[str] = field(default_factory=set)
    authorized_dests: set[str] = field(default_factory=set)
    untrusted_seen: list[str] = field(default_factory=list)
    query_results: list[SqlResult] = field(default_factory=list)
    # (sql, result column names) -> tier label per column, positional.
    column_tiers: Callable[[str, list[str]], list[str]] = _default_tiers
    probe: Callable[[str], bool] = lambda text: False  # ground truth: does text contain a payload?
    confirm: Callable[[ToolCall], bool] = lambda call: False  # harness callback; deny by default
    extras: dict[str, Any] = field(default_factory=dict)
    defense_ms: float = 0.0


class Defense:
    """No defense. Subclasses override the hooks they need."""

    name = "none"
    system_note = ""

    def present_untrusted(self, text: str, ref: str, state: RunState) -> str | None:
        """Return the text to show the model, or None to withhold it."""
        return text

    def enrichment_input(self, narrative: str) -> str | None:
        """Hook for the enrichment step. Return the text to send, or None to skip the row."""
        return narrative

    def prepare_sql(self, sql: str, state: RunState) -> tuple[str | None, str | None]:
        """Return (sql to run, refusal message). A refusal replaces execution."""
        return sql, None

    def present_error(self, error: str, state: RunState) -> str:
        return error

    def check_tool_call(self, action: Action, state: RunState) -> Verdict:
        return Verdict()

    def check_final(self, action: Action, state: RunState) -> Verdict:
        return Verdict()


@dataclass
class AgentSpec:
    actor: str  # event actor: triage | analyst | data_quality
    system_prompt: str
    allowed_actions: tuple[str, ...]
    max_steps: int = 8
    final_needs: tuple[str, ...] = ()  # a final answer must set at least one of these fields


@dataclass
class Outcome:
    status: str  # ok | malformed | step_budget
    final: Action | None = None
    final_flagged: bool = False
    steps: int = 0
    tokens: int = 0
    latency_ms: float = 0.0
    invalid_actions: int = 0
    blocked: list[ToolCall] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    confirm_requests: int = 0


def _digest(a: Action) -> str:
    d = {k: v for k, v in a.model_dump().items() if v is not None and k != "action"}
    return ", ".join(f"{k}={str(v)[:60]}" for k, v in d.items())


def run_agent(
    spec: AgentSpec,
    model: ModelClient,
    defense: Defense,
    state: RunState,
    sandbox: SqlSandbox,
    sinks: Sinks,
    log: EventLog,
    *,
    seed: int = 0,
) -> Outcome:
    out = Outcome(status="step_budget")
    system = spec.system_prompt + (("\n" + defense.system_note) if defense.system_note else "")
    transcript: list[str] = []
    seen_sql: dict[str, int] = {}
    for step in range(spec.max_steps):
        user = state.task_text + ("\n\n" + "\n\n".join(transcript) if transcript else "")
        try:
            res = model.generate(system, user, Action, temperature=0.0, seed=seed)
        except MalformedOutput as exc:
            out.status = "malformed"
            log.emit(spec.actor, "decide", decision="malformed output", output_ref=str(exc)[:120])
            return out
        out.steps += 1
        out.tokens += res.tokens
        out.latency_ms += res.latency_ms
        act = res.parsed
        assert isinstance(act, Action)
        out.actions.append(act)

        if act.action not in spec.allowed_actions:
            out.invalid_actions += 1
            transcript.append(f"[tool error] action {act.action!r} is not available to you.")
            log.emit(spec.actor, "blocked", tool=act.action, blocked_reason="action not allowed")
            continue

        if act.action == "sql":
            run_sql, refusal = defense.prepare_sql(act.sql or "", state)
            if refusal is not None or run_sql is None:
                r = SqlResult(act.sql or "", False, error=refusal or "refused")
                state.query_results.append(r)
                transcript.append(f"[sql] {act.sql}\n{refusal}")
                log.emit(
                    spec.actor, "blocked", tool="sql", blocked_reason="query refused by policy"
                )
                continue
            r = sandbox.run(run_sql)
            state.query_results.append(r)
            shown, trust, poisoned = _present_sql(r, defense, state, len(state.query_results) - 1)
            transcript.append(f"[sql] {act.sql}\n{shown}")
            key = " ".join((act.sql or "").split()).lower()
            if key in seen_sql:  # same note for every defense: a loop helps nobody
                transcript.append(
                    f"[note] you already ran exactly this query (step {seen_sql[key]}). "
                    "Running it again changes nothing: change the query, or give your final answer."
                )
            seen_sql.setdefault(key, step + 1)
            log.emit(
                spec.actor, "query", inputs=[f"{t}:Q{step}/*" for t in sandbox.tables if t in (act.sql or "")],
                trust=trust, tool="sql", args_digest=act.sql, output_ref=f"{len(r.rows)} rows" if r.ok else r.error,
                latency_ms=res.latency_ms, tokens=res.tokens, poisoned=poisoned,
                excerpt=shown[:240] if poisoned else None,
                tainted_spans=[(0, min(240, len(shown)))] if poisoned else None,
            )  # fmt: skip
            continue

        # Action tools: escalate | export_report | open_ticket | final
        if (
            act.action == "final"
            and spec.final_needs
            and not any(getattr(act, f) is not None for f in spec.final_needs)
        ):
            out.invalid_actions += 1
            transcript.append(
                "[tool error] your final action was empty. Set "
                + " or ".join(spec.final_needs)
                + "."
            )
            continue
        if act.action == "final":
            v = defense.check_final(act, state)
            out.final, out.final_flagged = act, v.flagged or not v.allow
            log.emit(
                spec.actor, "decide", decision=act.answer or act.category or "done",
                output_ref=("FLAGGED: " + (v.reason or "")) if out.final_flagged else None,
                latency_ms=res.latency_ms, tokens=res.tokens,
            )  # fmt: skip
            if v.flagged or not v.allow:
                log.emit(
                    "guard", "blocked", blocked_reason=v.reason or "answer flagged", tool="final"
                )
            out.status = "ok"
            return out

        call = ToolCall(act.action, act.model_dump(exclude_none=True, exclude={"action"}))
        if (
            act.action == "escalate"
            and state.candidate_ids
            and act.group_id not in state.candidate_ids
        ):
            out.invalid_actions += 1
            transcript.append("[tool error] unknown group_id; use an id from the candidate list.")
            continue
        verdict = defense.check_tool_call(act, state)
        if verdict.allow and verdict.needs_confirmation:
            out.confirm_requests += 1
            if not state.confirm(call):
                verdict = Verdict(False, f"confirmation denied: {verdict.reason}")
        if not verdict.allow:
            call.allowed, call.reason = False, verdict.reason
            out.blocked.append(call)
            sinks.calls.append(call)
            transcript.append(f"[tool blocked by policy] {verdict.reason}")
            log.emit(
                "guard", "blocked", tool=act.action, args_digest=_digest(act),
                blocked_reason=verdict.reason or "policy",
                trust="untrusted", poisoned=state.probe(_digest(act)),
            )  # fmt: skip
            continue
        sinks.calls.append(call)
        if act.action == "escalate":
            sinks.escalate(act.group_id or "", act.reason or "")
            transcript.append(f"[escalate] recorded {act.group_id}")
        elif act.action == "open_ticket":
            sinks.open_ticket(act.ticket or "")
            transcript.append(
                "[open_ticket] recorded. The ticket is filed; your next action must be final(category, answer)."
            )
        else:  # export_report
            sinks.export_report(act.dest or "", digest=str(hash(state.task_text))[:8])
            transcript.append(f"[export_report] sent to {act.dest}")
        log.emit(
            spec.actor, "tool_call", tool=act.action, args_digest=_digest(act),
            trust="untrusted" if state.probe(_digest(act)) else "trusted",
            poisoned=state.probe(_digest(act)), latency_ms=res.latency_ms, tokens=res.tokens,
        )  # fmt: skip
    return out


_PRIMITIVES = (type(None), bool, int, float, Decimal, date, datetime, time, timedelta)


def _present_sql(
    r: SqlResult, defense: Defense, state: RunState, k: int = 0
) -> tuple[str, str, bool]:
    """Render a result for the model, passing untrusted cells through the defense.

    A cell is shown raw if its column tier is at most structured, or if its Python value is a
    number/date/boolean (a form that cannot carry an instruction). Every other untrusted cell
    (str, list, dict, tuple, bytes) is serialised and routed through the defense.
    """
    if not r.ok:
        return defense.present_error(r.render(), state), "trusted", False
    trusts = state.column_tiers(r.sql, list(r.columns))
    if len(trusts) != len(r.columns):
        trusts = ["untrusted"] * len(r.columns)
    rows: list[tuple[Any, ...]] = []
    poisoned = False
    for row in r.rows:
        new = list(row)
        for i, (v, t) in enumerate(zip(row, trusts, strict=True)):
            if t == "untrusted" and not isinstance(v, _PRIMITIVES):
                text = (
                    v.decode("utf-8", "replace")
                    if isinstance(v, bytes | bytearray)
                    else v
                    if isinstance(v, str)
                    else json.dumps(v, default=str, ensure_ascii=False)
                )
                poisoned = poisoned or state.probe(text)
                state.extras.setdefault("untrusted_raw", []).append(text)
                shown = defense.present_untrusted(text, f"Q{k}:{i}:{r.columns[i]}", state)
                new[i] = "[withheld]" if shown is None else shown
                if shown is not None:
                    state.untrusted_seen.append(shown)
        rows.append(tuple(new))
    view = SqlResult(r.sql, True, r.columns, rows, truncated=r.truncated)
    return view.render(), max_trust(*trusts), poisoned
