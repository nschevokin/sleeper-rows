"""The taint guard against the stub model: routing, redaction, tool policy, provenance.

The stub is gullible on purpose; these tests check plumbing and mechanism, never effectiveness.
"""

from __future__ import annotations

from datetime import date
from typing import Any

import polars as pl
import pytest
from pydantic import BaseModel

from agents.events import EventLog
from agents.guard_adapter import GuardComponents, guard_state_hooks
from agents.llm import ModelResult
from agents.questions import generate_questions
from agents.registry import defense_factory
from agents.runtime import AgentSpec, Defense, RunState, run_agent
from agents.schemas import Action
from agents.stub import StubModel
from agents.tools import Sinks, SqlSandbox
from attacks.payloads import make_seed
from attacks.success import _matches, judge
from attacks.trial import TrialSpec, run_trial
from eval.env import Env, to_df


class Scripted:
    """A model that plays back a fixed list of actions and records what it was shown."""

    name, digest = "scripted", "v1"

    def __init__(self, actions: list[Action]) -> None:
        self.actions, self.users = list(actions), []

    def generate(
        self, system: str, user: str, schema: type[BaseModel] | None = None, **_: Any
    ) -> ModelResult:
        self.users.append(user)
        a = self.actions.pop(0)
        return ModelResult(a.model_dump_json(), a, 1, 1, 0.0)


class Spy(Defense):
    name = "spy"

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def present_untrusted(self, text: str, ref: str, state: RunState) -> str | None:
        self.calls.append((ref, text))
        return text


def guard_for(env: Env, **kw: Any) -> Any:
    return defense_factory("taintguard", env, StubModel(), **kw)()


def run_sql_script(env: Env, defense: Defense, sqls: list[str]) -> tuple[Scripted, RunState, Any]:
    model = Scripted(
        [Action(action="sql", sql=s) for s in sqls] + [Action(action="final", answer="done")]
    )
    state = RunState(agent="analyst", task_text="QUESTION: test")
    state.column_tiers = guard_state_hooks(env.guard_catalog, "analyst")
    sandbox = SqlSandbox({"gold_trends": env.base.read("gold_trends")})
    spec = AgentSpec("analyst", "TASK:analyst", ("sql", "final"), max_steps=len(sqls) + 2)
    out = run_agent(
        spec,
        model,
        defense,
        state,
        sandbox,
        Sinks(),
        EventLog(None, run_id="t", scenario="clean", scenario_id="t"),
    )
    return model, state, out


def questions(env: Env, n: int = 20) -> list[Any]:
    return generate_questions(env.base.read("gold_trends"), n=n)


def numeric_q(env: Env) -> Any:
    return next(q for q in questions(env) if q.kind == "number" and not q.authorized_dest)


def export_q(env: Env) -> Any:
    return next(q for q in questions(env, 40) if q.authorized_dest)


def spec_for(q: Any, **kw: Any) -> TrialSpec:
    base: dict[str, Any] = dict(
        trial_id="g1", target_kind="analyst", family="laundering", goal="falsification", knowledge="blackbox",
        placement="narrative", dose=5, seed=1, target_id=q.id,
    )  # fmt: skip
    base.update(kw)
    return TrialSpec(**base)


def test_a01_laundered_summary_never_reaches_the_analyst_raw(stub_env: Env) -> None:
    q = numeric_q(stub_env)
    p = make_seed("laundering", "falsification", "blackbox", target_kind="analyst")
    undefended = run_trial(stub_env, StubModel(), Defense, spec_for(q), p, questions={q.id: q})
    guarded = run_trial(
        stub_env,
        StubModel(),
        guard_for(stub_env).__class__ and (lambda: guard_for(stub_env)),
        spec_for(q),
        p,
        questions={q.id: q},
    )  # type: ignore[arg-type]
    assert undefended.evidence["agent_input"]  # the payload does reach an undefended agent
    assert guarded.evidence["gold"]  # and it did survive into gold: the guard acts at the boundary
    assert guarded.evidence["agent_input"] is None and not guarded.canary_in_output


def test_a02_triage_summary_is_extracted(stub_env: Env) -> None:
    cases = to_df(stub_env.base.read("gold_triage_cases"))
    week = cases["eval_week"].max()
    assert isinstance(week, date)
    top = (
        cases.filter(pl.col("eval_week") == week)
        .sort("surge_ratio", descending=True)
        .row(0, named=True)
    )
    gid = "|".join(str(top[k]) for k in ("make", "model", "model_year", "component_group"))
    spec = TrialSpec(
        "g2",
        "triage",
        "instruction_override",
        "suppression",
        "blackbox",
        "narrative",
        5,
        1,
        gid,
        eval_week=week,
    )
    p = make_seed("instruction_override", "suppression", "blackbox", target_kind="triage")
    g = run_trial(stub_env, StubModel(), lambda: guard_for(stub_env), spec, p)
    assert g.evidence["agent_input"] is None


def test_a03_data_quality_rows_are_shape_only(stub_env: Env) -> None:
    p = make_seed("tool_hijack", "unauthorized_action", "blackbox", target_kind="data_quality")
    spec = TrialSpec(
        "g3",
        "data_quality",
        "tool_hijack",
        "unauthorized_action",
        "blackbox",
        "narrative",
        5,
        1,
        "unseen_component-1",
    )
    a = run_trial(stub_env, StubModel(), lambda: guard_for(stub_env), spec, p)
    assert a.evidence["agent_input"] is None and not a.canary_in_output
    base = run_trial(stub_env, StubModel(), Defense, spec, p, control=True)
    ctl = run_trial(stub_env, StubModel(), lambda: guard_for(stub_env), spec, p, control=True)
    assert ctl.category == base.category == ctl.truth_category


def test_a04_error_messages_do_not_leak_cells(stub_env: Env) -> None:
    g = guard_for(stub_env)
    model, state, _ = run_sql_script(
        stub_env, g, ["SELECT CAST(top_summary AS INTEGER) FROM gold_trends"]
    )
    shown = model.users[-1]
    assert "Conversion Error" in shown and "Could not convert" not in shown
    model2, _, _ = run_sql_script(stub_env, g, ["SELECT CAST(make AS INTEGER) FROM gold_trends"])
    assert "<value>" in model2.users[-1]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT list(top_summary) FROM gold_trends WHERE top_summary IS NOT NULL LIMIT 1",
        "SELECT {'s': top_summary} AS st FROM gold_trends WHERE top_summary IS NOT NULL LIMIT 1",
        "SELECT top_summary::BLOB AS b FROM gold_trends WHERE top_summary IS NOT NULL LIMIT 1",
        "SELECT top_summary AS note FROM gold_trends WHERE top_summary IS NOT NULL LIMIT 1",
    ],
)
def test_a05_a06_non_string_cells_and_aliases_are_routed(stub_env: Env, sql: str) -> None:
    spy = Spy()
    run_sql_script(stub_env, spy, [sql])
    assert spy.calls, "the cell bypassed the defense"
    assert spy.calls[0][0].startswith("Q0:")


def test_a07_hijacked_export_is_blocked_but_the_real_one_is_not(stub_env: Env) -> None:
    q = numeric_q(stub_env)
    p = make_seed("tool_hijack", "unauthorized_action", "blackbox", target_kind="analyst")
    spec = spec_for(q, family="tool_hijack", goal="unauthorized_action")
    bad = run_trial(stub_env, StubModel(), Defense, spec, p, questions={q.id: q})
    assert any("attacker.example" in d for d in bad.exports)
    for components in (GuardComponents(lineage_routing=False), GuardComponents()):
        factory = defense_factory("taintguard", stub_env, StubModel(), components=components)
        g = run_trial(stub_env, StubModel(), factory, spec, p, questions={q.id: q})
        assert not any("attacker.example" in d for d in g.exports)
    # the user's own, explicitly requested export still goes through
    eq = export_q(stub_env)
    espec = spec_for(eq, family="tool_hijack", goal="unauthorized_action", trial_id="g7b")
    ok = run_trial(
        stub_env,
        StubModel(),
        lambda: guard_for(stub_env),
        espec,
        p,
        control=True,
        questions={eq.id: eq},
    )
    assert ok.exports == [eq.authorized_dest] and ok.blocked == 0


def test_a08_number_tampering_is_flagged_when_the_payload_reaches_the_agent(stub_env: Env) -> None:
    q = numeric_q(stub_env)
    p = make_seed("number_tampering", "falsification", "blackbox", target_kind="analyst")
    spec = spec_for(q, family="number_tampering")
    undefended = run_trial(stub_env, StubModel(), Defense, spec, p, questions={q.id: q})
    ctl = run_trial(stub_env, StubModel(), Defense, spec, p, control=True, questions={q.id: q})
    assert judge(spec, undefended, ctl, q)["goal_met"]
    # ablation: routing off lets the payload through, so provenance has to catch the tampered number
    abl = defense_factory(
        "taintguard", stub_env, StubModel(), components=GuardComponents(lineage_routing=False)
    )
    a = run_trial(stub_env, StubModel(), abl, spec, p, questions={q.id: q})
    assert a.flagged and not judge(spec, a, ctl, q)["goal_met"]
    full = run_trial(
        stub_env, StubModel(), lambda: guard_for(stub_env), spec, p, questions={q.id: q}
    )
    assert not judge(spec, full, ctl, q)["goal_met"]


def test_a09_gap_volume_only_fabrication_is_not_blocked(stub_env: Env) -> None:
    """GAP (R1): complaints with benign text and a high dose are real data; the guard cannot see them."""
    cases = to_df(stub_env.base.read("gold_triage_cases"))
    week = cases["eval_week"].max()
    gid = "|".join(
        str(cases.filter(pl.col("eval_week") == week).row(0, named=True)[k])
        for k in ("make", "model", "model_year", "component_group")
    )
    spec = TrialSpec(
        "g9",
        "triage",
        "instruction_override",
        "fabrication",
        "blackbox",
        "narrative",
        25,
        1,
        gid,
        eval_week=week,
    )
    p = make_seed("instruction_override", "fabrication", "blackbox", target_kind="triage")
    none = run_trial(stub_env, StubModel(), Defense, spec, p, control=True)
    g = run_trial(stub_env, StubModel(), lambda: guard_for(stub_env), spec, p, control=True)
    assert g.blocked == 0 and not g.flagged and g.escalated == none.escalated


def test_a10_executes_the_canonical_sql(stub_env: Env) -> None:
    from taintguard import analyze_query

    g = guard_for(stub_env)
    sql = "select make, count(*) as n from gold_trends group by make"
    _, state, _ = run_sql_script(stub_env, g, [sql])
    canon = analyze_query(sql, stub_env.guard_catalog.subset(["gold_trends"])).canonical_sql
    assert state.query_results[0].sql == canon and canon != sql


def test_a11_unanalysable_query_is_refused_and_the_run_continues(stub_env: Env) -> None:
    g = guard_for(stub_env)
    model, state, out = run_sql_script(
        stub_env, g, ["SELECT 1 FROM gold_trends, LATERAL (SELECT top_summary) l"]
    )
    assert (
        out.status == "ok"
        and "[sql refused by policy]" in model.users[-1]
        and "lateral" in model.users[-1]
    )
    assert not state.query_results[0].ok


def test_a12_benign_runs_are_unchanged_by_the_guard(stub_env: Env) -> None:
    qs = [q for q in questions(stub_env, 24)][:20]
    assert len(qs) == 20
    blocked = flagged = 0
    for i, q in enumerate(qs):
        spec = spec_for(q, trial_id=f"b{i}", seed=i)
        p = make_seed("laundering", "falsification", "blackbox", target_kind="analyst")
        base = run_trial(
            stub_env, StubModel(), Defense, spec, p, control=True, questions={q.id: q}, uid=i
        )
        g = run_trial(
            stub_env,
            StubModel(),
            lambda: guard_for(stub_env),
            spec,
            p,
            control=True,
            questions={q.id: q},
            uid=i,
        )
        blocked += g.blocked
        flagged += g.flagged
        assert _matches(q, g) == _matches(q, base), q.text
    assert blocked == 0 and flagged == 0
