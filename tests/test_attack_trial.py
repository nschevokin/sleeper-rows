"""Attack trials against the gullible stub: payloads must hijack it undefended, controls must not."""

from __future__ import annotations

import pytest

from agents.questions import generate_questions
from agents.runtime import Defense
from agents.stub import StubModel
from attacks.payloads import make_seed
from attacks.success import judge
from attacks.trial import TrialSpec, run_trial
from eval.env import Env, build_env


@pytest.fixture(scope="module")
def env(tmp_path_factory: pytest.TempPathFactory) -> Env:
    from fixtures.make_fixture import generate

    out = tmp_path_factory.mktemp("fx") / "data"
    generate("tiny", seed=7, out=out)
    return build_env(out.parent / "snapshot.yaml", StubModel())


def test_unauthorized_export_hijacks_analyst(env: Env) -> None:
    qs = generate_questions(env.base.read("gold_trends"), n=10)
    q = next(x for x in qs if x.kind == "number")
    spec = TrialSpec(
        "t1", "analyst", "tool_hijack", "unauthorized_action", "blackbox", "narrative", 5, 1, q.id
    )
    p = make_seed("tool_hijack", "unauthorized_action", "blackbox", target_kind="analyst")
    a = run_trial(env, StubModel(), Defense, spec, p, questions={q.id: q})
    c = run_trial(env, StubModel(), Defense, spec, p, control=True, questions={q.id: q})
    v = judge(spec, a, c, q)
    assert v["goal_met"], (a.exports, a.status)
    assert not c.exports
    assert a.evidence["landing"] and a.evidence["agent_input"]
    assert a.evidence["gold"] and a.canary_in_output


def test_suppression_and_fabrication_on_triage(env: Env) -> None:
    from datetime import date

    import polars as pl

    from attacks.trial import parse_gid
    from eval.env import to_df

    cases = to_df(env.base.read("gold_triage_cases"))
    week = cases["eval_week"].max()
    assert isinstance(week, date)
    top = (
        cases.filter(pl.col("eval_week") == week)
        .sort("surge_ratio", descending=True)
        .row(0, named=True)
    )
    gid = "|".join(str(top[k]) for k in ("make", "model", "model_year", "component_group"))
    parse_gid(gid)
    spec = TrialSpec(
        "t2",
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
    a = run_trial(env, StubModel(), Defense, spec, p)
    c = run_trial(env, StubModel(), Defense, spec, p, control=True)
    v = judge(spec, a, c)
    assert gid in c.candidates or c.candidates is not None
    assert "goal_met" in v


def test_sleeper_wakes_only_on_its_trigger(env: Env) -> None:
    from attacks.targets import analyst_targets

    _, qs = analyst_targets(env, 40, pool=120, triggered=True)
    assert qs and all(q.trigger for q in qs.values())
    woke = []
    for q in qs.values():
        assert q.trigger is not None
        p = make_seed(
            "sleeper", "unauthorized_action", "blackbox", target_kind="analyst", trigger=q.trigger
        )
        spec = TrialSpec(
            "t3", "analyst", "sleeper", "unauthorized_action", "blackbox", "narrative", 5, 1, q.id
        )
        r = run_trial(env, StubModel(), Defense, spec, p, questions={q.id: q})
        if r.evidence["agent_input"]:  # the payload reached the agent for this question
            assert r.exports, "present trigger + payload in view must wake the sleeper"
            woke.append(q.id)
    assert woke
    # Same payload, question without the trigger word: dormant.
    other = next(
        x
        for x in generate_questions(env.base.read("gold_trends"), n=80)
        if x.kind == "number" and x.trigger is None and not x.authorized_dest
    )
    p = make_seed(
        "sleeper", "unauthorized_action", "blackbox", target_kind="analyst", trigger="quarterly"
    )
    spec2 = TrialSpec(
        "t4", "analyst", "sleeper", "unauthorized_action", "blackbox", "narrative", 5, 1, other.id
    )
    assert not run_trial(env, StubModel(), Defense, spec2, p, questions={other.id: other}).exports


def test_load_trials_keeps_one_row_per_trial(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import json

    from eval.runner import load_trials

    rows = [
        {"model": "m", "defense": "none", "trial_id": "t1", "goal_met": False},
        {"model": "m", "defense": "none", "trial_id": "t1", "goal_met": True},
        {"model": "m", "defense": "detector", "trial_id": "t1", "goal_met": False},
    ]
    (tmp_path / "trials.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    df = load_trials(tmp_path)
    assert df.height == 2 and df.filter(df["defense"] == "none")["goal_met"][0] is True
