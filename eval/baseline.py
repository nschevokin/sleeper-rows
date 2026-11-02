"""Normal accuracy of every LLM component on clean data, before any attack."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import polars as pl

from agents.analyst import run_analyst
from agents.data_quality import run_data_quality
from agents.dq_cases import make_cases
from agents.events import EventLog
from agents.guard_adapter import guard_state_hooks
from agents.llm import ModelClient
from agents.questions import generate_questions
from agents.runtime import Defense
from agents.stub import StubModel
from agents.triage import run_triage
from eval import scoring
from eval.env import Env, load_labels, to_df


@dataclass
class BaselineReport:
    model: str
    digest: str
    synthetic: bool
    enrichment: dict[str, float] = field(default_factory=dict)
    triage: dict[str, Any] = field(default_factory=dict)
    analyst: dict[str, float] = field(default_factory=dict)
    data_quality: dict[str, float] = field(default_factory=dict)
    rows: list[dict[str, Any]] = field(default_factory=list)  # per-item results
    cost: dict[str, float] = field(default_factory=dict)  # defense side effects on benign runs
    seconds: float = 0.0


def run_baseline(
    env: Env,
    model: ModelClient,
    *,
    defense: Defense | None = None,
    max_weeks: int | None = None,
    k: int = 15,
    n_questions: int = 100,
    dq_per_category: int = 5,
    events_dir: Path | None = None,
    seed: int = 0,
) -> BaselineReport:
    t0 = time.perf_counter()
    defense = defense or Defense()
    rep = BaselineReport(model.name, model.digest, env.snapshot.synthetic)
    store = env.base
    blocked = flagged = confirms = steps = 0
    hook = lambda agent: {"column_tiers": guard_state_hooks(env.guard_catalog, agent)}  # noqa: E731

    # --- enrichment: agreement of the component tag with NHTSA's own COMPDESC -----------------
    enr = pl.from_arrow(store.read("enriched_complaints"))
    stg = pl.from_arrow(store.read("stg_complaints"))
    assert isinstance(enr, pl.DataFrame) and isinstance(stg, pl.DataFrame)
    ok = enr.filter(pl.col("status") == "ok")
    rep.enrichment = {
        "n": float(enr.height),
        "malformed_rate": 1 - ok.height / max(enr.height, 1),
        "component_agreement": scoring.enrichment_agreement(enr, stg),
        "majority_baseline": scoring.majority_share(stg["component_group"].to_list()),
    }

    # --- triage ------------------------------------------------------------------------------
    labels = load_labels(store)
    cases_df = to_df(env.base.read("gold_triage_cases"))
    weeks = sorted(set(cases_df["eval_week"].to_list()))
    if max_weeks:
        weeks = weeks[-max_weeks:]
    tables = env.tables()
    tp = fp = fn = 0
    all_pos = all_cand = 0
    rule_tp = rule_fp = rule_fn = 0
    for w in weeks:
        wk: date = w
        log = EventLog(
            events_dir / f"clean-triage-{wk}.jsonl" if events_dir else None,
            run_id=f"clean-triage-{wk}", scenario="clean", scenario_id=f"triage-{wk}",
        )  # fmt: skip
        res, _, _ = run_triage(
            model, tables, wk, defense, log, k=k, seed=seed, state_hooks=hook("triage")
        )
        blocked += len(res.outcome.blocked)
        flagged += res.outcome.final_flagged
        confirms += res.outcome.confirm_requests
        steps += res.outcome.steps
        log.close()
        pos = scoring.positives_for_week(labels, wk)
        a, b, c = scoring.triage_counts(res.candidates, res.escalated, pos)
        tp, fp, fn = tp + a, fp + b, fn + c
        rep.rows.append(
            {
                "component": "triage",
                "item": str(wk),
                "tp": a,
                "fp": b,
                "fn": c,
                "status": res.outcome.status,
            }
        )
        cand_pos = len(set(res.candidates) & pos)
        all_pos += cand_pos
        all_cand += len(res.candidates)
        # trivial rule baseline: surge ratio >= 2.5 and >= 4 complaints (no model)
        top = {r["make"] + "|" + r["model"] + f"|{r['model_year']}|" + r["component_group"]
               for r in cases_df.filter(pl.col("eval_week") == wk).iter_rows(named=True)
               if r["surge_ratio"] >= 2.5 and r["n_4w"] >= 4}  # fmt: skip
        ra, rb, rc = scoring.triage_counts(res.candidates, list(top & set(res.candidates)), pos)
        rule_tp, rule_fp, rule_fn = rule_tp + ra, rule_fp + rb, rule_fn + rc
    m = scoring.prf(tp, fp, fn)
    rule = scoring.prf(rule_tp, rule_fp, rule_fn)
    rep.triage = {
        "weeks": len(weeks), "precision": m.precision, "recall": m.recall, "f1": m.f1,
        "tp": tp, "fp": fp, "fn": fn,
        "baseline_never_escalate_recall": 0.0,
        "baseline_escalate_all_precision": all_pos / max(all_cand, 1),
        "baseline_rule_precision": rule.precision, "baseline_rule_recall": rule.recall,
    }  # fmt: skip

    # --- analyst -------------------------------------------------------------------------------
    gold_trends = store.read("gold_trends")
    questions = generate_questions(gold_trends, n=n_questions, seed=env.snapshot.seed)
    if isinstance(model, StubModel):
        for q in questions:
            model.hints[q.text] = (q.peek_where, q.sql)
    correct = 0
    export_ok = 0
    export_n = 0
    for q in questions:
        log = EventLog(
            events_dir / f"clean-analyst-{q.id}.jsonl" if events_dir else None,
            run_id=f"clean-analyst-{q.id}", scenario="clean", scenario_id=f"analyst-{q.id}",
        )  # fmt: skip
        res_a, _, sinks = run_analyst(
            model, tables, q, defense, log, seed=seed, state_hooks=hook("analyst")
        )
        blocked += len(res_a.outcome.blocked)
        flagged += res_a.outcome.final_flagged
        confirms += res_a.outcome.confirm_requests
        steps += res_a.outcome.steps
        log.close()
        good = scoring.analyst_correct(q, res_a.value, res_a.text)
        correct += good
        if q.authorized_dest:
            export_n += 1
            export_ok += any(e["dest"] == q.authorized_dest for e in sinks.exports)
        rep.rows.append(
            {"component": "analyst", "item": q.id, "correct": good, "status": res_a.outcome.status}
        )
    rep.analyst = {
        "n": len(questions), "exact_match": correct / len(questions),
        "export_requests_honoured": export_ok / export_n if export_n else float("nan"),
        "baseline_constant_zero": sum(1 for q in questions if q.kind == "number" and q.truth == 0) / len(questions),
    }  # fmt: skip

    # --- data quality ---------------------------------------------------------------------------
    base_file = (
        env.snapshot.updates[-1] if env.snapshot.updates else env.snapshot.files["complaints"]
    )
    import random

    dq = make_cases(
        base_file,
        env.contracts.model("raw_complaints"),
        env.refs,
        per_category=dq_per_category,
        seed=env.snapshot.seed,
    )
    hit = 0
    cats: list[str] = []
    for case in dq:
        log = EventLog(
            events_dir / f"clean-dq-{case.id}.jsonl" if events_dir else None,
            run_id=f"clean-dq-{case.id}", scenario="clean", scenario_id=f"dq-{case.id}",
        )  # fmt: skip
        res_d, _, _ = run_data_quality(
            model, case, defense, log, seed=seed, state_hooks=hook("data_quality")
        )
        blocked += len(res_d.outcome.blocked)
        flagged += res_d.outcome.final_flagged
        confirms += res_d.outcome.confirm_requests
        steps += res_d.outcome.steps
        log.close()
        good = res_d.category == case.category
        hit += good
        cats.append(case.category)
        rep.rows.append(
            {
                "component": "data_quality",
                "item": case.id,
                "correct": good,
                "status": res_d.outcome.status,
            }
        )
    _ = random
    rep.data_quality = {
        "n": len(dq),
        "accuracy": hit / len(dq),
        "majority_baseline": scoring.majority_share(cats),
    }
    rep.cost = {
        "false_blocks": float(blocked), "benign_flags": float(flagged),
        "confirm_requests": float(confirms), "agent_steps": float(steps),
        "query_refusals": float(getattr(defense, "query_refusals", 0)),
        "extraction_loss": float(getattr(defense, "extraction_loss", 0)),
        "defense_model_ms": float(getattr(defense, "latency_ms", 0.0)),
    }  # fmt: skip
    rep.seconds = time.perf_counter() - t0
    return rep
