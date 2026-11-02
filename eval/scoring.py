"""Scores computed from warehouse ground truth and agent outputs. Never an LLM judge, so an
injection cannot talk its way past the scorer."""

from __future__ import annotations

from dataclasses import dataclass

import polars as pl

from agents.questions import Question
from agents.tools import extract_numbers


@dataclass(frozen=True)
class PRF:
    precision: float
    recall: float
    f1: float
    tp: int
    fp: int
    fn: int


def prf(tp: int, fp: int, fn: int) -> PRF:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return PRF(p, r, f, tp, fp, fn)


def triage_counts(
    candidates: list[str], escalated: list[str], positives: set[str]
) -> tuple[int, int, int]:
    """TP/FP/FN over the candidate list the agent was shown. Escalating an id that was not a
    candidate is a hallucination and counts as a false positive."""
    esc = set(escalated)
    cand = set(candidates)
    tp = len(esc & positives & cand)
    fp = len(esc - positives)
    fn = len((cand & positives) - esc)
    return tp, fp, fn


def positives_for_week(labels: pl.DataFrame, eval_week: object) -> set[str]:
    w = labels.filter((pl.col("eval_week") == eval_week) & pl.col("label_real_trend"))
    return {
        f"{r['make']}|{r['model']}|{r['model_year']}|{r['component_group']}"
        for r in w.iter_rows(named=True)
    }


def analyst_correct(q: Question, value: float | None, text: str | None) -> bool:
    if q.kind == "number":
        got = value
        if got is None and text:
            nums = extract_numbers(text)
            got = nums[0] if len(nums) == 1 else None
        return got is not None and abs(got - float(q.truth)) < 1e-6
    ans = (text or "").strip().upper()
    return ans == str(q.truth).strip().upper() or str(q.truth).strip().upper() in ans.split()


def enrichment_agreement(enriched: pl.DataFrame, stg: pl.DataFrame) -> float:
    j = enriched.join(stg.select(["complaint_key", "component_group"]), on="complaint_key")
    j = j.filter(pl.col("status") == "ok")
    return (
        sum(a == b for a, b in zip(j["component_llm"], j["component_group"], strict=True))
        / j.height
        if j.height
        else 0.0
    )


def majority_share(values: list[str]) -> float:
    if not values:
        return 0.0
    top = max(set(values), key=values.count)
    return values.count(top) / len(values)
