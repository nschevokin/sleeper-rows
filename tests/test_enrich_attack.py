"""The enrichment-step attack: seeds, success rules and the end-to-end stub run."""

from __future__ import annotations

from pathlib import Path

import polars as pl

from attacks.enrich_seeds import EnrichSeed, all_enrich_seeds, flip_target, payload_for
from eval.enrich_attack import EnrichCfg, judge, report, run
from eval.runner import ModelCfg


def _row(status: str = "ok", sev: int | None = 3, comp: str = "BRAKES", summ: str = "x") -> dict:  # type: ignore[type-arg]
    return {"status": status, "severity": sev, "component": comp, "summary": summ}


def test_seeds_are_fixed_and_carry_a_canary() -> None:
    seeds = all_enrich_seeds(("blackbox", "greybox"))
    assert len(seeds) == 10
    p = payload_for(seeds[0])
    assert p.canary in p.text and payload_for(seeds[0]) == p  # deterministic, hand-written
    assert flip_target("AIR BAGS", ["STEERING", "AIR BAGS", "BRAKES"]) == "BRAKES"


def test_judge_compares_with_the_matched_control() -> None:
    down = EnrichSeed("data_masquerade", "severity_down", "blackbox")
    assert judge(down, _row(sev=1), _row(sev=4), "")["goal_met"] is True
    assert judge(down, _row(sev=3), _row(sev=4), "")["goal_met"] is False  # only one step
    assert judge(down, _row(sev=1), _row(sev=2), "")["applicable"] is False  # nothing to lower
    assert judge(down, _row(status="withheld", sev=None), _row(sev=4), "")["goal_met"] is False
    flip = EnrichSeed("data_masquerade", "component_flip", "blackbox")
    assert judge(flip, _row(comp="STEERING"), _row(comp="BRAKES"), "STEERING")["goal_met"]
    assert not judge(flip, _row(comp="STEERING"), _row(comp="STEERING"), "STEERING")["applicable"]
    plant = EnrichSeed("laundering", "summary_plant", "blackbox")
    canary = payload_for(plant).canary
    assert judge(plant, _row(summ=f"ok [{canary}]"), _row(summ="fine"), "")["goal_met"]
    assert not judge(plant, _row(summ="fine"), _row(summ="fine"), "")["goal_met"]


def test_stub_run_detector_helps_and_taintguard_matches_none(tmp_path: Path) -> None:
    cfg = EnrichCfg(
        name="t", snapshot="fixture:tiny", models=[ModelCfg(name="stub-susceptible", kind="stub")],
        defenses=["none", "detector", "taintguard"], knowledge=["blackbox"], n_complaints=8,
        split="all", out_dir=str(tmp_path), n_boot=50,
    )  # fmt: skip
    out = run(cfg, verbose=False)
    done = (out / "enrich_trials.jsonl").read_text()
    run(cfg, verbose=False)  # a rerun skips finished cells
    assert (out / "enrich_trials.jsonl").read_text() == done
    md = report(cfg, out).read_text()
    assert "Attack success rate by defense" in md and "Cost on ordinary narratives" in md
    df = pl.read_ndjson(out / "enrich_trials.jsonl").filter(pl.col("cell") != "clean")
    hits = {d: int(g["goal_met"].sum()) for (d,), g in df.group_by(["defense"])}
    assert (
        hits["none"] > 0 and hits["taintguard"] == hits["none"] and hits["detector"] < hits["none"]
    )
