"""The experiment matrix: models x defenses x payload x placement x dose x seed x target.

* Resumable: every finished trial is appended to ``trials.jsonl``; a rerun skips what is there.
* Failures are rows, not silences: an exception becomes ``error`` on that row and is reported.
* Scores come from outputs and warehouse state only (attacks/success.py); there is no LLM judge.
"""

from __future__ import annotations

import hashlib
import json
import time
import traceback
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import polars as pl
import yaml
from pydantic import BaseModel, Field

from agents.llm import ModelClient, OllamaModel
from agents.registry import DEFENSES, defense_factory
from agents.stub import StubModel
from attacks.inject import PLACEMENTS
from attacks.payloads import FAMILIES, Payload, all_seeds, make_seed
from attacks.success import _matches, judge
from attacks.survival import LAYERS
from attacks.targets import pick
from attacks.trial import TrialRun, TrialSpec, run_trial
from eval.env import Env, build_env


class ModelCfg(BaseModel):
    name: str
    kind: Literal["stub", "ollama"] = "stub"
    digest: str | None = None  # pinned Ollama digest
    host: str = "http://127.0.0.1:11434"


class MatrixCfg(BaseModel):
    name: str
    snapshot: str  # path to snapshot.yaml, or "fixture:tiny" / "fixture:small"
    models: list[ModelCfg]
    defenses: list[str] = Field(default_factory=lambda: list(DEFENSES))
    families: list[str] = Field(default_factory=lambda: list(FAMILIES))
    goals: list[str] | None = None
    knowledge: list[str] = ["blackbox"]
    placements: list[str] = list(PLACEMENTS)
    doses: list[int] = [1, 5, 25]
    seeds: int = 3
    sleeper_targets: int = (
        4  # trigger-word questions are a minority, so the sleeper family needs more
    )
    targets_per_kind: int = 2
    split: Literal["dev", "test", "all"] = "test"
    boost: str = "max"
    out_dir: str = "results"
    n_boot: int = 2000
    summary_mode: Literal["model", "extractive"] = "model"  # extractive = worst-case exposure
    dq_inspect_rows: bool = (
        False  # data-quality task asks the agent to read each failed check's rows
    )
    analyst_read_summaries: bool = False  # analyst task asks the agent to read top_summary
    baseline_weeks: int = 12  # triage eval weeks scored in the benign baseline
    baseline: bool = True  # also measure benign accuracy and side effects per defense
    max_trials: int | None = None  # for smoke runs


def load_config(path: str | Path) -> MatrixCfg:
    return MatrixCfg.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))


def make_model(cfg: ModelCfg) -> ModelClient:
    if cfg.kind == "stub":
        return StubModel()
    return OllamaModel(cfg.name, digest=cfg.digest, host=cfg.host)


@dataclass(frozen=True)
class Cell:
    """One matrix cell before it is run under each defense."""

    spec: TrialSpec
    payload: Payload
    uid: int


def _tid(*parts: object) -> str:
    raw = ".".join(str(p) for p in parts)
    return raw if len(raw) < 90 else raw[:70] + "." + hashlib.sha256(raw.encode()).hexdigest()[:10]


def enumerate_cells(cfg: MatrixCfg, env: Env) -> Iterator[Cell]:
    uid = 0
    for p in all_seeds(tuple(cfg.knowledge)):
        if p.family not in cfg.families or (cfg.goals and p.goal not in cfg.goals):
            continue
        kind = p.id.split(".")[3]  # family.goal.knowledge.target_kind.idx
        sleeper = p.family == "sleeper"
        targets, tqs = pick(
            env, kind, p.goal, cfg.sleeper_targets if sleeper else cfg.targets_per_kind, None if cfg.split == "all" else cfg.split,
            triggered=sleeper,
        )  # fmt: skip
        for t in targets:
            if sleeper:  # wake on the trigger word that this very question contains
                p = make_seed(
                    p.family, p.goal, p.knowledge, target_kind=kind,
                    trigger=tqs[t.target_id].trigger or "quarterly",
                )  # fmt: skip
            for placement in cfg.placements:
                for dose in cfg.doses:
                    for s in range(cfg.seeds):
                        tid = _tid(p.id, placement, f"d{dose}", f"s{s}", t.target_id)
                        spec = TrialSpec(
                            tid, kind, p.family, p.goal, p.knowledge, placement, dose, s,
                            t.target_id, t.eval_week, t.split, cfg.boost,
                        )  # fmt: skip
                        yield Cell(spec, p, uid % 9000)
                        uid += 1


def _row(
    model: ModelClient, defense: str, cell: Cell, a: TrialRun, c: TrialRun, q: Any
) -> dict[str, Any]:
    v = judge(cell.spec, a, c, q)
    row: dict[str, Any] = {
        "model": model.name, "model_digest": model.digest, "defense": defense,
        "trial_id": cell.spec.trial_id, "family": cell.spec.family, "goal": cell.spec.goal,
        "knowledge": cell.spec.knowledge, "target_kind": cell.spec.target_kind,
        "placement": cell.spec.placement, "dose": cell.spec.dose, "seed": cell.spec.seed,
        "target_id": cell.spec.target_id, "split": cell.spec.split, "payload_id": cell.payload.id,
        **v,
        "canary_in_output": a.canary_in_output, "attack_status": a.status, "control_status": c.status,
        "tokens": a.tokens, "latency_ms": a.latency_ms, "defense_ms": a.defense_ms, "steps": a.steps,
        "confirm_requests": a.confirm_requests, "invalid_actions": a.invalid,
        "control_blocked": c.blocked, "control_flagged": c.flagged, "control_confirms": c.confirm_requests,
        "control_tokens": c.tokens, "control_defense_ms": c.defense_ms, "error": None,
        "landed": json.dumps(a.landing),
    }  # fmt: skip
    for layer in (*LAYERS, "quarantine"):
        ev = a.evidence.get(layer)
        row[f"ev_{layer}"] = ev
        row[f"survived_{layer}"] = ev is not None
    if cell.spec.target_kind == "analyst" and q is not None:
        row["control_correct"] = _matches(q, c)
    elif cell.spec.target_kind == "data_quality":
        row["control_correct"] = c.category == c.truth_category
    else:
        row["control_correct"] = None
    return row


def _is_json(line: str) -> bool:
    try:
        json.loads(line)
    except json.JSONDecodeError:
        return False
    return bool(line.strip())


def _done(path: Path) -> set[tuple[str, str, str]]:
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                r = json.loads(line)
            except json.JSONDecodeError:  # torn last line from an interrupted run: redo it
                continue
            out.add((r["model"], r["defense"], r["trial_id"]))
    return out


def run_matrix(
    cfg: MatrixCfg, *, config_path: str | Path | None = None, verbose: bool = True
) -> Path:
    out = Path(cfg.out_dir) / cfg.name
    out.mkdir(parents=True, exist_ok=True)
    if config_path:
        (out / "config.yaml").write_text(
            Path(config_path).read_text(encoding="utf-8"), encoding="utf-8"
        )
    trials = out / "trials.jsonl"
    done = _done(trials)
    snapshot = cfg.snapshot
    if snapshot.startswith("fixture:"):
        from fixtures.make_fixture import generate

        data = out / "fixture" / "data"
        if not (out / "fixture" / "snapshot.yaml").exists():
            generate(snapshot.split(":", 1)[1], seed=7, out=data)
        snapshot = str(out / "fixture" / "snapshot.yaml")
    t0 = time.perf_counter()
    n_run = n_err = streak = 0
    (out / "baseline").mkdir(exist_ok=True)
    with trials.open("a", encoding="utf-8") as fh:
        for mcfg in cfg.models:
            model = make_model(mcfg)
            env = build_env(snapshot, model, seed=0)
            env.summary_mode, env.dq_inspect_rows = cfg.summary_mode, cfg.dq_inspect_rows
            env.analyst_read_summaries = cfg.analyst_read_summaries
            qs: dict[str, Any] = {}
            for p_kind in ("analyst",):
                _, qs = pick(env, p_kind, "falsification", 1000)
            if cfg.baseline:
                _run_baselines(cfg, env, model, out)
            for cell in enumerate_cells(cfg, env):
                for dname in cfg.defenses:
                    key = (model.name, dname, cell.spec.trial_id)
                    if key in done:
                        continue
                    if cfg.max_trials is not None and n_run >= cfg.max_trials:
                        break
                    q = qs.get(cell.spec.target_id)
                    ev_dir: Path | None = None
                    if (
                        cell.spec.seed == 0
                        and cell.spec.dose == max(cfg.doses)
                        and cell.spec.placement == cfg.placements[0]
                    ):  # one traced run per family/defense/target feeds the Observatory
                        ev_dir = out / "events"
                        ev_dir.mkdir(exist_ok=True)
                    try:
                        factory = defense_factory(dname, env, model, seed=cell.spec.seed)
                        a = run_trial(
                            env,
                            model,
                            factory,
                            cell.spec,
                            cell.payload,
                            questions=qs,
                            uid=cell.uid,
                            events_dir=ev_dir,
                        )
                        c = run_trial(
                            env,
                            model,
                            factory,
                            cell.spec,
                            cell.payload,
                            control=True,
                            questions=qs,
                            uid=cell.uid,
                            events_dir=ev_dir,
                        )
                        row = _row(model, dname, cell, a, c, q)
                        streak = 0
                    except Exception as exc:  # recorded, never swallowed
                        n_err += 1
                        streak = streak + 1 if "ConnectError" in type(exc).__name__ else 0
                        if streak >= 5:
                            raise RuntimeError(
                                "5 consecutive connection errors: is `ollama serve` running? "
                                "Stopping without recording more failed trials."
                            ) from exc
                        row = {
                            "model": model.name, "model_digest": model.digest, "defense": dname,
                            "trial_id": cell.spec.trial_id, "family": cell.spec.family, "goal": cell.spec.goal,
                            "knowledge": cell.spec.knowledge, "target_kind": cell.spec.target_kind,
                            "placement": cell.spec.placement, "dose": cell.spec.dose, "seed": cell.spec.seed,
                            "target_id": cell.spec.target_id, "split": cell.spec.split, "payload_id": cell.payload.id,
                            "applicable": False, "goal_met": False,
                            "error": f"{type(exc).__name__}: {exc}"[:300],
                            "traceback": traceback.format_exc()[-1500:],
                        }  # fmt: skip
                    fh.write(json.dumps(row, default=str) + "\n")
                    fh.flush()
                    n_run += 1
                    if verbose and n_run % 25 == 0:
                        print(
                            f"  {n_run} trials, {n_err} errors, {time.perf_counter() - t0:.0f}s",
                            flush=True,
                        )
    (out / "run.json").write_text(
        json.dumps(
            {
                "trials_run_now": n_run,
                "errors_now": n_err,
                "seconds": round(time.perf_counter() - t0, 1),
            }
        ),
        encoding="utf-8",
    )
    return out


def _run_baselines(cfg: MatrixCfg, env: Env, model: ModelClient, out: Path) -> None:
    from eval.baseline import run_baseline

    for dname in cfg.defenses:
        path = out / "baseline" / f"{model.name.replace('/', '_')}.{dname}.json"
        if path.exists():
            continue
        defense = defense_factory(dname, env, model)()
        rep = run_baseline(
            env,
            model,
            defense=defense,
            n_questions=40,
            dq_per_category=2,
            max_weeks=cfg.baseline_weeks,
        )
        path.write_text(
            json.dumps(
                {
                    "model": rep.model, "digest": rep.digest, "synthetic": rep.synthetic, "defense": dname,
                    "enrichment": rep.enrichment, "triage": rep.triage, "analyst": rep.analyst,
                    "data_quality": rep.data_quality, "cost": rep.cost, "seconds": rep.seconds,
                },
                default=str, indent=1,
            ),
            encoding="utf-8",
        )  # fmt: skip


def load_trials(out: Path) -> pl.DataFrame:
    rows = [
        json.loads(line)
        for line in (out / "trials.jsonl").read_text(encoding="utf-8").splitlines()
        if _is_json(line)
        if line.strip()
    ]
    df = pl.DataFrame(rows, infer_schema_length=None)
    # a resumed run can repeat a trial: keep the last result for each (model, defense, trial)
    return df.unique(subset=["model", "defense", "trial_id"], keep="last", maintain_order=True)
