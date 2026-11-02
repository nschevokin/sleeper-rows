"""Show what a model actually does on a few clean analyst and data-quality tasks.

Use it when baseline accuracy looks too low to trust: it prints each step's action (the SQL the
model wrote, loops, a final answer that does not match the truth), so a harness or prompt fault
can be told apart from a model that simply cannot do the task.

    uv run python -m eval.diagnose --config eval/configs/basecheck.yaml -n 4
"""

from __future__ import annotations

import argparse
import random
from typing import Any

from agents.analyst import run_analyst
from agents.data_quality import run_data_quality
from agents.dq_cases import make_cases
from agents.events import EventLog
from agents.questions import generate_questions
from agents.runtime import Defense
from eval import scoring
from eval.env import build_env
from eval.runner import load_config, make_model


def _show(actions: list[Any], status: str) -> None:
    for i, a in enumerate(actions):
        d = {k: v for k, v in a.model_dump().items() if v is not None and k != "action"}
        body = " ".join(f"{k}={str(v)[:230]!r}" for k, v in d.items())
        print(f"    step {i + 1}: {a.action} {body}")
    print(f"    status: {status} after {len(actions)} action(s)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="eval.diagnose")
    ap.add_argument("--config", required=True)
    ap.add_argument("-n", type=int, default=4, help="analyst questions and DQ cases to show")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    model = make_model(cfg.models[0])
    env = build_env(cfg.snapshot, model, seed=0)
    tables = env.tables()
    log = EventLog(None, run_id="diag", scenario="clean", scenario_id="diag")

    print("\n=== ANALYST ===")
    qs = [
        q
        for q in generate_questions(tables["gold_trends"], n=60, seed=env.snapshot.seed)
        if q.kind == "number"
    ]
    for q in qs[: a.n]:
        res, _, _ = run_analyst(model, tables, q, Defense(), log)
        ok = scoring.analyst_correct(q, res.value, res.text)
        print(
            f"\n[{q.id}] {q.text}\n    truth={q.truth} got={res.value!r}/{res.text!r} correct={ok}"
        )
        print(f"    expected SQL: {q.sql}")
        _show(res.outcome.actions, res.outcome.status)

    print("\n=== DATA QUALITY ===")
    base = env.snapshot.updates[-1] if env.snapshot.updates else env.snapshot.files["complaints"]
    cases = make_cases(
        base,
        env.contracts.model("raw_complaints"),
        env.refs,
        per_category=1,
        seed=env.snapshot.seed,
    )
    random.Random(0).shuffle(cases)
    for case in cases[: a.n]:
        res_d, _, _ = run_data_quality(model, case, Defense(), log)
        print(f"\n[{case.id}] truth category={case.category} got={res_d.category!r}")
        _show(res_d.outcome.actions, res_d.outcome.status)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
