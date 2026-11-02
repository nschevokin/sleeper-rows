"""Dagster definitions: the same step functions as the CLI, as an asset graph plus a daily schedule.

Configuration comes from the environment, never from code:
  SLEEPER_SNAPSHOT   path to the snapshot manifest   (default .fixture/snapshot.yaml)
  SLEEPER_WAREHOUSE  warehouse directory             (default .warehouse)
  SLEEPER_MODE       stub | ollama                   (default stub)
  SLEEPER_MODEL      Ollama model name, ollama mode only

Run:  uv run dagster dev -m pipeline.definitions     (UI)
      uv run python -m pipeline.definitions          (materialise everything once, no UI)
The schedule is defined but DEFAULT_STATUS is STOPPED: switch it on in the UI or with
`dagster schedule start`. Nothing runs unattended until you do.
"""

from __future__ import annotations

import os
from typing import Any

import dagster as dg
from taintguard.contracts import load_contracts

from agents.enrichment import Enricher
from pipeline import build
from pipeline.cli import CONTRACTS, ROOT, _model
from pipeline.ingest import load_refs
from pipeline.snapshot import load_snapshot
from pipeline.warehouse import Warehouse


def _cfg() -> dict[str, str]:
    return {
        "snapshot": os.environ.get("SLEEPER_SNAPSHOT", ".fixture/snapshot.yaml"),
        "warehouse": os.environ.get("SLEEPER_WAREHOUSE", ".warehouse"),
        "mode": os.environ.get("SLEEPER_MODE", "stub"),
        "model": os.environ.get("SLEEPER_MODEL", ""),
    }


def _ctx() -> tuple[Any, Any, Warehouse]:
    c = _cfg()
    return load_snapshot(c["snapshot"]), load_contracts(CONTRACTS), Warehouse(c["warehouse"])


@dg.asset(group_name="pipeline", description="Contract-tested landing of backfill and daily files.")
def raw_landing() -> dg.MaterializeResult:
    snap, contracts, wh = _ctx()
    res = build.ingest_snapshot(wh, snap, contracts)
    return dg.MaterializeResult(
        metadata={"files": len(res), "summary": str([r.summary() for r in res])[:2000]}
    )


@dg.asset(deps=[raw_landing], group_name="pipeline", description="SQL staging models.")
def staging() -> dg.MaterializeResult:
    snap, _, wh = _ctx()
    return dg.MaterializeResult(metadata={k: v for k, v in build.stage(wh, snap).items()})


@dg.asset(
    deps=[staging], group_name="pipeline", description="LLM enrichment (quarantined from gold SQL)."
)
def enriched() -> dg.MaterializeResult:
    snap, _, wh = _ctx()
    c = _cfg()
    refs = load_refs(snap.reference["components"], snap.reference["vehicles"])
    systems = sorted({x.split(":", 1)[0].upper() for x in refs["components"]})
    model = _model(c["mode"], c["model"] or None, ROOT / "models.lock.yaml")
    spec = load_contracts(CONTRACTS).model("enriched_complaints")
    n = build.enrich(
        wh,
        Enricher(model, systems, contract=spec),
        scope=snap.scope,
        label_window_days=snap.label_window_days,
    )
    return dg.MaterializeResult(
        metadata={
            "rows_enriched": n,
            "model": model.name,
            "digest": str(model.digest),
            "synthetic": snap.synthetic,
        }
    )


@dg.asset(deps=[enriched], group_name="pipeline", description="Gold marts used by the agents.")
def gold() -> dg.MaterializeResult:
    snap, _, wh = _ctx()
    return dg.MaterializeResult(metadata={k: v for k, v in build.gold(wh, snap).items()})


daily_job = dg.define_asset_job("daily_build", selection=dg.AssetSelection.groups("pipeline"))

daily_schedule = dg.ScheduleDefinition(
    job=daily_job,
    cron_schedule="30 5 * * *",
    default_status=dg.DefaultScheduleStatus.STOPPED,
)

defs = dg.Definitions(
    assets=[raw_landing, staging, enriched, gold], jobs=[daily_job], schedules=[daily_schedule]
)

if __name__ == "__main__":  # materialise everything once, in-process
    r = dg.materialize([raw_landing, staging, enriched, gold])
    raise SystemExit(0 if r.success else 1)
