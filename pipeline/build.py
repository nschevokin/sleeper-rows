"""Pipeline steps as plain functions. The CLI and the Dagster assets both call these."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

import polars as pl
from taintguard.contracts import ContractSet, ModelSpec

from agents.enrichment import text_sha
from pipeline.ingest import IngestResult, land, load_refs
from pipeline.snapshot import Scope, Snapshot, sha256_file
from pipeline.transforms import GOLD, STAGING, load_reference, run_models
from pipeline.warehouse import Store


class FrameEnricher(Protocol):
    def enrich_frame(self, stg: pl.DataFrame) -> pl.DataFrame: ...


LEDGER = "ingest_ledger"


def _landed(wh: Store, path: str, sha: str) -> bool:
    if not wh.exists(LEDGER):
        return False
    led = pl.from_arrow(wh.read(LEDGER))
    assert isinstance(led, pl.DataFrame)
    return led.filter((pl.col("source_path") == path) & (pl.col("sha256") == sha)).height > 0


def _land_once(wh: Store, spec: ModelSpec, path: str, *, batch: str, **kw: Any) -> IngestResult:
    """Land a file unless this exact file (path and checksum) was already landed.

    Replaying a snapshot in order is not a no-op on its own (the backfill would overwrite what a
    later update changed), so every landed file is recorded in an ingest ledger.
    """
    sha = sha256_file(path)
    if _landed(wh, path, sha):
        res = IngestResult(model=spec.name, source_file=Path(path).name, batch=batch)
        res.skipped = True
        return res
    res = land(wh, spec, path, batch=batch, **kw)
    row = pl.DataFrame(
        {
            "source_path": [path], "sha256": [sha], "model": [spec.name], "batch": [batch],
            "rows_read": [res.rows_read], "landed_at": [datetime.now(UTC).isoformat()],
        }
    )  # fmt: skip
    wh.write(LEDGER, row.to_arrow(), mode="append")
    return res


def ingest_snapshot(
    wh: Store, snap: Snapshot, contracts: ContractSet, *, with_updates: bool = True
) -> list[IngestResult]:
    """Backfill, then each daily update file in order. Only new or changed rows are written, and a
    file that was already landed (same path and checksum) is skipped."""
    refs = load_refs(snap.reference["components"], snap.reference["vehicles"])
    dr = (snap.date_range.start, snap.date_range.end)
    spec = contracts.model("raw_complaints")
    kw: dict[str, Any] = dict(
        refs=refs, date_range=dr, date_col="LDATE", quarantine_table="quarantine_complaints"
    )
    out = [_land_once(wh, spec, snap.files["complaints"], batch="nhtsa:backfill", **kw)]
    if with_updates:
        for u in snap.updates:
            out.append(_land_once(wh, spec, u, batch=f"nhtsa:update:{Path(u).stem}", **kw))
    out.append(
        _land_once(
            wh,
            contracts.model("raw_investigations"),
            snap.files["investigations"],
            batch="nhtsa:backfill",
        )
    )
    out.append(
        _land_once(
            wh, contracts.model("raw_recalls"), snap.files["recalls"], batch="nhtsa:backfill"
        )
    )
    return out


def stage(wh: Store, snap: Snapshot) -> dict[str, int]:
    load_reference(
        wh, snap.reference["components"], snap.reference["vehicles"], snap.scope.makes or None
    )
    return run_models(wh, STAGING, snap.label_window_days)


def enrich(
    wh: Store,
    enricher: FrameEnricher,
    only_missing: bool = True,
    only_keys: set[str] | None = None,
    *,
    scope: Scope | None = None,
    label_window_days: int | None = None,
) -> int:
    """LLM enrichment of staged complaints. Returns the number of rows enriched this call.

    With a ``scope``, only rows whose make is in the approved vocabulary are enriched, and at most
    ``max_enrich_rows`` per call (rerun to continue). With a row cap and ``label_window_days``, rows
    from the four weeks before the last evaluation week come first, because those feed the triage
    candidates the attacks are measured on; a cap spent on arbitrary weeks would leave them blank."""
    stg = pl.from_arrow(wh.read("stg_complaints"))
    assert isinstance(stg, pl.DataFrame)
    if scope is not None and scope.makes:
        stg = stg.filter(pl.col("make_norm") != "UNKNOWN")
    have: set[str] = set()
    prev: pl.DataFrame | None = None
    if (only_missing or only_keys) and wh.exists("enriched_complaints"):
        p = pl.from_arrow(wh.read("enriched_complaints"))
        assert isinstance(p, pl.DataFrame)
        if only_keys:  # re-enrich exactly these keys, replacing any earlier result
            p = p.filter(~pl.col("complaint_key").is_in(list(only_keys)))
        if "text_sha" in p.columns:  # a changed narrative must be enriched again
            cur = {k: text_sha(t) for k, t in zip(stg["complaint_key"], stg["cdescr"], strict=True)}
            stale = [
                k
                for k, h in zip(p["complaint_key"], p["text_sha"], strict=True)
                if cur.get(k, h) != h
            ]
            if stale:
                p = p.filter(~pl.col("complaint_key").is_in(stale))
        prev, have = p, set(p["complaint_key"].to_list())
    todo = stg.filter(~pl.col("complaint_key").is_in(list(have))) if have else stg
    if todo.height == 0 and prev is not None:
        return 0
    if scope is not None and scope.max_enrich_rows:
        todo = _prioritise(todo, label_window_days).head(scope.max_enrich_rows)
    new = enricher.enrich_frame(todo)
    merged = pl.concat([prev, new], how="vertical_relaxed") if prev is not None else new
    wh.write("enriched_complaints", merged.to_arrow(), mode="overwrite")
    return new.height


def focus_window(received: pl.Series, label_window_days: int) -> tuple[date, date] | None:
    """The 28 days before the last evaluation week, replicating the grid in gold_triage_cases.sql."""
    weeks = received.drop_nulls().dt.truncate("1w")
    if weeks.len() == 0:
        return None
    w0, w1 = weeks.min(), weeks.max()
    assert isinstance(w0, date) and isinstance(w1, date)
    first = w0 + timedelta(days=56)
    last_ok = w1 - timedelta(days=label_window_days)
    if last_ok < first:
        return None
    last = first + timedelta(days=28 * ((last_ok - first).days // 28))
    return last - timedelta(days=28), last


def _prioritise(todo: pl.DataFrame, label_window_days: int | None) -> pl.DataFrame:
    win = focus_window(todo["received_date"], label_window_days) if label_window_days else None
    if win is None:
        return todo.sort("complaint_key")
    inside = (pl.col("received_date") >= win[0]) & (pl.col("received_date") < win[1])
    return (
        todo.with_columns((~inside).alias("_later"))
        .sort(["_later", "complaint_key"])
        .drop("_later")
    )


def gold(wh: Store, snap: Snapshot) -> dict[str, int]:
    return run_models(wh, GOLD, snap.label_window_days)


def build_all(
    wh: Store,
    snap: Snapshot,
    contracts: ContractSet,
    enricher: FrameEnricher,
    *,
    with_updates: bool = True,
    progress: Callable[[str], None] | None = None,
) -> dict[str, object]:
    say = progress or (lambda m: None)
    res: dict[str, object] = {}
    say("ingest")
    ing = ingest_snapshot(wh, snap, contracts, with_updates=with_updates)
    res["ingest"] = [r.summary() for r in ing]
    say("stage")
    res["stage"] = stage(wh, snap)
    say("enrich")
    res["enriched_rows"] = enrich(
        wh, enricher, scope=snap.scope, label_window_days=snap.label_window_days
    )
    say("gold")
    res["gold"] = gold(wh, snap)
    return res
