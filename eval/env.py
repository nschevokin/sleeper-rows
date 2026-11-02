"""The experiment environment: a clean, fully built in-memory copy of the pipeline state.

Attack trials clone this, land poisoned rows through the real landing code, recompute gold in
DuckDB and run agents, then throw the clone away. The real Iceberg warehouse is never touched.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import polars as pl
from taintguard.contracts import ContractSet, load_contracts

from agents.enrichment import DiskCache, Enricher
from agents.llm import ModelClient
from agents.runtime import Defense
from pipeline import build
from pipeline.ingest import load_refs
from pipeline.snapshot import Snapshot, load_snapshot
from pipeline.warehouse import MemoryWarehouse, Store

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Env:
    snapshot: Snapshot
    contracts: ContractSet
    refs: dict[str, set[str]]
    base: MemoryWarehouse
    systems: list[str]
    enrich_cache: MutableMapping[str, dict[str, Any]] = field(default_factory=dict)
    extract_cache: dict[str, Any] = field(default_factory=dict)
    summary_mode: str = "model"  # exposure condition, set from the matrix config
    dq_inspect_rows: bool = False
    analyst_read_summaries: bool = False
    _catalog: Any = None

    def enricher(
        self, model: ModelClient, defense: Defense | None = None, seed: int = 0
    ) -> Enricher:
        return Enricher(
            model,
            self.systems,
            defense,
            self.enrich_cache,
            seed,
            self.summary_mode,
            self.contracts.model("enriched_complaints"),
        )

    @property
    def guard_catalog(self) -> Any:
        """Taint catalog for the pipeline SQL, built once per environment."""
        if self._catalog is None:
            from agents.guard_adapter import make_guard_catalog

            self._catalog = make_guard_catalog(self.contracts, self.snapshot.label_window_days)
        return self._catalog

    def tables(self, store: Store | None = None) -> dict[str, Any]:
        s = store or self.base
        return {n: s.read(n) for n in ("gold_trends", "gold_triage_cases")}


def systems_of(contracts_refs: dict[str, set[str]]) -> list[str]:
    return sorted({c.split(":", 1)[0].upper() for c in contracts_refs["components"]})


def build_env(
    snapshot_path: str | Path,
    model: ModelClient,
    *,
    source: Store | None = None,
    contracts_dir: str | Path | None = None,
    with_updates: bool = True,
    defense: Defense | None = None,
    seed: int = 0,
) -> Env:
    """Build the clean environment. With ``source`` (the Iceberg warehouse) raw tables are copied
    from it; otherwise the snapshot is landed fresh into memory."""
    snap = load_snapshot(snapshot_path)
    contracts = load_contracts(contracts_dir or ROOT / "contracts")
    refs = load_refs(snap.reference["components"], snap.reference["vehicles"])
    mem = MemoryWarehouse()
    if source is not None:
        for n in ("raw_complaints", "raw_investigations", "raw_recalls", "quarantine_complaints"):
            if source.exists(n):
                mem.write(n, source.read(n))
        from pipeline.transforms import load_reference

        load_reference(
            mem, snap.reference["components"], snap.reference["vehicles"], snap.scope.makes or None
        )
    else:
        build.ingest_snapshot(mem, snap, contracts, with_updates=with_updates)
    build.stage(mem, snap)
    env = Env(snap, contracts, refs, mem, systems_of(refs))
    if not snap.synthetic:  # real runs: model calls are slow, so remember them on disk
        env.enrich_cache = DiskCache(
            Path(snapshot_path).resolve().parent / ".cache" / "enrich.jsonl"
        )
    build.enrich(
        mem,
        env.enricher(model, defense, seed),
        scope=snap.scope,
        label_window_days=snap.label_window_days,
    )
    build.gold(mem, snap)
    return env


def to_df(table: Any) -> pl.DataFrame:
    df = pl.from_arrow(table)
    assert isinstance(df, pl.DataFrame)
    return df


def load_labels(store: Store) -> pl.DataFrame:
    return to_df(store.read("gold_triage_labels"))
