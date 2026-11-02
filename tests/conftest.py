"""Shared fixtures: a tiny synthetic NHTSA-schema dataset and a warehouse built from it."""

from __future__ import annotations

from pathlib import Path

import polars as pl
import pytest
from taintguard.contracts import ContractSet, load_contracts

from fixtures.make_fixture import generate
from pipeline.build import ingest_snapshot
from pipeline.snapshot import Snapshot, load_snapshot
from pipeline.transforms import STAGING, load_reference, run_models
from pipeline.warehouse import Warehouse

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def contracts() -> ContractSet:
    return load_contracts(ROOT / "contracts")


@pytest.fixture(scope="session")
def tiny_snapshot(tmp_path_factory: pytest.TempPathFactory) -> Snapshot:
    out = tmp_path_factory.mktemp("fixture") / "data"
    generate("tiny", seed=7, out=out)
    return load_snapshot(out.parent / "snapshot.yaml")


def ingest_all(
    wh: Warehouse, snap: Snapshot, contracts: ContractSet, with_updates: bool = True
) -> None:
    ingest_snapshot(wh, snap, contracts, with_updates=with_updates)
    load_reference(wh, snap.reference["components"], snap.reference["vehicles"])


def null_enrichment(wh: Warehouse) -> None:
    keys = pl.from_arrow(wh.read("raw_complaints").select(["_key"]))
    assert isinstance(keys, pl.DataFrame)
    df = pl.DataFrame(
        {
            "complaint_key": keys["_key"],
            "component_llm": pl.Series([None] * keys.height, dtype=pl.String),
            "severity_llm": pl.Series([None] * keys.height, dtype=pl.Int64),
            "summary_llm": pl.Series([None] * keys.height, dtype=pl.String),
            "text_sha": pl.Series([None] * keys.height, dtype=pl.String),
        }
    )
    wh.write("enriched_complaints", df.to_arrow(), mode="overwrite")


@pytest.fixture()
def landed(tmp_path: Path, tiny_snapshot: Snapshot, contracts: ContractSet) -> Warehouse:
    wh = Warehouse(tmp_path / "wh")
    ingest_all(wh, tiny_snapshot, contracts)
    return wh


@pytest.fixture()
def gold(landed: Warehouse, tiny_snapshot: Snapshot) -> Warehouse:
    null_enrichment(landed)
    run_models(landed, STAGING, tiny_snapshot.label_window_days)
    from pipeline.transforms import GOLD

    run_models(landed, GOLD, tiny_snapshot.label_window_days)
    return landed


@pytest.fixture(scope="session")
def stub_env(tmp_path_factory: pytest.TempPathFactory):  # type: ignore[no-untyped-def]
    """A fully built clean environment on the tiny fixture, enriched by the stub model."""
    from agents.stub import StubModel
    from eval.env import build_env

    out = tmp_path_factory.mktemp("envfx") / "data"
    generate("tiny", seed=7, out=out)
    return build_env(out.parent / "snapshot.yaml", StubModel())
