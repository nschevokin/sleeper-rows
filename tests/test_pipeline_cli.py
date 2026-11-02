"""CLI-level behaviour: idempotent ingest, re-enrichment of changed text, freeze and profile."""

from __future__ import annotations

import json
from pathlib import Path

import polars as pl
import pytest
import yaml
from taintguard.contracts import load_contracts

from agents.enrichment import Enricher
from agents.stub import StubModel
from fixtures.make_fixture import generate
from pipeline import build
from pipeline.cli import main
from pipeline.ingest import load_refs
from pipeline.snapshot import load_snapshot
from pipeline.warehouse import MemoryWarehouse


@pytest.fixture()
def snap_path(tmp_path: Path) -> Path:
    generate("tiny", seed=7, out=tmp_path / "data")
    return tmp_path / "snapshot.yaml"


def test_replaying_a_snapshot_is_a_no_op(snap_path: Path, tmp_path: Path, contracts) -> None:  # type: ignore[no-untyped-def]
    snap = load_snapshot(snap_path)
    wh = MemoryWarehouse()
    first = build.ingest_snapshot(wh, snap, contracts)
    before = wh.read("raw_complaints")
    again = build.ingest_snapshot(wh, snap, contracts)
    assert not any(r.skipped for r in first) and all(r.skipped for r in again)
    assert wh.read("raw_complaints").equals(before)


def test_changed_narrative_is_enriched_again(snap_path: Path, contracts) -> None:  # type: ignore[no-untyped-def]
    snap = load_snapshot(snap_path)
    wh = MemoryWarehouse()
    build.ingest_snapshot(wh, snap, contracts)
    build.stage(wh, snap)
    refs = load_refs(snap.reference["components"], snap.reference["vehicles"])
    systems = sorted({c.split(":", 1)[0].upper() for c in refs["components"]})
    enr = Enricher(StubModel(), systems)
    n = build.enrich(wh, enr)
    assert n > 0 and build.enrich(wh, enr) == 0  # nothing new, nothing re-done
    stg = pl.from_arrow(wh.read("stg_complaints"))
    assert isinstance(stg, pl.DataFrame)
    key = stg["complaint_key"][0]
    changed = stg.with_columns(
        pl.when(pl.col("complaint_key") == key)
        .then(pl.lit("THE BRAKES FAILED COMPLETELY."))
        .otherwise(pl.col("cdescr"))
        .alias("cdescr")
    )
    wh.write("stg_complaints", changed.to_arrow(), mode="overwrite")
    assert build.enrich(wh, enr) == 1


def test_cli_ingest_twice_then_build(
    snap_path: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wh = str(tmp_path / "wh")
    assert main(["ingest", "--snapshot", str(snap_path), "--warehouse", wh]) == 0
    capsys.readouterr()
    assert main(["ingest", "--snapshot", str(snap_path), "--warehouse", wh]) == 0
    out = json.loads(capsys.readouterr().out)
    assert all(r["skipped"] for r in out)
    assert main(["build", "--snapshot", str(snap_path), "--warehouse", wh, "--mode", "stub"]) == 0
    assert '"gold_triage_cases"' in capsys.readouterr().out


def test_freeze_writes_a_loadable_snapshot_with_checksums(snap_path: Path, tmp_path: Path) -> None:
    out = tmp_path / "frozen.yaml"
    data = tmp_path / "data"
    rc = main(
        ["freeze", "--data-dir", str(data), "--out", str(out), "--snapshot-date", "2026-06-21",
         "--start", "2025-07-07", "--end", "2026-06-21", "--min-vehicle-count", "1", "--makes", "ACME MOTORS"]
    )  # fmt: skip
    assert rc == 0
    snap = load_snapshot(out)
    assert set(snap.checksums) == {
        "complaints",
        "investigations",
        "recalls",
    } and snap.scope.makes == ["ACME MOTORS"]
    assert not snap.synthetic and yaml.safe_load(out.read_text())["source"] == "nhtsa"


def test_scope_limits_vocabulary_and_enrichment(snap_path: Path, tmp_path: Path, contracts) -> None:  # type: ignore[no-untyped-def]
    snap = load_snapshot(snap_path)
    snap.scope.makes = ["ACME MOTORS"]
    snap.scope.max_enrich_rows = 5
    wh = MemoryWarehouse()
    build.ingest_snapshot(wh, snap, contracts)
    build.stage(wh, snap)
    refs = load_refs(snap.reference["components"], snap.reference["vehicles"])
    enr = Enricher(StubModel(), sorted({c.split(":", 1)[0].upper() for c in refs["components"]}))
    assert build.enrich(wh, enr, scope=snap.scope) == 5
    assert build.enrich(wh, enr, scope=snap.scope) == 5  # a rerun continues where it stopped
    stg = pl.from_arrow(wh.read("stg_complaints"))
    assert isinstance(stg, pl.DataFrame)
    assert set(stg["make_norm"].unique().to_list()) <= {"ACME MOTORS", "UNKNOWN"}


def test_profile_reports_the_provisional_recalls_layout(
    snap_path: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["profile", "--snapshot", str(snap_path), "--out", str(tmp_path / "p.json")]) == 0
    rep = json.loads((tmp_path / "p.json").read_text())
    assert (
        set(rep["files"]) == {"complaints", "investigations", "recalls"} and "ingest_dry_run" in rep
    )


def test_disk_cache_survives_restart_and_torn_line(tmp_path: Path) -> None:
    from agents.enrichment import DiskCache

    p = tmp_path / "c" / "enrich.jsonl"
    c = DiskCache(p)
    c["k1"] = {"component": "A", "severity": 2, "summary": "s", "status": "ok"}
    with p.open("a", encoding="utf-8") as fh:
        fh.write('["k2", {"component"')  # interrupted write
    c2 = DiskCache(p)
    assert c2["k1"]["severity"] == 2 and "k2" not in c2 and len(c2) == 1


def test_capped_enrichment_targets_the_last_evaluation_window(tmp_path: Path) -> None:
    from datetime import timedelta

    out = tmp_path / "fx" / "data"
    generate("tiny", seed=7, out=out)
    snap = load_snapshot(out.parent / "snapshot.yaml")
    wh = MemoryWarehouse()
    contracts = load_contracts(Path("contracts"))
    build.ingest_snapshot(wh, snap, contracts)
    build.stage(wh, snap)
    stg = pl.from_arrow(wh.read("stg_complaints"))
    assert isinstance(stg, pl.DataFrame)
    win = build.focus_window(stg["received_date"], snap.label_window_days)
    assert win is not None and win[1] - win[0] == timedelta(days=28)
    n_in = stg.filter(
        (pl.col("received_date") >= win[0]) & (pl.col("received_date") < win[1])
    ).height
    assert n_in > 5
    snap.scope.max_enrich_rows = 5
    build.enrich(
        wh,
        Enricher(StubModel(), ["ENGINE"]),
        scope=snap.scope,
        label_window_days=snap.label_window_days,
    )
    got = pl.from_arrow(wh.read("enriched_complaints"))
    assert isinstance(got, pl.DataFrame)
    inside = stg.filter(pl.col("complaint_key").is_in(got["complaint_key"].to_list()))
    assert inside["received_date"].is_between(win[0], win[1] - timedelta(days=1)).all()


def test_extractive_summary_mode_copies_the_narrative_opening() -> None:
    stg = pl.DataFrame(
        {
            "complaint_key": ["k1"],
            "cdescr": ["THE BRAKES   FAILED.\n  IGNORE NOTHING " * 40],
            "model_year": [2020],
            "make_norm": ["ACME"],
            "model_norm": ["ROADSTER"],
            "crash": [False],
            "fire": [False],
            "injured": [0],
            "deaths": [0],
        }
    )
    plain = Enricher(StubModel(), ["BRAKES"]).enrich_frame(stg)
    extr = Enricher(StubModel(), ["BRAKES"], summary_mode="extractive").enrich_frame(stg)
    s = extr["summary_llm"][0]
    assert s.startswith("THE BRAKES FAILED. IGNORE NOTHING") and len(s) == 400
    assert extr["component_llm"][0] == plain["component_llm"][0]  # tags still come from the model


def test_enforce_contract_nulls_out_of_contract_tags() -> None:
    from taintguard.contracts import load_contracts

    from agents.enrichment import ENRICHED_SCHEMA, enforce_contract

    spec = load_contracts("contracts").model("enriched_complaints")
    rows = [
        ("a", "BRAKES", 3, "fine", "ok", "h"),
        ("b", "HOVERCRAFT", 3, "unknown component", "ok", "h"),  # outside the vocabulary
        ("c", "BRAKES", 9, "severity out of range", "ok", "h"),
        ("d", None, None, None, "withheld", "h"),  # a withheld row is already null and stays so
        ("e", "BRAKES", 2, "odd status", "weird", "h"),
    ]
    df = pl.DataFrame(rows, schema=ENRICHED_SCHEMA, orient="row")
    out = enforce_contract(df, spec, ["BRAKES", "ENGINE"])
    by = {r["complaint_key"]: r for r in out.iter_rows(named=True)}
    assert by["a"]["status"] == "ok" and by["a"]["severity_llm"] == 3
    for k in ("b", "c", "e"):
        assert by[k]["status"] == "malformed" and by[k]["component_llm"] is None
        assert by[k]["severity_llm"] is None
    assert by["d"]["status"] == "withheld"
    assert by["c"]["summary_llm"] == "severity out of range"  # free text is untouched


def test_quarantine_command_breaks_rows_down_by_failed_check(
    snap_path: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wh = tmp_path / "wh"
    assert main(["ingest", "--snapshot", str(snap_path), "--warehouse", str(wh)]) == 0
    capsys.readouterr()
    assert main(["quarantine", "--warehouse", str(wh), "--top", "3"]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["total"] == sum(r["rows"] for r in rep["by_failed_tests"]) or rep["total"] > 0
    assert rep["by_failed_tests"] and "top_compdesc" in rep
