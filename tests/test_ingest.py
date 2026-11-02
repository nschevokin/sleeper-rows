from __future__ import annotations

from pathlib import Path

import polars as pl
import pytest
from taintguard.contracts import ContractSet

from pipeline.ingest import SchemaDrift, land, load_refs, read_flat
from pipeline.snapshot import Snapshot, verify_checksums
from pipeline.warehouse import Warehouse

PII = [
    "CITY",
    "STATE",
    "VIN",
    "DEALER_NAME",
    "DEALER_TEL",
    "DEALER_CITY",
    "DEALER_STATE",
    "DEALER_ZIP",
    "VEHICLE_OPERATOR",
]


def test_pii_never_lands(landed: Warehouse) -> None:
    cols = set(landed.read("raw_complaints").column_names)
    assert not cols & set(PII)
    q = landed.read("quarantine_complaints").to_pylist()
    assert not any("TESTVILLE" in r["row_json"] or "NOT A REAL PERSON" in r["row_json"] for r in q)


def test_backfill_is_keyed_on_odino_and_component(landed: Warehouse) -> None:
    df = pl.from_arrow(landed.read("raw_complaints"))
    assert isinstance(df, pl.DataFrame)
    assert df["_key"].n_unique() == df.height
    assert (df["_key"] == df["ODINO"] + "|" + df["COMPDESC"]).all()
    # ODINO repeats for multiple components, as in the real file.
    assert df["ODINO"].n_unique() < df.height


def test_blank_flags_become_n(landed: Warehouse) -> None:
    df = pl.from_arrow(landed.read("raw_complaints"))
    assert isinstance(df, pl.DataFrame)
    for c in ("POLICE_RPT_YN", "ORIG_OWNER_YN", "CRASH"):
        assert set(df[c].unique()) <= {"Y", "N"}


def test_unseen_component_is_quarantined_not_loaded(landed: Warehouse) -> None:
    raw = pl.from_arrow(landed.read("raw_complaints"))
    q = pl.from_arrow(landed.read("quarantine_complaints"))
    assert isinstance(raw, pl.DataFrame) and isinstance(q, pl.DataFrame)
    assert q.height == 1
    assert "HYPERDRIVE" in q["_key"][0]
    assert "COMPDESC:accepted_values_ref:components" in q["failed_tests"][0]
    assert not raw["COMPDESC"].str.contains("HYPERDRIVE").any()


def test_daily_update_is_incremental_and_idempotent(
    tmp_path: Path, tiny_snapshot: Snapshot, contracts: ContractSet
) -> None:
    wh = Warehouse(tmp_path / "wh")
    refs = load_refs(tiny_snapshot.reference["components"], tiny_snapshot.reference["vehicles"])
    spec = contracts.model("raw_complaints")
    kw = dict(
        refs=refs,
        date_range=(tiny_snapshot.date_range.start, tiny_snapshot.date_range.end),
        date_col="LDATE",
    )
    first = land(wh, spec, tiny_snapshot.files["complaints"], batch="b0", **kw)  # type: ignore[arg-type]
    assert first.inserted == first.rows_read > 1000
    n0 = wh.count("raw_complaints")
    u = tiny_snapshot.updates[1]  # carries one changed narrative
    r1 = land(wh, spec, u, batch="b1", **kw)  # type: ignore[arg-type]
    assert r1.updated == 1 and r1.inserted > 0
    assert wh.count("raw_complaints") == n0 + r1.inserted
    r2 = land(wh, spec, u, batch="b2", **kw)  # type: ignore[arg-type]
    assert (r2.inserted, r2.updated, r2.refreshed) == (0, 0, 0)
    assert r2.unchanged == r2.rows_read


def test_cmplid_change_alone_is_a_refresh_not_an_update(
    tmp_path: Path, tiny_snapshot: Snapshot, contracts: ContractSet
) -> None:
    wh = Warehouse(tmp_path / "wh")
    spec = contracts.model("raw_complaints")
    kw = dict(
        refs=load_refs(tiny_snapshot.reference["components"], tiny_snapshot.reference["vehicles"])
    )
    df = read_flat(tiny_snapshot.files["complaints"], spec).head(50)
    land(wh, spec, "x", batch="b0", frame=df, **kw)  # type: ignore[arg-type]
    renum = df.head(5).with_columns((pl.col("CMPLID").cast(pl.Int64) + 9_000_000).cast(pl.String))
    r = land(wh, spec, "y", batch="b1", frame=renum, **kw)  # type: ignore[arg-type]
    assert (r.inserted, r.updated, r.refreshed) == (0, 0, 5)
    stored = pl.from_arrow(wh.read("raw_complaints"))
    assert isinstance(stored, pl.DataFrame)
    assert stored.filter(pl.col("CMPLID").cast(pl.Int64) >= 20_000_000).height == 5


def test_duplicate_keys_in_a_file_keep_the_last(
    tmp_path: Path, tiny_snapshot: Snapshot, contracts: ContractSet
) -> None:
    wh = Warehouse(tmp_path / "wh")
    spec = contracts.model("raw_complaints")
    refs = load_refs(tiny_snapshot.reference["components"], tiny_snapshot.reference["vehicles"])
    df = read_flat(tiny_snapshot.files["complaints"], spec).head(10)
    dup = pl.concat([df, df.head(1).with_columns(pl.lit("LATER VERSION").alias("CDESCR"))])
    r = land(wh, spec, "x", batch="b", frame=dup, refs=refs)
    assert r.duplicates_in_file == 1
    stored = pl.from_arrow(wh.read("raw_complaints"))
    assert isinstance(stored, pl.DataFrame)
    assert "LATER VERSION" in stored["CDESCR"].to_list()


def test_column_count_drift_fails_loudly(tmp_path: Path, contracts: ContractSet) -> None:
    bad = tmp_path / "bad.txt"
    bad.write_text("\t".join(["x"] * 40) + "\n")
    with pytest.raises(SchemaDrift, match="40 columns"):
        read_flat(bad, contracts.model("raw_complaints"))
    rcl = tmp_path / "rcl.txt"
    rcl.write_text("\t".join(["x"] * 31) + "\n")
    with pytest.raises(SchemaDrift, match="provisional"):
        read_flat(rcl, contracts.model("raw_recalls"))


def test_april_2026_files_with_51_columns_and_older_with_49_both_load(landed: Warehouse) -> None:
    df = pl.from_arrow(landed.read("raw_complaints"))
    assert isinstance(df, pl.DataFrame)
    assert (df["STATE_OF_INCIDENT"] == "ZZ").any() and (df["STATE_OF_INCIDENT"] == "").any()


def test_snapshot_checksums_detect_tampering(tiny_snapshot: Snapshot, tmp_path: Path) -> None:
    from pipeline.snapshot import sha256_file

    snap = tiny_snapshot.model_copy(deep=True)
    snap.checksums = {"investigations": sha256_file(snap.files["investigations"])}
    assert verify_checksums(snap) == []
    snap.checksums = {"investigations": "0" * 64}
    assert "investigations" in verify_checksums(snap)[0]


def test_time_travel_returns_the_pre_update_state(
    tmp_path: Path, tiny_snapshot: Snapshot, contracts: ContractSet
) -> None:
    wh = Warehouse(tmp_path / "wh")
    spec = contracts.model("raw_complaints")
    refs = load_refs(tiny_snapshot.reference["components"], tiny_snapshot.reference["vehicles"])
    land(wh, spec, tiny_snapshot.files["complaints"], batch="b0", refs=refs)
    snap0 = wh.snapshots("raw_complaints")[-1].snapshot_id
    n0 = wh.count("raw_complaints")
    land(wh, spec, tiny_snapshot.updates[0], batch="b1", refs=refs)
    assert wh.count("raw_complaints") > n0
    assert wh.read("raw_complaints", snapshot_id=snap0).num_rows == n0


def test_memory_store_lands_and_upserts_like_iceberg(
    tiny_snapshot: Snapshot, contracts: ContractSet
) -> None:
    from pipeline.warehouse import MemoryWarehouse

    mem = MemoryWarehouse()
    spec = contracts.model("raw_complaints")
    refs = load_refs(tiny_snapshot.reference["components"], tiny_snapshot.reference["vehicles"])
    land(mem, spec, tiny_snapshot.files["complaints"], batch="b0", refs=refs)
    n0 = mem.count("raw_complaints")
    r = land(mem, spec, tiny_snapshot.updates[1], batch="b1", refs=refs)
    assert r.updated == 1 and mem.count("raw_complaints") == n0 + r.inserted
    clone = mem.clone()
    land(clone, spec, tiny_snapshot.updates[2], batch="b2", refs=refs)
    assert mem.count("raw_complaints") < clone.count("raw_complaints")  # clone is isolated
