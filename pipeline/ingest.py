"""Landing: flat file -> validated, de-identified, incrementally upserted raw Iceberg table.

Rules from the plan, each with a test in tests/test_ingest.py:
  * header-less tab-delimited files; column count may drift (49..51) but never silently;
  * personal fields are dropped here and never stored;
  * complaints are keyed on ODINO + component (COMPDESC), never CMPLID, which can change
    between file versions;
  * only new or changed rows are written, so a daily update is a real incremental load;
  * every column marked ``structured`` has an enforced test; rows that fail go to quarantine
    instead of the raw table, so the trust tier is true of what is actually stored.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import polars as pl
import pyarrow as pa
from taintguard.contracts import ColumnSpec, ModelSpec

from pipeline.warehouse import Store

META_COLS = ["_key", "_row_hash", "_batch", "_source_file", "_ingested_at"]
# Columns that identify a row's content for change detection must not include churn fields.
HASH_EXCLUDE = {"CMPLID", "DATEA"}


class SchemaDrift(Exception):
    """A landing file does not match its contract (column count, ragged rows)."""


@dataclass
class TestResult:
    column: str
    test: str
    failed: int


@dataclass
class IngestResult:
    model: str
    source_file: str
    batch: str
    rows_read: int = 0
    out_of_range: int = 0
    duplicates_in_file: int = 0
    quarantined: int = 0
    inserted: int = 0
    updated: int = 0
    refreshed: int = 0  # same content, new CMPLID
    unchanged: int = 0
    skipped: bool = False  # this exact file was already landed (ledger hit)
    blank_flags_normalised: int = 0
    columns_seen: int = 0
    pii_dropped: list[str] = field(default_factory=list)
    test_results: list[TestResult] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["test_results"] = [t.__dict__ for t in self.test_results if t.failed]
        return d


def read_flat(path: str | Path, spec: ModelSpec) -> pl.DataFrame:
    """Read a header-less tab-delimited flat file as strings, named by contract position."""
    p = Path(path)
    src = spec.source or {}
    lo, hi = src.get("min_columns", len(spec.columns)), src.get("max_columns", len(spec.columns))
    with p.open("rb") as fh:
        first = fh.readline().decode("utf-8", errors="replace").rstrip("\r\n")
    if not first:
        raise SchemaDrift(f"{p.name}: empty file")
    ncols = first.count("\t") + 1
    if not lo <= ncols <= hi:
        raise SchemaDrift(
            f"{p.name}: {ncols} columns, contract {spec.name} allows {lo}..{hi}"
            + (
                " (layout is provisional: run `make profile` and fix the contract)"
                if src.get("provisional")
                else ""
            )
        )
    names = [c.name for c in sorted(spec.columns, key=lambda c: c.position or 0)][:ncols]
    try:
        df = pl.read_csv(
            p,
            separator="\t",
            has_header=False,
            new_columns=names,
            infer_schema=False,
            quote_char=None,
            encoding="utf8-lossy",
            truncate_ragged_lines=False,
        )
    except pl.exceptions.ComputeError as exc:
        raise SchemaDrift(f"{p.name}: ragged rows ({exc})") from exc
    # Files predating a field addition simply lack it; add it empty so the schema is stable.
    for c in spec.columns:
        if c.name not in df.columns:
            df = df.with_columns(pl.lit("").alias(c.name))
    df = df.select([c.name for c in sorted(spec.columns, key=lambda c: c.position or 0)])
    return df.with_columns(pl.all().fill_null("").str.strip_chars())


def _key_expr(spec: ModelSpec) -> pl.Expr:
    return pl.concat_str([pl.col(k) for k in spec.key], separator="|").alias("_key")


def _is_flag(col: ColumnSpec) -> bool:
    return any(isinstance(t, dict) and t.get("accepted_values") == ["Y", "N"] for t in col.tests)


def _test_exprs(col: ColumnSpec, refs: dict[str, set[str]]) -> list[tuple[str, pl.Expr]]:
    c = pl.col(col.name)
    out: list[tuple[str, pl.Expr]] = []
    for t in col.tests:
        if t == "not_null":
            out.append(("not_null", c != ""))
        elif isinstance(t, dict):
            if "accepted_values" in t:
                out.append(("accepted_values", c.is_in(t["accepted_values"])))
            elif "accepted_values_ref" in t:
                out.append(
                    (
                        f"accepted_values_ref:{t['accepted_values_ref']}",
                        c.is_in(sorted(refs[t["accepted_values_ref"]])),
                    )
                )
            elif "regex" in t:
                out.append(("regex", c.str.contains(t["regex"])))
            elif "range" in t:
                lo, hi = t["range"]
                n = c.cast(pl.Int64, strict=False)
                out.append(("range", (c == "") | n.is_between(lo, hi)))
            else:
                raise ValueError(f"{col.name}: unknown test {t}")
        else:
            raise ValueError(f"{col.name}: unknown test {t!r}")
    return out


def _row_hash(df: pl.DataFrame, cols: list[str]) -> pl.Series:
    joined = df.select(pl.concat_str([pl.col(c) for c in cols], separator="\x1f")).to_series()
    return pl.Series(
        "_row_hash",
        [hashlib.blake2b(s.encode("utf-8"), digest_size=8).hexdigest() for s in joined],
        dtype=pl.String,
    )


def land(
    wh: Store,
    spec: ModelSpec,
    path: str | Path,
    *,
    batch: str,
    refs: dict[str, set[str]] | None = None,
    date_range: tuple[date, date] | None = None,
    date_col: str | None = None,
    quarantine_table: str | None = None,
    frame: pl.DataFrame | None = None,
) -> IngestResult:
    """Land one flat file (or an already-parsed frame) into ``spec.name``."""
    refs = refs or {}
    res = IngestResult(model=spec.name, source_file=Path(path).name, batch=batch)
    df = frame if frame is not None else read_flat(path, spec)
    res.rows_read = df.height
    res.columns_seen = len(df.columns)

    # 1. De-identify first: personal fields never reach any table.
    pii = [c.name for c in spec.columns if c.pii and c.name in df.columns]
    df = df.drop(pii)
    res.pii_dropped = pii
    cols = [c for c in spec.columns if not c.pii]

    # 2. Documented quirk: blank Y/N flags are 'N'.
    for c in cols:
        if _is_flag(c) and c.name in df.columns:
            blanks = int((df[c.name] == "").sum())
            if blanks:
                res.blank_flags_normalised += blanks
                df = df.with_columns(
                    pl.when(pl.col(c.name) == "")
                    .then(pl.lit("N"))
                    .otherwise(pl.col(c.name))
                    .alias(c.name)
                )

    # 3. Window.
    if date_range and date_col:
        d = pl.col(date_col).str.strptime(pl.Date, "%Y%m%d", strict=False)
        keep = d.is_between(date_range[0], date_range[1]) | d.is_null()
        res.out_of_range = int(df.select((~keep).sum()).item())
        df = df.filter(keep)

    # 4. Enforced tests -> quarantine failing rows.
    fail_names = pl.Series("failed", [""] * df.height, dtype=pl.String)
    for col in cols:
        for tname, expr in _test_exprs(col, refs):
            ok = df.select(expr.alias("ok")).to_series()
            nfail = int((~ok).sum())
            res.test_results.append(TestResult(col.name, tname, nfail))
            if nfail:
                tag = f"{col.name}:{tname}"
                fail_names = pl.Series(
                    "failed",
                    [
                        f"{a},{tag}" if (not o and a) else (tag if not o else a)
                        for a, o in zip(fail_names, ok, strict=True)
                    ],
                    dtype=pl.String,
                )
    bad_mask = fail_names != ""
    df = df.with_columns(_key_expr(spec))
    bad = df.filter(bad_mask).with_columns(fail_names.filter(bad_mask).alias("failed_tests"))
    df = df.filter(~bad_mask)
    res.quarantined = bad.height
    now = datetime.now(UTC).replace(tzinfo=None)
    if bad.height and quarantine_table:
        q = pl.DataFrame(
            {
                "_key": bad["_key"],
                "failed_tests": bad["failed_tests"],
                "row_json": [
                    json.dumps(r, ensure_ascii=False)
                    for r in bad.drop(["_key", "failed_tests"]).iter_rows(named=True)
                ],
                "_batch": [batch] * bad.height,
                "_source_file": [res.source_file] * bad.height,
                "_ingested_at": [now] * bad.height,
            }
        )
        wh.write(quarantine_table, q.to_arrow(), mode="append")

    # 5. De-duplicate within the file (last wins), then diff against what is stored.
    before = df.height
    df = df.unique(subset=["_key"], keep="last", maintain_order=True)
    res.duplicates_in_file = before - df.height
    hash_cols = [c.name for c in cols if c.name not in HASH_EXCLUDE]
    df = df.with_columns(
        _row_hash(df, hash_cols),
        pl.lit(batch).alias("_batch"),
        pl.lit(res.source_file).alias("_source_file"),
        pl.lit(now).alias("_ingested_at"),
    )
    if not wh.exists(spec.name) or wh.count(spec.name) == 0:
        res.inserted = df.height
        if df.height or not wh.exists(spec.name):
            wh.write(spec.name, df.to_arrow(), mode="append")
        return res

    have_cols = ["_key", "_row_hash"] + (["CMPLID"] if "CMPLID" in df.columns else [])
    have = pl.from_arrow(wh.read(spec.name).select(have_cols))
    assert isinstance(have, pl.DataFrame)
    have = have.rename({c: f"{c}_old" for c in have_cols if c != "_key"})
    j = df.join(have, on="_key", how="left")
    is_new = j["_row_hash_old"].is_null()
    changed = (~is_new) & (j["_row_hash"] != j["_row_hash_old"])
    refreshed = (~is_new) & (~changed)
    if "CMPLID" in df.columns:
        refreshed = refreshed & (j["CMPLID"] != j["CMPLID_old"])
    res.inserted = int(is_new.sum())
    res.updated = int(changed.sum())
    res.refreshed = int(refreshed.sum())
    res.unchanged = df.height - res.inserted - res.updated - res.refreshed
    delta = j.filter(is_new | changed | refreshed).select(df.columns)
    if delta.height:
        wh.write(spec.name, delta.to_arrow(), mode="upsert", key=["_key"])
    return res


def load_refs(components: str | Path, vehicles: str | Path) -> dict[str, set[str]]:
    comp = {ln.strip() for ln in Path(components).read_text().splitlines() if ln.strip()}
    veh = pl.read_csv(vehicles)
    return {"components": comp, "vehicles": {f"{m}|{n}" for m, n in veh.iter_rows()}}


def as_arrow_pairs(df: pl.DataFrame) -> pa.Table:  # pragma: no cover - tiny helper
    return df.to_arrow()
