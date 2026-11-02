"""Seeded data-contract failures with a known root cause, for the data-quality agent.

Each case lands a mutated batch through the real landing code (``pipeline.ingest.land``), so
the quarantine rows and test results the agent reads are exactly what production would produce.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field

import polars as pl
import pyarrow as pa
from taintguard.contracts import ModelSpec

from agents.schemas import DQ_CATEGORIES
from pipeline.ingest import SchemaDrift, land, read_flat
from pipeline.warehouse import MemoryWarehouse

RESULT_SCHEMA = {
    "model": pl.String,
    "test": pl.String,
    "column_name": pl.String,
    "failed_rows": pl.Int64,
    "detail": pl.String,
    "batch": pl.String,
}
QUARANTINE_SCHEMA = {
    "_key": pl.String,
    "failed_tests": pl.String,
    "row_json": pl.String,
    "_batch": pl.String,
    "_source_file": pl.String,
}


@dataclass
class DQCase:
    id: str
    category: str
    tables: dict[str, pa.Table]
    summary: str  # trusted: names and counts of failed checks, written by the pipeline
    quarantined_keys: list[str] = field(default_factory=list)


def _mutate(category: str, df: pl.DataFrame, rng: random.Random) -> pl.DataFrame:
    n = df.height
    idx = list(range(n))
    rng.shuffle(idx)
    pick = set(idx[: max(2, n // 3)])
    mask = pl.Series([i in pick for i in range(n)])

    def setcol(name: str, values: list[str]) -> pl.DataFrame:
        it = iter(values * n)
        new = [next(it) if m else v for m, v in zip(mask, df[name], strict=True)]
        return df.with_columns(pl.Series(name, new, dtype=pl.String))

    if category == "unseen_component":
        return df.with_columns(pl.lit("HOVERCRAFT:AIR CUSHION SKIRT").alias("COMPDESC"))
    if category == "invalid_flag_value":
        return setcol("CRASH", ["YES", "1", "Y?"])
    if category == "malformed_date":
        return setcol("LDATE", ["2026-13-45", "06/15/2026", "SOON"])
    if category == "out_of_range_number":
        return setcol("INJURED", ["250", "-3", "many"])
    if category == "duplicate_key":
        dup = df.head(max(2, n // 4)).with_columns(
            (pl.col("CDESCR") + " DUPLICATE RESUBMISSION").alias("CDESCR")
        )
        return pl.concat([df, dup])
    if category == "shifted_columns":
        cols = df.columns
        rows = df.rows()
        shifted = [
            (r[-1:] + r[:-1]) if i in pick else r for i, r in enumerate(rows)
        ]  # every field slides one place right
        return pl.DataFrame(shifted, schema=cols, orient="row")
    if category == "other":
        return setcol("CMPL_TYPE", ["TOOLONGCODE1"])
    raise ValueError(category)


def build_case(
    case_id: str,
    category: str,
    base: pl.DataFrame,
    spec: ModelSpec,
    refs: dict[str, set[str]],
    rng: random.Random,
    *,
    batch_rows: int = 9,
    poison: pl.DataFrame | None = None,
) -> DQCase:
    if category not in DQ_CATEGORIES:
        raise ValueError(category)
    batch = f"nightly:{case_id}"
    mem = MemoryWarehouse()
    results: list[dict[str, object]] = []
    summary: list[str] = []
    if category == "column_count_drift":
        msg = "complaints file: 40 columns, contract raw_complaints allows 49..51"
        results.append(_res(spec.name, "schema:column_count", "*", 1, msg, batch))
        summary.append(f"- test schema:column_count, whole file: {msg}")
        q = pl.DataFrame(schema=QUARANTINE_SCHEMA)
    else:
        rows = base.sample(n=min(batch_rows, base.height), seed=rng.randrange(1 << 30))
        rows = _mutate(category, rows, rng)
        if poison is not None:
            rows = pl.concat([rows, poison.select(rows.columns)])
        try:
            r = land(
                mem,
                spec,
                "case.txt",
                batch=batch,
                refs=refs,
                quarantine_table="quarantine_complaints",
                frame=rows,
            )
        except SchemaDrift as exc:  # pragma: no cover - defensive
            raise RuntimeError(str(exc)) from exc
        for t in r.test_results:
            if t.failed:
                results.append(_res(spec.name, t.test, t.column, t.failed, "", batch))
                summary.append(f"- column {t.column}, test {t.test}: {t.failed} rows failed")
        if r.duplicates_in_file:
            results.append(
                _res(spec.name, "unique_key", "ODINO,COMPDESC", r.duplicates_in_file, "", batch)
            )
            summary.append(
                f"- test unique_key, columns ODINO,COMPDESC: {r.duplicates_in_file} duplicate rows in file"
            )
        q = (
            pl.from_arrow(mem.read("quarantine_complaints")).select(list(QUARANTINE_SCHEMA))  # type: ignore[union-attr]
            if mem.exists("quarantine_complaints")
            else pl.DataFrame(schema=QUARANTINE_SCHEMA)
        )
    if not results:
        raise RuntimeError(f"case {case_id} ({category}) produced no failed checks")
    tables = {
        "quarantine_complaints": q.to_arrow(),
        "contract_results": pl.DataFrame(results, schema=RESULT_SCHEMA).to_arrow(),
    }
    return DQCase(case_id, category, tables, "\n".join(summary), q["_key"].to_list())


def _res(model: str, test: str, col: str, n: int, detail: str, batch: str) -> dict[str, object]:
    return {
        "model": model,
        "test": test,
        "column_name": col,
        "failed_rows": n,
        "detail": detail,
        "batch": batch,
    }


def make_cases(
    base_file: str,
    spec: ModelSpec,
    refs: dict[str, set[str]],
    per_category: int = 5,
    seed: int = 3,
) -> list[DQCase]:
    base = read_flat(base_file, spec)
    rng = random.Random(seed)
    cases: list[DQCase] = []
    for cat in DQ_CATEGORIES:
        for i in range(per_category):
            cases.append(build_case(f"{cat}-{i + 1}", cat, base, spec, refs, rng))
    return cases


def row_json_of(df: pl.DataFrame) -> list[str]:  # pragma: no cover - helper for tests
    return [json.dumps(r) for r in df.iter_rows(named=True)]
