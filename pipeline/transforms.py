"""SQL transforms run in DuckDB over Iceberg tables, written back as Iceberg tables.

Each model is one SELECT in ``pipeline/sql/<name>.sql``. Keeping them single SELECTs is what
makes column-level lineage parseable by sqlglot.
"""

from __future__ import annotations

from pathlib import Path

import duckdb
import polars as pl
import sqlglot
from sqlglot import exp

from pipeline.warehouse import Store

SQL_DIR = Path(__file__).parent / "sql"
# Topological order: every model only reads earlier ones, raw tables or reference tables.
STAGING = ["stg_complaints"]
GOLD = ["gold_actions", "gold_trends", "gold_triage_cases", "gold_triage_labels"]
MODEL_ORDER = STAGING + GOLD


def render_sql(name: str, label_window_days: int = 120) -> str:
    sql = (SQL_DIR / f"{name}.sql").read_text(encoding="utf-8")
    return sql.replace("$LABEL_WINDOW_DAYS", str(int(label_window_days)))


def referenced_tables(sql: str) -> list[str]:
    tree = sqlglot.parse_one(sql, read="duckdb")
    ctes = {c.alias_or_name for c in tree.find_all(exp.CTE)}
    names = {t.name for t in tree.find_all(exp.Table) if t.name and t.name not in ctes}
    return sorted(names - {"generate_series"})


def run_model(wh: Store, name: str, label_window_days: int = 120) -> int:
    sql = render_sql(name, label_window_days)
    con = duckdb.connect()
    try:
        for t in referenced_tables(sql):
            if not wh.exists(t):
                raise RuntimeError(f"{name}: missing input table {t!r}; run upstream steps first")
            con.register(t, wh.read(t))
        out = con.sql(sql).arrow()
        out = out.read_all() if hasattr(out, "read_all") else out
    finally:
        con.close()
    wh.write(name, out, mode="overwrite")
    return out.num_rows


def run_models(wh: Store, names: list[str], label_window_days: int = 120) -> dict[str, int]:
    return {n: run_model(wh, n, label_window_days) for n in names}


def load_reference(
    wh: Store, components: str | Path, vehicles: str | Path, makes: list[str] | None = None
) -> None:
    """Reference tables are trusted: operator-approved vocabularies from the frozen snapshot."""
    comp = [ln.strip() for ln in Path(components).read_text().splitlines() if ln.strip()]
    wh.write("ref_components", pl.DataFrame({"compdesc": comp}).to_arrow(), mode="overwrite")
    veh = pl.read_csv(vehicles).with_columns(pl.all().str.to_uppercase())
    if makes:
        veh = veh.filter(pl.col("make").is_in([m.upper() for m in makes]))
    wh.write("ref_vehicles", veh.to_arrow(), mode="overwrite")
