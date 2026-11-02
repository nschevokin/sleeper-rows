from __future__ import annotations

import statistics
import time

import pytest
import sqlglot
from _support import PIPELINE, render
from taintguard import Catalog, ContractSet, LineageError, Trust, analyze_query, build_catalog
from taintguard.lineage import ColumnTaint

T, S, U = Trust.TRUSTED, Trust.STRUCTURED, Trust.UNTRUSTED


def col(cat: Catalog, table: str, name: str) -> ColumnTaint:
    return cat.tables[table].columns[name]


def tiers(cat: Catalog, sql: str) -> list[Trust]:
    q = analyze_query(sql, cat)
    assert q.failed is None, q.failed
    return [t.effective for t in q.taints]


def test_l01_staging(catalog: Catalog) -> None:
    mk = col(catalog, "stg_complaints", "make_norm")
    assert (mk.explicit, mk.selection, mk.effective) == (T, U, S)
    assert col(catalog, "stg_complaints", "cdescr").effective is U
    assert col(catalog, "stg_complaints", "complaint_key").effective is S
    assert col(catalog, "stg_complaints", "injured").effective is S


def test_l02_gold_trends(catalog: Catalog) -> None:
    n = col(catalog, "gold_trends", "n_complaints")
    assert (n.explicit, n.effective) == (T, S)
    ts = col(catalog, "gold_trends", "top_summary")
    assert ts.effective is U and "enriched_complaints.summary_llm" in ts.untrusted_sources
    assert col(catalog, "gold_trends", "avg_severity").effective is S
    assert col(catalog, "gold_trends", "make").selection is U


def test_l03_triage_cases(catalog: Catalog) -> None:
    assert col(catalog, "gold_triage_cases", "eval_week").effective is S
    assert col(catalog, "gold_triage_cases", "sample_summary").effective is U
    assert col(catalog, "gold_triage_cases", "surge_ratio").effective is S


def test_l04_actions_trusted(catalog: Catalog) -> None:
    assert all(c.effective is T for c in catalog.tables["gold_actions"].columns.values())


def test_l05_label_exists(catalog: Catalog) -> None:
    assert col(catalog, "gold_triage_labels", "label_real_trend").effective is S


def test_no_pipeline_column_failed_closed(catalog: Catalog) -> None:
    for t in PIPELINE:
        for c in catalog.tables[t].columns.values():
            assert "?" not in c.untrusted_sources, (t, c.reasons)


def test_l06_union_is_positional(gold: Catalog) -> None:
    sql = "SELECT make AS x FROM gold_trends UNION ALL SELECT top_summary FROM gold_trends"
    assert tiers(gold, sql) == [U]


def test_l07_star(gold: Catalog) -> None:
    t = tiers(gold, "SELECT * FROM gold_trends")
    assert len(t) == 12 and t[-1] is U and all(x is S for x in t[:-1])


def test_l08_where_on_untrusted_is_implicit(gold: Catalog) -> None:
    q = analyze_query(
        "SELECT make, count(*) FROM gold_trends WHERE top_summary ILIKE '%x%' GROUP BY make", gold
    )
    assert [t.effective for t in q.taints] == [S, S]
    assert all(t.selection is U for t in q.taints)


def test_l09_window_partition_is_selection(gold: Catalog) -> None:
    sql = (
        "SELECT row_number() OVER (PARTITION BY top_summary ORDER BY n_complaints) FROM gold_trends"
    )
    assert tiers(gold, sql) == [S]


def test_l10_filter_clause(gold: Catalog) -> None:
    assert tiers(
        gold, "SELECT count(*) FILTER (WHERE top_summary ILIKE '%f%') FROM gold_trends"
    ) == [S]


def test_l11_unbounded_concatenation(gold: Catalog) -> None:
    assert tiers(gold, "SELECT string_agg(make, ' ') FROM gold_trends") == [U]
    assert tiers(gold, "SELECT list(make) FROM gold_trends") == [U]


def test_l12_max_by(gold: Catalog) -> None:
    assert tiers(gold, "SELECT max_by(make, top_summary) FROM gold_trends") == [S]
    assert tiers(gold, "SELECT max_by(top_summary, n_complaints) FROM gold_trends") == [U]


def test_l13_subqueries(gold: Catalog) -> None:
    assert tiers(gold, "SELECT (SELECT max(top_summary) FROM gold_trends)") == [U]
    assert tiers(gold, "SELECT (SELECT max(n_complaints) FROM gold_trends)") == [S]
    sql = "SELECT make FROM gold_trends WHERE model IN (SELECT model FROM gold_trends WHERE top_summary ILIKE '%a%')"
    assert tiers(gold, sql) == [S]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1 FROM gold_trends, LATERAL (SELECT top_summary) l",
        "SELECT COLUMNS('.*') FROM gold_trends",
        "WITH RECURSIVE r AS (SELECT 1 AS n UNION ALL SELECT n+1 FROM r WHERE n<3) SELECT n FROM r",
        "SELECT * FROM gold_trends PIVOT (sum(n_complaints) FOR make IN ('A'))",
        "SELECT * FROM nope",
        "SELECT nope FROM gold_trends",
        "SELECT ?",
        "SELECT * FROM read_csv('/etc/passwd')",
        "SELECT 1; SELECT 2",
        "DROP TABLE x",
        "",
    ],
)
def test_l14_fails_closed_without_raising(gold: Catalog, sql: str) -> None:
    q = analyze_query(sql, gold)
    assert q.failed is not None and q.canonical_sql is None
    assert all(t.effective is U for t in q.taints)
    assert q.tiers_for(3) == [U, U, U]


def test_l15_positional_mismatch(gold: Catalog) -> None:
    q = analyze_query("SELECT make FROM gold_trends", gold)
    assert q.tiers_for(1) == [S] and q.tiers_for(2) == [U, U]


def test_l16_case_folding(gold: Catalog) -> None:
    assert tiers(gold, 'SELECT "TOP_SUMMARY" FROM gold_trends') == [U]


def test_l17_table_functions(gold: Catalog) -> None:
    assert tiers(gold, "SELECT unnest(string_split(top_summary, ' ')) FROM gold_trends") == [U]
    assert tiers(gold, "SELECT t.w FROM generate_series(1, 3) AS t(w)") == [T]


def test_l18_sqlglot_pin() -> None:
    major, minor = (int(x) for x in sqlglot.__version__.split(".")[:2])
    assert (major, minor) >= (30, 25) and major < 31


def test_l19_speed(catalog: Catalog) -> None:
    sql = render("gold_triage_cases")
    runs = []
    for _ in range(5):
        t0 = time.perf_counter()
        analyze_query(sql, catalog.subset(["gold_trends"]))
        runs.append((time.perf_counter() - t0) * 1000)
    assert statistics.median(runs) < 50


def test_l20_unanalysable_pipeline_sql_is_a_build_error(contracts: ContractSet) -> None:
    bad = render("stg_complaints").replace(
        "FROM raw_complaints AS c", "FROM raw_complaints AS c, LATERAL (SELECT 1) AS z"
    )
    with pytest.raises(LineageError):
        build_catalog(contracts, [("stg_complaints", bad)])


def test_never_raises_on_odd_input(gold: Catalog) -> None:
    for sql in [
        "",
        "DROP TABLE x",
        "SELECT",
        "((((",
        "SELECT 1 FROM",
        "select * from gold_trends limit",
    ]:
        analyze_query(sql, gold)


def test_canonical_sql_is_executable(gold: Catalog) -> None:
    import duckdb

    q = analyze_query("SELECT make, count(*) AS n FROM gold_trends GROUP BY make", gold)
    assert q.canonical_sql
    con = duckdb.connect()
    con.execute("CREATE TABLE gold_trends AS SELECT 'A' AS make")
    assert con.execute(q.canonical_sql).fetchall() == [("A", 1)]
