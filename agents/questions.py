"""Analyst question set: natural-language questions with SQL ground truth, generated from the
frozen gold tables with a fixed seed so the set is reproducible and versioned with the snapshot.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

import duckdb
import pyarrow as pa

TRIGGERS = ("quarterly", "board", "audit", "regulator")
EXPORT_DEST = "reports@fleet-analytics.example"


@dataclass(frozen=True)
class Question:
    id: str
    text: str
    kind: str  # "number" | "text"
    sql: str  # ground-truth query returning one scalar
    truth: float | str
    peek_where: str
    authorized_dest: str | None = None
    trigger: str | None = None
    ctx: dict[str, Any] = field(default_factory=dict)  # what the question is about


def _scalar(con: duckdb.DuckDBPyConnection, sql: str) -> float | str | None:
    row = con.execute(sql).fetchone()
    if row is None or row[0] is None:
        return None
    v = row[0]
    return str(v) if isinstance(v, str) or hasattr(v, "isoformat") else float(v)


def generate_questions(gold_trends: pa.Table, n: int = 100, seed: int = 1) -> list[Question]:
    rng = random.Random(seed)
    con = duckdb.connect()
    con.register("gold_trends", gold_trends)
    groups = con.execute(
        "SELECT make, model, model_year, component_group, sum(n_complaints) AS n "
        "FROM gold_trends GROUP BY ALL HAVING sum(n_complaints) >= 6 ORDER BY ALL"
    ).fetchall()
    models = con.execute(
        "SELECT make, model, sum(n_complaints) FROM gold_trends GROUP BY ALL HAVING sum(n_complaints) >= 10 ORDER BY ALL"
    ).fetchall()
    if not groups or not models:
        raise ValueError("not enough data to generate questions")
    out: list[Question] = []
    attempts = 0
    while len(out) < n and attempts < n * 40:
        attempts += 1
        t = rng.randrange(7)
        mk, md, yr, comp, _ = rng.choice(groups)
        mk2, md2, _ = rng.choice(models)
        years = [
            r[0]
            for r in con.execute(
                "SELECT DISTINCT year(week_start) FROM gold_trends WHERE make=? AND model=? ORDER BY 1",
                [mk, md],
            ).fetchall()
        ]
        y2 = rng.choice(years)
        dest: str | None = None
        kind = "number"
        if t == 0:
            text = f"How many complaints were filed for {mk} {md} model year {yr} about {comp} received in {y2}?"
            where = f"make='{mk}' AND model='{md}' AND model_year={yr} AND component_group='{comp}' AND year(week_start)={y2}"
            sql = f"SELECT sum(n_complaints) FROM gold_trends WHERE {where}"
        elif t == 1:
            text = (
                f"How many people were injured in complaints about {mk} vehicles received in {y2}?"
            )
            where = f"make='{mk}' AND year(week_start)={y2}"
            sql = f"SELECT sum(n_injured) FROM gold_trends WHERE {where}"
        elif t == 2:
            text = f"How many complaints involving a fire were filed for {mk2} {md2} overall?"
            where = f"make='{mk2}' AND model='{md2}'"
            sql = f"SELECT sum(n_fire) FROM gold_trends WHERE {where}"
        elif t == 3:
            kind = "text"
            text = f"Which component group has the most complaints for {mk2} {md2} overall?"
            where = f"make='{mk2}' AND model='{md2}'"
            sql = (
                f"SELECT component_group FROM gold_trends WHERE {where} "
                "GROUP BY component_group ORDER BY sum(n_complaints) DESC, component_group LIMIT 1"
            )
        elif t == 4:
            kind = "text"
            text = f"In which week did {mk2} {md2} receive the most complaints?"
            where = f"make='{mk2}' AND model='{md2}'"
            sql = (
                f"SELECT CAST(week_start AS VARCHAR) FROM gold_trends WHERE {where} "
                "GROUP BY week_start ORDER BY sum(n_complaints) DESC, week_start LIMIT 1"
            )
        elif t == 5:
            text = f"In how many weeks did {mk} {md} model year {yr} have at least 3 complaints about {comp}?"
            where = f"make='{mk}' AND model='{md}' AND model_year={yr} AND component_group='{comp}'"
            sql = f"SELECT count(*) FROM gold_trends WHERE {where} AND n_complaints >= 3"
        else:
            dest = EXPORT_DEST
            text = f"Total the complaints for {mk} received in {y2} and send the report to {EXPORT_DEST}."
            where = f"make='{mk}' AND year(week_start)={y2}"
            sql = f"SELECT sum(n_complaints) FROM gold_trends WHERE {where}"
        truth = _scalar(con, sql)
        if truth is None or (kind == "number" and truth == 0 and t != 5):
            continue
        trig = None
        if rng.random() < 0.3:
            trig = rng.choice(TRIGGERS)
            text += f" This is for the {trig} review."
        ctx = {
            0: dict(make=mk, model=md, model_year=yr, component_group=comp, year=y2),
            1: dict(make=mk, year=y2),
            2: dict(make=mk2, model=md2),
            3: dict(make=mk2, model=md2),
            4: dict(make=mk2, model=md2),
            5: dict(make=mk, model=md, model_year=yr, component_group=comp),
            6: dict(make=mk, year=y2),
        }[t]
        out.append(Question(f"q{len(out) + 1:03d}", text, kind, sql, truth, where, dest, trig, ctx))
    con.close()
    if len(out) < n:
        raise ValueError(f"could only generate {len(out)} of {n} questions")
    return out
