from __future__ import annotations

import polars as pl

from pipeline.transforms import MODEL_ORDER, referenced_tables, render_sql
from pipeline.warehouse import Warehouse


def _df(wh: Warehouse, name: str) -> pl.DataFrame:
    df = pl.from_arrow(wh.read(name))
    assert isinstance(df, pl.DataFrame)
    return df


def test_every_model_only_reads_earlier_models_or_inputs() -> None:
    known = {
        "raw_complaints",
        "raw_investigations",
        "raw_recalls",
        "ref_vehicles",
        "ref_components",
        "enriched_complaints",
    }
    for name in MODEL_ORDER:
        for t in referenced_tables(render_sql(name)):
            assert t in known, f"{name} reads {t} before it exists"
        known.add(name)


def test_staging_maps_vehicles_through_the_closed_vocabulary(gold: Warehouse) -> None:
    stg = _df(gold, "stg_complaints")
    ref = _df(gold, "ref_vehicles")
    assert set(stg["make_norm"].unique()) <= set(ref["make"]) | {"UNKNOWN"}
    assert set(stg["model_norm"].unique()) <= set(ref["model"]) | {"UNKNOWN"}


def test_gold_trends_counts_reconcile_with_staging(gold: Warehouse) -> None:
    stg = _df(gold, "stg_complaints").filter(
        pl.col("make_norm") != "UNKNOWN", pl.col("model_year").is_not_null()
    )
    trends = _df(gold, "gold_trends")
    assert trends["n_complaints"].sum() == stg.height
    assert trends["n_injured"].sum() == stg["injured"].sum()
    assert trends["n_complaints"].dtype == pl.Int64


def test_labels_cover_the_same_cases_and_have_both_classes(gold: Warehouse) -> None:
    cases, labels = _df(gold, "gold_triage_cases"), _df(gold, "gold_triage_labels")
    assert cases.height == labels.height > 20
    assert 0 < labels["label_real_trend"].sum() < labels.height


def test_agents_visible_case_table_has_no_label_column(gold: Warehouse) -> None:
    assert not any("label" in c for c in _df(gold, "gold_triage_cases").columns)


def test_label_requires_an_action_after_the_evaluation_week(gold: Warehouse) -> None:
    labels, actions = _df(gold, "gold_triage_labels"), _df(gold, "gold_actions")
    pos = labels.filter(pl.col("label_real_trend")).head(10)
    for r in pos.iter_rows(named=True):
        hit = actions.filter(
            (pl.col("make") == r["make"]) & (pl.col("model") == r["model"])
            & (pl.col("model_year") == r["model_year"]) & (pl.col("component_group") == r["component_group"])
            & (pl.col("action_date") >= r["eval_week"])
        )  # fmt: skip
        assert hit.height >= 1
