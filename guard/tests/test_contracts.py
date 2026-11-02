from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from _support import ROOT, render
from taintguard import ContractError, Trust, build_catalog, load_contracts

S, U = Trust.STRUCTURED, Trust.UNTRUSTED
STG = ("stg_complaints", render("stg_complaints"))


def contracts_with(tmp_path: Path, extra: str):  # type: ignore[no-untyped-def]
    d = tmp_path / "c"
    shutil.copytree(ROOT / "contracts", d, dirs_exist_ok=True)
    (d / "extra.yaml").write_text("version: 2\nmodels:\n" + extra)
    return load_contracts(d)


def derived(sql: str, col: str, trust: str, extra: str = "") -> tuple[str, str]:
    return (
        f"  - name: t1\n    columns:\n      - {{name: {col}, trust: {trust}{extra}}}\n",
        sql,
    )


def build(tmp_path: Path, yaml_: str, sql: str):  # type: ignore[no-untyped-def]
    return build_catalog(contracts_with(tmp_path, yaml_), [STG, ("t1", sql)])


def test_c01_mislabel_is_refused(tmp_path: Path) -> None:
    y = "  - name: gold_trends\n    columns:\n      - {name: top_summary, trust: structured, tests: [{range: [0, 5]}]}\n"
    steps = [STG, "enriched_complaints", ("gold_trends", render("gold_trends"))]
    with pytest.raises(ContractError):
        build_catalog(contracts_with(tmp_path, y), steps)


def test_c02_wrong_validator_is_refused(tmp_path: Path) -> None:
    y = "  - name: gold_trends\n    columns:\n      - {name: top_summary, trust: structured, validated_by: typed_cast}\n"
    steps = [STG, "enriched_complaints", ("gold_trends", render("gold_trends"))]
    with pytest.raises(ContractError, match="does not match"):
        build_catalog(contracts_with(tmp_path, y), steps)


def test_c03_typed_cast_promotes(tmp_path: Path) -> None:
    sql = "SELECT try_cast(regexp_extract(cdescr, '\\d+') AS INTEGER) AS n FROM stg_complaints"
    y = "  - name: t1\n    columns:\n      - {name: n, trust: structured, validated_by: typed_cast}\n"
    n = build(tmp_path, y, sql).tables["t1"].columns["n"]
    assert n.effective is S and n.promoted_by == "typed_cast"


def test_c04_unknown_validator(tmp_path: Path) -> None:
    sql = "SELECT try_cast(regexp_extract(cdescr, '\\d+') AS INTEGER) AS n FROM stg_complaints"
    y = "  - name: t1\n    columns:\n      - {name: n, trust: structured, validated_by: anything_else}\n"
    with pytest.raises(ContractError):
        build(tmp_path, y, sql)


def test_c05_promotion_cannot_reach_trusted(tmp_path: Path) -> None:
    sql = "SELECT try_cast(regexp_extract(cdescr, '\\d+') AS INTEGER) AS n FROM stg_complaints"
    y = "  - name: t1\n    columns:\n      - {name: n, trust: trusted, validated_by: typed_cast}\n"
    with pytest.raises(ContractError):
        build(tmp_path, y, sql)


@pytest.mark.parametrize("rx", ["^.*$", "^[A-Z ]{0,40}$", "^\\d+$"])
def test_c06_loose_regex_refused(tmp_path: Path, rx: str) -> None:
    y = f"  - name: raw_x\n    source: {{role: x}}\n    columns:\n      - {{name: A, position: 1, trust: structured, tests: [{{regex: '{rx}'}}]}}\n"
    with pytest.raises(ContractError):
        contracts_with(tmp_path, y)


def test_c06_real_contracts_load() -> None:
    assert load_contracts(ROOT / "contracts").models


def test_c07_llm_derived_rules(tmp_path: Path) -> None:
    base = "  - name: e1\n    llm_derived: true\n    columns:\n      - "
    with pytest.raises(ContractError):
        contracts_with(tmp_path, base + "{name: a, trust: trusted}\n")
    with pytest.raises(ContractError):
        contracts_with(tmp_path, base + "{name: a, trust: structured}\n")
    cs = contracts_with(tmp_path, base + "{name: summary, trust: untrusted}\n")
    assert cs.model("e1").column("summary").tier is U


def test_c08_derived_from_cannot_lower_trust(tmp_path: Path) -> None:
    y = "  - name: e1\n    llm_derived: true\n    columns:\n      - {name: k, trust: trusted, derived_from: stg_complaints.complaint_key}\n"
    cs = contracts_with(tmp_path, y)  # upstream is SQL-computed, so the check happens at build time
    with pytest.raises(ContractError):
        build_catalog(cs, [STG, "e1"])


def test_c09_literal_choice(tmp_path: Path) -> None:
    sql = "SELECT CASE WHEN cdescr ILIKE '%fire%' THEN 'F' ELSE 'O' END AS k FROM stg_complaints"
    y = "  - name: t1\n    columns:\n      - {name: k, trust: structured, validated_by: literal_choice}\n"
    k = build(tmp_path, y, sql).tables["t1"].columns["k"]
    assert k.effective is S and k.promoted_by == "literal_choice"


def test_c10_gap_python_written_declaration_is_unverifiable(contracts) -> None:  # type: ignore[no-untyped-def]
    """GAP (R5): the library cannot read Python, so a trusted declaration on a python-written
    table is accepted as given. This test changes if that ever gets closed."""
    assert contracts.model("quarantine_complaints").column("failed_tests").tier is Trust.TRUSTED
