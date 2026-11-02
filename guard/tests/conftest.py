"""Fixtures for the library tests. They read the repo's contracts and SQL from disk but import nothing
from the project, so the library stays usable on its own."""

from __future__ import annotations

import pytest
from _support import PIPELINE, ROOT, render
from taintguard import Catalog, ContractSet, build_catalog, load_contracts


@pytest.fixture(scope="session")
def contracts() -> ContractSet:
    return load_contracts(ROOT / "contracts")


@pytest.fixture(scope="session")
def catalog(contracts: ContractSet) -> Catalog:
    steps: list[str | tuple[str, str]] = [
        n if n == "enriched_complaints" else (n, render(n)) for n in PIPELINE
    ]
    return build_catalog(contracts, steps)


@pytest.fixture(scope="session")
def gold(catalog: Catalog) -> Catalog:
    return catalog.subset(["gold_trends", "gold_triage_cases", "gold_actions"])
