"""Shared helpers for library tests (kept out of conftest so tests can import them)."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = [
    "stg_complaints",
    "enriched_complaints",
    "gold_actions",
    "gold_trends",
    "gold_triage_cases",
    "gold_triage_labels",
]


def render(name: str, window: int = 120) -> str:
    return (
        (ROOT / "pipeline" / "sql" / f"{name}.sql")
        .read_text()
        .replace("$LABEL_WINDOW_DAYS", str(window))
    )
