"""Typed outputs for every LLM component. A malformed output is a failure, never a retry."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, create_model

ACTIONS = ("sql", "escalate", "export_report", "open_ticket", "final")

DQ_CATEGORIES = (
    "unseen_component",
    "column_count_drift",
    "invalid_flag_value",
    "malformed_date",
    "out_of_range_number",
    "duplicate_key",
    "shifted_columns",
    "other",
)


class Action(BaseModel):
    """One step of a tool loop. Flat on purpose: small local models handle it reliably."""

    model_config = ConfigDict(extra="ignore")

    action: Literal["sql", "escalate", "export_report", "open_ticket", "final"]
    sql: str | None = None
    group_id: str | None = None
    reason: str | None = Field(default=None, max_length=300)
    dest: str | None = None
    ticket: str | None = Field(default=None, max_length=1000)
    answer: str | None = Field(default=None, max_length=1500)
    value: float | None = None
    category: str | None = None
    caveat: str | None = None


class Extraction(BaseModel):
    """What the quarantined extractor may return: typed values only, no free text."""

    model_config = ConfigDict(extra="forbid")

    component: str
    severity: int = Field(ge=1, le=5)


class Enrichment(Extraction):
    """Enrichment output: the two typed tags plus one free-text summary line."""

    summary: str = Field(max_length=200)


class Detection(BaseModel):
    is_injection: bool
    score: float = Field(ge=0.0, le=1.0)


def with_component_enum(model: type[BaseModel], systems: list[str]) -> type[BaseModel]:
    """Clone ``Extraction``/``Enrichment`` with ``component`` restricted to the closed vocabulary."""
    enum_type = Literal[tuple(sorted(systems))]  # type: ignore[valid-type]
    fields: dict[str, tuple[object, object]] = {}
    for name, f in model.model_fields.items():
        if name == "component":
            fields[name] = (enum_type, ...)
        else:
            fields[name] = (f.annotation, f)
    return create_model(f"{model.__name__}Closed", __config__=model.model_config, **fields)  # type: ignore[call-overload]
