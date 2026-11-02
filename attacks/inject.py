"""Build poisoned complaints in the real flat-file layout and land them like any other batch.

Placements (plan):
  narrative  the complaint text (CDESCR), the realistic main channel
  field      another free-text or loosely validated field (MODELTXT, MFR_NAME, DOT, TIRE_SIZE) or a
             structured one whose bounding test should quarantine the row (CMPL_TYPE, DRIVE_TRAIN)
  batch      a third-party aggregator batch that RE-SUBMITS existing complaint keys with replaced
             text: no new rows, no volume change, only content (the attacker controls file-level
             content). It exercises the update path of incremental landing.
Dose: how many poisoned rows per targeted group (1, 5 or 25 in the full matrix).

Poisoned rows are made only for the local in-memory copy of the data. Nothing is ever submitted
anywhere.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import date, timedelta

import polars as pl
from taintguard.contracts import ModelSpec

from attacks.payloads import Payload

PLACEMENTS = ("narrative", "field", "batch")
FIELD_TARGETS = ("MODELTXT", "MFR_NAME", "DOT", "TIRE_SIZE", "CMPL_TYPE", "DRIVE_TRAIN")
ODINO_BASE = 990_000_000  # 9 digits, outside the range any real or fixture complaint uses
CMPLID_BASE = 990_000_000
META = ("_key", "_row_hash", "_batch", "_source_file", "_ingested_at")


@dataclass
class PoisonSet:
    frame: pl.DataFrame  # in read_flat layout: every contract column, PII columns empty
    odinos: list[str]
    keys: list[str]
    placement: str
    batch: str
    canary: str | None
    text: str
    group: dict[str, object] = field(default_factory=dict)

    def is_poisoned_ref(self, ref: str) -> bool:
        return any(f"ODINO={o}" in ref for o in self.odinos)


def _benign_sentence(component: str) -> str:
    return f"THE CONTACT STATED THAT THE {component} FAILED WHILE DRIVING. THE DEALER COULD NOT DUPLICATE THE FAILURE."


def _template_row(
    raw: pl.DataFrame, group: dict[str, object], rng: random.Random
) -> dict[str, str]:
    """A real complaint from the group if one exists (so all other fields look plausible)."""
    comp = str(group["component_group"])
    m = raw.filter(
        (pl.col("MAKETXT").str.to_uppercase() == group["make"])
        & (pl.col("MODELTXT").str.to_uppercase() == group["model"])
        & (pl.col("YEARTXT") == str(group["model_year"]))
        & (pl.col("COMPDESC").str.to_uppercase().str.starts_with(comp))
    )
    if m.height:
        return {k: str(v) for k, v in m.row(rng.randrange(m.height), named=True).items()}
    # No existing row: synthesise one from the vocabulary.
    any_row = {k: str(v) for k, v in raw.row(0, named=True).items()}
    return {k: ("" if k not in ("COMPDESC",) else v) for k, v in any_row.items()}


def build_poison(
    raw: pl.DataFrame,
    spec: ModelSpec,
    group: dict[str, object],
    payload: Payload | None,
    benign_text: str,
    *,
    placement: str,
    dose: int,
    window: tuple[date, date],
    components: set[str],
    seed: int,
    boost: str = "max",
    batch_tag: str = "public",
    uid: int = 0,
) -> PoisonSet:
    """``payload=None`` builds the matched control: same rows, benign text of equal length."""
    if placement not in PLACEMENTS:
        raise ValueError(placement)
    rng = random.Random(seed)
    text = payload.text if payload else benign_text
    comp_group = str(group["component_group"])
    cols = [c.name for c in sorted(spec.columns, key=lambda c: c.position or 0)]
    raw_cols = raw.drop([c for c in META if c in raw.columns])
    rows: list[dict[str, str]] = []
    odinos: list[str] = []
    span = max((window[1] - window[0]).days, 1)
    for i in range(dose):
        base = _template_row(raw_cols, group, rng)
        row = {c: base.get(c, "") for c in cols}
        # Vehicle identity must stay inside the vocabulary for the row to reach gold.
        row["MAKETXT"], row["MODELTXT"] = str(group["make"]), str(group["model"])
        row["YEARTXT"] = str(group["model_year"])
        if not row["COMPDESC"] or not row["COMPDESC"].upper().startswith(comp_group):
            row["COMPDESC"] = sorted(c for c in components if c.upper().startswith(comp_group))[0]
        if placement == "batch":
            # Re-submit an existing key with replaced content. Key collision overwrites the real row.
            if base.get("ODINO", ""):
                row["ODINO"] = base["ODINO"]
            row["CMPLID"] = str(CMPLID_BASE + uid * 1000 + i)
            odinos.append(row["ODINO"])
        else:
            odino = str(ODINO_BASE + uid * 1000 + i)
            row["ODINO"], row["CMPLID"] = odino, str(CMPLID_BASE + uid * 1000 + i)
            ld = window[0] + timedelta(days=rng.randrange(span + 1))
            row["LDATE"] = ld.strftime("%Y%m%d")
            row["FAILDATE"] = (ld - timedelta(days=rng.randint(0, 5))).strftime("%Y%m%d")
            row["DATEA"] = (ld + timedelta(days=2)).strftime("%Y%m%d")
            odinos.append(odino)
        if boost in ("fire", "max"):
            row["FIRE"], row["INJURED"] = "Y", "1"
        if boost == "max":
            row["CRASH"], row["DEATHS"] = "Y", "1"
        benign = _benign_sentence(comp_group)
        if placement == "field":
            tgt = FIELD_TARGETS[(seed + i) % len(FIELD_TARGETS)]
            row["CDESCR"] = benign
            row[tgt] = text  # lands as-is; staging or an enforced test decides its fate
        else:
            row["CDESCR"] = f"{text} {benign}"[:2048]
        rows.append(row)
    frame = pl.DataFrame(rows, schema={c: pl.String for c in cols})
    key_cols = spec.key
    keys = ["|".join(r[k] for k in key_cols) for r in rows]
    return PoisonSet(
        frame, odinos, keys, placement, f"aggregator:{batch_tag}" if placement == "batch" else f"public:{batch_tag}",
        payload.canary if payload else None, text, dict(group),
    )  # fmt: skip
