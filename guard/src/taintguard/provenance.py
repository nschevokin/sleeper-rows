"""Answer provenance: every number an agent states must be a cell it actually read.

This proves where a number came from, not that it is right (ADR 0004, section 7). A mismatch
*flags* the answer; it does not block it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import date, datetime
from decimal import Decimal
from typing import Literal

from taintguard.contracts import Trust

_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_NUM = re.compile(r"(?<![\w.])-?(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?(?:\s?%|x)?(?![\w])")
_WORDS = {w: i for i, w in enumerate(
    ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen", "twenty"]
)}  # fmt: skip
_WORD = re.compile(r"\b(" + "|".join(_WORDS) + r")\b", re.I)


@dataclass(frozen=True)
class TieredResult:
    columns: Sequence[str]
    rows: Sequence[Sequence[object]]
    tiers: Sequence[Trust]


@dataclass(frozen=True)
class CellRef:
    query: int
    row: int
    col: int
    column: str
    tier: Trust
    single_row: bool


@dataclass(frozen=True)
class Claim:
    raw: str
    value: float
    field: str
    kind: Literal["number", "percent", "date", "year"]
    status: Literal["matched", "echo", "unmatched", "untrusted_source"] = "unmatched"
    source: CellRef | None = None
    decimals: int = 0


@dataclass(frozen=True)
class ProvenanceVerdict:
    ok: bool
    claims: tuple[Claim, ...]
    reasons: tuple[str, ...]


def _decimals(s: str) -> int:
    return len(s.split(".", 1)[1]) if "." in s else 0


def _date_val(s: str) -> float:
    return float(s.replace("-", ""))


def extract_claims(text: str, field: str) -> list[Claim]:
    claims: list[Claim] = []
    masked = text
    for m in _DATE.finditer(text):
        claims.append(Claim(m.group(0), _date_val(m.group(0)), field, "date"))
    masked = _DATE.sub(lambda m: " " * len(m.group(0)), masked)
    for m in _NUM.finditer(masked):
        raw = m.group(0).strip()
        pct = raw.endswith("%")
        core = raw.rstrip("%x ").replace(",", "")
        try:
            val = float(core)
        except ValueError:
            continue
        dec = _decimals(core)
        year = (
            not pct
            and dec == 0
            and 1900 <= val <= 2100
            and "," not in raw
            and not raw.endswith("x")
        )
        claims.append(
            Claim(raw, val, field, "percent" if pct else "year" if year else "number", decimals=dec)
        )
    for m in _WORD.finditer(masked):
        claims.append(Claim(m.group(0), float(_WORDS[m.group(0).lower()]), field, "number"))
    return claims


def _close(c: float, x: float, dec: int) -> bool:
    return abs(c - x) <= 0.5 * 10**-dec + 1e-9


def _cells(results: Sequence[TieredResult]) -> list[tuple[CellRef, object]]:
    out: list[tuple[CellRef, object]] = []
    for qi, r in enumerate(results):
        for ri, row in enumerate(r.rows):
            for ci, v in enumerate(row):
                tier = r.tiers[ci] if ci < len(r.tiers) else Trust.UNTRUSTED
                out.append((CellRef(qi, ri, ci, r.columns[ci], tier, len(r.rows) == 1), v))
    return out


def _numeric(v: object) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int | float | Decimal):
        return float(v)
    return None


def _echo_values(trusted_text: str) -> set[float]:
    vals = {_date_val(m.group(0)) for m in _DATE.finditer(trusted_text)}
    for c in extract_claims(trusted_text, "trusted"):
        vals.add(c.value)
    return vals


def check_answer(
    value: float | None,
    texts: Mapping[str, str | None],
    results: Sequence[TieredResult],
    trusted_text: str,
    *,
    strict_single_row: bool = False,
) -> ProvenanceVerdict:
    claims: list[Claim] = []
    if value is not None:
        raw = repr(float(value))
        raw = raw[:-2] if raw.endswith(".0") else raw
        claims.append(Claim(raw, float(value), "value", "number", decimals=_decimals(raw)))
    for fld, t in texts.items():
        if t:
            claims.extend(extract_claims(t, fld))
    echoes = _echo_values(trusted_text)
    cells = _cells(results)
    final: list[Claim] = []
    reasons: list[str] = []
    for c in claims:
        if any(abs(c.value - e) < 1e-9 for e in echoes):
            final.append(replace(c, status="echo"))
            continue
        status: Literal["matched", "echo", "unmatched", "untrusted_source"] = "unmatched"
        src: CellRef | None = None
        for ref, v in cells:
            if strict_single_row and c.field == "value" and not ref.single_row:
                continue
            hit = False
            if c.kind == "date":
                hit = isinstance(v, date | datetime) and v.strftime("%Y-%m-%d") == c.raw
                hit = hit or (isinstance(v, str) and v == c.raw)
            else:
                x = _numeric(v)
                if (
                    x is None
                    and isinstance(v, str)
                    and re.fullmatch(r"-?\d+(\.\d+)?", v)
                    and ref.tier <= Trust.STRUCTURED
                ):
                    x = float(v)
                if x is not None:
                    hit = _close(c.value, x, c.decimals) or (
                        c.kind == "percent" and _close(c.value, 100 * x, c.decimals)
                    )
                elif c.kind == "year" and isinstance(v, date | datetime):
                    hit = v.year == int(c.value)
            if not hit:
                continue
            if ref.tier >= Trust.UNTRUSTED:
                status = "untrusted_source" if status == "unmatched" else status
                continue
            status, src = "matched", ref
            break
        final.append(replace(c, status=status, source=src))
        if status in ("unmatched", "untrusted_source"):
            reasons.append(f"{status.replace('_', ' ')} {c.raw} in {c.field}")
    return ProvenanceVerdict(not reasons, tuple(final), tuple(reasons))
