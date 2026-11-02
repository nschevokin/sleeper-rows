"""Experiment snapshot: the frozen input every reproducible result is computed from."""

from __future__ import annotations

import hashlib
from datetime import date
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict


class DateRange(BaseModel):
    start: date
    end: date


class Scope(BaseModel):
    """Bounds the real-data run so a laptop can finish it (a 7B model cannot enrich millions of rows).

    ``makes`` restricts the vehicle vocabulary, so everything else maps to UNKNOWN and is dropped from
    gold. ``max_enrich_rows`` caps LLM calls per ``build`` run; reruns continue where it stopped.
    """

    makes: list[str] = []
    max_enrich_rows: int | None = None


class Snapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    source: str  # "fixture" | "nhtsa"
    synthetic: bool = False
    snapshot_date: date
    seed: int
    date_range: DateRange
    label_window_days: int = 120
    files: dict[str, str]
    updates: list[str] = []
    reference: dict[str, str]
    # sha256 of each landing file, filled in by `pipeline.cli freeze` for real data.
    checksums: dict[str, str] = {}
    scope: Scope = Scope()

    def path(self, p: str) -> Path:
        return Path(p)


def load_snapshot(path: str | Path) -> Snapshot:
    p = Path(path).resolve()
    doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    snap = Snapshot.model_validate(doc)
    base = p.parent

    def fix(s: str) -> str:
        q = Path(s)
        return str(q if q.is_absolute() else (base / q).resolve())

    snap.files = {k: fix(v) for k, v in snap.files.items()}
    snap.updates = [fix(u) for u in snap.updates]
    snap.reference = {k: fix(v) for k, v in snap.reference.items()}
    return snap


def sha256_file(path: str | Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def verify_checksums(snap: Snapshot) -> list[str]:
    """Return a list of mismatch messages; empty means every pinned file matches."""
    problems = []
    for role, expected in snap.checksums.items():
        path = snap.files.get(role)
        if path is None:
            problems.append(f"{role}: pinned but not listed in files")
            continue
        got = sha256_file(path)
        if got != expected:
            problems.append(f"{role}: sha256 {got[:12]}… != pinned {expected[:12]}…")
    return problems
