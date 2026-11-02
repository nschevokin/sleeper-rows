"""Quarantined extraction: one cell of untrusted text in, a closed typed record out.

The extractor model has no tools, no task text, no history and no retries. The library
re-validates its output and renders it itself, so model-written text never reaches an agent.
(ADR 0004, section 5.)
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import types
import typing
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel

ModelCall = Callable[[str, str, type[BaseModel]], BaseModel | None]


class SchemaNotClosed(ValueError):
    pass


def _closed_annotation(ann: Any, info: Any) -> bool:
    origin = typing.get_origin(ann)
    if origin is typing.Union or origin is types.UnionType:
        return all(a is type(None) or _closed_annotation(a, info) for a in typing.get_args(ann))
    if origin is Literal:
        return all(isinstance(v, str | int | bool) for v in typing.get_args(ann))
    if isinstance(ann, type) and issubclass(ann, Enum):
        return True
    if ann is bool:
        return True
    if ann in (int, float):
        meta = {type(m).__name__: m for m in getattr(info, "metadata", [])}
        lo = "Ge" in meta or "Gt" in meta
        hi = "Le" in meta or "Lt" in meta
        return lo and hi
    return False


def check_schema_closed(schema: type[BaseModel]) -> None:
    """Raise unless every field is a closed vocabulary or a bounded number, and extras are forbidden."""
    if schema.model_config.get("extra") != "forbid":
        raise SchemaNotClosed(f"{schema.__name__}: extra must be 'forbid'")
    for name, f in schema.model_fields.items():
        if not _closed_annotation(f.annotation, f):
            raise SchemaNotClosed(f"{schema.__name__}.{name}: not a closed type ({f.annotation})")


@dataclass(frozen=True)
class ExtractionResult:
    status: Literal["ok", "malformed", "empty"]
    values: Mapping[str, str | int | float | bool] | None
    latency_ms: float = 0.0


class QuarantinedExtractor:
    def __init__(
        self,
        call: ModelCall,
        schema: type[BaseModel],
        system_prompt: str,
        *,
        max_input_chars: int = 2048,
        cache: dict[str, ExtractionResult] | None = None,
    ) -> None:
        check_schema_closed(schema)
        self.call, self.schema, self.system_prompt = call, schema, system_prompt
        self.max_input_chars = max_input_chars
        self.cache = cache if cache is not None else {}
        self.calls = 0
        self.latency_ms = 0.0

    def extract(self, text: str) -> ExtractionResult:
        if not text or not text.strip():
            return ExtractionResult("empty", None)
        text = text[: self.max_input_chars]
        key = hashlib.sha256((self.system_prompt + "\x00" + text).encode()).hexdigest()
        if key in self.cache:
            return self.cache[key]
        t0 = time.perf_counter()
        self.calls += 1
        try:
            raw = self.call(self.system_prompt, text, self.schema)  # exactly one attempt, no retry
            res = self._validate(raw)
        except Exception:
            res = ExtractionResult("malformed", None)
        ms = (time.perf_counter() - t0) * 1000
        self.latency_ms += ms
        res = ExtractionResult(res.status, res.values, ms)
        self.cache[key] = res
        return res

    def _validate(self, raw: BaseModel | None) -> ExtractionResult:
        if raw is None:
            return ExtractionResult("malformed", None)
        again = self.schema.model_validate(raw.model_dump())  # never trust the adapter's parser
        vals = {n: getattr(again, n) for n in self.schema.model_fields}
        for v in vals.values():
            if isinstance(v, Enum):
                vals = {k: (x.value if isinstance(x, Enum) else x) for k, x in vals.items()}
                break
        return ExtractionResult("ok", vals)


def render_extraction(res: ExtractionResult) -> str:
    if res.status == "ok" and res.values is not None:
        body = "; ".join(f"{k}={v}" for k, v in res.values.items())
        return f"[extracted {body}]"
    if res.status == "empty":
        return "[empty]"
    return "[withheld: extractor output malformed]"


_SHAPE_KEEP = set("-/:.,+")


def shape(value: str, max_len: int = 40) -> str:
    """Deterministic, model-free shape of a string: digits 9, capitals A, lowercase a, space _."""
    out: list[str] = []
    for ch in value:
        if ch.isdigit() and ch.isascii():
            out.append("9")
        elif "A" <= ch <= "Z":
            out.append("A")
        elif "a" <= ch <= "z":
            out.append("a")
        elif ch.isspace():
            out.append("_")
        elif ch in _SHAPE_KEEP:
            out.append(ch)
        else:
            out.append("?")
    compact = re.sub(r"(.)\1{4,}", lambda m: f"{m.group(1)}{{{len(m.group(0))}}}", "".join(out))
    return compact if len(compact) <= max_len else compact[:max_len] + f"…(len={len(value)})"


def shape_record(json_text: str, fields: Mapping[str, Literal["shape", "length"]]) -> str:
    try:
        obj = json.loads(json_text)
        if not isinstance(obj, dict):
            raise ValueError
    except ValueError:
        return shape(json_text)
    parts: list[str] = []
    for k, mode in fields.items():
        if k not in obj:
            continue
        v = "" if obj[k] is None else str(obj[k])
        parts.append(f"{k}=<text len={len(v)}>" if mode == "length" else f"{k}={shape(v)}")
    return " ".join(parts)
