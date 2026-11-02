"""Model backends behind one interface.

* ``OllamaModel``   local open model, pinned by digest (the laptop runs).
* ``RecordingModel`` wraps another model and writes every call to a JSONL cassette.
* ``ReplayModel``   serves a cassette; a miss is an error, so CI can never silently call a model.
* ``StubModel``     deterministic, rule-based, deliberately gullible. PLUMBING TESTS ONLY: its
  numbers are never findings, and every results table records the model name so reports say so.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


class MalformedOutput(Exception):
    """The model's output did not validate against the schema. Counted as a failure."""

    def __init__(self, raw: str, detail: str):
        super().__init__(detail)
        self.raw = raw


class ReplayMiss(KeyError):
    """A call has no recording."""


@dataclass
class ModelResult:
    text: str
    parsed: BaseModel | None
    tokens_in: int
    tokens_out: int
    latency_ms: float

    @property
    def tokens(self) -> int:
        return self.tokens_in + self.tokens_out


class ModelClient(Protocol):
    name: str
    digest: str

    def generate(
        self,
        system: str,
        user: str,
        schema: type[BaseModel] | None = None,
        *,
        temperature: float = 0.0,
        seed: int = 0,
    ) -> ModelResult: ...


def parse_output(text: str, schema: type[T] | None) -> T | None:
    if schema is None:
        return None
    try:
        return schema.model_validate_json(text)
    except ValidationError as exc:
        raise MalformedOutput(text, str(exc).splitlines()[0]) from exc


def call_key(
    name: str, system: str, user: str, schema: type[BaseModel] | None, temperature: float, seed: int
) -> str:
    h = hashlib.sha256()
    for part in (
        name,
        system,
        user,
        schema.__name__ if schema else "",
        f"{temperature}",
        f"{seed}",
    ):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


class OllamaModel:
    def __init__(
        self,
        model: str,
        *,
        digest: str | None = None,
        host: str = "http://127.0.0.1:11434",
        num_ctx: int = 8192,
        max_tokens: int = 700,
        timeout: float = 300.0,
    ):
        self.name = model
        self.host = host.rstrip("/")
        self.num_ctx, self.max_tokens, self.timeout = num_ctx, max_tokens, timeout
        self.digest = self._resolve_digest(digest)

    def _resolve_digest(self, expected: str | None) -> str:
        r = httpx.get(f"{self.host}/api/tags", timeout=30)
        r.raise_for_status()
        for m in r.json().get("models", []):
            if m.get("name") == self.name or m.get("model") == self.name:
                actual = str(m["digest"])
                if expected and not actual.startswith(expected.removeprefix("sha256:")[:12]):
                    raise RuntimeError(
                        f"{self.name}: digest {actual[:12]} does not match pinned {expected[:12]}"
                    )
                return actual
        raise RuntimeError(f"model {self.name!r} is not pulled; run `ollama pull {self.name}`")

    def generate(
        self,
        system: str,
        user: str,
        schema: type[BaseModel] | None = None,
        *,
        temperature: float = 0.0,
        seed: int = 0,
    ) -> ModelResult:
        payload: dict[str, Any] = {
            "model": self.name,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {
                "temperature": temperature,
                "seed": seed,
                "num_ctx": self.num_ctx,
                "num_predict": self.max_tokens,
            },
        }
        if schema is not None:
            payload["format"] = schema.model_json_schema()
        t0 = time.perf_counter()
        r = httpx.post(f"{self.host}/api/chat", json=payload, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        text = data["message"]["content"]
        return ModelResult(
            text=text,
            parsed=parse_output(text, schema),
            tokens_in=int(data.get("prompt_eval_count", 0)),
            tokens_out=int(data.get("eval_count", 0)),
            latency_ms=(time.perf_counter() - t0) * 1000,
        )


class RecordingModel:
    def __init__(self, inner: ModelClient, cassette: Path):
        self.inner = inner
        self.name, self.digest = inner.name, inner.digest
        self.cassette = cassette
        cassette.parent.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        system: str,
        user: str,
        schema: type[BaseModel] | None = None,
        *,
        temperature: float = 0.0,
        seed: int = 0,
    ) -> ModelResult:
        try:
            res = self.inner.generate(system, user, schema, temperature=temperature, seed=seed)
        except MalformedOutput as exc:
            self._write(system, user, schema, temperature, seed, exc.raw, 0, 0, 0.0)
            raise
        self._write(
            system,
            user,
            schema,
            temperature,
            seed,
            res.text,
            res.tokens_in,
            res.tokens_out,
            res.latency_ms,
        )
        return res

    def _write(
        self, system: str, user: str, schema: type[BaseModel] | None, temperature: float, seed: int,
        text: str, tin: int, tout: int, ms: float,
    ) -> None:  # fmt: skip
        rec = {
            "key": call_key(self.name, system, user, schema, temperature, seed),
            "model": self.name,
            "digest": self.digest,
            "text": text,
            "tokens_in": tin,
            "tokens_out": tout,
            "latency_ms": ms,
        }
        with self.cassette.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


class ReplayModel:
    def __init__(self, cassette: Path, name: str, digest: str = "replay"):
        self.name, self.digest = name, digest
        self.records: dict[str, dict[str, Any]] = {}
        for line in cassette.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                self.records[rec["key"]] = rec

    def generate(
        self,
        system: str,
        user: str,
        schema: type[BaseModel] | None = None,
        *,
        temperature: float = 0.0,
        seed: int = 0,
    ) -> ModelResult:
        key = call_key(self.name, system, user, schema, temperature, seed)
        rec = self.records.get(key)
        if rec is None:
            raise ReplayMiss(f"no recording for call {key[:12]} ({self.name})")
        text = rec["text"]
        return ModelResult(
            text, parse_output(text, schema), rec["tokens_in"], rec["tokens_out"], rec["latency_ms"]
        )
