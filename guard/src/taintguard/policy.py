"""Tool-call policy: capability checks for closed arguments, contact and overlap checks for free text.

Taint cannot be traced through an LLM's generation, so the guard controls what the model saw
(see extractor) and which argument values are acceptable (this module). ADR 0004, section 6.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal


class Decision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    CONFIRM = "confirm"


@dataclass(frozen=True)
class ArgRule:
    kind: Literal["capability", "free_text", "closed", "query"]
    source: str | None = None
    values: frozenset[str] | None = None
    normalise: Literal["exact", "casefold"] = "exact"


@dataclass(frozen=True)
class ToolPolicy:
    tools: Mapping[str, Mapping[str, ArgRule]]


@dataclass
class Capabilities:
    trusted_text: str = ""
    allowed: dict[str, frozenset[str]] = field(default_factory=dict)
    untrusted_texts: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ToolVerdict:
    decision: Decision
    reasons: tuple[str, ...] = ()
    argument: str | None = None


_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", re.I)
_URL = re.compile(r"https?://[^\s,;)>\]]+", re.I)
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|co|gov|edu|info|biz|us|uk|de|ru|cn|example|test|invalid)\b",
    re.I,
)
_TOKEN = re.compile(r"[a-z0-9']+")


def contacts(text: str) -> set[str]:
    """Casefolded emails, URLs and bare domains in ``text``."""
    t = text.casefold()
    out = {m.group(0).rstrip(".,") for m in _EMAIL.finditer(t)}
    out |= {m.group(0).rstrip(".,") for m in _URL.finditer(t)}
    out |= {m.group(0) for m in _DOMAIN.finditer(t)}
    return out


def max_ngram_overlap(a: str, b: str) -> int:
    """Length of the longest run of word tokens that appears in both texts."""
    ta, tb = _TOKEN.findall(a.casefold()), _TOKEN.findall(b.casefold())
    if not ta or not tb:
        return 0
    best = 0
    prev = [0] * (len(tb) + 1)
    for i in range(1, len(ta) + 1):
        cur = [0] * (len(tb) + 1)
        for j in range(1, len(tb) + 1):
            if ta[i - 1] == tb[j - 1]:
                cur[j] = prev[j - 1] + 1
                best = max(best, cur[j])
        prev = cur
    return best


def _norm(v: str, how: str) -> str:
    return v.strip().casefold() if how == "casefold" else v.strip()


def check_call(
    tool: str,
    args: Mapping[str, object],
    policy: ToolPolicy,
    caps: Capabilities,
    *,
    ngram: int = 8,
) -> ToolVerdict:
    rules = policy.tools.get(tool)
    if rules is None:
        return ToolVerdict(Decision.BLOCK, (f"unknown tool {tool}",), tool)
    confirm: list[str] = []
    for name, value in args.items():
        if value is None:
            continue
        rule = rules.get(name)
        if rule is None:
            return ToolVerdict(Decision.BLOCK, (f"unexpected argument {name}",), name)
        s = value if isinstance(value, str) else str(value)
        if rule.kind == "query":
            continue
        if rule.kind in ("capability", "closed"):
            allowed = (
                caps.allowed.get(rule.source or name, frozenset())
                if rule.kind == "capability"
                else (rule.values or frozenset())
            )
            if _norm(s, rule.normalise) not in {_norm(a, rule.normalise) for a in allowed}:
                return ToolVerdict(Decision.BLOCK, (f"{name} not in the permitted set",), name)
            continue
        extra = contacts(s) - contacts(caps.trusted_text)
        if extra:
            return ToolVerdict(Decision.BLOCK, ("contact not in trusted text",), name)
        if any(max_ngram_overlap(s, u) >= ngram for u in caps.untrusted_texts):
            confirm.append(f"{name} copies untrusted text")
    if confirm:
        return ToolVerdict(Decision.CONFIRM, tuple(confirm), None)
    return ToolVerdict(Decision.ALLOW)
