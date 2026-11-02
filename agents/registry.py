"""Defense registry: build any defense by name so the eval matrix and CLIs share one place."""

from __future__ import annotations

from collections.abc import Callable

from agents.defenses import DetectorDefense, PromptHardening
from agents.guard_adapter import GuardComponents, TaintGuard
from agents.llm import ModelClient
from agents.runtime import Defense
from eval.env import Env

DEFENSES = ("none", "prompt_hardening", "detector", "taintguard")


def defense_factory(
    name: str,
    env: Env,
    model: ModelClient,
    *,
    detector_model: ModelClient | None = None,
    seed: int = 0,
    components: GuardComponents | None = None,
) -> Callable[[], Defense]:
    """A zero-argument factory, so each trial gets a fresh defense (fresh counters)."""
    if name == "none":
        return Defense
    if name == "prompt_hardening":
        return PromptHardening
    if name == "detector":
        return lambda: DetectorDefense(detector_model or model, seed)
    if name == "taintguard":
        return lambda: TaintGuard(
            env.guard_catalog, model, env.systems, env.contracts.model("raw_complaints"),
            components=components, seed=seed, cache=env.extract_cache,
        )  # fmt: skip
    raise ValueError(f"unknown defense {name!r}; choose from {DEFENSES}")
