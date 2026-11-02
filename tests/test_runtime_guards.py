"""Harness behaviour that must hold for every model: no empty finals, no silent query loops."""

from __future__ import annotations

from typing import Any

import pyarrow as pa
from pydantic import BaseModel

from agents.events import EventLog
from agents.llm import ModelResult
from agents.runtime import AgentSpec, Defense, RunState, run_agent
from agents.schemas import Action
from agents.tools import Sinks, SqlSandbox


class Scripted:
    name, digest = "scripted", "0"

    def __init__(self, actions: list[Action]):
        self.actions, self.prompts = list(actions), []

    def generate(
        self, system: str, user: str, schema: type[BaseModel] | None = None, **kw: Any
    ) -> ModelResult:
        self.prompts.append(user)
        return ModelResult("{}", self.actions.pop(0), 1, 1, 0.0)


def _run(actions: list[Action], needs: tuple[str, ...]) -> tuple[Any, Scripted]:
    m = Scripted(actions)
    sb = SqlSandbox({"t": pa.table({"x": [1, 2]})})
    spec = AgentSpec("analyst", "TASK:analyst", ("sql", "final"), max_steps=5, final_needs=needs)
    out = run_agent(
        spec, m, Defense(), RunState(agent="analyst", task_text="Q"), sb, Sinks(),
        EventLog(None, run_id="r", scenario="clean", scenario_id="s"),
    )  # fmt: skip
    return out, m


def test_empty_final_is_rejected_and_the_model_can_retry() -> None:
    out, m = _run([Action(action="final"), Action(action="final", value=3.0)], ("value", "answer"))
    assert out.status == "ok" and out.final is not None and out.final.value == 3.0
    assert out.invalid_actions == 1 and "final action was empty" in m.prompts[1]


def test_repeating_a_query_adds_a_note() -> None:
    q = Action(action="sql", sql="SELECT count(*) FROM t")
    out, m = _run([q, q, Action(action="final", value=2.0)], ())
    assert out.status == "ok" and "already ran exactly this query" in m.prompts[2]
    assert "already ran" not in m.prompts[1]
