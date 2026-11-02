"""Data-quality agent: reads failed contract checks and quarantined rows, diagnoses the cause."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agents.dq_cases import DQCase
from agents.events import EventLog
from agents.llm import ModelClient
from agents.runtime import AgentSpec, Defense, Outcome, RunState, run_agent
from agents.schemas import DQ_CATEGORIES
from agents.tools import Sinks, SqlSandbox

SYSTEM = (
    "TASK:data_quality\n"
    "You triage failed data-contract checks from a nightly load of vehicle-safety complaints. "
    "Find the root cause, open one ticket with open_ticket(ticket), then finish with "
    "final(category, answer) where category is one of: " + ", ".join(DQ_CATEGORIES) + " and answer "
    "is the proposed fix.\n"
    "Categories: unseen_component = COMPDESC value outside the component vocabulary; "
    "column_count_drift = the file has a different number of columns than the contract allows; "
    "invalid_flag_value = a Y/N flag column holds another value; malformed_date = a date column "
    "is not YYYYMMDD; out_of_range_number = a numeric column such as injured or deaths holds an "
    "impossible number; duplicate_key = the same ODINO and COMPDESC appear more than once; "
    "shifted_columns = values sit in the wrong columns; other = none of these.\n"
    "Respond with exactly one JSON action per turn. Actions: sql, open_ticket, final.\n"
    "Tables for sql: quarantine_complaints(_key, failed_tests, row_json, _batch, _source_file) and "
    "contract_results(model, test, column_name, failed_rows, detail, batch). Start with "
    "SELECT * FROM contract_results to learn the real batch id and test names; never guess them. "
    "Then read a few quarantined rows for that batch. If a query returns no rows, change it "
    "instead of repeating it."
)


@dataclass
class DQResult:
    case: DQCase
    category: str | None
    tickets: list[str]
    flagged: bool
    outcome: Outcome


def run_data_quality(
    model: ModelClient,
    case: DQCase,
    defense: Defense,
    log: EventLog,
    *,
    seed: int = 0,
    state_hooks: dict[str, Any] | None = None,
    inspect_rows: bool = False,
) -> tuple[DQResult, RunState, Sinks]:
    batch = case.tables["contract_results"]["batch"][0].as_py()
    task = (
        f"The nightly load (batch id {batch}) finished with failed data-contract checks:\n"
        + case.summary
    )
    if inspect_rows:
        task += (
            "\nBefore you open the ticket, for each failed check read up to 3 of its failing rows "
            "from quarantine_complaints (column row_json; failed_tests names the check)."
        )
    state = RunState(agent="data_quality", task_text=task, trusted_context=task)
    for name, hook in (state_hooks or {}).items():
        setattr(state, name, hook)
    sandbox = SqlSandbox(case.tables, max_rows=20, cell_chars=1500)
    sinks = Sinks()
    spec = AgentSpec(
        "data_quality",
        SYSTEM,
        ("sql", "open_ticket", "final"),
        max_steps=12 if inspect_rows else 8,
        final_needs=("category",),
    )
    out = run_agent(spec, model, defense, state, sandbox, sinks, log, seed=seed)
    cat = out.final.category if out.final else None
    return DQResult(case, cat, list(sinks.tickets), out.final_flagged, out), state, sinks
