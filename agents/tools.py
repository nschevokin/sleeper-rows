"""Sandboxed tools. Nothing here can reach outside the process.

* ``SqlSandbox``  read-only DuckDB over in-memory Arrow tables: one SELECT, no file access.
* ``Sinks``       ``escalate`` and ``open_ticket`` write to lists; ``export_report`` posts to a
  local mock endpoint that only logs the call. "Unauthorized action" is measured against it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import duckdb
import pyarrow as pa
import sqlglot
from sqlglot import exp

_DENY_FUNCS = {
    "read_csv", "read_csv_auto", "read_parquet", "read_json", "read_text", "read_blob",
    "glob", "getenv", "sniff_csv", "iceberg_scan", "parquet_scan", "query", "query_table",
    "duckdb_secrets", "load_extension", "install_extension", "error",
}  # fmt: skip
_NUM = re.compile(r"-?\d[\d,]*\.?\d*")


@dataclass
class SqlResult:
    sql: str
    ok: bool
    columns: list[str] = field(default_factory=list)
    rows: list[tuple[Any, ...]] = field(default_factory=list)
    error: str | None = None
    truncated: bool = False

    def render(self) -> str:
        if not self.ok:
            return f"ERROR: {self.error}"
        lines = ["\t".join(self.columns)]
        lines += ["\t".join("" if v is None else str(v) for v in r) for r in self.rows]
        if self.truncated:
            lines.append("... (truncated)")
        return "\n".join(lines)

    def numbers(self) -> set[float]:
        """Every numeric cell, for the answer provenance check."""
        out: set[float] = set()
        for r in self.rows:
            for v in r:
                if isinstance(v, bool):
                    continue
                if (
                    isinstance(v, int | float)
                    or v is not None
                    and hasattr(v, "__float__")
                    and not isinstance(v, str)
                ):
                    out.add(float(v))
        return out


class SqlSandbox:
    def __init__(self, tables: dict[str, pa.Table], max_rows: int = 30, cell_chars: int = 300):
        self.tables = tables
        self.max_rows, self.cell_chars = max_rows, cell_chars

    def validate(self, sql: str) -> str | None:
        """Return an error message if the statement is not a single read-only SELECT."""
        try:
            stmts = sqlglot.parse(sql, read="duckdb")
        except sqlglot.errors.ParseError as exc:
            return f"syntax error: {str(exc).splitlines()[0]}"
        if len(stmts) != 1 or stmts[0] is None:
            return "exactly one statement is allowed"
        tree = stmts[0]
        if not isinstance(tree, exp.Select | exp.Union | exp.Subquery):
            return "only SELECT statements are allowed"
        for node in tree.find_all(exp.Anonymous, exp.Func):
            name = (node.name or node.sql_name() or "").lower()
            if name in _DENY_FUNCS:
                return f"function {name} is not allowed"
        for t in tree.find_all(exp.Table):
            if (
                t.name
                and t.name not in self.tables
                and t.name not in {c.alias_or_name for c in tree.find_all(exp.CTE)}
            ):
                return f"unknown table {t.name!r}; available: {', '.join(sorted(self.tables))}"
        return None

    def run(self, sql: str) -> SqlResult:
        err = self.validate(sql)
        if err:
            return SqlResult(sql, False, error=err)
        con = duckdb.connect(":memory:", config={"enable_external_access": False})
        try:
            for name, tbl in self.tables.items():
                con.register(name, tbl)
            con.execute("SET lock_configuration = true")
            cur = con.execute(sql)
            cols = [d[0] for d in cur.description]
            fetched = cur.fetchmany(self.max_rows + 1)
        except duckdb.Error as exc:
            return SqlResult(sql, False, error=str(exc).splitlines()[0])
        finally:
            con.close()
        truncated = len(fetched) > self.max_rows
        rows = [tuple(self._clip(v) for v in r) for r in fetched[: self.max_rows]]
        return SqlResult(sql, True, cols, rows, truncated=truncated)

    def _clip(self, v: Any) -> Any:
        if isinstance(v, str) and len(v) > self.cell_chars:
            return v[: self.cell_chars - 1] + "…"
        return v


@dataclass
class ToolCall:
    tool: str
    args: dict[str, Any]
    allowed: bool = True
    reason: str | None = None


@dataclass
class Sinks:
    """Local effects of the three action tools."""

    escalations: list[tuple[str, str]] = field(default_factory=list)
    tickets: list[str] = field(default_factory=list)
    exports: list[dict[str, Any]] = field(default_factory=list)
    calls: list[ToolCall] = field(default_factory=list)

    def escalate(self, group_id: str, reason: str) -> None:
        self.escalations.append((group_id, reason))

    def open_ticket(self, text: str) -> None:
        self.tickets.append(text)

    def export_report(self, dest: str, digest: str) -> None:
        # The mock endpoint: records the call, sends nothing anywhere.
        self.exports.append({"dest": dest, "digest": digest})


def extract_numbers(text: str) -> list[float]:
    """Numbers as a reader would see them: '1,234' is 1234; a trailing '.' is punctuation."""
    out = []
    for m in _NUM.findall(text):
        s = m.replace(",", "").rstrip(".")
        if s and s != "-":
            try:
                out.append(float(s))
            except ValueError:
                continue
    return out
