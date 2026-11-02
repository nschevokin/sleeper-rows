"""Local Apache Iceberg warehouse (PyIceberg, SQLite catalog, files on disk).

Why Iceberg on a laptop: every write is a snapshot, so we can time-travel to the exact
moment before a poisoned row landed and diff what it changed downstream.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

import polars as pl
import pyarrow as pa
from pyiceberg.catalog.sql import SqlCatalog
from pyiceberg.exceptions import NamespaceAlreadyExistsError, NoSuchTableError

NAMESPACE = "lake"


@dataclass(frozen=True)
class SnapshotInfo:
    snapshot_id: int
    committed_at: datetime
    operation: str


def _normalize(table: pa.Table) -> pa.Table:
    """Iceberg wants plain string/large_string, not string_view; timestamps in microseconds."""
    fields = []
    for f in table.schema:
        t = f.type
        if pa.types.is_string_view(t) or pa.types.is_string(t):
            t = pa.large_string()
        elif pa.types.is_timestamp(t):
            t = pa.timestamp("us")
        fields.append(pa.field(f.name, t, nullable=True))
    return table.cast(pa.schema(fields))


class Warehouse:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.catalog = SqlCatalog(
            "sleeper",
            uri=f"sqlite:///{self.root / 'catalog.db'}",
            warehouse=f"file://{self.root / 'data'}",
        )
        with contextlib.suppress(NamespaceAlreadyExistsError):
            self.catalog.create_namespace(NAMESPACE)

    def _ident(self, name: str) -> str:
        return f"{NAMESPACE}.{name}"

    def exists(self, name: str) -> bool:
        try:
            self.catalog.load_table(self._ident(name))
        except NoSuchTableError:
            return False
        return True

    def read(self, name: str, snapshot_id: int | None = None) -> pa.Table:
        tbl = self.catalog.load_table(self._ident(name))
        return tbl.scan(snapshot_id=snapshot_id).to_arrow()

    def write(
        self, name: str, data: pa.Table, mode: str = "overwrite", key: list[str] | None = None
    ) -> None:
        """mode: ``overwrite`` replaces the table, ``append`` adds rows, ``upsert`` merges on ``key``."""
        data = _normalize(data)
        ident = self._ident(name)
        if not self.exists(name):
            self.catalog.create_table(ident, schema=data.schema)
        tbl = self.catalog.load_table(ident)
        if mode == "overwrite" and tbl.current_snapshot() is not None:
            tbl.overwrite(data)
        elif mode == "overwrite" or mode == "append":
            tbl.append(data)
        elif mode == "upsert":
            if not key:
                raise ValueError("upsert needs key columns")
            tbl.upsert(data, join_cols=key)
        else:
            raise ValueError(f"unknown mode {mode!r}")

    def snapshots(self, name: str) -> list[SnapshotInfo]:
        tbl = self.catalog.load_table(self._ident(name))
        out = []
        for s in tbl.metadata.snapshots:
            op = s.summary.operation.value if s.summary else "unknown"
            out.append(
                SnapshotInfo(s.snapshot_id, datetime.fromtimestamp(s.timestamp_ms / 1000, UTC), op)
            )
        return out

    def count(self, name: str) -> int:
        return self.read(name).num_rows

    def names(self) -> list[str]:
        return sorted(t[1] for t in self.catalog.list_tables(NAMESPACE))


class Store(Protocol):
    """What landing, transforms and agents need from a warehouse."""

    def exists(self, name: str) -> bool: ...
    def read(self, name: str, snapshot_id: int | None = None) -> pa.Table: ...
    def write(
        self, name: str, data: pa.Table, mode: str = "overwrite", key: list[str] | None = None
    ) -> None: ...
    def count(self, name: str) -> int: ...
    def names(self) -> list[str]: ...


class MemoryWarehouse:
    """In-memory Store used for attack trials: cheap to clone, never touches the real warehouse.

    Arrow tables are immutable, so ``clone`` is a shallow dict copy.
    """

    def __init__(self, tables: dict[str, pa.Table] | None = None):
        self.tables: dict[str, pa.Table] = dict(tables or {})

    @classmethod
    def from_store(cls, store: Store, names: Iterable[str] | None = None) -> MemoryWarehouse:
        return cls({n: store.read(n) for n in (names if names is not None else store.names())})

    def clone(self) -> MemoryWarehouse:
        return MemoryWarehouse(self.tables)

    def exists(self, name: str) -> bool:
        return name in self.tables

    def read(self, name: str, snapshot_id: int | None = None) -> pa.Table:
        if snapshot_id is not None:
            raise NotImplementedError("MemoryWarehouse has no snapshots")
        return self.tables[name]

    def write(
        self, name: str, data: pa.Table, mode: str = "overwrite", key: list[str] | None = None
    ) -> None:
        data = _normalize(data)
        if mode == "overwrite" or name not in self.tables:
            self.tables[name] = data
        elif mode == "append":
            self.tables[name] = pa.concat_tables([self.tables[name], data])
        elif mode == "upsert":
            if not key:
                raise ValueError("upsert needs key columns")
            old = pl.from_arrow(self.tables[name])
            new = pl.from_arrow(data)
            assert isinstance(old, pl.DataFrame) and isinstance(new, pl.DataFrame)
            kept = old.join(new.select(key), on=key, how="anti")
            self.tables[name] = _normalize(
                pl.concat([kept, new], how="vertical_relaxed").to_arrow()
            )
        else:
            raise ValueError(f"unknown mode {mode!r}")

    def count(self, name: str) -> int:
        return self.tables[name].num_rows

    def names(self) -> list[str]:
        return sorted(self.tables)
