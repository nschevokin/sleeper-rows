"""Column-level taint over SQL: explicit value flow, selection (implicit) flow and row existence.

Design: docs/adr/0004-taint-guard-design.md (section 3). The resolver walks sqlglot scopes
itself because ``sqlglot.lineage`` loses table-function, EXISTS and ``count(*)`` dependencies.
It fails closed: anything it cannot analyse yields all-UNTRUSTED columns, never an exception.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import sqlglot
from sqlglot import exp
from sqlglot.optimizer.qualify import qualify
from sqlglot.optimizer.scope import Scope, build_scope

from taintguard.contracts import ContractError, ContractSet, Trust

Node = Any  # sqlglot 30 splits Expr/Expression; the tree is duck-typed here

T, S, U = Trust.TRUSTED, Trust.STRUCTURED, Trust.UNTRUSTED

CONCAT_AGGS = {
    "string_agg",
    "group_concat",
    "listagg",
    "list",
    "array_agg",
    "histogram",
    "array_concat_agg",
}
ALLOWED_TABLE_FUNCS = {"generate_series", "generateseries", "range", "unnest"}
_ARG_FUNCS = {"max_by", "min_by", "arg_max", "arg_min", "argmax", "argmin"}
# Meta columns every landed table carries (written by the ingest code, not by a source file).
META_TIERS: dict[str, Trust] = {
    "_key": S,
    "_row_hash": S,
    "_batch": T,
    "_source_file": T,
    "_ingested_at": T,
}


class LineageError(ValueError):
    """Raised at build time when pipeline SQL cannot be analysed (a silent fallback would hide it)."""


@dataclass(frozen=True)
class ColumnTaint:
    explicit: Trust = T  # value flow
    selection: Trust = T  # implicit flow: which rows / values were selected
    rows: Trust = T  # row-existence floor of the sources
    untrusted_sources: frozenset[str] = (
        frozenset()
    )  # base "table.column" leaves with explicit UNTRUSTED
    reasons: tuple[str, ...] = ()
    promoted_by: str | None = None

    @property
    def effective(self) -> Trust:
        return max(self.explicit, min(S, max(self.selection, self.rows)))

    @property
    def as_predicate(self) -> Trust:
        """Tier carried when this value is used to choose rows."""
        return max(self.explicit, self.selection, self.rows)

    def join(self, o: ColumnTaint) -> ColumnTaint:
        return ColumnTaint(
            max(self.explicit, o.explicit),
            max(self.selection, o.selection),
            max(self.rows, o.rows),
            self.untrusted_sources | o.untrusted_sources,
            self.reasons + tuple(r for r in o.reasons if r not in self.reasons),
        )


def fail(reason: str) -> ColumnTaint:
    return ColumnTaint(U, U, S, frozenset({"?"}), (reason,))


@dataclass
class TableTaint:
    columns: dict[str, ColumnTaint]  # lowercase names, ordered
    row_floor: Trust = S


@dataclass
class Catalog:
    tables: dict[str, TableTaint] = field(default_factory=dict)
    types: Mapping[str, Mapping[str, str]] | None = None

    def qualify_schema(self) -> dict[str, dict[str, str]]:
        out: dict[str, dict[str, str]] = {}
        for n, t in self.tables.items():
            known = {k.lower(): v for k, v in ((self.types or {}).get(n) or {}).items()}
            out[n] = {c: known.get(c, "VARCHAR") for c in t.columns}
        return out

    def subset(self, names: Sequence[str]) -> Catalog:
        keep = {n.lower() for n in names}
        return Catalog({n: t for n, t in self.tables.items() if n in keep}, self.types)


@dataclass(frozen=True)
class QueryTaint:
    columns: tuple[str, ...]
    taints: tuple[ColumnTaint, ...]
    canonical_sql: str | None
    touches_untrusted: bool
    failed: str | None
    exprs: tuple[Node | None, ...] = field(default=(), compare=False, repr=False)

    def tiers_for(self, n_result_columns: int) -> list[Trust]:
        if self.failed or n_result_columns != len(self.taints):
            return [U] * n_result_columns
        return [t.effective for t in self.taints]

    def sources_for(self, n_result_columns: int) -> list[frozenset[str]]:
        if self.failed or n_result_columns != len(self.taints):
            return [frozenset({"?"})] * n_result_columns
        return [t.untrusted_sources for t in self.taints]


# --------------------------------------------------------------------------------------------
# Validators: the only way a column may be declared lower than the SQL says it is.


def _type_is_text(dt: Node | None) -> bool:
    if dt is None or not isinstance(dt, exp.DataType):
        return True
    if dt.args.get("nested") or dt.expressions:
        return True
    return dt.this in {
        exp.DataType.Type.VARCHAR, exp.DataType.Type.TEXT, exp.DataType.Type.CHAR,
        exp.DataType.Type.NVARCHAR, exp.DataType.Type.NCHAR, exp.DataType.Type.BINARY,
        exp.DataType.Type.VARBINARY, exp.DataType.Type.JSON, exp.DataType.Type.JSONB,
        exp.DataType.Type.BLOB if hasattr(exp.DataType.Type, "BLOB") else exp.DataType.Type.BINARY,
        exp.DataType.Type.UNKNOWN, exp.DataType.Type.USERDEFINED,
    }  # fmt: skip


_PREDICATES = (
    exp.EQ,
    exp.NEQ,
    exp.GT,
    exp.GTE,
    exp.LT,
    exp.LTE,
    exp.Is,
    exp.Like,
    exp.ILike,
    exp.Between,
)


def _is_literal(n: Node) -> bool:
    return isinstance(n, exp.Literal | exp.Null | exp.Boolean)


def _is_predicate(n: Node) -> bool:
    if isinstance(n, exp.Paren):
        return _is_predicate(n.this)
    if isinstance(n, exp.Not):
        return _is_predicate(n.this)
    if isinstance(n, exp.And | exp.Or):
        return _is_predicate(n.left) and _is_predicate(n.right)
    if isinstance(n, exp.In):
        return not n.args.get("query") and all(_is_literal(e) for e in n.expressions)
    return isinstance(n, _PREDICATES)


def _typed_cast(n: Node) -> bool:
    while isinstance(n, exp.Alias | exp.Paren):
        n = n.this
    if isinstance(n, exp.Cast | exp.TryCast):
        return not _type_is_text(n.args.get("to"))
    if isinstance(n, exp.StrToTime | exp.StrToDate | exp.TsOrDsToDate):
        return True
    if _is_predicate(n):
        return True
    if isinstance(n, exp.Coalesce):
        return all(_typed_cast(a) or _is_literal(a) for a in [n.this, *n.expressions])
    if isinstance(n, exp.Case):
        results = [i.args["true"] for i in n.args.get("ifs", [])] + (
            [n.args["default"]] if n.args.get("default") else []
        )
        return bool(results) and all(_typed_cast(r) or _is_literal(r) for r in results)
    return False


def _literal_choice(n: Node) -> bool:
    while isinstance(n, exp.Alias | exp.Paren):
        n = n.this
    if isinstance(n, exp.Case):
        results = [i.args["true"] for i in n.args.get("ifs", [])] + (
            [n.args["default"]] if n.args.get("default") else []
        )
        return bool(results) and all(_is_literal(r) for r in results)
    if isinstance(n, exp.Coalesce):
        return all(_is_literal(a) for a in [n.this, *n.expressions])
    return False


VALIDATORS: dict[str, Callable[[Node], bool]] = {
    "typed_cast": _typed_cast,
    "literal_choice": _literal_choice,
}


# --------------------------------------------------------------------------------------------
# The resolver


def _fname(n: Node) -> str:
    if isinstance(n, exp.Anonymous):
        return str(n.name).lower()
    try:
        return n.sql_name().lower()
    except Exception:
        return type(n).__name__.lower()


def _leftmost(e: Node) -> Node:
    while isinstance(e, exp.SetOperation):
        e = e.left
    return e


class _Resolver:
    def __init__(self, catalog: Catalog) -> None:
        self.cat = catalog
        self.memo: dict[tuple[int, str], ColumnTaint] = {}

    # ---- scopes
    def output(self, scope: Scope, i: int) -> ColumnTaint:
        key = (id(scope.expression), f"o{i}")
        if key in self.memo:
            return self.memo[key]
        e: Any = scope.expression
        if isinstance(e, exp.SetOperation):
            res = ColumnTaint()
            for b in scope.set_operation_scopes:
                res = res.join(self.output(b, i))
        else:
            res = self.expr(scope, e.selects[i]).join(self.context(scope))
        self.memo[key] = res
        return res

    def context(self, scope: Scope) -> ColumnTaint:
        key = (id(scope.expression), "ctx")
        if key in self.memo:
            return self.memo[key]
        self.memo[key] = ColumnTaint()  # cycle guard
        e: Any = scope.expression
        if isinstance(e, exp.SetOperation):
            res = ColumnTaint()
            for b in scope.set_operation_scopes:
                res = res.join(self.context(b))
            self.memo[key] = res
            return res
        nodes: list[Node] = []
        for j in e.args.get("joins") or []:
            if j.args.get("on") is not None:
                nodes.append(j.args["on"])
            nodes.extend(j.args.get("using") or [])
        for k in ("where", "having", "qualify"):
            if e.args.get(k) is not None:
                nodes.append(e.args[k])
        g = e.args.get("group")
        if g is not None:
            if g.args.get("all"):
                nodes.extend(s for s in e.selects if not s.find(exp.AggFunc))
            else:
                nodes.append(g)
        o = e.args.get("order")
        if o is not None and (e.args.get("limit") is not None or e.args.get("offset") is not None):
            nodes.extend(e.selects if o.args.get("all") else [o])
        if e.args.get("distinct") is not None:
            nodes.extend(e.selects)
        sel = T
        for n in nodes:
            sel = max(sel, self.expr(scope, n).as_predicate)
        rows = T
        for src in scope.sources.values():
            if isinstance(src, exp.Table):
                if isinstance(src.this, exp.Func):
                    t = self.expr(scope, src.this)
                    rows = max(rows, min(S, t.as_predicate))
                else:
                    tt = self.cat.tables.get(src.name.lower())
                    rows = max(rows, tt.row_floor if tt else S)
            else:
                c = self.context(src)
                rows, sel = max(rows, c.rows), max(sel, c.selection)
        res = ColumnTaint(T, sel, rows)
        self.memo[key] = res
        return res

    # ---- columns
    def column(self, scope: Scope, col: exp.Column) -> ColumnTaint:
        name, tbl = col.name.lower(), col.table
        s: Scope | None = scope
        found: Scope | None = None
        while s is not None:
            if tbl and tbl in s.sources:
                found = s
                break
            if not tbl:
                hits = [
                    n for n, src in s.sources.items()
                    if isinstance(src, Scope) and name in [x.alias_or_name.lower() for x in _leftmost(src.expression).selects]
                ]  # fmt: skip
                if len(hits) == 1:
                    tbl, found = hits[0], s
                    break
                if len(hits) > 1:
                    return fail(f"ambiguous column {name}")
            s = s.parent
        if found is None or not tbl:
            return fail(f"unresolved column {col.sql()}")
        src = found.sources[tbl]
        if isinstance(src, exp.Table):
            if isinstance(src.this, exp.Func):
                return self.expr(found, src.this)
            tt = self.cat.tables.get(src.name.lower())
            if tt is None:
                return fail(f"unknown table {src.name}")
            ct = tt.columns.get(name)
            return ct if ct is not None else fail(f"unknown column {src.name}.{name}")
        e = src.expression
        if src.is_udtf or isinstance(e, exp.Unnest):
            return self.expr(found, e)
        names = [x.alias_or_name.lower() for x in _leftmost(e).selects]
        if name not in names:
            return fail(f"unknown column {tbl}.{name}")
        return self.output(src, names.index(name))

    # ---- expressions (never descend into nested SELECTs; those are handled as scopes)
    def _sub(self, scope: Scope, select: Node) -> Scope | None:
        for sc in scope.subquery_scopes:
            if sc.expression is select:
                return sc
        return None

    def _subquery(self, scope: Scope, node: Node) -> ColumnTaint | None:
        inner = node.this if isinstance(node, exp.Subquery | exp.Exists) else node
        while isinstance(inner, exp.Subquery):
            inner = inner.this
        sc = self._sub(scope, inner)
        if sc is None:
            return fail("subquery scope not found")
        n_out = len(_leftmost(sc.expression).selects)
        outs = [self.output(sc, i) for i in range(n_out)]
        return ColumnTaint() if not outs else outs[0] if len(outs) == 1 else _join_all(outs)

    def expr(self, scope: Scope, node: Node | None) -> ColumnTaint:
        if node is None:
            return ColumnTaint()
        if isinstance(node, exp.Column):
            return self.column(scope, node)
        if isinstance(node, exp.Exists) or (
            isinstance(node, exp.In) and node.args.get("query") is not None
        ):
            inner = node.this if isinstance(node, exp.Exists) else node.args["query"]
            st = self._subquery(scope, inner)
            assert st is not None
            ctx = self._ctx_of(scope, inner)
            pred = max(st.as_predicate, ctx.as_predicate)
            # a boolean has a bounded form, so an implicit flow can reach structured at most
            res = ColumnTaint(min(S, pred), T, T, frozenset(), st.reasons)
            if isinstance(node, exp.In):
                res = res.join(self.expr(scope, node.this))
            return res
        if isinstance(node, exp.Subquery | exp.Select | exp.SetOperation):
            st = self._subquery(scope, node)
            assert st is not None
            return st
        if isinstance(node, exp.Window):
            res = self.expr(scope, node.this)
            for k in ("partition_by", "order"):
                v = node.args.get(k)
                for x in v if isinstance(v, list) else [v]:
                    if x is not None:
                        res = res.join(ColumnTaint(T, self.expr(scope, x).as_predicate, T))
            return res
        if isinstance(node, exp.Filter):
            return self.expr(scope, node.this).join(
                ColumnTaint(T, self.expr(scope, node.expression).as_predicate, T)
            )
        if isinstance(node, exp.ArgMax | exp.ArgMin) or (
            isinstance(node, exp.Anonymous) and _fname(node) in _ARG_FUNCS
        ):
            args = (
                [node.this, node.expression]
                if not isinstance(node, exp.Anonymous)
                else list(node.expressions)
            )
            res = self.expr(scope, args[0])
            for a in args[1:]:
                res = res.join(ColumnTaint(T, self.expr(scope, a).as_predicate, T))
            return res
        res = ColumnTaint()
        for child in node.iter_expressions():
            res = res.join(self.expr(scope, child))
        concat = (isinstance(node, exp.Func) and _fname(node) in CONCAT_AGGS) or isinstance(
            node, exp.ArrayAgg | exp.GroupConcat
        )
        if concat and res.effective >= S:
            res = res.join(
                ColumnTaint(U, T, T, res.untrusted_sources, ("unbounded concatenation",))
            )
        return res

    def _ctx_of(self, scope: Scope, select: Node) -> ColumnTaint:
        while isinstance(select, exp.Subquery):
            select = select.this
        sc = self._sub(scope, select)
        return self.context(sc) if sc else fail("subquery scope not found")


def _join_all(xs: Sequence[ColumnTaint]) -> ColumnTaint:
    out = ColumnTaint()
    for x in xs:
        out = out.join(x)
    return out


_DENY_NODES = ("Lateral", "Pivot", "Columns", "Placeholder", "Parameter", "MatchRecognize")


def _deny_pass(tree: Node, root: Scope, catalog: Catalog) -> None:
    for name in _DENY_NODES:
        cls = getattr(exp, name, None)
        if cls is not None and tree.find(cls) is not None:
            raise LineageError(name.lower())
    w = tree.find(exp.With)
    if w is not None and w.args.get("recursive"):
        raise LineageError("recursive")
    for star in tree.find_all(exp.Star):
        if star.find_ancestor(exp.AggFunc) is None:
            raise LineageError("star")
    for sc in root.traverse():
        for src in sc.sources.values():
            if isinstance(src, exp.Table):
                if isinstance(src.this, exp.Func):
                    if _fname(src.this) not in ALLOWED_TABLE_FUNCS:
                        raise LineageError("table_function")
                elif src.name.lower() not in catalog.tables:
                    raise LineageError("unknown_table")


def _failed(reason: str, n_cols: int = 1) -> QueryTaint:
    return QueryTaint(("*",) * n_cols, (fail(reason),) * n_cols, None, True, reason)


def analyze_query(sql: str, catalog: Catalog) -> QueryTaint:
    """Taint of every output column of ``sql``. Never raises: failure means all columns UNTRUSTED."""
    try:
        stmts = sqlglot.parse(sql, read="duckdb")
        if len(stmts) != 1 or stmts[0] is None:
            return _failed("parse: exactly one statement")
        tree: Node = stmts[0]
        while isinstance(tree, exp.Subquery):
            tree = tree.this
        if not isinstance(tree, exp.Select | exp.SetOperation):
            return _failed("parse: not a SELECT")
        ctes = {c.alias_or_name.lower() for c in tree.find_all(exp.CTE)}
        for t in tree.find_all(exp.Table):
            if (
                not isinstance(t.this, exp.Func)
                and t.name
                and t.name.lower() not in catalog.tables | dict.fromkeys(ctes)
            ):
                return _failed("unknown_table")
        schema: Any = catalog.qualify_schema()
        tree = qualify(
            tree,
            schema=schema,
            dialect="duckdb",
            validate_qualify_columns=True,
            quote_identifiers=True,
        )
        root = build_scope(tree)
        if root is None:
            return _failed("internal: no scope")
        _deny_pass(tree, root, catalog)
        res = _Resolver(catalog)
        first = _leftmost(tree)
        names = tuple(s.alias_or_name or f"_col_{i}" for i, s in enumerate(first.selects))
        taints = tuple(res.output(root, i) for i in range(len(names)))
        exprs = tuple(first.selects) if isinstance(tree, exp.Select) else (None,) * len(names)
        touches = _touches_untrusted(tree, root, res)
        return QueryTaint(names, taints, tree.sql(dialect="duckdb"), touches, None, exprs)
    except LineageError as exc:
        return _failed(f"{exc}")
    except Exception as exc:  # parse/optimizer errors, recursion, anything unexpected
        return _failed(f"{type(exc).__name__}")


def _touches_untrusted(tree: Node, root: Scope, res: _Resolver) -> bool:
    for sc in root.traverse():
        for col in sc.columns:
            if res.column(sc, col).explicit >= U:
                return True
    return False


# --------------------------------------------------------------------------------------------
# Building the pipeline catalog


def _seed(contracts: ContractSet) -> Catalog:
    cat = Catalog()
    for m in contracts.models.values():
        if m.sql is not None or m.llm_derived:
            continue
        cols: dict[str, ColumnTaint] = {}
        for c in m.columns:
            if c.pii:
                continue
            src = frozenset({f"{m.name}.{c.name.lower()}"}) if c.tier is U else frozenset()
            cols[c.name.lower()] = ColumnTaint(c.tier, T, T, src)
        if m.source is not None:
            for n, tier in META_TIERS.items():
                cols.setdefault(n, ColumnTaint(tier, T, T))
        cat.tables[m.name.lower()] = TableTaint(cols, m.floor)
    return cat


def _apply_contract(contracts: ContractSet, name: str, q: QueryTaint) -> TableTaint:
    spec = contracts.model_ci(name)
    cols: dict[str, ColumnTaint] = {}
    for i, (cn, t) in enumerate(zip(q.columns, q.taints, strict=True)):
        cs = spec.column_ci(cn) if spec else None
        if cs is not None:
            declared = cs.tier
            if declared < t.effective:
                vname = cs.validated_by
                if vname is None:
                    raise ContractError(
                        f"{name}.{cn}: declared {declared.label} but computed {t.effective.label}"
                    )
                v = VALIDATORS.get(vname)
                if v is None:
                    raise ContractError(f"{name}.{cn}: unknown validator {vname!r}")
                node = q.exprs[i] if i < len(q.exprs) else None
                if node is None or not v(node):
                    raise ContractError(
                        f"{name}.{cn}: validated_by={vname} does not match expression {node.sql() if node else '?'}"
                    )
                t = ColumnTaint(
                    min(t.explicit, S),
                    t.selection,
                    t.rows,
                    frozenset(),
                    (*t.reasons, f"promoted by {vname}"),
                    vname,
                )
                if t.effective > declared:
                    raise ContractError(f"{name}.{cn}: a promotion cannot reach {declared.label}")
        cols[cn.lower()] = t
    floor = max((t.rows for t in q.taints), default=S)
    if spec is not None and spec.row_floor:
        floor = max(floor, spec.floor)
    return TableTaint(cols, floor)


def _apply_llm_model(contracts: ContractSet, name: str, cat: Catalog) -> TableTaint:
    spec = contracts.model_ci(name)
    if spec is None or not spec.llm_derived:
        raise ContractError(f"{name}: not an llm_derived contract model")
    cols: dict[str, ColumnTaint] = {}
    for c in spec.columns:
        if c.derived_from:
            sm, _, sc = c.derived_from.partition(".")
            up = cat.tables.get(sm.lower(), TableTaint({})).columns.get(sc.lower())
            if up is None:
                raise ContractError(
                    f"{name}.{c.name}: derived_from {c.derived_from!r} not in catalog"
                )
            if c.tier < up.effective:
                raise ContractError(
                    f"{name}.{c.name}: declared {c.trust} below upstream {up.effective.label}"
                )
            cols[c.name.lower()] = ColumnTaint(
                max(c.tier, up.explicit), up.selection, up.rows, up.untrusted_sources
            )
        else:
            src = frozenset({f"{spec.name}.{c.name.lower()}"}) if c.tier is U else frozenset()
            cols[c.name.lower()] = ColumnTaint(c.tier, T, T, src)
    return TableTaint(cols, spec.floor)


def build_catalog(
    contracts: ContractSet,
    steps: Sequence[str | tuple[str, str]],
    *,
    types: Mapping[str, Mapping[str, str]] | None = None,
) -> Catalog:
    """Seed with landing/reference/python models, then add each step in pipeline order.

    A ``str`` step names an ``llm_derived`` contract model; a ``(name, sql)`` step is analysed.
    Pipeline SQL that cannot be analysed is a build-time ``LineageError``.
    """
    cat = _seed(contracts)
    cat.types = types
    for step in steps:
        if isinstance(step, str):
            cat.tables[step.lower()] = _apply_llm_model(contracts, step, cat)
            continue
        name, sql = step
        q = analyze_query(sql, cat)
        if q.failed:
            raise LineageError(f"{name}: pipeline SQL cannot be analysed ({q.failed})")
        cat.tables[name.lower()] = _apply_contract(contracts, name, q)
    return cat


def explain(
    cat: Catalog, table: str
) -> dict[str, Any]:  # small helper for reports and the Observatory
    t = cat.tables[table.lower()]
    return {
        c: {
            "explicit": v.explicit.label, "selection": v.selection.label, "rows": v.rows.label,
            "effective": v.effective.label, "sources": sorted(v.untrusted_sources),
        }
        for c, v in t.columns.items()
    }  # fmt: skip
