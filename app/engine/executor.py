"""Execution engine: pruning planner + local replay executor.

Every number the UI calls *measured* comes from this module actually reading
files.  Every number it calls *estimated* comes from ``plan_only`` which never
touches the lake.  The two are kept structurally separate so an estimate can
never be mistaken for a benefit that was observed.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

from .. import store
from ..engine import lake
from . import sqlparse_lite as sql


class ExecError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Comparison helpers
# ---------------------------------------------------------------------------


def _coerce_pair(a: Any, b: Any) -> tuple[Any, Any]:
    if isinstance(a, str) and isinstance(b, (int, float)):
        try:
            return float(a), float(b)
        except ValueError:
            return a, str(b)
    if isinstance(b, str) and isinstance(a, (int, float)):
        try:
            return float(a), float(b)
        except ValueError:
            return str(a), b
    return a, b


def _cmp(a: Any, b: Any) -> int | None:
    if a is None or b is None:
        return None
    a, b = _coerce_pair(a, b)
    try:
        return -1 if a < b else (1 if a > b else 0)
    except TypeError:
        return None


def _month(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v)
    return s[:7] if len(s) >= 7 else s


def _year(v: Any) -> int | None:
    if v is None:
        return None
    try:
        return int(str(v)[:4])
    except ValueError:
        return None


def apply_scalar_func(name: str, args: list[Any]) -> Any:
    if name == "year":
        return _year(args[0])
    if name == "month":
        return _month(args[0])
    if name == "lower":
        return str(args[0]).lower() if args[0] is not None else None
    if name == "upper":
        return str(args[0]).upper() if args[0] is not None else None
    if name == "substr":
        s = args[0]
        if s is None:
            return None
        start = int(args[1]) if len(args) > 1 else 1
        length = int(args[2]) if len(args) > 2 else len(str(s))
        s = str(s)
        # 1-based, like the usual SQL substr
        return s[start - 1: start - 1 + length]
    raise ExecError(f"unsupported function {name}")


# ---------------------------------------------------------------------------
# Predicate evaluation
# ---------------------------------------------------------------------------


def _like_regex(pattern: str) -> re.Pattern[str]:
    out = []
    for ch in pattern:
        if ch == "%":
            out.append(".*")
        elif ch == "_":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return re.compile("".join(out) + r"\Z", re.DOTALL)


def eval_expr(node: sql.Node, row: dict[str, Any], agg_ctx: dict | None = None) -> Any:
    if isinstance(node, sql.Column):
        if agg_ctx is not None and node.name in agg_ctx:
            return agg_ctx[node.name]
        if node.name not in row:
            raise ExecError(f"unknown column {node.name!r}")
        return row[node.name]
    if isinstance(node, sql.Literal):
        return node.value
    if isinstance(node, sql.Star):
        raise ExecError("* is not a value expression")
    if isinstance(node, sql.Func):
        if node.is_aggregate:
            if agg_ctx is None:
                raise ExecError(f"aggregate {node.name}() without grouping context")
            key = sql.format_expr(node)
            if key not in agg_ctx:
                raise ExecError(f"aggregate {key} was not computed")
            return agg_ctx[key]
        args = [eval_expr(a, row, agg_ctx) for a in node.args]
        return apply_scalar_func(node.name, args)
    if isinstance(node, sql.BinaryOp):
        if node.op == "and":
            return bool(eval_expr(node.left, row, agg_ctx)) and bool(eval_expr(node.right, row, agg_ctx))
        if node.op == "or":
            return bool(eval_expr(node.left, row, agg_ctx)) or bool(eval_expr(node.right, row, agg_ctx))
        left = eval_expr(node.left, row, agg_ctx)
        right = eval_expr(node.right, row, agg_ctx)
        if node.op == "like":
            if left is None or right is None:
                return False
            return bool(_like_regex(str(right)).match(str(left)))
        c = _cmp(left, right)
        if c is None:
            return False
        return {
            "=": c == 0, "<>": c != 0, "!=": c != 0,
            "<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0,
        }[node.op]
    if isinstance(node, sql.NotOp):
        return not bool(eval_expr(node.expr, row, agg_ctx))
    if isinstance(node, sql.Between):
        v = eval_expr(node.expr, row, agg_ctx)
        lo = eval_expr(node.low, row, agg_ctx)
        hi = eval_expr(node.high, row, agg_ctx)
        c1, c2 = _cmp(v, lo), _cmp(v, hi)
        return c1 is not None and c2 is not None and c1 >= 0 and c2 <= 0
    if isinstance(node, sql.InList):
        v = eval_expr(node.expr, row, agg_ctx)
        values = [eval_expr(x, row, agg_ctx) for x in node.values]
        hit = any(_cmp(v, x) == 0 for x in values if v is not None)
        return (not hit) if node.negated else hit
    raise ExecError(f"cannot evaluate {type(node).__name__}")


# ---------------------------------------------------------------------------
# Pruning
# ---------------------------------------------------------------------------


@dataclass
class PruneResult:
    kept: list[dict[str, Any]]
    pruned: list[dict[str, Any]]
    decisions: list[dict[str, Any]]
    partition_values: dict[str, list[str]] = field(default_factory=dict)


def _partition_bounds(select: sql.Select) -> dict[str, dict[str, Any]]:
    """Extract constraints usable for partition pruning, per partition column."""
    out: dict[str, dict[str, Any]] = {}
    for col, node in select.equalities():
        out.setdefault(col, {"eq": [], "ranges": [], "in": None})
        if isinstance(node, sql.InList):
            out[col]["in"] = [v.value for v in node.values if isinstance(v, sql.Literal)]
        else:
            vals = sql.literal_values(node)
            if len(vals) == 1:
                out[col]["eq"].append(vals[0])
    for col, op, node in select.ranges():
        vals = sql.literal_values(node)
        if len(vals) == 1:
            out.setdefault(col, {"eq": [], "ranges": [], "in": None})
            out[col]["ranges"].append((op, vals[0]))
    return out


def _partition_key_match(part_col: str, part_value: Any, constraint: dict[str, Any]) -> bool:
    values: list[Any] = []
    if constraint.get("in") is not None:
        values = list(constraint["in"])
    elif constraint.get("eq"):
        values = list(constraint["eq"])
    if values:
        return any(_cmp(part_value, v) == 0 for v in values)
    for op, v in constraint.get("ranges", []):
        c = _cmp(part_value, v)
        if c is None:
            return True
        ok = {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0}[op]
        if not ok:
            return False
    return True


def _zone_map_can_match(stats: dict[str, Any], constraints: dict[str, Any]) -> bool:
    lo, hi = stats.get("min"), stats.get("max")
    if lo is None and hi is None:
        return True
    if constraints.get("in") is not None:
        return any(
            _cmp(lo, v) in (None, -1, 0) and _cmp(hi, v) in (None, 0, 1)
            for v in constraints["in"]
        )
    for v in constraints.get("eq", []):
        if _cmp(v, lo) == -1 or _cmp(v, hi) == 1:
            return False
    for op, v in constraints.get("ranges", []):
        if op in ("<", "<="):
            if _cmp(lo, v) in (0, 1):
                return False
        elif op in (">", ">="):
            if _cmp(hi, v) in (-1, 0):
                return False
    return True


def prune_files(
    files: list[dict[str, Any]],
    select: sql.Select,
    table: dict[str, Any],
) -> PruneResult:
    partition_cols = table.get("partition_cols") or []
    constraints = _partition_bounds(select)

    # Map derived partition keys (month:order_time) onto their source column.
    mapped: dict[str, tuple[str, str | None]] = {}
    for pc in partition_cols:
        if ":" in pc:
            kind, src = pc.split(":", 1)
            mapped[pc] = (src, kind)
        else:
            mapped[pc] = (pc, None)

    kept, pruned, decisions = [], [], []
    for f in files:
        reason = None
        detail: dict[str, Any] = {}
        part = f.get("partition") or {}
        for pc, (src, kind) in mapped.items():
            if pc not in part:
                continue
            pv = part[pc]
            cons = constraints.get(src)
            if not cons:
                continue
            cmp_value = _month(pv) if kind == "month" else pv
            # Month partitions need the constraint expressed in months.
            if kind == "month":
                cons = {
                    "eq": [_month(v) for v in cons.get("eq", [])],
                    "in": [_month(v) for v in cons["in"]] if cons.get("in") is not None else None,
                    "ranges": [(op, _month(v)) for op, v in cons.get("ranges", [])],
                }
            if not _partition_key_match(pc, cmp_value, cons):
                reason = "partition"
                detail = {"partition_column": pc, "partition_value": pv}
                break

        if reason is None and select.where is not None:
            conjuncts = sql._split_and(select.where)
            stats = f.get("stats") or {}
            for c in conjuncts:
                colname, cons = _constraint_for_conjunct(c)
                if colname is None:
                    continue
                entry = stats.get(colname)
                if not entry:
                    continue
                if not _zone_map_can_match(entry, cons):
                    reason = "zone_map"
                    detail = {
                        "column": colname,
                        "file_min": entry.get("min"),
                        "file_max": entry.get("max"),
                    }
                    break

        if reason:
            pruned.append(f)
            decisions.append({"file": f["rel_path"], "pruned": True, "reason": reason, **detail})
        else:
            kept.append(f)

    return PruneResult(kept=kept, pruned=pruned, decisions=decisions)


def _constraint_for_conjunct(node: sql.Node) -> tuple[str | None, dict[str, Any] | None]:
    if isinstance(node, sql.BinaryOp) and node.op == "=":
        if isinstance(node.left, sql.Column) and not isinstance(node.right, sql.Column):
            vals = sql.literal_values(node.right)
            return node.left.name, {"eq": vals} if len(vals) == 1 else None
        if isinstance(node.right, sql.Column) and not isinstance(node.left, sql.Column):
            vals = sql.literal_values(node.left)
            return node.right.name, {"eq": vals} if len(vals) == 1 else None
    if isinstance(node, sql.BinaryOp) and node.op in {"<", "<=", ">", ">="}:
        if isinstance(node.left, sql.Column) and not isinstance(node.right, sql.Column):
            vals = sql.literal_values(node.right)
            return node.left.name, {"ranges": [(node.op, vals[0])]} if len(vals) == 1 else None
        if isinstance(node.right, sql.Column) and not isinstance(node.left, sql.Column):
            flip = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}[node.op]
            vals = sql.literal_values(node.left)
            return node.right.name, {"ranges": [(flip, vals[0])]} if len(vals) == 1 else None
    if isinstance(node, sql.Between) and isinstance(node.expr, sql.Column):
        return node.expr.name, {"ranges": [(">=", node.low.value), ("<=", node.high.value)]}
    if isinstance(node, sql.InList) and not node.negated and isinstance(node.expr, sql.Column):
        return node.expr.name, {"in": [v.value for v in node.values if isinstance(v, sql.Literal)]}
    # Function predicates (year(col)=2024 / month(col) >= '2024-01') prune on f(min)/f(max)
    if isinstance(node, sql.BinaryOp) and node.op in {"=", "<", "<=", ">", ">="}:
        if isinstance(node.left, sql.Func) and node.left.name in {"year", "month"} and node.left.args:
            col = node.left.args[0]
            if isinstance(col, sql.Column):
                vals = sql.literal_values(node.right)
                if len(vals) == 1:
                    key = node.op if node.op != "=" else "eq_func"
                    return f"__func__:{node.left.name}:{col.name}", {key: [vals[0]]}
    return None, None


def _zone_stats_for_file(f: dict[str, Any], key: str) -> dict[str, Any] | None:
    if not key.startswith("__func__:"):
        return (f.get("stats") or {}).get(key)
    _, fn, col = key.split(":", 2)
    entry = (f.get("stats") or {}).get(col)
    if not entry:
        return None
    lo, hi = entry.get("min"), entry.get("max")
    if lo is None or hi is None:
        return entry
    transform = _month if fn == "month" else _year
    return {"min": transform(lo), "max": transform(hi), "nulls": entry.get("nulls", 0)}


def zone_prune_functions(files: list[dict[str, Any]], select: sql.Select) -> list[dict[str, Any]]:
    """Prune files whose zone maps exclude a function predicate like year(ts)=2024."""
    if select.where is None:
        return files
    kept = []
    for f in files:
        ok = True
        for c in sql._split_and(select.where):
            key, cons = _constraint_for_conjunct(c)
            if key is None or not key.startswith("__func__:"):
                continue
            stats = _zone_stats_for_file(f, key)
            if stats is None:
                continue
            if cons and "eq_func" in cons:
                cons = {"eq": cons["eq_func"]}
            if not _zone_map_can_match(stats, cons or {}):
                ok = False
                break
        if ok:
            kept.append(f)
    return kept


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


@dataclass
class ExecResult:
    columns: list[str]
    rows: list[dict[str, Any]]
    metrics: dict[str, Any]
    plan: dict[str, Any]
    error: str | None = None


def execute(
    conn,
    select: sql.Select,
    *,
    files_override: list[dict[str, Any]] | None = None,
    collect_rows: bool = True,
    max_result_rows: int = 500,
) -> ExecResult:
    started = time.perf_counter()
    table = store.table_row(conn, select.table)
    if table is None:
        raise ExecError(f"unknown table {select.table!r}")
    files = files_override if files_override is not None else store.file_rows(conn, select.table)
    _validate_columns(select, table)

    pruned = prune_files(files, select, table)
    kept = pruned.kept
    # Function-based pruning needs stats that may be absent from partition-pruned
    # candidate list; apply on the survivors.
    kept = zone_prune_functions(kept, select)

    if select.order_by and select.order_by == tuple(table.get("sort_keys") or ()) and select.limit:
        # Files are already ordered by sort key; stable scan order allows early exit.
        kept = sorted(kept, key=lambda f: str((f.get("stats") or {}).get(select.order_by[0], {}).get("min") or ""))

    scanned_bytes = 0
    scanned_rows = 0
    matched_rows = 0
    agg_calls = select.aggregate_calls()
    group_cols = list(select.group_by)
    groups: dict[tuple, dict[str, Any]] = {}
    out_rows: list[dict[str, Any]] = []
    early_stop = False
    limit_stop = False

    needs_grouping = select.has_aggregation()
    # A LIMIT can stop the scan early only when the requested order is already
    # the physical sort order, so the first N matching rows are the answer.
    sort_prefix_ok = bool(
        select.order_by
        and select.limit is not None
        and select.order_by == tuple(table.get("sort_keys") or ())
        and all(isinstance(c, str) for c in select.order_by)
    )

    for f in kept:
        scanned_bytes += int(f["bytes"])
        rows = lake.read_rows(select.table, f["rel_path"])
        scanned_rows += len(rows)
        for row in rows:
            if select.where is not None and not eval_expr(select.where, row):
                continue
            matched_rows += 1
            if needs_grouping:
                key = tuple(row.get(c) for c in group_cols)
                acc = groups.get(key)
                if acc is None:
                    acc = _new_accumulator(agg_calls)
                    groups[key] = acc
                _accumulate(acc, agg_calls, row)
                continue
            if collect_rows and len(out_rows) < max_result_rows:
                out_rows.append({c: row.get(c) for c in _plain_columns(select)})
            elif not collect_rows:
                out_rows.append({})
            if collect_rows and not select.order_by and select.limit is not None and len(out_rows) >= select.limit:
                # Unsorted top-N is complete once N rows survive.
                early_stop = True
                break
        if early_stop:
            break
        if (
            sort_prefix_ok
            and not needs_grouping
            and len(out_rows) >= select.limit
        ):
            early_stop = True
            break

    if needs_grouping:
        if not groups and not group_cols and agg_calls:
            # Aggregate with no GROUP BY always returns one row, even on zero input.
            ctx = {}
            for call in agg_calls:
                ctx[sql.format_expr(call)] = _empty_agg(call)
            out_rows.append(
                {item.alias or sql.format_expr(item.expr): _eval_group_item(item.expr, {}, ctx, {})
                 for item in select.items}
            )
            groups = {}
        for key, acc in groups.items():
            ctx = {}
            for call in agg_calls:
                ctx[sql.format_expr(call)] = _finish_agg(call, acc)
            if group_cols:
                row_ctx = {c: v for c, v in zip(group_cols, key)}
            else:
                row_ctx = {}
            out = {}
            for item in select.items:
                label = item.alias or sql.format_expr(item.expr)
                out[label] = _eval_group_item(item.expr, row_ctx, ctx, acc)
            out_rows.append(out)
        if select.order_by:
            sort_cols = list(select.order_by)
            out_rows.sort(
                key=lambda r: tuple((r.get(c) is None, _sort_val(r.get(c))) for c in sort_cols)
            )
        if select.limit is not None:
            out_rows = out_rows[: select.limit]
    else:
        for item in select.items:
            label = item.alias or sql.format_expr(item.expr)
            if isinstance(item.expr, sql.Column) and select.order_by == (item.expr.name,):
                out_rows.sort(key=lambda r: (r.get(label) is None, _sort_val(r.get(label))))
        if select.limit is not None:
            out_rows = out_rows[: select.limit]

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    result_bytes = sum(len(json.dumps(r, ensure_ascii=False)) for r in out_rows)

    plan = {
        "table": select.table,
        "files_total": len(files),
        "files_scanned": len(kept),
        "files_pruned": len(files) - len(kept),
        "prune_reasons": _summarize_reasons(pruned.decisions, files, kept),
        "steps": [
            {"step": "scan", "detail": f"{len(files)} candidate files"},
            {
                "step": "partition prune",
                "detail": f"{len(files) - len(kept) - _count_zone(pruned.decisions)} files removed",
            },
            {"step": "zone map prune", "detail": f"{_count_zone(pruned.decisions)} files removed"},
            {"step": "filter", "detail": f"{matched_rows} rows matched"},
        ],
        "group_by": list(select.group_by),
        "aggregates": [sql.format_expr(c) for c in agg_calls],
        "order_by": list(select.order_by),
        "limit": select.limit,
        "early_stop": early_stop,
        "columns": list(select.columns_used()),
    }

    metrics = {
        "duration_ms": round(elapsed_ms, 3),
        "bytes_scanned": scanned_bytes,
        "rows_scanned": scanned_rows,
        "rows_matched": matched_rows,
        "rows_returned": len(out_rows) if not needs_grouping else len(groups),
        "result_bytes": result_bytes,
        "files_scanned": len(kept),
        "files_total": len(files),
        "files_pruned": len(files) - len(kept),
    }
    return ExecResult(
        columns=[i.alias or sql.format_expr(i.expr) for i in select.items],
        rows=out_rows,
        metrics=metrics,
        plan=plan,
    )


def _plain_columns(select: sql.Select) -> list[str]:
    cols = []
    for item in select.items:
        if isinstance(item.expr, sql.Column):
            cols.append(item.expr.name)
        elif isinstance(item.expr, sql.Func) and not item.expr.is_aggregate:
            cols.append(item.alias or sql.format_expr(item.expr))
    return cols


def _validate_columns(select: sql.Select, table: dict[str, Any]) -> None:
    known = {c["name"] for c in (table.get("columns") or [])}
    if not known:
        return
    used = select.columns_used()
    unknown = sorted(c for c in used if c not in known)
    if unknown:
        raise ExecError(
            f"unknown column(s) {', '.join(unknown)} on table {table['name']}; "
            f"available: {', '.join(sorted(known))}"
        )


def _empty_agg(call: sql.Func) -> Any:
    if call.name == "count":
        return 0
    return None


def _sort_val(v: Any):
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return (0, v)
    return (1, str(v))


def _new_accumulator(calls: list[sql.Func]) -> dict[str, Any]:
    return {"__rows__": 0, "__acc__": {sql.format_expr(c): {"n": 0, "sum": 0, "min": None, "max": None, "vals": set()} for c in calls}}


def _accumulate(acc: dict[str, Any], calls: list[sql.Func], row: dict[str, Any]) -> None:
    acc["__rows__"] += 1
    for call in calls:
        slot = acc["__acc__"][sql.format_expr(call)]
        if call.name == "count" and (not call.args or isinstance(call.args[0], sql.Star)):
            slot["n"] += 1
            continue
        val = eval_expr(call.args[0], row) if call.args else None
        if val is None:
            continue
        if call.distinct:
            slot["vals"].add(json.dumps(val, sort_keys=True, default=str))
            continue
        slot["n"] += 1
        if call.name in ("sum", "avg"):
            slot["sum"] += val
        elif call.name == "min":
            slot["min"] = val if slot["min"] is None else min(slot["min"], val)
        elif call.name == "max":
            slot["max"] = val if slot["max"] is None else max(slot["max"], val)
        elif call.name == "count":
            slot["n"] += 0


def _finish_agg(call: sql.Func, acc: dict[str, Any]) -> Any:
    slot = acc["__acc__"][sql.format_expr(call)]
    if call.distinct:
        return len(slot["vals"])
    if call.name == "count":
        return slot["n"]
    if call.name == "sum":
        return slot["sum"] if slot["n"] else None
    if call.name == "avg":
        return (slot["sum"] / slot["n"]) if slot["n"] else None
    if call.name == "min":
        return slot["min"]
    if call.name == "max":
        return slot["max"]
    raise ExecError(f"unsupported aggregate {call.name}")


def _eval_group_item(expr: sql.Node, row_ctx: dict[str, Any], ctx: dict[str, Any], acc: dict[str, Any]) -> Any:
    if isinstance(expr, sql.Func) and expr.is_aggregate:
        return ctx[sql.format_expr(expr)]
    if isinstance(expr, sql.Column):
        return row_ctx.get(expr.name)
    if isinstance(expr, sql.Func):
        args = [_eval_group_item(a, row_ctx, ctx, acc) for a in expr.args]
        return apply_scalar_func(expr.name, args)
    if isinstance(expr, sql.Literal):
        return expr.value
    if isinstance(expr, sql.BinaryOp):
        return eval_expr(expr, row_ctx, ctx)
    return eval_expr(expr, row_ctx, ctx)


def _compute_agg(call: sql.Func, rows: list[dict[str, Any]]) -> Any:
    if call.name == "count":
        if not call.args or isinstance(call.args[0], sql.Star):
            return len(rows)
        vals = [eval_expr(call.args[0], r) for r in rows]
        vals = [v for v in vals if v is not None]
        if call.distinct:
            vals = list({json.dumps(v, sort_keys=True, default=str) for v in vals})
        return len(vals)
    vals = [eval_expr(call.args[0], r) for r in rows] if call.args else []
    vals = [v for v in vals if v is not None]
    if call.distinct:
        seen = {}
        for v in vals:
            seen[json.dumps(v, sort_keys=True, default=str)] = v
        vals = list(seen.values())
    if not vals:
        return None
    if call.name == "sum":
        return sum(vals)
    if call.name == "avg":
        return sum(vals) / len(vals)
    if call.name == "min":
        return min(vals)
    if call.name == "max":
        return max(vals)
    raise ExecError(f"unsupported aggregate {call.name}")


def _count_zone(decisions: list[dict[str, Any]]) -> int:
    return sum(1 for d in decisions if d.get("reason") == "zone_map")


def _summarize_reasons(decisions, files, kept) -> dict[str, int]:
    out = {"partition": 0, "zone_map": 0}
    for d in decisions:
        out[d["reason"]] = out.get(d["reason"], 0) + 1
    total = len(files)
    out["function_zone_map"] = max(0, total - len(kept) - sum(1 for d in decisions if d.get("reason")))
    return out


# ---------------------------------------------------------------------------
# Plan-only (no data read) — used by simulations and the UI's "explain"
# ---------------------------------------------------------------------------


def candidate_files(conn, select: sql.Select) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    table = store.table_row(conn, select.table)
    if table is None:
        raise ExecError(f"unknown table {select.table!r}")
    return table, store.file_rows(conn, select.table)


def describe_plan(conn, select: sql.Select) -> dict[str, Any]:
    table, files = candidate_files(conn, select)
    pruned = prune_files(files, select, table)
    kept = zone_prune_functions(pruned.kept, select)
    return {
        "table": table["name"],
        "stats_stale": table["stats_stale"],
        "partition_cols": table["partition_cols"],
        "sort_keys": table["sort_keys"],
        "files_total": len(files),
        "files_scanned": len(kept),
        "files_pruned": len(files) - len(kept),
        "pruned_by": {
            "partition": sum(1 for d in pruned.decisions if d["reason"] == "partition"),
            "zone_map": sum(1 for d in pruned.decisions if d["reason"] == "zone_map"),
        },
        "candidate_bytes": sum(int(f["bytes"]) for f in kept),
        "candidate_rows": sum(int(f["row_count"]) for f in kept),
        "sampled_prune_reasons": pruned.decisions[:5],
    }
