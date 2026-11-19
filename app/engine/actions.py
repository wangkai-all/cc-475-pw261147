"""Simulation, apply, and undo.

Contract enforced here:

* ``simulate`` never mutates data.  It stores a plan plus **modelled**
  estimates with explicit bounds, and the state fingerprint of the catalog it
  was computed from.
* ``apply`` refuses to run unless a rollback point was created first and the
  catalog state still matches the simulation.  "Before" and "after" numbers in
  the apply record are both **measured** by re-executing the query.
* ``undo`` restores the layout from the rollback point and measures again.

No code path copies a modelled estimate into a `measured` field.
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from typing import Any

from .. import store
from . import analyzer, executor, lake, sqlparse_lite as sql


class ActionError(ValueError):
    """A precondition failed.  The HTTP layer maps this to 409/422."""

    def __init__(self, message: str, *, code: str = "action_error", detail: dict | None = None):
        super().__init__(message)
        self.code = code
        self.detail = detail or {}


# ---------------------------------------------------------------------------
# Layout helpers
# ---------------------------------------------------------------------------


def _file_suffix() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")


def _partition_of(row: dict[str, Any], partition_cols: tuple[str, ...]) -> dict[str, str]:
    part: dict[str, str] = {}
    for pc in partition_cols:
        if ":" in pc:
            kind, src = pc.split(":", 1)
            val = row.get(src)
            if val is None:
                continue
            if kind == "month":
                part[pc] = str(val)[:7]
            elif kind == "year":
                part[pc] = str(val)[:4]
            else:
                part[pc] = str(val)
        else:
            val = row.get(pc)
            if val is not None:
                part[pc] = str(val)
    return part


def _partition_path(part: dict[str, str]) -> str:
    if not part:
        return ""
    segs = []
    for k in sorted(part):
        key = k.split(":", 1)[1] if ":" in k else k
        segs.append(f"{key}={part[k]}")
    return "/".join(segs)


def rewrite_layout(
    conn,
    table: str,
    *,
    partition_cols: tuple[str, ...] | None = None,
    sort_keys: tuple[str, ...] | None = None,
    target_file_bytes: int = 8 * 1024 * 1024,
) -> dict[str, Any]:
    """Physically rewrite one table's files into a new layout.

    Returns a summary of what changed.  Caller is responsible for the rollback
    point; this function mutates the lake and catalog.
    """
    meta = store.table_row(conn, table)
    if meta is None:
        raise ActionError(f"unknown table {table!r}")
    partition_cols = tuple(partition_cols if partition_cols is not None else meta["partition_cols"])
    sort_keys = tuple(sort_keys if sort_keys is not None else meta["sort_keys"])

    old_files = store.file_rows(conn, table)
    rows: list[dict[str, Any]] = []
    for f in old_files:
        rows.extend(lake.read_rows(table, f["rel_path"]))

    # Group by target partition.
    buckets: dict[tuple, list[dict[str, Any]]] = {}
    for row in rows:
        part = _partition_of(row, partition_cols)
        key = tuple(sorted(part.items()))
        buckets.setdefault(key, []).append(row)

    staging = os.path.join(store.LAKE_DIR, f"{table}__staging_{_file_suffix()}")
    os.makedirs(staging, exist_ok=True)

    spec_cols = [
        lake.ColumnSpec(c["name"], c.get("kind", "str")) for c in meta.get("columns") or []
    ]
    new_files: list[dict[str, Any]] = []
    columns = [
        lake.ColumnSpec(c["name"], c.get("kind", "str")) for c in meta.get("columns") or []
    ]
    for pkey, bucket in buckets.items():
        part = dict(pkey)
        if sort_keys:
            bucket.sort(key=lambda r: tuple((r.get(k) is None, str(r.get(k))) for k in sort_keys))
        for i, chunk in enumerate(_split_by_size(bucket, target_file_bytes, columns)):
            rel = "/".join(p for p in [_partition_path(part), f"part-{i:04d}.jsonl"] if p)
            path = os.path.join(staging, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            size = _write_rows(path, chunk)
            stats = lake.compute_stats(chunk, columns)
            new_files.append(
                {"rel_path": rel, "partition": part, "row_count": len(chunk),
                 "bytes": size, "stats": stats}
            )

    # Swap directories: remove old, move staging into place.
    final = os.path.join(store.LAKE_DIR, table)
    trash = os.path.join(store.LAKE_DIR, f"{table}__trash_{_file_suffix()}")
    if os.path.isdir(final):
        os.rename(final, trash)
    os.rename(staging, final)
    shutil.rmtree(trash, ignore_errors=True)

    now = store.utcnow()
    conn.execute("DELETE FROM files WHERE table_name=?", (table,))
    for nf in new_files:
        conn.execute(
            "INSERT INTO files(table_name,rel_path,partition_json,row_count,bytes,stats_json,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (table, nf["rel_path"], json.dumps(nf["partition"]), nf["row_count"], nf["bytes"],
             json.dumps(nf["stats"]), now),
        )
    conn.execute(
        "UPDATE tables SET partition_cols=?, sort_keys=?, stats_updated_at=?, "
        "last_data_change_at=? WHERE name=?",
        (json.dumps(list(partition_cols)), json.dumps(list(sort_keys)), now, now, table),
    )
    store.refresh_table_aggregates(conn, table)
    return {
        "table": table,
        "partition_cols": list(partition_cols),
        "sort_keys": list(sort_keys),
        "files_before": len(old_files),
        "files_after": len(new_files),
        "rows": len(rows),
        "bytes_before": sum(int(f["bytes"]) for f in old_files),
        "bytes_after": sum(int(f["bytes"]) for f in new_files),
    }


def _split_by_size(rows: list[dict[str, Any]], target_bytes: int,
                   columns: list[lake.ColumnSpec]) -> list[list[dict[str, Any]]]:
    if not rows:
        return [[]]
    # Estimate average serialized row size from a sample, then chunk.
    sample = rows[: min(200, len(rows))]
    per_row = max(40, sum(len(json.dumps(r, separators=(",", ":"), sort_keys=True)) for r in sample) // len(sample))
    per_file = max(50, target_bytes // per_row)
    return [rows[i: i + per_file] for i in range(0, len(rows), per_file)] or [rows]


def _write_rows(path: str, rows: list[dict[str, Any]]) -> int:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
    os.replace(tmp, path)
    return os.path.getsize(path)


def materialize_summary(conn, table: str, group_by: list[str], aggregates: list[str],
                        output_columns: list[str]) -> dict[str, Any]:
    meta = store.table_row(conn, table)
    if meta is None:
        raise ActionError(f"unknown table {table!r}")
    summary = f"{table}__summary"
    if store.table_row(conn, summary):
        drop_table(conn, summary)

    items = list(group_by) + [f"{expr} as {label}" for expr, label in zip(aggregates, output_columns[len(group_by):])]
    sql_text = f"select {', '.join(items)} from {table}"
    if group_by:
        sql_text += f" group by {', '.join(group_by)}"
    select = sql.parse(sql_text)
    result = executor.execute(conn, select, collect_rows=True, max_result_rows=100000)

    now = store.utcnow()
    cols = []
    for name in group_by:
        kind = next((c.get("kind", "str") for c in meta.get("columns") or [] if c["name"] == name), "str")
        cols.append({"name": name, "kind": kind})
    for label in output_columns[len(group_by):]:
        cols.append({"name": label, "kind": "float" if label.startswith(("sum(", "avg(")) else "int"})
    conn.execute(
        "INSERT INTO tables(name,description,partition_cols,sort_keys,columns_json,row_count,bytes,"
        "file_count,stats_updated_at,last_data_change_at,created_at,materialized_from) "
        "VALUES(?,?,?,?,?,0,0,0,?,?,?,?)",
        (summary, f"Materialized aggregate of {table}", "[]", "[]", json.dumps(cols),
         now, now, now, table),
    )
    rel = "part-0000.jsonl"
    path = os.path.join(store.LAKE_DIR, summary, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    size = _write_rows(path, result.rows)
    specs = [lake.ColumnSpec(c["name"], c["kind"]) for c in cols]
    conn.execute(
        "INSERT INTO files(table_name,rel_path,partition_json,row_count,bytes,stats_json,created_at) "
        "VALUES(?,?,?,?,?,?,?)",
        (summary, rel, "{}", len(result.rows), size,
         json.dumps(lake.compute_stats(result.rows, specs)), now),
    )
    store.refresh_table_aggregates(conn, summary)
    rewritten = (
        f"select {', '.join(output_columns)} from {summary}"
        + (f" order by {', '.join(output_columns[:1])}" if False else "")
    )
    return {"summary_table": summary, "rows": len(result.rows), "bytes": size,
            "rewritten_query": rewritten, "build_ms": round(result.metrics["duration_ms"], 2)}


def drop_table(conn, table: str) -> None:
    conn.execute("DELETE FROM files WHERE table_name=?", (table,))
    conn.execute("DELETE FROM tables WHERE name=?", (table,))
    shutil.rmtree(os.path.join(store.LAKE_DIR, table), ignore_errors=True)


# ---------------------------------------------------------------------------
# Rollback points
# ---------------------------------------------------------------------------


def create_rollback_point(conn, table: str, kind: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Snapshot catalog rows + file bytes *before* a mutating action."""
    meta = store.table_row(conn, table)
    if meta is None:
        raise ActionError(f"cannot snapshot unknown table {table!r}")
    raw = dict(conn.execute("SELECT * FROM tables WHERE name=?", (table,)).fetchone())
    files = store.file_rows(conn, table)
    ts = store.utcnow()
    manifest: dict[str, Any] = {
        "table": table,
        "kind": kind,
        "tables_row": raw,
        "files": [
            {
                "rel_path": f["rel_path"],
                "partition": f["partition"],
                "row_count": f["row_count"],
                "bytes": f["bytes"],
                "stats": f["stats"],
                "created_at": f["created_at"],
            }
            for f in files
        ],
        "created_at": ts,
    }
    manifest.update(extra or {})
    cur = conn.execute(
        "INSERT INTO rollback_points(apply_id,ts,kind,manifest_json,state) VALUES(?,?,?,?,?)",
        (None, ts, kind, store.json_dumps(manifest), "preparing"),
    )
    rp_id = int(cur.lastrowid)
    backup_dir = os.path.join(store.BACKUP_DIR, f"rp-{rp_id:05d}")
    os.makedirs(backup_dir, exist_ok=True)
    src = os.path.join(store.LAKE_DIR, table)
    if os.path.isdir(src):
        shutil.copytree(src, os.path.join(backup_dir, "lake", table))
    manifest["backup_dir"] = os.path.relpath(backup_dir, store.DATA_DIR)
    conn.execute(
        "UPDATE rollback_points SET manifest_json=?, state='available' WHERE id=?",
        (store.json_dumps(manifest), rp_id),
    )
    return {"id": rp_id, "ts": ts, "kind": kind, "backup_dir": manifest["backup_dir"],
            "files": len(files), "bytes": sum(int(f["bytes"]) for f in files)}


def restore_rollback_point(conn, rp: dict[str, Any]) -> dict[str, Any]:
    manifest = json.loads(rp["manifest_json"])
    table = manifest["table"]
    backup = os.path.join(store.DATA_DIR, manifest["backup_dir"])
    final = os.path.join(store.LAKE_DIR, table)
    shutil.rmtree(final, ignore_errors=True)
    backup_lake = os.path.join(backup, "lake", table)
    if os.path.isdir(backup_lake):
        shutil.copytree(backup_lake, final)

    # Restore table row + file rows.
    t = manifest["tables_row"]
    conn.execute(
        "INSERT INTO tables(name,description,partition_cols,sort_keys,columns_json,row_count,bytes,"
        "file_count,stats_updated_at,last_data_change_at,created_at,materialized_from) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(name) DO UPDATE SET description=excluded.description,"
        "partition_cols=excluded.partition_cols,sort_keys=excluded.sort_keys,"
        "columns_json=excluded.columns_json,row_count=excluded.row_count,bytes=excluded.bytes,"
        "file_count=excluded.file_count,stats_updated_at=excluded.stats_updated_at,"
        "last_data_change_at=excluded.last_data_change_at,"
        "materialized_from=excluded.materialized_from",
        (t["name"], t.get("description", ""), t["partition_cols"], t["sort_keys"],
         t.get("columns_json") or "[]", t["row_count"], t["bytes"], t["file_count"],
         t["stats_updated_at"], t["last_data_change_at"], t["created_at"],
         t.get("materialized_from")),
    )
    conn.execute("DELETE FROM files WHERE table_name=?", (table,))
    now = store.utcnow()
    for f in manifest["files"]:
        conn.execute(
            "INSERT INTO files(table_name,rel_path,partition_json,row_count,bytes,stats_json,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (table, f["rel_path"], json.dumps(f["partition"]), f["row_count"], f["bytes"],
             json.dumps(f["stats"]), f["created_at"]),
        )
    store.refresh_table_aggregates(conn, table)
    created = manifest.get("created_tables") or []
    for name in created:
        drop_table(conn, name)
    return {"table": table, "restored_files": len(manifest["files"]),
            "restored_at": now, "dropped_tables": created}


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------


def _target_column(advisory: dict[str, Any]) -> str | None:
    rec = (advisory.get("rationale") or {}).get("recommendation") or {}
    if rec.get("cluster_by"):
        return rec["cluster_by"]
    spec = rec.get("partition_by") or []
    if spec:
        return spec[-1].split(":", 1)[-1]
    return None


def _synthetic_query(conn, table: str, column: str) -> dict[str, Any] | None:
    """A stated, reproducible query over one slice of ``column``.

    Used when the advisory (e.g. small files) has no linked history query.
    The plan records this as a synthetic measurement query so nobody mistakes
    it for real traffic.
    """
    meta = store.table_row(conn, table)
    if meta is None:
        return None
    files = store.file_rows(conn, table)
    entry = {}
    for f in files:
        entry = (f.get("stats") or {}).get(column) or {}
        if entry:
            break
    kind = analyzer._column_kind(meta, column)
    if kind == "date" and entry.get("min"):
        lo = str(entry["min"])[:7]
        hi = str(entry["max"])[:7]
        # Prefer a one-month window where the column has data.
        month_lo = sorted({str(((f.get("stats") or {}).get(column) or {}).get("min"))[:7]
                           for f in files if ((f.get("stats") or {}).get(column) or {}).get("min")})[0]
        from datetime import date

        y, m = int(month_lo[:4]), int(month_lo[5:7])
        ny, nm = (y + 1, 1) if m == 12 else (y, m + 1)
        next_month = f"{ny:04d}-{nm:02d}-01"
        day = (date(ny, nm, 1) - __import__("datetime").timedelta(days=1)).isoformat()
        return {
            "query": f"select count(*) as n from {table} where {column} >= '{month_lo}-01' "
                     f"and {column} <= '{day}'",
            "source": f"合成测量查询：{column} 单月窗口（该建议没有关联历史查询）",
            "execution_id": None,
            "synthetic": True,
        }
    values = entry.get("distinct_values") or []
    if values:
        v = values[0]
        quoted = f"'{v}'" if isinstance(v, str) else str(v)
        return {
            "query": f"select count(*) as n from {table} where {column} = {quoted}",
            "source": f"合成测量查询：{column} 单个取值（该建议没有关联历史查询）",
            "execution_id": None,
            "synthetic": True,
        }
    return None


def _representative_query(conn, advisory: dict[str, Any]) -> dict[str, Any]:
    """Pick the query an action will be measured against."""
    if advisory.get("fingerprint"):
        row = conn.execute(
            "SELECT * FROM executions WHERE fingerprint=? AND status='ok' "
            "ORDER BY ts DESC LIMIT 1",
            (advisory["fingerprint"],),
        ).fetchone()
        if row:
            return {"query": row["query"], "source": "建议关联的执行样本",
                    "execution_id": row["id"]}
    # Prefer a historical query that actually filters the column we are about
    # to repartition / cluster on: that is what the change is meant to help.
    target = _target_column(advisory)
    if target:
        candidates = conn.execute(
            "SELECT id, query, fingerprint FROM executions "
            "WHERE table_name=? AND status='ok' ORDER BY ts DESC LIMIT 200",
            (advisory["table_name"],),
        ).fetchall()
        best = None
        for c in candidates:
            try:
                sel = sql.parse(c["query"])
            except sql.QueryError:
                continue
            if sel.table != advisory["table_name"]:
                continue
            if analyzer._predicate_span(sel, target) is not None:
                best = c
                break
        if best is not None:
            return {"query": best["query"], "source": f"包含 {target} 谓词的历史样本",
                    "execution_id": best["id"]}
        synthetic = _synthetic_query(conn, advisory["table_name"], target)
        if synthetic is not None:
            return synthetic

    row = conn.execute(
        "SELECT table_name, fingerprint, SUM(duration_ms) AS t FROM executions "
        "WHERE table_name=? AND status='ok' GROUP BY fingerprint "
        "ORDER BY t DESC LIMIT 1",
        (advisory["table_name"],),
    ).fetchone()
    if row:
        sample = conn.execute(
            "SELECT query, id FROM executions WHERE fingerprint=? AND status='ok' "
            "ORDER BY ts DESC LIMIT 1",
            (row["fingerprint"],),
        ).fetchone()
        return {"query": sample["query"], "source": "该表累计耗时最高的查询",
                "execution_id": sample["id"]}
    return {"query": f"select count(*) as n from {advisory['table_name']}",
            "source": "回退到全表计数查询", "execution_id": None}


def simulate(conn, advisory_id: int) -> dict[str, Any]:
    adv_row = conn.execute("SELECT * FROM advisories WHERE id=?", (advisory_id,)).fetchone()
    if adv_row is None:
        raise ActionError("advisory not found", code="not_found")
    advisory = dict(adv_row)
    advisory["rationale"] = json.loads(advisory["rationale_json"])
    table = advisory["table_name"]
    meta = store.table_row(conn, table)
    if meta is None:
        raise ActionError(f"table {table!r} no longer exists")

    rec = advisory["rationale"].get("recommendation") or {}
    action = rec.get("action") or _default_action(advisory["kind"])
    files = store.file_rows(conn, table)
    subject = _representative_query(conn, advisory)
    select = sql.parse(subject["query"])
    assumptions: list[str] = []
    estimates: dict[str, Any] = {}
    steps: list[dict[str, Any]] = []
    target: dict[str, Any] = {"table": table}

    if action == "add_partition":
        spec = rec.get("partition_by") or []
        if not spec:
            raise ActionError("recommendation has no partition columns")
        column = spec[-1].split(":", 1)[-1]
        column_kind = analyzer._column_kind(meta, column)
        projection = analyzer.project_repartition(
            files, column, column_kind, select,
            kept_partitions=tuple(rec.get("keep_partitions") or meta["partition_cols"]),
        )
        if projection is None:
            raise ActionError("query has no predicate to prune with on this table")
        new_cols = tuple(rec.get("keep_partitions") or meta["partition_cols"]) + tuple(spec)
        sort_keys = tuple(rec.get("sort_keys") or meta["sort_keys"])
        target.update({"partition_cols": list(new_cols), "sort_keys": list(sort_keys),
                       "target_file_bytes": 8 * 1024 * 1024})
        steps = [
            {"op": "read_all_rows", "table": table, "rows": meta["row_count"]},
            {"op": "repartition", "by": list(new_cols)},
            {"op": "rewrite_files", "target_file_bytes": target["target_file_bytes"]},
            {"op": "recompute_zone_maps"},
            {"op": "swap_catalog"},
        ]
        avg_bytes = meta["bytes"] / max(1, meta["file_count"])
        estimates = _estimate_from_files(projection, avg_bytes, len(files), column)
        assumptions = projection.assumptions
        action_label = f"按 {column} 增加/替换分区 {', '.join(spec)}"

    elif action == "cluster":
        column = rec.get("cluster_by")
        if not column:
            raise ActionError("recommendation has no cluster column")
        column_kind = analyzer._column_kind(meta, column)
        projection = analyzer.project_cluster(files, column, select)
        if projection is None:
            raise ActionError("query has no predicate to prune with on this table")
        sort_keys = tuple(rec.get("sort_keys") or (column,))
        target.update({"partition_cols": list(meta["partition_cols"]),
                       "sort_keys": list(sort_keys),
                       "target_file_bytes": rec.get("target_file_bytes", 1024 * 1024)})
        steps = [
            {"op": "read_all_rows", "table": table, "rows": meta["row_count"]},
            {"op": "sort", "keys": list(sort_keys)},
            {"op": "rewrite_files", "target_file_bytes": target["target_file_bytes"]},
            {"op": "recompute_zone_maps"},
            {"op": "swap_catalog"},
        ]
        avg_bytes = meta["bytes"] / max(1, meta["file_count"])
        estimates = _estimate_from_files(projection, avg_bytes, len(files), column)
        assumptions = projection.assumptions + [
            "cluster output file size is chosen so each file holds a narrow key range"
        ]
        action_label = f"按 {column} 排序/聚簇并重写文件"

    elif action == "materialize":
        group_by = rec.get("group_by") or []
        agg_exprs = rec.get("aggregates") or []
        out_labels = _output_labels(select)
        target.update({"summary_table": f"{table}__summary", "group_by": list(group_by),
                       "aggregates": list(agg_exprs)})
        steps = [
            {"op": "aggregate_once", "table": table, "group_by": list(group_by),
             "aggregates": list(agg_exprs)},
            {"op": "create_table", "name": target["summary_table"]},
            {"op": "point_query_at_summary"},
        ]
        # Estimate: the summary's scan size is bounded by the group count; the
        # exact count is unknown without running the aggregation (which is the
        # very work we are trying to avoid repeating).
        group_est = _group_estimate(files, table, group_by)
        estimates = {
            "files_scanned": {"value": 1.0, "bound_low": 1.0, "bound_high": 1.0,
                              "basis": "summary is written as a single file"},
            "bytes_scanned": {"value": None, "bound_low": None, "bound_high": None,
                              "basis": f"unknown before build; group cardinality {group_est['label']}"},
            "group_cardinality": group_est,
        }
        assumptions = [
            "衡量收益需要先构建一次汇总表",
            "查询必须改写为读取汇总表",
            "汇总表的新鲜度不会自动维护",
        ]
        action_label = "物化重复聚合结果为汇总表"

    elif action == "compact":
        target_bytes = int(rec.get("target_file_bytes") or 8 * 1024 * 1024)
        small = [f for f in files if int(f["bytes"]) < target_bytes]
        target.update({"target_file_bytes": target_bytes,
                       "partition_cols": list(meta["partition_cols"]),
                       "sort_keys": list(meta["sort_keys"])})
        steps = [
            {"op": "group_small_files", "input_files": len(small)},
            {"op": "merge_and_rewrite", "target_file_bytes": target_bytes},
            {"op": "recompute_zone_maps"},
            {"op": "swap_catalog"},
        ]
        partition_dirs = len({
            json.dumps(f.get("partition") or {}, sort_keys=True) for f in files
        })
        projected_files = max(partition_dirs, round(meta["bytes"] / target_bytes))
        estimates = {
            "files_scanned": {
                "value": projected_files, "bound_low": projected_files,
                "bound_high": projected_files,
                "basis": f"max(partition directories={partition_dirs}, "
                         f"bytes / target file size): compaction cannot merge across partitions",
            },
            "partition_dirs": {"value": partition_dirs,
                               "basis": "existing partition directories are preserved"},
            "bytes_scanned": {
                "value": meta["bytes"], "bound_low": meta["bytes"], "bound_high": meta["bytes"],
                "basis": "compaction does not remove rows",
            },
            "duration_ms": {"value": None, "bound_low": None, "bound_high": None,
                            "basis": "not estimated; local duration depends on row parsing, "
                                     "not file count"},
        }
        assumptions = [
            "合并保留所有行",
            "更少的文件会降低每文件开销，但该收益大小未建模",
        ]
        action_label = f"合并小文件至 {target_bytes // (1024*1024)} MiB"

    else:
        raise ActionError(f"no apply action for {action!r}")

    state_fp = store.state_fingerprint(conn, table)
    plan = {
        "advisory_id": advisory_id,
        "kind": advisory["kind"],
        "table": table,
        "action": action,
        "action_label": action_label,
        "target": target,
        "steps": steps,
        "measurement": {
            "query": subject["query"],
            "source": subject["source"],
            "execution_id": subject["execution_id"],
            "method": "变更前后各执行同一条查询，记录实测指标",
        },
        "estimates": estimates,
        "assumptions": assumptions,
        "estimate_disclaimer": "这些数字是由目录统计推导的模型估算，不是实测结果，可能与实际不符。",
        "state_fingerprint": state_fp,
        "created_at": store.utcnow(),
    }
    cur = conn.execute(
        "INSERT INTO simulations(advisory_id,ts,plan_json,estimate_json,state_fingerprint,superseded) "
        "VALUES(?,?,?,?,?,0)",
        (advisory_id, store.utcnow(), store.json_dumps(plan),
         store.json_dumps(estimates), state_fp),
    )
    sim_id = int(cur.lastrowid)
    conn.execute(
        "UPDATE advisories SET status='simulated', updated_at=? WHERE id=? AND status='open'",
        (store.utcnow(), advisory_id),
    )
    plan["simulation_id"] = sim_id
    return plan


def _default_action(kind: str) -> str:
    return {
        "overscan": "cluster",
        "partition_miss": "add_partition",
        "repeated_aggregation": "materialize",
        "small_files": "compact",
    }.get(kind, "")


def _output_labels(select: sql.Select) -> list[str]:
    return [item.alias or sql.format_expr(item.expr) for item in select.items]


def _group_estimate(files, table, group_by) -> dict[str, Any]:
    if not group_by:
        return {"value": 1, "label": "1 (no grouping)"}
    src = group_by[0]
    max_distinct = 0
    for f in files:
        entry = (f.get("stats") or {}).get(src) or {}
        max_distinct = max(max_distinct, int(entry.get("distinct") or 0))
    if max_distinct:
        return {"value": max_distinct, "label": f"~{max_distinct} distinct {src} values"}
    return {"value": None, "label": f"unknown distinct count for {src}"}


def _estimate_from_files(projection: analyzer.PruneProjection, avg_bytes: float,
                         total_files: int, column: str) -> dict[str, Any]:
    files_scanned = projection.files_scanned
    new_total = projection.total_files or float(total_files)
    avg = avg_bytes
    return {
        "files_scanned": {
            "value": round(files_scanned, 1),
            "bound_low": round(projection.lower, 1),
            "bound_high": round(projection.upper, 1),
            "basis": projection.basis,
        },
        "total_files_after": {
            "value": round(new_total, 1),
            "basis": "file count the proposed layout would contain",
        },
        "bytes_scanned": {
            "value": round(files_scanned * avg),
            "bound_low": round(projection.lower * avg),
            "bound_high": round(projection.upper * avg),
            "basis": "projected files x current average bytes per file",
        },
        "duration_ms": {
            "value": None, "bound_low": None, "bound_high": None,
            "basis": "not estimated: I/O savings do not translate linearly into wall time",
        },
        "prune_column": column,
        "current_files": total_files,
        "projected_prune_pct": round(projection.prune_fraction * 100, 1),
    }


# ---------------------------------------------------------------------------
# Apply / undo
# ---------------------------------------------------------------------------


def apply_simulation(conn, simulation_id: int) -> dict[str, Any]:
    sim_row = conn.execute("SELECT * FROM simulations WHERE id=?", (simulation_id,)).fetchone()
    if sim_row is None:
        raise ActionError("simulation not found", code="not_found")
    if sim_row["superseded"]:
        raise ActionError("simulation has been superseded; re-run simulate",
                          code="simulation_superseded")
    plan = json.loads(sim_row["plan_json"])
    table = plan["table"]
    adv_row = conn.execute("SELECT * FROM advisories WHERE id=?", (plan["advisory_id"],)).fetchone()
    if adv_row is None or adv_row["status"] == "resolved":
        raise ActionError("advisory is already resolved", code="already_resolved")

    current_fp = store.state_fingerprint(conn, table)
    if current_fp != sim_row["state_fingerprint"]:
        raise ActionError(
            "catalog state changed since this simulation was computed; estimates no longer apply. "
            "Run simulate again.",
            code="state_changed",
            detail={"simulation_state": sim_row["state_fingerprint"], "current_state": current_fp},
        )

    subject = plan["measurement"]["query"]
    select = sql.parse(subject)
    original_select = select
    table_meta = store.table_row(conn, table)
    if table_meta is None:
        raise ActionError(f"table {table!r} no longer exists")

    # 1) measure BEFORE on the current layout
    before = executor.execute(conn, select, collect_rows=False, max_result_rows=0)
    before_measured = _measurement("before", before.metrics)
    before_measured["query"] = subject

    # 2) rollback point BEFORE any mutation
    extra: dict[str, Any] = {"action": plan["action"], "simulation_id": simulation_id}
    if plan["action"] == "materialize":
        extra["created_tables"] = [plan["target"]["summary_table"]]
    rp = create_rollback_point(conn, table, kind=f"pre-{plan['action']}", extra=extra)

    cur = conn.execute(
        "INSERT INTO applies(advisory_id,simulation_id,ts,status,before_json,after_json,"
        "rollback_point_id,note) VALUES(?,?,?,?,?,?,?,?)",
        (plan["advisory_id"], simulation_id, store.utcnow(), "applying",
         store.json_dumps(before_measured), "{}", rp["id"], ""),
    )
    apply_id = int(cur.lastrowid)
    conn.execute("UPDATE rollback_points SET apply_id=? WHERE id=?", (apply_id, rp["id"]))
    conn.commit()  # rollback point must exist on disk before we touch data

    try:
        change = _perform(conn, plan)
    except Exception as exc:  # noqa: BLE001 - restore then surface
        restore_rollback_point(conn, conn.execute(
            "SELECT * FROM rollback_points WHERE id=?", (rp["id"],)
        ).fetchone())
        conn.execute(
            "UPDATE applies SET status='failed', note=? WHERE id=?", (str(exc), apply_id)
        )
        conn.commit()
        raise ActionError(f"apply failed and was rolled back: {exc}", code="apply_failed") from exc

    # 3) measure AFTER through the same query (or the rewritten one for a summary)
    after_query = change.pop("after_query", subject)
    after_select = sql.parse(after_query)
    after = executor.execute(conn, after_select, collect_rows=False, max_result_rows=0)
    after_measured = _measurement("after", after.metrics)
    after_measured["query"] = after_query
    after_measured["rewritten"] = after_query != subject

    after_measured["restore_query"] = subject
    conn.execute(
        "UPDATE applies SET status='applied', after_json=?, note=? WHERE id=?",
        (store.json_dumps(after_measured), change.get("summary", ""), apply_id),
    )
    conn.execute(
        "UPDATE advisories SET status='resolved', updated_at=? WHERE id=?",
        (store.utcnow(), plan["advisory_id"]),
    )
    conn.execute(
        "UPDATE simulations SET superseded=1 WHERE advisory_id=? AND id<>?",
        (plan["advisory_id"], simulation_id),
    )
    store.log_undo(conn, "apply", apply_id, {
        "advisory_id": plan["advisory_id"], "simulation_id": simulation_id,
        "change": change, "rollback_point": rp["id"],
    })
    conn.commit()

    return {
        "apply_id": apply_id,
        "advisory_id": plan["advisory_id"],
        "action": plan["action"],
        "action_label": plan["action_label"],
        "table": table,
        "before": before_measured,
        "after": after_measured,
        "estimates": plan["estimates"],
        "change": change,
        "rollback_point": rp,
        "estimated_vs_measured": _compare(plan["estimates"], before_measured, after_measured),
    }


def _perform(conn, plan: dict[str, Any]) -> dict[str, Any]:
    action = plan["action"]
    target = plan["target"]
    table = plan["table"]
    if action in ("add_partition", "cluster", "compact"):
        summary = rewrite_layout(
            conn, table,
            partition_cols=tuple(target.get("partition_cols") or ()),
            sort_keys=tuple(target.get("sort_keys") or ()),
            target_file_bytes=int(target.get("target_file_bytes") or 8 * 1024 * 1024),
        )
        return {"rewrite": summary, "after_query": plan["measurement"]["query"]}
    if action == "materialize":
        rec = plan["target"]
        select = sql.parse(plan["measurement"]["query"])
        out_labels = _output_labels(select)
        built = materialize_summary(
            conn, table, list(rec["group_by"]), list(rec["aggregates"]), out_labels
        )
        return {"materialize": built, "after_query": built["rewritten_query"],
                "summary": f"created {built['summary_table']} with {built['rows']} rows"}
    raise ActionError(f"unsupported action {action!r}")


def _measurement(stage: str, metrics: dict[str, Any]) -> dict[str, Any]:
    return {
        "stage": stage,
        "measured": True,
        "duration_ms": round(metrics["duration_ms"], 3),
        "bytes_scanned": metrics["bytes_scanned"],
        "rows_scanned": metrics["rows_scanned"],
        "files_scanned": metrics["files_scanned"],
        "files_total": metrics["files_total"],
        "files_pruned": metrics["files_pruned"],
        "rows_returned": metrics["rows_returned"],
        "rows_matched": metrics.get("rows_matched"),
    }


def _compare(estimates: dict[str, Any], before: dict, after: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    est_files = estimates.get("files_scanned", {})
    if est_files.get("value") is not None:
        actual = after["files_scanned"]
        out["files_scanned"] = {
            "estimated": est_files["value"],
            "estimated_range": [est_files.get("bound_low"), est_files.get("bound_high")],
            "actual": actual,
            "delta_from_estimate": actual - est_files["value"],
            "within_bounds": _within(actual, est_files.get("bound_low"), est_files.get("bound_high")),
        }
    out["duration_ms"] = {
        "estimated": None,
        "actual_before": before["duration_ms"],
        "actual_after": after["duration_ms"],
    }
    out["measured_reduction"] = {
        "bytes_scanned_pct": _pct_reduction(before["bytes_scanned"], after["bytes_scanned"]),
        "files_scanned_pct": _pct_reduction(before["files_scanned"], after["files_scanned"]),
        "duration_ms_pct": _pct_reduction(before["duration_ms"], after["duration_ms"]),
    }
    return out


def _within(v, lo, hi) -> bool | None:
    if lo is None or hi is None:
        return None
    return lo <= v <= hi


def _pct_reduction(before: float, after: float) -> float | None:
    if not before:
        return None
    return round(100.0 * (before - after) / before, 1)


def undo_apply(conn, apply_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM applies WHERE id=?", (apply_id,)).fetchone()
    if row is None:
        raise ActionError("apply not found", code="not_found")
    if row["status"] != "applied":
        raise ActionError(f"apply status is {row['status']!r}; nothing to undo", code="not_undoable")
    rp = conn.execute(
        "SELECT * FROM rollback_points WHERE id=?", (row["rollback_point_id"],)
    ).fetchone()
    if rp is None or rp["state"] != "available":
        raise ActionError("rollback point is missing or already used", code="no_rollback_point")

    plan = json.loads(
        conn.execute("SELECT plan_json FROM simulations WHERE id=?", (row["simulation_id"],)).fetchone()["plan_json"]
    )
    after = json.loads(row["after_json"])
    measure_query = after.get("restore_query") or plan["measurement"]["query"]

    restored = restore_rollback_point(conn, rp)
    conn.execute("UPDATE rollback_points SET state='used' WHERE id=?", (rp["id"],))

    measured = executor.execute(conn, sql.parse(measure_query), collect_rows=False, max_result_rows=0)
    undo_measure = _measurement("after_undo", measured.metrics)
    conn.execute("UPDATE applies SET status='undone' WHERE id=?", (apply_id,))
    conn.execute(
        "UPDATE advisories SET status='open', updated_at=? WHERE id=?",
        (store.utcnow(), row["advisory_id"]),
    )
    store.log_undo(conn, "undo", apply_id, {
        "restored": restored, "measured": undo_measure,
        "rollback_point": rp["id"],
    })
    conn.commit()
    return {
        "apply_id": apply_id,
        "status": "undone",
        "restored": restored,
        "measurement": undo_measure,
        "original_before": json.loads(row["before_json"]),
    }


# ---------------------------------------------------------------------------
# Stats validation
# ---------------------------------------------------------------------------


def verify_stats(conn, table: str) -> dict[str, Any]:
    """Recompute zone maps from the actual files and compare with the catalog."""
    meta = store.table_row(conn, table)
    if meta is None:
        raise ActionError(f"unknown table {table!r}", code="not_found")
    files = store.file_rows(conn, table)
    specs = [lake.ColumnSpec(c["name"], c.get("kind", "str")) for c in meta.get("columns") or []]
    drift = []
    checked_rows = 0
    for f in files:
        rows = lake.read_rows(table, f["rel_path"])
        checked_rows += len(rows)
        actual = lake.compute_stats(rows, specs)
        for col, entry in actual.items():
            claimed = (f.get("stats") or {}).get(col) or {}
            for key in ("min", "max"):
                if str(entry.get(key)) != str(claimed.get(key)):
                    drift.append({
                        "file": f["rel_path"], "column": col, "field": key,
                        "catalog": claimed.get(key), "actual": entry.get(key),
                    })
        if len(drift) >= 50:
            break
    stale = bool(meta["last_data_change_at"] and meta["stats_updated_at"]
                 and meta["last_data_change_at"] > meta["stats_updated_at"])
    return {
        "table": table,
        "checked_files": len(files),
        "checked_rows": checked_rows,
        "drift_count": len(drift),
        "drift_samples": drift[:20],
        "stats_updated_at": meta["stats_updated_at"],
        "last_data_change_at": meta["last_data_change_at"],
        "stale": stale,
        "verdict": "ok" if not drift and not stale else "needs_refresh",
    }


def refresh_stats(conn, table: str) -> dict[str, Any]:
    meta = store.table_row(conn, table)
    if meta is None:
        raise ActionError(f"unknown table {table!r}", code="not_found")
    specs = [lake.ColumnSpec(c["name"], c.get("kind", "str")) for c in meta.get("columns") or []]
    now = store.utcnow()
    files = store.file_rows(conn, table)
    for f in files:
        rows = lake.read_rows(table, f["rel_path"])
        stats = lake.compute_stats(rows, specs)
        conn.execute("UPDATE files SET stats_json=? WHERE id=?", (json.dumps(stats), f["id"]))
    conn.execute(
        "UPDATE tables SET stats_updated_at=?, last_data_change_at=? WHERE name=?",
        (now, now, table),
    )
    store.log_undo(conn, "analyze", None, {"table": table, "files": len(files)})
    conn.commit()
    return {"table": table, "stats_updated_at": now, "files": len(files)}
