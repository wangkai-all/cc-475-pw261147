"""Local data lake: seeded table generation, file layout, and row scanning.

Tables are stored as JSONL files under ``.data/lake/<table>/<rel_path>``.  The
catalog mirrors each file's partition values, row count, byte size and per
column zone maps (min/max/null count).  The analyzer prunes with exactly the
same zone maps the executor uses, so a "files scanned" number shown in a
simulation is produced by the same code path as the real execution.
"""

from __future__ import annotations

import json
import os
import random
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any, Iterable

from .. import store


@dataclass(frozen=True)
class ColumnSpec:
    name: str
    kind: str  # int | float | date | str | category
    categories: tuple[str, ...] = ()
    low: float = 0
    high: float = 100
    null_rate: float = 0.0


@dataclass
class TableSpec:
    name: str
    description: str
    columns: tuple[ColumnSpec, ...]
    partition_cols: tuple[str, ...] = ()
    sort_keys: tuple[str, ...] = ()
    days: tuple[date, date] | None = None
    hours: bool = False
    total_rows: int = 200_000
    rows_per_file: int = 600


COUNTRIES = ("CN", "US", "DE", "IN", "BR", "JP", "GB", "FR")
CHANNELS = ("web", "app", "store", "partner")
DEVICES = ("ios", "android", "desktop", "tablet")
EVENT_TYPES = ("view", "click", "add_to_cart", "purchase", "refund")


def default_specs() -> list[TableSpec]:
    d0, d1 = date(2024, 1, 1), date(2024, 12, 31)
    return [
        TableSpec(
            name="events",
            description="Clickstream events, partitioned by event_date; rows unsorted inside a file.",
            columns=(
                ColumnSpec("event_time", "ts"),
                ColumnSpec("event_date", "date"),
                ColumnSpec("user_id", "int", low=1, high=900000),
                ColumnSpec("event_type", "category", categories=EVENT_TYPES),
                ColumnSpec("country", "category", categories=COUNTRIES),
                ColumnSpec("device", "category", categories=DEVICES),
                ColumnSpec("revenue", "float", low=0, high=500, null_rate=0.85),
                ColumnSpec("campaign_id", "int", low=1, high=400),
            ),
            partition_cols=("event_date",),
            sort_keys=(),
            days=(d0, d1),
            rows_per_file=500,
        ),
        TableSpec(
            name="orders",
            description="Order fact table, unpartitioned single directory; date predicates cannot prune.",
            columns=(
                ColumnSpec("order_time", "date"),
                ColumnSpec("customer_id", "int", low=1, high=300000),
                ColumnSpec("status", "category", categories=("new", "paid", "shipped", "cancelled", "returned")),
                ColumnSpec("country", "category", categories=COUNTRIES),
                ColumnSpec("channel", "category", categories=CHANNELS),
                ColumnSpec("amount", "float", low=5, high=2000),
                ColumnSpec("item_count", "int", low=1, high=20),
            ),
            partition_cols=(),
            sort_keys=(),
            days=(d0, d1),
            total_rows=240_000,
        ),
        TableSpec(
            name="page_views",
            description="Web logs partitioned by view_date and hour; hundreds of tiny files.",
            columns=(
                ColumnSpec("view_time", "ts"),
                ColumnSpec("view_date", "date"),
                ColumnSpec("hour", "category", categories=tuple(f"{h:02d}" for h in range(24))),
                ColumnSpec("session_id", "int", low=1, high=2000000),
                ColumnSpec("path", "category", categories=("/", "/search", "/product", "/cart", "/help", "/login")),
                ColumnSpec("country", "category", categories=COUNTRIES),
                ColumnSpec("device", "category", categories=DEVICES),
                ColumnSpec("latency_ms", "float", low=5, high=3000),
            ),
            partition_cols=("view_date", "hour"),
            sort_keys=(),
            days=(date(2024, 6, 1), date(2024, 6, 14)),
            hours=True,
            rows_per_file=160,
        ),
        TableSpec(
            name="users",
            description="User dimension, small, already sorted by signup_date.",
            columns=(
                ColumnSpec("signup_date", "date"),
                ColumnSpec("user_id", "int", low=1, high=900000),
                ColumnSpec("country", "category", categories=COUNTRIES),
                ColumnSpec("plan", "category", categories=("free", "plus", "pro", "enterprise")),
                ColumnSpec("age", "int", low=18, high=80),
            ),
            partition_cols=(),
            sort_keys=("signup_date",),
            days=(date(2022, 1, 1), date(2024, 12, 31)),
            total_rows=80_000,
        ),
    ]


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


def _value(col: ColumnSpec, rng: random.Random, days=None) -> Any:
    if col.null_rate and rng.random() < col.null_rate:
        return None
    if col.kind == "int":
        return rng.randint(int(col.low), int(col.high))
    if col.kind == "float":
        return round(rng.uniform(col.low, col.high), 2)
    if col.kind == "category":
        idx = min(int(rng.random() ** 2 * len(col.categories)), len(col.categories) - 1)
        return col.categories[idx]
    if col.kind == "date":
        return _rand_date(rng, days[0], days[1]) if days else None
    if col.kind == "ts":
        d = _rand_date(rng, days[0], days[1]) if days else "2024-01-01"
        return f"{d} {rng.randint(0,23):02d}:{rng.randint(0,59):02d}:{rng.randint(0,59):02d}"
    return f"{col.name}_{rng.randint(1, 5000):05d}"


def _rand_date(rng: random.Random, lo: date, hi: date) -> str:
    return (lo + timedelta(days=rng.randint(0, max(0, (hi - lo).days)))).isoformat()


def generate_rows(spec: TableSpec, rng: random.Random, n: int, fixed: dict[str, Any] | None = None):
    fixed = fixed or {}
    days = spec.days
    rows = []
    for _ in range(n):
        row = {}
        for col in spec.columns:
            row[col.name] = fixed.get(col.name, _value(col, rng, days))
        rows.append(row)
    return rows


def compute_stats(rows: list[dict[str, Any]], columns: Iterable[ColumnSpec]) -> dict[str, Any]:
    stats: dict[str, Any] = {}
    for col in columns:
        vals = [r.get(col.name) for r in rows if r.get(col.name) is not None]
        entry: dict[str, Any] = {"nulls": len(rows) - len(vals)}
        if not vals:
            entry.update({"min": None, "max": None})
        elif col.kind in ("int", "float", "date") or isinstance(vals[0], (int, float)):
            entry.update({"min": min(vals), "max": max(vals)})
        else:
            distinct = sorted(set(vals))
            entry.update({"min": distinct[0], "max": distinct[-1], "distinct": len(distinct)})
            if len(distinct) <= 64:
                entry["distinct_values"] = distinct
        stats[col.name] = entry
    return stats


def write_file(table: str, rel_path: str, rows: list[dict[str, Any]]) -> int:
    path = os.path.join(store.LAKE_DIR, table, rel_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
    os.replace(tmp, path)
    return os.path.getsize(path)


def remove_file(table: str, rel_path: str) -> None:
    path = os.path.join(store.LAKE_DIR, table, rel_path)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    parent = os.path.dirname(path)
    lake_root = os.path.join(store.LAKE_DIR, table)
    while parent.startswith(lake_root + os.sep):
        try:
            os.rmdir(parent)
        except OSError:
            break
        parent = os.path.dirname(parent)


def read_rows(table: str, rel_path: str) -> list[dict[str, Any]]:
    path = os.path.join(store.LAKE_DIR, table, rel_path)
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


# ---------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------


def seed(conn, reset: bool = False) -> None:
    """Create the demo lake.  Idempotent unless ``reset``."""
    if store.get_meta(conn, "seeded") == "1" and not reset:
        return
    if reset:
        for t in ("undo_log", "applies", "rollback_points", "simulations", "advisories",
                  "executions", "files", "tables", "meta"):
            conn.execute(f"DELETE FROM {t}")
        _wipe_lake()
    rng = random.Random(20261119)
    created = store.utcnow()
    for spec in default_specs():
        _materialize(conn, spec, rng, created)
    store.set_meta(conn, "seeded", "1")
    store.set_meta(conn, "seed_version", "1")
    conn.commit()


def _wipe_lake() -> None:
    root = store.LAKE_DIR
    if not os.path.isdir(root):
        return
    for entry in os.listdir(root):
        path = os.path.join(root, entry)
        if os.path.isdir(path):
            for dirpath, dirnames, filenames in os.walk(path, topdown=False):
                for f in filenames:
                    os.unlink(os.path.join(dirpath, f))
                for d in dirnames:
                    os.rmdir(os.path.join(dirpath, d))
            os.rmdir(path)


def _materialize(conn, spec: TableSpec, rng: random.Random, created: str) -> None:
    conn.execute("DELETE FROM files WHERE table_name=?", (spec.name,))
    conn.execute(
        "INSERT OR REPLACE INTO tables(name,description,partition_cols,sort_keys,columns_json,"
        "row_count,bytes,file_count,stats_updated_at,last_data_change_at,created_at) "
        "VALUES(?,?,?,?,?,0,0,0,?,?,?)",
        (spec.name, spec.description, json.dumps(list(spec.partition_cols)),
         json.dumps(list(spec.sort_keys)),
         json.dumps([{"name": c.name, "kind": c.kind} for c in spec.columns]),
         created, created, created),
    )
    if spec.days is None:
        raise ValueError(f"{spec.name}: days required")
    start, end = spec.days

    if spec.partition_cols:
        day_col = next(c for c in spec.columns if c.name in ("event_date", "view_date"))
        day = start
        while day <= end:
            for hour in (range(24) if spec.hours else [None]):
                n = spec.rows_per_file
                if spec.hours:
                    n = rng.randint(70, 260)
                elif day.month == 11 and day.day in (11, 12, 13):
                    n = spec.rows_per_file * 3  # holiday spike
                fixed = {day_col.name: day.isoformat()}
                if spec.name == "events":
                    fixed["event_time"] = f"{day.isoformat()} 00:00:00"
                else:
                    fixed["view_time"] = f"{day.isoformat()} 00:00:00"
                if hour is not None:
                    fixed["hour"] = f"{hour:02d}"
                rows = generate_rows(spec, rng, n, fixed)
                part = {day_col.name: day.isoformat()}
                rel_parts = [f"{day_col.name}={day.isoformat()}"]
                if hour is not None:
                    rel_parts.append(f"hour={hour:02d}")
                    part["hour"] = f"{hour:02d}"
                _insert_file(conn, spec, rows, "/".join(rel_parts) + "/part-000.jsonl", part, created)
            day += timedelta(days=1)
    else:
        n_files = max(1, min(24, spec.total_rows // 40_000 + 1))
        per_file = max(1, spec.total_rows // n_files)
        for i in range(n_files):
            rows = generate_rows(spec, rng, per_file)
            if spec.sort_keys:
                rows.sort(key=lambda r: (r[spec.sort_keys[0]] is None, str(r[spec.sort_keys[0]])))
            _insert_file(conn, spec, rows, f"part-{i:03d}.jsonl", {}, created)


def _insert_file(conn, spec: TableSpec, rows, rel_path, partition, created):
    size = write_file(spec.name, rel_path, rows)
    stats = compute_stats(rows, spec.columns)
    conn.execute(
        "INSERT INTO files(table_name,rel_path,partition_json,row_count,bytes,stats_json,created_at) "
        "VALUES(?,?,?,?,?,?,?)",
        (spec.name, rel_path, json.dumps(partition), len(rows), size, json.dumps(stats), created),
    )
    store.refresh_table_aggregates(conn, spec.name)
