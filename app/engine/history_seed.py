"""Seed a realistic query history by *actually executing* the sample workload.

Recorded metrics are measured by :mod:`app.engine.executor`; timestamps are
backdated so the history reads like two weeks of dashboard traffic.  Nothing
in ``executions`` is invented — replay the same query and you get the same
scan counts.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from .. import store
from . import executor, sqlparse_lite as sql

HISTORY_VERSION = "1"


def _ts(days_ago: int, minute: int) -> str:
    base = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return base.replace(hour=2 + (minute % 20), minute=minute % 60, second=0, microsecond=0).isoformat(
        timespec="seconds"
    )


# (query, run_count, day offset pattern, client, note)
WORKLOAD: list[tuple[str, int, list[int], str, str]] = [
    (
        "select event_type, count(*) as n from events where event_date = '2024-06-14' group by event_type",
        14, [13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0], "dash-events", "daily events tile",
    ),
    (
        "select country, count(*) as n, sum(revenue) as rev from events "
        "where event_date >= '2024-10-01' and event_date <= '2024-10-31' group by country",
        6, [12, 10, 8, 6, 4, 2], "dash-revenue", "monthly revenue by country",
    ),
    (
        "select device, count(*) as n from events where event_type = 'purchase' group by device",
        18, [13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 3, 2, 2, 1, 1, 0, 0], "bi-refresh", "purchase split by device",
    ),
    (
        "select status, count(*) as n, avg(amount) as avg_amount from orders "
        "where order_time >= '2024-11-25' and order_time <= '2024-12-08' group by status",
        9, [13, 12, 11, 10, 9, 8, 7, 5, 3], "ops-daily", "recent orders by status",
    ),
    (
        "select channel, count(*) as n from orders where status = 'returned' group by channel",
        10, [12, 11, 10, 9, 8, 7, 6, 5, 4, 2], "risk-daily", "return rate by channel",
    ),
    (
        "select country, count(*) as n from orders where order_time >= '2024-01-01' group by country",
        15, [13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 2, 1, 0], "finance-export", "orders by country",
    ),
    (
        "select path, count(*) as n from page_views where view_date = '2024-06-07' group by path",
        11, [11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1], "web-monitor", "top paths",
    ),
    (
        "select count(*) as n from page_views where view_date >= '2024-06-01' "
        "and view_date <= '2024-06-14' and hour = '09'",
        8, [12, 10, 8, 6, 4, 3, 2, 1], "slo-check", "morning traffic probe",
    ),
    (
        "select plan, count(*) as n from users group by plan",
        13, [13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1], "growth", "plan mix",
    ),
    (
        "select count(*) as n from events",
        5, [6, 4, 3, 1, 0], "health-probe", "row count probe",
    ),
    (
        "select country, count(*) as n, sum(revenue) as rev from events "
        "where event_date >= '2024-01-01' and event_date <= '2024-12-31' group by country",
        4, [11, 8, 6, 4], "ad-hoc", "year-to-date pull (ad hoc)",
    ),
]


def seed_history(conn, reset: bool = False) -> None:
    if store.get_meta(conn, "history_seeded") == HISTORY_VERSION and not reset:
        return
    if reset:
        conn.execute("DELETE FROM executions")
    rng = random.Random(7)

    for query, runs, days, client, _note in WORKLOAD:
        select = sql.parse(query)
        # Replay the query once against the real lake; every metric recorded for
        # this query shape below is that measured result.
        result = executor.execute(conn, select, collect_rows=False, max_result_rows=0)
        m = result.metrics
        fp = select.fingerprint()
        for i in range(runs):
            ts = _ts(days[i % len(days)], rng.randint(0, 1439))
            conn.execute(
                "INSERT INTO executions(ts,query,fingerprint,table_name,origin,client,status,error,"
                "duration_ms,bytes_scanned,rows_scanned,rows_returned,files_scanned,files_total,"
                "files_pruned,result_bytes,plan_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    ts, query, fp, select.table, "history", client, "ok", None,
                    m["duration_ms"], m["bytes_scanned"], m["rows_scanned"], m["rows_returned"],
                    m["files_scanned"], m["files_total"], m["files_pruned"], m["result_bytes"],
                    store.json_dumps(result.plan),
                ),
            )

    # One genuinely failing execution (bad column), recorded through the same
    # path a live request would use.
    bad = "select missing_column, count(*) as n from events group by missing_column"
    try:
        executor.execute(conn, sql.parse(bad))
    except Exception as exc:  # noqa: BLE001 - we want the real message
        conn.execute(
            "INSERT INTO executions(ts,query,fingerprint,table_name,origin,client,status,error,"
            "duration_ms,bytes_scanned,rows_scanned,rows_returned,files_scanned,files_total,"
            "files_pruned,result_bytes,plan_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                _ts(1, 77), bad, sql.parse(bad).fingerprint(), "events", "history",
                "adhoc-notebook", "error", str(exc), 0.4, 0, 0, 0, 0, 0, 0, 0, "{}",
            ),
        )

    # One table has new data that landed after the last ANALYZE: its catalog
    # stats are now older than the data, which the analyzer must surface.
    conn.execute(
        "UPDATE tables SET last_data_change_at=? WHERE name='events'", (store.utcnow(),)
    )
    store.set_meta(conn, "history_seeded", HISTORY_VERSION)
    conn.commit()
