"""Detectors for query-history problems.

Every advisory carries structured, human-readable evidence (``evidence_json``)
and links the exact execution samples it was derived from.  Nothing here is a
black box: each finding names the metric, the threshold, the observed value and
the rows it came from.
"""

from __future__ import annotations

import json
import math
import statistics
from dataclasses import dataclass, field
from typing import Any

from .. import store
from . import sqlparse_lite as sql

# Tunables live in one place so the UI can show the rule that fired.
CONFIG = {
    # overscan: scanned bytes per returned byte above this is "scanning too much"
    "overscan_ratio": 50.0,
    "overscan_min_bytes": 1_000_000,
    "overscan_floor_result_bytes": 64 * 1024,
    # partition miss: a selective predicate while most files are still scanned
    "partition_min_files": 4,
    "partition_max_selectivity": 0.25,
    "partition_min_prune_gap": 0.5,
    # repeated aggregation
    "repeat_min_runs": 12,
    "repeat_min_total_ms": 3000.0,
    # small files
    "small_file_bytes": 512 * 1024,
    "small_file_min_count": 24,
    # abnormal executions: >= this multiple of the fingerprint median
    "abnormal_multiplier": 4.0,
    "abnormal_min_ms": 400.0,
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _pct(x: float) -> float:
    return round(100.0 * x, 1)


# ---------------------------------------------------------------------------
# History summaries
# ---------------------------------------------------------------------------


def load_executions(conn, limit: int = 5000) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM executions ORDER BY ts ASC, id ASC LIMIT ?", (limit,)
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["plan"] = _safe_json(d.get("plan_json"))
        out.append(d)
    return out


def _safe_json(raw: Any) -> Any:
    try:
        return json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        return {}


@dataclass
class FingerprintStats:
    fingerprint: str
    table: str
    sample_query: str
    runs: list[dict[str, Any]] = field(default_factory=list)
    select: sql.Select | None = None

    @property
    def count(self) -> int:
        return len(self.runs)

    @property
    def avg_ms(self) -> float:
        return statistics.fmean(r["duration_ms"] for r in self.runs) if self.runs else 0.0

    @property
    def total_ms(self) -> float:
        return sum(r["duration_ms"] for r in self.runs)

    @property
    def avg_bytes(self) -> float:
        return statistics.fmean(r["bytes_scanned"] for r in self.runs) if self.runs else 0.0

    @property
    def avg_rows_scanned(self) -> float:
        return statistics.fmean(r["rows_scanned"] for r in self.runs) if self.runs else 0.0

    @property
    def avg_rows_returned(self) -> float:
        return statistics.fmean(max(1, r["rows_returned"]) for r in self.runs) if self.runs else 1.0

    @property
    def avg_result_bytes(self) -> float:
        return statistics.fmean(max(1, r["result_bytes"]) for r in self.runs) if self.runs else 1.0

    @property
    def median_ms(self) -> float:
        return statistics.median(r["duration_ms"] for r in self.runs) if self.runs else 0.0


def group_executions(execs: list[dict[str, Any]]) -> list[FingerprintStats]:
    groups: dict[str, FingerprintStats] = {}
    for e in execs:
        if e.get("status") != "ok":
            continue
        fp = e["fingerprint"]
        g = groups.get(fp)
        if g is None:
            g = FingerprintStats(
                fingerprint=fp,
                table=e["table_name"],
                sample_query=e["query"],
            )
            groups[fp] = g
        g.runs.append(e)
    for g in groups.values():
        try:
            g.select = sql.parse(g.runs[-1]["query"])
        except sql.QueryError:
            g.select = None
    return list(groups.values())


# ---------------------------------------------------------------------------
# Layout model: exact zone-map pruning + modelled repartitioning
# ---------------------------------------------------------------------------


@dataclass
class PruneProjection:
    """Remaining files under a proposed layout.

    ``files_scanned`` is a model, not a measurement.  ``total_files`` is the
    file count the proposed layout would have, so pruning is compared against
    the new layout rather than today's file count (which may differ by an order
    of magnitude after a rewrite).  ``lower``/``upper`` bracket the model error.
    """

    files_scanned: float
    lower: float
    upper: float
    basis: str
    assumptions: list[str]
    total_files: float = 0.0

    @property
    def prune_fraction(self) -> float:
        if self.total_files <= 0:
            return 0.0
        return max(0.0, 1.0 - self.files_scanned / self.total_files)

    def as_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": round(self.files_scanned, 1),
            "total_files": round(self.total_files, 1),
            "prune_pct": round(self.prune_fraction * 100, 1),
            "bound_low": round(self.lower, 1),
            "bound_high": round(self.upper, 1),
            "basis": self.basis,
            "assumptions": self.assumptions,
        }


def _granularity_for(column_kind: str | None, partition_col: str) -> str:
    if partition_col.startswith("month:"):
        return "month"
    if column_kind == "date":
        return "month"
    return "value"


def _partition_value(column: str, kind: str) -> str:
    return f"month:{column}" if kind == "month" else column


def _predicate_span(select: sql.Select, column: str) -> dict[str, Any] | None:
    """Uniform [lo,hi] constraint on a column, plus point values."""
    eq: list[Any] = []
    lo = hi = None
    for col, node in select.equalities():
        if col != column:
            continue
        if isinstance(node, sql.InList):
            eq.extend(v.value for v in node.values if isinstance(v, sql.Literal))
        else:
            eq.extend(sql.literal_values(node))
    for col, op, node in select.ranges():
        if col != column:
            continue
        vals = sql.literal_values(node)
        if len(vals) != 1:
            continue
        v = vals[0]
        if op in (">=", ">"):
            lo = v if lo is None else max(lo, v, key=str)
        elif op in ("<=", "<"):
            hi = v if hi is None else min(hi, v, key=str)
    for col, node in select.equalities():
        if col.startswith("__func__:"):
            _, fn, src = col.split(":", 2)
            if src == column:
                eq.extend(v.value for v in node.values if isinstance(v, sql.Literal))
    if not eq and lo is None and hi is None:
        return None
    return {"eq": eq, "lo": lo, "hi": hi}


def _overlap_fraction(stat_min: Any, stat_max: Any, span: dict[str, Any]) -> float:
    """Fraction of the file's [min,max] that the predicate admits (uniform model)."""
    if stat_min is None or stat_max is None:
        return 1.0
    if span.get("eq"):
        hits = sum(1 for v in span["eq"] if _between(stat_min, v, stat_max))
        return 1.0 if hits else 0.0
    lo = span.get("lo")
    hi = span.get("hi")
    if lo is None and hi is None:
        return 1.0
    a, b = str(stat_min), str(stat_max)
    # date-space arithmetic: compare on ISO prefix so months work
    if _is_month_bounds(lo, hi):
        a, b = a[:7], b[:7]
    lo_c = a if lo is None or str(lo) <= a else str(lo)
    hi_c = b if hi is None or str(hi) >= b else str(hi)
    if _cmp_str(lo_c, hi_c) > 0:
        return 0.0
    total = _span_days(a, b)
    kept = _span_days(lo_c, hi_c)
    if total <= 0:
        return 1.0
    return max(0.0, min(1.0, kept / total))


def _between(lo: Any, v: Any, hi: Any) -> bool:
    return _cmp_str(str(lo), str(v)) <= 0 and _cmp_str(str(v), str(hi)) <= 0


def _cmp_str(a: str, b: str) -> int:
    return -1 if a < b else (1 if a > b else 0)


def _span_days(a: str, b: str) -> float:
    from datetime import date

    try:
        da = date.fromisoformat(a[:10])
        db = date.fromisoformat(b[:10])
        return max(0.0, float((db - da).days + 1))
    except ValueError:
        return 1.0


def _is_month_bounds(lo: Any, hi: Any) -> bool:
    for v in (lo, hi):
        if v is None:
            continue
        s = str(v)
        if len(s) == 7 and s[4] == "-":
            return True
    return False


def project_repartition(files: list[dict[str, Any]], column: str, column_kind: str | None,
                        select: sql.Select, sort_keys: tuple[str, ...] = (),
                        target_file_bytes: int = 8 * 1024 * 1024,
                        kept_partitions: tuple[str, ...] = ()) -> PruneProjection | None:
    """Model the file count after laying rows out by ``column``.

    Computed on the *new* partition granularity — a month is one directory, not
    a fraction of today's files — so it does not inherit the error of the
    current layout's wide zone maps.
    """
    span = _predicate_span(select, column)
    if span is None:
        return None
    total_bytes = sum(int(f["bytes"]) for f in files)
    total_rows = sum(int(f["row_count"]) for f in files)
    if total_rows == 0:
        return None

    if column_kind == "date" or column.startswith("month:"):
        buckets = _date_buckets(files, column, span)
        if buckets is None:
            return None
        full, partial, total_months = buckets
        per_month = max(1, math.ceil(total_bytes / max(1, total_months) / target_file_bytes))
        # Partitions that are kept stay in the path, so the new layout still has
        # one directory per kept-partition value under every new partition.
        kept_dirs = _kept_partition_dirs(files, kept_partitions)
        # Files per month across *all* retained sub-partitions.  A query that
        # filters only the new date column still reads every retained
        # sub-partition (e.g. all hours) inside the months it touches.
        per_month = max(1, per_month) * kept_dirs
        per_keep = _per_group_files(files, kept_partitions, target_file_bytes,
                                    total_months, total_bytes)
        total_files = float(total_months * kept_dirs * per_keep) if kept_partitions else float(total_months * per_month)
        per_scanned_month = per_keep * kept_dirs
        # A partial month is assumed half-scanned; bounds are "skip every partial
        # month" and "scan every partial month".  Retained sub-partition
        # directories inside each month are always scanned when not constrained.
        est = float((full + partial * 0.5) * per_scanned_month)
        return PruneProjection(
            files_scanned=est,
            lower=float(full * per_scanned_month),
            upper=float((full + partial) * per_scanned_month),
            basis="projected month partitions overlapping the date predicate",
            assumptions=[
                f"one directory per calendar month on {column}",
                "every month directory is exactly prunable (month is in the path)",
                "partially covered months are assumed half-scanned",
                f"output files target {target_file_bytes // (1024*1024)} MiB",
            ],
            total_files=total_files,
        )

    values = span.get("eq") or []
    if values:
        distinct_hit = len({str(v) for v in values})
        total_distinct = max(1, _distinct_count(files, column))
        per_value_bytes = total_bytes / total_distinct
        per_file = max(1, math.ceil(per_value_bytes / target_file_bytes))
        kept_dirs = _kept_partition_dirs(files, kept_partitions)
        est = float(distinct_hit * per_file * kept_dirs)
        total_files = float(total_distinct * per_file * kept_dirs)
        return PruneProjection(
            files_scanned=est,
            lower=est,
            upper=est,
            basis="one partition per distinct predicate value",
            assumptions=[f"partition by {column}", "each distinct value is its own partition"],
            total_files=total_files,
        )
    return None


def _per_group_files(files, kept_partitions, target_file_bytes, total_months, total_bytes) -> int:
    if not kept_partitions:
        return 1
    return max(1, math.ceil(total_bytes / max(1, total_months) / max(1, _kept_partition_dirs(files, kept_partitions)) / target_file_bytes))


def _kept_partition_dirs(files: list[dict[str, Any]], kept_partitions: tuple[str, ...]) -> int:
    """Multiplier from retained partition keys in the *output* layout.

    A retained key that is itself a date is re-bucketed to months (handled by
    the new date bucket), so it does not multiply.  Retained non-date keys
    (hour, category) survive per value and do not reduce the file count below
    their cardinality either — they divide the bytes, they do not multiply the
    directory count in this model, so the conservative multiplier is 1 and the
    lower bound of pruning is reported separately.
    """
    if not kept_partitions:
        return 1
    keys = {
        json.dumps({k: (f.get("partition") or {}).get(k) for k in kept_partitions}, sort_keys=True)
        for f in files
    }
    return max(1, len(keys))


def _table_min(files, column):
    vals = [((f.get("stats") or {}).get(column) or {}).get("min") for f in files]
    vals = [v for v in vals if v is not None]
    return min(vals) if vals else "1970-01-01"


def _table_max(files, column):
    vals = [((f.get("stats") or {}).get(column) or {}).get("max") for f in files]
    vals = [v for v in vals if v is not None]
    return max(vals) if vals else "1970-01-01"


def _distinct_count(files, column) -> int:
    for f in files:
        entry = (f.get("stats") or {}).get(column) or {}
        if entry.get("distinct"):
            return int(entry["distinct"])
    return 1


def _date_buckets(files, column, span) -> tuple[int, int, int] | None:
    """(fully covered months, partially covered months, total months)."""
    table_lo = str(_table_min(files, column))[:10]
    table_hi = str(_table_max(files, column))[:10]
    total_months = max(1, _months_between(_month_start_of(table_lo), _month_start_of(table_hi)))

    eq = span.get("eq") or []
    if eq:
        months = {str(v)[:7] for v in eq}
        return len(months), 0, total_months

    lo = str(span.get("lo") or table_lo)[:10]
    hi = str(span.get("hi") or table_hi)[:10]
    lo = max(lo, table_lo)
    hi = min(hi, table_hi)
    if _cmp_str(lo, hi) > 0:
        return 0, 0, total_months

    full = partial = 0
    m = _month_start_of(lo)
    last = _month_start_of(hi)
    while _cmp_str(m, last) <= 0:
        start_ok = _cmp_str(lo, m) <= 0
        end_ok = _cmp_str(hi, _month_end(m)) >= 0
        if start_ok and end_ok:
            full += 1
        else:
            partial += 1
        m = _month_start_after(m)
    return full, partial, total_months


def _month_start_of(d: str) -> str:
    return d[:7] + "-01"


def _month_start_after(d: str) -> str:
    y, m = int(d[:4]), int(d[5:7])
    m += 1
    if m > 12:
        y, m = y + 1, 1
    return f"{y:04d}-{m:02d}-01"


def _month_end(d: str) -> str:
    from datetime import date, timedelta

    y, m = int(d[:4]), int(d[5:7])
    ny, nm = (y + 1, 1) if m == 12 else (y, m + 1)
    return (date(ny, nm, 1) - timedelta(days=1)).isoformat()


def _months_between(a: str, b: str) -> int:
    return (int(b[:4]) - int(a[:4])) * 12 + (int(b[5:7]) - int(a[5:7])) + 1


def project_cluster(files: list[dict[str, Any]], column: str, select: sql.Select,
                    target_file_bytes: int = 1024 * 1024) -> PruneProjection | None:
    """Model pruning after rewriting the table sorted by ``column``.

    Sorted output gives each file a contiguous key range, so zone maps can skip
    files whose range excludes the predicate.  The fraction of the key domain a
    predicate touches is estimated from catalog statistics.
    """
    span = _predicate_span(select, column)
    if span is None or not files:
        return None
    total_bytes = sum(int(f["bytes"]) for f in files)
    total_files = max(1.0, math.ceil(total_bytes / target_file_bytes))

    kind_entry = None
    for f in files:
        kind_entry = (f.get("stats") or {}).get(column)
        if kind_entry:
            break
    if not kind_entry:
        return None

    eq = span.get("eq") or []
    if eq:
        distinct_total = _distinct_count(files, column)
        frac = min(1.0, len({str(v) for v in eq}) / max(1, distinct_total))
        basis = "equality predicate vs distinct-value count on the cluster key"
    else:
        lo = str(span.get("lo") or _table_min(files, column))[:10]
        hi = str(span.get("hi") or _table_max(files, column))[:10]
        domain = max(1.0, _span_days(str(_table_min(files, column))[:10],
                                     str(_table_max(files, column))[:10]))
        frac = min(1.0, max(0.0, _span_days(lo, hi) / domain))
        basis = "range predicate vs key domain span"

    if eq and kind_entry.get("distinct") is None:
        return None
    frac = max(frac, 1.0 / total_files)
    est = max(1.0, total_files * frac)
    return PruneProjection(
        files_scanned=est,
        lower=max(1.0, est * 0.5),
        upper=min(total_files, est * 2.0),
        basis=f"sorted-layout range model ({basis})",
        assumptions=[
            f"table rewritten sorted by {column}",
            "each output file holds a contiguous slice of the sort key",
            f"output files target {target_file_bytes // (1024*1024)} MiB",
            "the predicate's key range is read at full density",
        ],
        total_files=total_files,
    )


# ---------------------------------------------------------------------------
# Diagnostics: stale stats & abnormal executions
# ---------------------------------------------------------------------------


def stale_tables(conn) -> list[dict[str, Any]]:
    out = []
    for t in store.list_tables(conn):
        if t["stats_stale"]:
            out.append(
                {
                    "table": t["name"],
                    "stats_updated_at": t["stats_updated_at"],
                    "last_data_change_at": t["last_data_change_at"],
                    "message": "catalog statistics are older than the last data change; "
                               "pruning and simulation estimates may be wrong",
                }
            )
    return out


def abnormal_executions(execs: list[dict[str, Any]], groups: list[FingerprintStats]) -> list[dict[str, Any]]:
    by_fp = {g.fingerprint: g for g in groups}
    findings = []
    for e in execs:
        reasons = []
        if e.get("status") != "ok":
            reasons.append({"kind": "error", "detail": e.get("error") or "execution failed"})
        g = by_fp.get(e["fingerprint"])
        if g and g.count >= 4:
            med = g.median_ms
            if med > 0 and e["duration_ms"] >= CONFIG["abnormal_min_ms"] and e["duration_ms"] > CONFIG["abnormal_multiplier"] * med:
                reasons.append(
                    {
                        "kind": "slow_outlier",
                        "detail": f"{e['duration_ms']:.0f} ms vs {med:.0f} ms median for the same query",
                    }
                )
            med_bytes = statistics.median(r["bytes_scanned"] for r in g.runs)
            if e["bytes_scanned"] > 2 * med_bytes + 1_500_000 and e["bytes_scanned"] > 2_000_000:
                reasons.append(
                    {
                        "kind": "scan_spike",
                        "detail": f"scanned {e['bytes_scanned']:,} B vs {med_bytes:,.0f} B median",
                    }
                )
        if e.get("files_total") and e["files_scanned"] >= e["files_total"] and e["files_total"] >= CONFIG["partition_min_files"]:
            try:
                sel = sql.parse(e["query"])
            except sql.QueryError:
                sel = None
            if sel is not None and sel.where is None:
                reasons.append(
                    {
                        "kind": "unfiltered_full_scan",
                        "detail": f"no WHERE clause, scanned all {e['files_total']} files",
                    }
                )
        if reasons:
            findings.append({"execution_id": e["id"], "ts": e["ts"], "query": e["query"],
                             "table": e["table_name"], "reasons": reasons})
    return findings


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def _advisory(kind, table, title, severity, confidence, rationale, sample_ids, fingerprint=None):
    return {
        "kind": kind,
        "table_name": table,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "rationale_json": json.dumps(rationale, ensure_ascii=False),
        "sample_ids": sample_ids,
        "fingerprint": fingerprint,
    }


def detect(conn) -> list[dict[str, Any]]:
    execs = load_executions(conn)
    groups = group_executions(execs)
    tables = {t["name"]: t for t in store.list_tables(conn)}
    files_by_table = {name: store.file_rows(conn, name) for name in tables}
    advisories: list[dict[str, Any]] = []

    for g in groups:
        table = tables.get(g.table)
        if table is None or g.select is None or g.count < 2:
            continue
        files = files_by_table[table["name"]]
        if not files:
            continue
        partition_gap = _partition_gap(g, table, files)
        date_partition_finding = partition_gap >= CONFIG["partition_min_prune_gap"]

        # -- overscan ------------------------------------------------------
        ratio = g.avg_bytes / max(CONFIG["overscan_floor_result_bytes"], g.avg_result_bytes)
        scanned_frac = g.runs[-1]["files_scanned"] / max(1, g.runs[-1]["files_total"])
        # A query with no predicate and no limit has nothing to prune; that is a
        # full scan, reported by the abnormal-execution view instead.
        prunable = g.select.where is not None or g.select.limit is not None
        if prunable and ratio >= CONFIG["overscan_ratio"] and g.avg_bytes >= CONFIG["overscan_min_bytes"]:
            rationale = {
                "rule": f"扫描字节 / 返回字节 >= {CONFIG['overscan_ratio']:.0f}（返回字节按下限 {CONFIG['overscan_floor_result_bytes']//1024} KiB 计）",
                "observed": {
                    "avg_bytes_scanned": round(g.avg_bytes),
                    "avg_result_bytes": round(g.avg_result_bytes),
                    "result_bytes_floor": CONFIG["overscan_floor_result_bytes"],
                    "ratio": round(ratio, 1),
                    "avg_rows_scanned": round(g.avg_rows_scanned),
                    "avg_rows_returned": round(g.avg_rows_returned),
                    "runs": g.count,
                    "files_scanned_pct": _pct(scanned_frac),
                },
                "evidence": [
                    f"该查询形状 {g.count} 次执行平均扫描 {g.avg_bytes/1e6:.1f} MB，"
                    f"只返回 {g.avg_result_bytes/1024:.1f} KB",
                    f"行选择率约 {g.avg_rows_returned / max(1.0, g.avg_rows_scanned) * 100:.3f}%",
                ],
            }
            cluster = _cluster_candidate(g.select, table)
            if cluster is not None and not date_partition_finding:
                column, column_kind = cluster
                partition_cols = table.get("partition_cols") or []
                if partition_cols:
                    # The table is already physically partitioned: sorting inside
                    # each partition cannot prune across partition directories.
                    pron = project_repartition(
                        files, column, _column_kind(table, column), g.select,
                        kept_partitions=tuple(partition_cols),
                    )
                    rationale["recommendation"] = {
                        "action": "add_partition",
                        "partition_by": [f"month:{column}" if column_kind == "date" else column],
                        "keep_partitions": partition_cols,
                        "sort_keys": table["sort_keys"],
                        "note": "replace the current partition column; "
                                "sorting inside existing partitions does not prune",
                    }
                else:
                    pron = project_cluster(files, column, g.select)
                    rationale["recommendation"] = {
                        "action": "cluster",
                        "cluster_by": column,
                        "sort_keys": [column],
                        "target_file_bytes": 1024 * 1024,
                    }
                if pron is not None:
                    rationale["alternative_projection"] = pron.as_dict()
                    if pron.prune_fraction < 0.25:
                        # Predicate already covers the key domain: a layout change
                        # will not remove scans, so do not pretend it will.
                        rationale["recommendation"] = None
                        rationale["evidence"].append(
                            f"调整布局仅能在 {column} 上裁掉约 "
                            f"{pron.prune_fraction*100:.0f}% 的文件；该扫描量来自查询范围本身，"
                            "不是布局问题，因此不给出布局建议"
                        )
                        pron = None
                if pron is not None:
                    rationale["evidence"].append(
                        f"当前布局中 {column} 不是可裁剪键，每个文件的 zone map 覆盖整表范围"
                    )
            elif not date_partition_finding:
                # No column to lay the table out by: the scan comes from the
                # predicate's own range or from a non-key filter.  Say so
                # instead of leaving the recommendation blank without a reason.
                rationale["recommendation"] = None
                rationale["evidence"].append(
                    "该查询的过滤条件不在任何可分区/排序的列上，调整物理布局无法裁剪这次扫描；"
                    "建议从查询本身入手（缩小时间范围、增加聚合粒度或限制返回列）"
                )
            if not date_partition_finding:
                # If a partition gap explains the scan, only that finding is
                # raised for this query: one cause, one advisory.
                sev = "high" if ratio >= 500 else "medium"
                advisories.append(_advisory(
                    "overscan", table["name"],
                    f"查询扫描字节是返回值的 {ratio:,.0f} 倍",
                    sev, "high" if g.count >= 5 else "medium", rationale,
                    [r["id"] for r in g.runs[-3:]], g.fingerprint,
                ))

        # -- partition miss / missing partition ---------------------------
        if files and len(files) >= CONFIG["partition_min_files"]:
            candidate = _partition_candidate(g.select, table)
            if candidate is not None:
                column, kind = candidate
                pron = project_repartition(
                    files, column, _column_kind(table, column), g.select,
                    kept_partitions=tuple(table.get("partition_cols") or ()),
                )
                if pron is not None:
                    observed_prune = 1.0 - (g.runs[-1]["files_scanned"] / max(1, g.runs[-1]["files_total"]))
                    projected_prune = pron.prune_fraction
                    if projected_prune - observed_prune >= CONFIG["partition_min_prune_gap"]:
                        spec = _partition_value(column, kind)
                        sort_projection = project_cluster(files, column, g.select)
                        rationale = {
                            "rule": "查询有明显选择性的谓词，但当前布局几乎不裁剪文件；"
                                    f"投影裁剪率比实测高出 {_pct(CONFIG['partition_min_prune_gap'])} 个百分点以上",
                            "observed": {
                                "predicate_column": column,
                                "current_partition_cols": table["partition_cols"],
                                "files_scanned": g.runs[-1]["files_scanned"],
                                "files_total": g.runs[-1]["files_total"],
                                "observed_prune_pct": _pct(observed_prune),
                                "projected_prune_pct": _pct(projected_prune),
                                "projected": pron.as_dict(),
                            },
                            "evidence": [
                                f"查询在 {column} 上有过滤条件，但仍读取了 "
                                f"{g.runs[-1]['files_scanned']}/{g.runs[-1]['files_total']} 个文件",
                                f"该谓词覆盖列取值范围约 "
                                f"{_selectivity_hint(files, column, g.select):.1%} 的行",
                                f"目录记录显示该表当前分区列为 "
                                f"{', '.join(table['partition_cols']) or '无'}",
                            ],
                            "recommendation": {
                                "action": "add_partition",
                                "partition_by": [spec],
                                "keep_partitions": table["partition_cols"],
                                "sort_keys": table["sort_keys"],
                            },
                            "confidence": "medium",
                        }
                        if sort_projection is not None:
                            rationale["alternatives"] = [{
                                "action": "cluster",
                                "cluster_by": column,
                                "sort_keys": [column],
                                "target_file_bytes": 1024 * 1024,
                                "projected": sort_projection.as_dict(),
                                "tradeoff": "no new partition directories, but the whole table "
                                            "is still scanned once per query when the predicate "
                                            "is not a prefix of the sort key",
                            }]
                        advisories.append(_advisory(
                            "partition_miss", table["name"],
                            f"{column} 上的时间谓词只裁掉 {_pct(observed_prune)}% 的文件",
                            "high" if projected_prune - observed_prune > 0.8 else "medium",
                            "medium", rationale, [r["id"] for r in g.runs[-3:]], g.fingerprint,
                        ))

        # -- repeated aggregation -----------------------------------------
        if (
            g.count >= CONFIG["repeat_min_runs"]
            and g.total_ms >= CONFIG["repeat_min_total_ms"]
            and g.select.has_aggregation()
        ):
            aggs = [sql.format_expr(c) for c in g.select.aggregate_calls()]
            rationale = {
                "rule": f"同一规范化查询形状执行 >= {CONFIG['repeat_min_runs']} 次，"
                        f"且累计耗时 >= {CONFIG['repeat_min_total_ms']:.0f} 毫秒，且包含聚合",
                "observed": {
                    "runs": g.count,
                    "total_ms": round(g.total_ms),
                    "avg_ms": round(g.avg_ms),
                    "group_by": list(g.select.group_by),
                    "aggregates": aggs,
                    "avg_rows_scanned": round(g.avg_rows_scanned),
                    "distinct_fingerprint": g.fingerprint,
                },
                "evidence": [
                    f"{g.count} 次执行共享同一个规范化查询形状",
                    f"累计计算时间 {g.total_ms/1000:.1f} 秒",
                    "每次执行都从原始表重新聚合",
                ],
                "recommendation": {
                    "action": "materialize",
                    "group_by": list(g.select.group_by),
                    "aggregates": aggs,
                },
                "confidence": "high",
            }
            advisories.append(_advisory(
                "repeated_aggregation", table["name"],
                f"同一聚合被重复执行 {g.count} 次（累计 {g.total_ms/1000:.1f} 秒）",
                "medium", "high", rationale, [r["id"] for r in g.runs[-3:]], g.fingerprint,
            ))

    # -- small files ------------------------------------------------------
    for name, files in files_by_table.items():
        if len(files) < CONFIG["small_file_min_count"]:
            continue
        t = tables[name]
        if not t.get("columns"):
            continue
        small = [f for f in files if int(f["bytes"]) < CONFIG["small_file_bytes"]]
        if len(small) < CONFIG["small_file_min_count"]:
            continue
        total_bytes = sum(int(f["bytes"]) for f in files)
        sizes = sorted(int(f["bytes"]) for f in files)
        median = statistics.median(sizes)
        partition_dirs = len({json.dumps(f.get("partition") or {}, sort_keys=True) for f in files})
        target_bytes = 8 * 1024 * 1024
        compacted_files = max(partition_dirs, round(total_bytes / target_bytes))
        rationale = {
            "rule": f"文件数 >= {CONFIG['small_file_min_count']}，其中小文件（< "
                    f"{CONFIG['small_file_bytes']//1024} KiB）数量 >= {CONFIG['small_file_min_count']}",
            "observed": {
                "file_count": len(files),
                "small_files": len(small),
                "median_file_bytes": int(median),
                "avg_file_bytes": round(total_bytes / len(files)),
                "total_bytes": total_bytes,
                "partitions": partition_dirs,
                "files_after_compaction": compacted_files,
            },
            "evidence": [
                f"{len(small)}/{len(files)} 个文件小于 {CONFIG['small_file_bytes']//1024} KiB"
                f"（中位数 {median/1024:.0f} KiB）",
                f"每次全表扫描需要打开 {len(small)} 个小文件",
            ],
            "confidence": "high",
        }
        if compacted_files < len(files) * 0.9:
            rationale["recommendation"] = {"action": "compact", "target_file_bytes": target_bytes}
            rationale["evidence"].append(
                f"合并后约剩 {compacted_files} 个文件（下限为 {partition_dirs} 个分区目录）"
            )
        else:
            # Files are already one-per-partition: merging inside a partition has
            # nothing to merge.  Only a coarser partition granularity helps.
            date_cols = [pc for pc in (t.get("partition_cols") or [])
                         if _column_kind(t, pc.split(":", 1)[-1]) == "date"]
            if date_cols:
                column = date_cols[0].split(":", 1)[-1]
                rationale["recommendation"] = {
                    "action": "add_partition",
                    "partition_by": [f"month:{column}"],
                    "keep_partitions": [pc for pc in t["partition_cols"]
                                        if pc not in date_cols],
                    "sort_keys": t["sort_keys"],
                    "note": "compaction cannot merge across partition directories; "
                            "coarsen the date partition instead",
                }
                rationale["evidence"].append(
                    f"{partition_dirs} 个分区目录每个只有 1 个文件，按 {target_bytes//(1024*1024)} MiB "
                    f"目标合并无法把文件数降到 {partition_dirs} 以下；改为按月分区 {column} 可以"
                )
            else:
                rationale["recommendation"] = None
                rationale["evidence"].append(
                    "文件已按当前布局合并到极限；文件数由分区目录决定，而不是合并策略"
                )
        advisories.append(_advisory(
            "small_files", name,
            f"{len(small)} 个小文件抬高扫描开销",
            "medium" if len(small) >= 100 else "low", "high", rationale,
            [], None,
        ))

    advisories.sort(key=lambda a: (SEVERITY_ORDER.get(a["severity"], 9), a["kind"], a["table_name"]))
    return advisories


def _partition_gap(g: "FingerprintStats", table: dict[str, Any],
                   files: list[dict[str, Any]]) -> float:
    """Best partition-pruning improvement available for this query, in [0,1]."""
    if not files:
        return 0.0
    candidate = _partition_candidate(g.select, table)
    if candidate is None:
        return 0.0
    column, kind = candidate
    pron = project_repartition(
        files, column, _column_kind(table, column), g.select,
        kept_partitions=tuple(table.get("partition_cols") or ()),
    )
    if pron is None:
        return 0.0
    observed = 1.0 - (g.runs[-1]["files_scanned"] / max(1, g.runs[-1]["files_total"]))
    return pron.prune_fraction - observed


def _cluster_candidate(select: sql.Select, table: dict[str, Any]) -> tuple[str, str] | None:
    """Most selective non-partition predicate column to sort/cluster by."""
    existing = {pc.split(":", 1)[-1] for pc in (table.get("partition_cols") or [])}
    best = None
    for column, kind in _predicate_columns(select, table):
        if column in existing or kind not in ("date", "category", "int"):
            continue
        span = _predicate_span(select, column)
        if span is None:
            continue
        score = 2 if kind == "date" else 1
        if span.get("eq") or span.get("lo") is not None or span.get("hi") is not None:
            score += 1
        if best is None or score > best[2]:
            best = (column, kind, score)
    if best is None:
        return None
    return best[0], best[1]


def _column_kind(table: dict[str, Any], column: str) -> str | None:
    for c in table.get("columns") or []:
        if c.get("name") == column:
            return c.get("kind")
    return None


def _selectivity_hint(files: list[dict[str, Any]], column: str, select: sql.Select) -> float:
    span = _predicate_span(select, column)
    if not span or not files:
        return 1.0
    total = sum(_overlap_fraction((f.get("stats") or {}).get(column, {}).get("min"),
                                  (f.get("stats") or {}).get(column, {}).get("max"), span)
                * int(f["row_count"]) for f in files)
    rows = sum(int(f["row_count"]) for f in files) or 1
    return total / rows


def _partition_candidate(select: sql.Select, table: dict[str, Any]) -> tuple[str, str] | None:
    """A selective column worth partitioning on, with granularity."""
    if select.where is None:
        return None
    partition_cols = table.get("partition_cols") or []
    existing_sources = {pc.split(":", 1)[1] if ":" in pc else pc for pc in partition_cols}
    best = None
    for column, kind in _predicate_columns(select, table):
        if column in existing_sources:
            continue
        # Partitioning is recommended for time columns only: date partitions are
        # bounded in count and match how analytical predicates are written.
        # Category/ID predicates are handled by the clustering path instead.
        if kind != "date":
            continue
        span = _predicate_span(select, column)
        if span is None:
            continue
        width = len(span.get("eq") or []) or 0
        # A narrow point set or an explicit range is a good partition key.
        if width == 0 and span.get("lo") is None and span.get("hi") is None:
            continue
        score = 2 if kind == "date" else 1
        if best is None or score > best[2]:
            best = (column, kind, score)
    if best is None:
        return None
    column, _kind, _score = best
    return column, "month"


def _predicate_columns(select: sql.Select, table: dict[str, Any]) -> list[tuple[str, str]]:
    kinds = {c["name"]: c.get("kind") for c in (table.get("columns") or [])}
    seen: list[tuple[str, str]] = []
    for col, node in select.equalities():
        src = col
        if col.startswith("__func__:"):
            _, _, src = col.split(":", 2)
        if src in kinds and (src, kinds[src]) not in seen:
            seen.append((src, kinds[src]))
    for col, op, node in select.ranges():
        src = col
        if col.startswith("__func__:"):
            _, _, src = col.split(":", 2)
        if src in kinds and (src, kinds[src]) not in seen:
            seen.append((src, kinds[src]))
    return seen
