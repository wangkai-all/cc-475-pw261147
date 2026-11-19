"""Minimal JSON-over-HTTP API built on the standard library.

Routes are deliberately explicit; the frontend is a single static page served
from :mod:`app.webui`.
"""

from __future__ import annotations

import json
import os
import re
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from . import store
from .engine import actions, analyzer, executor, history_seed, lake
from .engine import sqlparse_lite as sql
from .webui import STATIC_DIR, content_type, read_static

ROUTES: list[tuple[str, re.Pattern[str], Callable[..., Any]]] = []


def route(method: str, pattern: str):
    def deco(fn):
        ROUTES.append((method, re.compile(f"^{pattern}$"), fn))
        return fn

    return deco


class ApiError(Exception):
    def __init__(self, status: int, message: str, *, code: str = "error", detail: dict | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.detail = detail or {}


def _json_body(handler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length") or 0)
    if length == 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ApiError(400, f"invalid JSON body: {exc}", code="bad_json") from exc
    if not isinstance(body, dict):
        raise ApiError(400, "JSON body must be an object", code="bad_json")
    return body


def _int(value: Any, name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ApiError(422, f"{name} must be an integer", code="bad_param") from exc


class Handler(BaseHTTPRequestHandler):
    server_version = "QueryHistoryAnalyzer/1.0"

    def log_message(self, fmt, *args):  # quieter default logging
        if os.environ.get("QHA_VERBOSE"):
            super().log_message(fmt, *args)

    # -- dispatch ----------------------------------------------------------

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method: str):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path.startswith("/api/"):
            self._api(method, path, query)
            return
        # static
        if path == "/" or path == "":
            path = "/index.html"
        self._static(path)

    def _api(self, method: str, path: str, query: dict[str, list[str]]):
        for m, pattern, fn in ROUTES:
            if m != method:
                continue
            match = pattern.match(path)
            if match:
                handler = self
                body = _json_body(self) if method in ("POST", "DELETE") else {}
                try:
                    result = fn(self, body, query, **match.groupdict())
                    self._send_json(200, result)
                except ApiError as exc:
                    self._send_json(exc.status, {"error": str(exc), "code": exc.code, "detail": exc.detail})
                except actions.ActionError as exc:
                    self._send_json(409, {"error": str(exc), "code": exc.code, "detail": exc.detail})
                except sql.QueryError as exc:
                    self._send_json(422, {"error": f"SQL not supported: {exc}", "code": "query_error"})
                except executor.ExecError as exc:
                    self._send_json(422, {"error": str(exc), "code": "execution_error"})
                except store.sqlite3.Error as exc:  # pragma: no cover - defensive
                    self._send_json(500, {"error": f"database error: {exc}", "code": "db_error"})
                except Exception as exc:  # noqa: BLE001
                    traceback.print_exc()
                    self._send_json(500, {"error": str(exc), "code": "internal_error"})
                return
        self._send_json(404, {"error": f"no route for {method} {path}", "code": "not_found"})

    # -- responses ---------------------------------------------------------

    def _send_json(self, status: int, obj: Any):
        payload = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _static(self, path: str):
        rel = path.lstrip("/")
        if ".." in rel.split("/"):
            self._send_json(400, {"error": "bad path", "code": "bad_path"})
            return
        data = read_static(rel)
        if data is None:
            self._send_json(404, {"error": "not found", "code": "not_found"})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type(rel))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@route("GET", r"/api/health")
def health(handler, body, query):
    return {"ok": True, "db": store.DB_PATH, "lake": store.LAKE_DIR}


@route("GET", r"/api/tables")
def tables(handler, body, query):
    with store.db() as conn:
        data = store.list_tables(conn)
        history_stale = analyzer.stale_tables(conn)
    return {"tables": data, "stale_tables": history_stale,
            "thresholds": analyzer.CONFIG}


@route("GET", r"/api/tables/(?P<name>[a-zA-Z0-9_]+)")
def table_detail(handler, body, query, name):
    with store.db() as conn:
        meta = store.table_row(conn, name)
        if meta is None:
            raise ApiError(404, f"unknown table {name!r}", code="not_found")
        files = store.file_rows(conn, name)
    sizes = sorted(int(f["bytes"]) for f in files)
    return {
        "table": meta,
        "file_count": len(files),
        "file_size": {
            "min": sizes[0] if sizes else 0,
            "median": sizes[len(sizes) // 2] if sizes else 0,
            "max": sizes[-1] if sizes else 0,
        },
        "partitions": sorted({json.dumps(f["partition"], sort_keys=True) for f in files})[:200],
        "sample_files": [
            {"rel_path": f["rel_path"], "bytes": f["bytes"], "row_count": f["row_count"],
             "partition": f["partition"]}
            for f in files[:8]
        ],
    }


@route("GET", r"/api/history")
def history(handler, body, query, **kw):
    table = (query.get("table") or [None])[0]
    fp = (query.get("fingerprint") or [None])[0]
    limit = _int((query.get("limit") or ["100"])[0], "limit")
    clauses, params = [], []
    if table:
        clauses.append("table_name=?")
        params.append(table)
    if fp:
        clauses.append("fingerprint=?")
        params.append(fp)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with store.db() as conn:
        rows = conn.execute(
            f"SELECT * FROM executions {where} ORDER BY ts DESC LIMIT ?", (*params, limit)
        ).fetchall()
        total = conn.execute(f"SELECT COUNT(*) AS n FROM executions {where}", params).fetchone()["n"]
    items = []
    for r in rows:
        d = dict(r)
        try:
            d["plan"] = json.loads(d.pop("plan_json") or "{}")
        except ValueError:
            d["plan"] = {}
        items.append(d)
    return {"total": total, "items": items}


@route("GET", r"/api/history/groups")
def history_groups(handler, body, query, **kw):
    """Per-fingerprint rollup: the query samples behind each advisory."""
    with store.db() as conn:
        execs = analyzer.load_executions(conn)
        groups = analyzer.group_executions(execs)
        abnormal = analyzer.abnormal_executions(execs, groups)
    out = []
    for g in sorted(groups, key=lambda x: -x.total_ms):
        out.append({
            "fingerprint": g.fingerprint,
            "table": g.table,
            "sample_query": g.sample_query,
            "runs": g.count,
            "total_ms": round(g.total_ms, 1),
            "avg_ms": round(g.avg_ms, 1),
            "avg_bytes": round(g.avg_bytes),
            "avg_rows_scanned": round(g.avg_rows_scanned),
            "avg_rows_returned": round(g.avg_rows_returned),
            "sample_ids": [r["id"] for r in g.runs[-3:]],
            "is_aggregation": bool(g.select and g.select.has_aggregation()),
        })
    return {"groups": out, "abnormal": abnormal[:50]}


@route("GET", r"/api/executions/(?P<eid>[0-9]+)")
def execution_detail(handler, body, query, eid):
    with store.db() as conn:
        row = conn.execute("SELECT * FROM executions WHERE id=?", (_int(eid, "id"),)).fetchone()
    if row is None:
        raise ApiError(404, "execution not found", code="not_found")
    d = dict(row)
    d["plan"] = json.loads(d.pop("plan_json") or "{}")
    return d


@route("POST", r"/api/executions")
def run_adhoc(handler, body, query):
    """Execute a query live and record it in the history."""
    text = (body.get("query") or "").strip()
    if not text:
        raise ApiError(422, "query is required", code="bad_param")
    client = body.get("client") or "ui-adhoc"
    select = sql.parse(text)
    with store.db() as conn:
        try:
            result = executor.execute(conn, select)
            status, error = "ok", None
            metrics = result.metrics
            plan = result.plan
        except executor.ExecError as exc:
            status, error, metrics, plan, result = "error", str(exc), _empty_metrics(), {}, None
        conn.execute(
            "INSERT INTO executions(ts,query,fingerprint,table_name,origin,client,status,error,"
            "duration_ms,bytes_scanned,rows_scanned,rows_returned,files_scanned,files_total,"
            "files_pruned,result_bytes,plan_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (store.utcnow(), text, select.fingerprint(), select.table, "adhoc", client, status, error,
             metrics["duration_ms"], metrics["bytes_scanned"], metrics["rows_scanned"],
             metrics["rows_returned"], metrics["files_scanned"], metrics["files_total"],
             metrics["files_pruned"], metrics["result_bytes"], store.json_dumps(plan)),
        )
    if status == "error":
        raise ApiError(422, f"execution failed: {error}", code="execution_error")
    return {
        "columns": result.columns,
        "rows": result.rows,
        "metrics": result.metrics,
        "plan": result.plan,
        "fingerprint": select.fingerprint(),
    }


def _empty_metrics() -> dict[str, Any]:
    return {"duration_ms": 0.0, "bytes_scanned": 0, "rows_scanned": 0, "rows_returned": 0,
            "result_bytes": 0, "files_scanned": 0, "files_total": 0, "files_pruned": 0}


@route("GET", r"/api/advisories")
def list_advisories(handler, body, query, **kw):
    with store.db() as conn:
        analyzer.detect(conn)  # keep findings fresh; persisted rows are below
        rows = conn.execute(
            "SELECT * FROM advisories WHERE status<>'dismissed' ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, id"
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["rationale"] = json.loads(d.pop("rationale_json"))
            d["sample_executions"] = _samples(conn, d["sample_ids"]) if d.get("sample_ids") else []
            if d["fingerprint"]:
                g = conn.execute(
                    "SELECT COUNT(*) AS runs, AVG(duration_ms) AS avg_ms, SUM(duration_ms) AS total_ms, "
                    "AVG(bytes_scanned) AS avg_bytes FROM executions WHERE fingerprint=? AND status='ok'",
                    (d["fingerprint"],),
                ).fetchone()
                d["history"] = {"runs": g["runs"], "avg_ms": round(g["avg_ms"] or 0, 1),
                                "total_ms": round(g["total_ms"] or 0, 1),
                                "avg_bytes": round(g["avg_bytes"] or 0)}
            d.pop("sample_ids", None)
            out.append(d)
    return {"advisories": out, "thresholds": analyzer.CONFIG}


def _samples(conn, ids_json: str) -> list[dict[str, Any]]:
    try:
        ids = json.loads(ids_json)
    except ValueError:
        return []
    if not ids:
        return []
    marks = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT id, ts, query, duration_ms, bytes_scanned, rows_scanned, rows_returned, "
        f"files_scanned, files_total, client FROM executions WHERE id IN ({marks}) ORDER BY ts DESC",
        ids,
    ).fetchall()
    return [dict(r) for r in rows]


@route("POST", r"/api/analyze")
def analyze(handler, body, query):
    """Re-run detection and persist advisories (idempotent per kind+table+fingerprint)."""
    with store.db() as conn:
        findings = analyzer.detect(conn)
        persisted = []
        now = store.utcnow()
        for f in findings:
            existing = conn.execute(
                "SELECT id, status FROM advisories WHERE kind=? AND table_name=? AND "
                "COALESCE(fingerprint,'')=COALESCE(?,'')",
                (f["kind"], f["table_name"], f["fingerprint"]),
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE advisories SET title=?, severity=?, confidence=?, rationale_json=?, "
                    "sample_ids=?, updated_at=? WHERE id=?",
                    (f["title"], f["severity"], f["confidence"], f["rationale_json"],
                     json.dumps(f["sample_ids"]), now, existing["id"]),
                )
                persisted.append(existing["id"])
            else:
                cur = conn.execute(
                    "INSERT INTO advisories(kind,table_name,title,severity,confidence,"
                    "rationale_json,sample_ids,fingerprint,status,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (f["kind"], f["table_name"], f["title"], f["severity"], f["confidence"],
                     f["rationale_json"], json.dumps(f["sample_ids"]), f["fingerprint"],
                     "open", now, now),
                )
                persisted.append(int(cur.lastrowid))
        conn.commit()
        # drop stale open advisories whose finding disappeared
        keys = {(f["kind"], f["table_name"], f["fingerprint"] or "") for f in findings}
        for row in conn.execute("SELECT id,kind,table_name,fingerprint,status FROM advisories").fetchall():
            if row["status"] == "open" and (row["kind"], row["table_name"], row["fingerprint"] or "") not in keys:
                conn.execute("DELETE FROM advisories WHERE id=?", (row["id"],))
        conn.commit()
    return {"created_or_updated": persisted, "count": len(persisted)}


@route("GET", r"/api/advisories/(?P<aid>[0-9]+)")
def advisory_detail(handler, body, query, aid):
    with store.db() as conn:
        row = conn.execute("SELECT * FROM advisories WHERE id=?", (_int(aid, "id"),)).fetchone()
        if row is None:
            raise ApiError(404, "advisory not found", code="not_found")
        d = dict(row)
        d["rationale"] = json.loads(d.pop("rationale_json"))
        d["sample_executions"] = _samples(conn, d["sample_ids"]) if d.get("sample_ids") else []
        sims = conn.execute(
            "SELECT id, ts, plan_json, estimate_json, superseded FROM simulations "
            "WHERE advisory_id=? ORDER BY id DESC", (d["id"],),
        ).fetchall()
        d["simulations"] = []
        for s in sims:
            sd = dict(s)
            sd["plan"] = json.loads(sd.pop("plan_json"))
            sd["estimates"] = json.loads(sd.pop("estimate_json"))
            d["simulations"].append(sd)
        applies = conn.execute(
            "SELECT * FROM applies WHERE advisory_id=? ORDER BY id DESC", (d["id"],),
        ).fetchall()
        d["applies"] = [
            {
                "id": a["id"], "ts": a["ts"], "status": a["status"],
                "before": json.loads(a["before_json"]),
                "after": json.loads(a["after_json"]),
                "rollback_point_id": a["rollback_point_id"],
                "note": a["note"],
                "simulation_id": a["simulation_id"],
            }
            for a in applies
        ]
        d.pop("sample_ids", None)
    return d


@route("POST", r"/api/advisories/(?P<aid>[0-9]+)/simulate")
def simulate(handler, body, query, aid):
    with store.db() as conn:
        plan = actions.simulate(conn, _int(aid, "id"))
        conn.commit()
        plan["advisory"] = dict(
            conn.execute("SELECT id, kind, table_name, title FROM advisories WHERE id=?",
                         (plan["advisory_id"],)).fetchone()
        )
    return {"simulation": plan, "explanation": _explain(plan)}


def _explain(plan: dict[str, Any]) -> list[str]:
    """Plain-language walk through the model so its assumptions are visible."""
    lines = [
        f"Action: {plan['action_label']} on {plan['table']}.",
        f"Measurement query: `{plan['measurement']['query']}`",
        "Steps: " + " -> ".join(s["op"] for s in plan["steps"]) + ".",
    ]
    for key, est in plan.get("estimates", {}).items():
        if not isinstance(est, dict):
            continue
        if est.get("value") is None:
            lines.append(f"{key}: not estimated ({est.get('basis', '')}).")
        else:
            lines.append(
                f"{key}: est {est['value']:,} "
                f"(range {est.get('bound_low')}..{est.get('bound_high')}); {est.get('basis')}"
            )
    lines.append("Assumptions: " + "; ".join(plan.get("assumptions", []) or ["none"]))
    return lines


@route("POST", r"/api/simulations/(?P<sid>[0-9]+)/apply")
def apply_sim(handler, body, query, sid):
    with store.db() as conn:
        result = actions.apply_simulation(conn, _int(sid, "id"))
        conn.commit()
    return result


@route("POST", r"/api/applies/(?P<aid>[0-9]+)/undo")
def undo_apply(handler, body, query, aid):
    with store.db() as conn:
        result = actions.undo_apply(conn, _int(aid, "id"))
        conn.commit()
    return result


@route("GET", r"/api/rollback-points")
def rollback_points(handler, body, query):
    with store.db() as conn:
        rows = conn.execute(
            "SELECT id, apply_id, ts, kind, state, manifest_json FROM rollback_points ORDER BY id DESC"
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        m = json.loads(d.pop("manifest_json"))
        d["table"] = m.get("table")
        d["files"] = len(m.get("files", []))
        d["snapshot_bytes"] = sum(int(f.get("bytes", 0)) for f in m.get("files", []))
        d["backup_dir"] = m.get("backup_dir")
        out.append(d)
    return {"rollback_points": out}


@route("GET", r"/api/undo-log")
def undo_log(handler, body, query):
    with store.db() as conn:
        rows = conn.execute(
            "SELECT * FROM undo_log ORDER BY id DESC LIMIT 200"
        ).fetchall()
        applies = conn.execute(
            "SELECT a.*, ad.kind AS advisory_kind, ad.title AS advisory_title "
            "FROM applies a LEFT JOIN advisories ad ON ad.id=a.advisory_id ORDER BY a.id DESC"
        ).fetchall()
    return {
        "undo_log": [
            {"id": r["id"], "ts": r["ts"], "action": r["action"], "apply_id": r["apply_id"],
             "detail": json.loads(r["detail_json"])}
            for r in rows
        ],
        "applies": [
            {"id": a["id"], "ts": a["ts"], "status": a["status"], "advisory_id": a["advisory_id"],
             "advisory_kind": a["advisory_kind"], "advisory_title": a["advisory_title"],
             "simulation_id": a["simulation_id"], "rollback_point_id": a["rollback_point_id"],
             "before": json.loads(a["before_json"]), "after": json.loads(a["after_json"]),
             "note": a["note"]}
            for a in applies
        ],
    }


@route("GET", r"/api/validations/stats")
def validate_stats_list(handler, body, query):
    with store.db() as conn:
        return {"tables": analyzer.stale_tables(conn),
                "tables_all": [
                    {"table": t["name"], "stats_updated_at": t["stats_updated_at"],
                     "last_data_change_at": t["last_data_change_at"], "stats_stale": t["stats_stale"]}
                    for t in store.list_tables(conn)
                ]}


@route("GET", r"/api/validations/stats/(?P<name>[a-zA-Z0-9_]+)")
def validate_stats(handler, body, query, name):
    with store.db() as conn:
        return actions.verify_stats(conn, name)


@route("POST", r"/api/validations/stats/(?P<name>[a-zA-Z0-9_]+)/refresh")
def refresh_stats(handler, body, query, name):
    with store.db() as conn:
        result = actions.refresh_stats(conn, name)
    return result


@route("GET", r"/api/validations/anomalies")
def anomalies(handler, body, query):
    with store.db() as conn:
        execs = analyzer.load_executions(conn)
        groups = analyzer.group_executions(execs)
        abnormal = analyzer.abnormal_executions(execs, groups)
    return {"anomalies": abnormal, "scanned": len(execs)}


@route("POST", r"/api/admin/reseed")
def reseed(handler, body, query):
    if os.environ.get("QHA_ALLOW_RESEED", "1") != "1":
        raise ApiError(403, "reseeding is disabled", code="forbidden")
    with store.db() as conn:
        lake.seed(conn, reset=True)
        history_seed.seed_history(conn, reset=True)
        conn.commit()
        counts = {
            "executions": conn.execute("SELECT COUNT(*) n FROM executions").fetchone()["n"],
            "tables": conn.execute("SELECT COUNT(*) n FROM tables").fetchone()["n"],
        }
    return {"ok": True, "counts": counts}
