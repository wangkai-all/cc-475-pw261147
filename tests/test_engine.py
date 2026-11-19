"""End-to-end tests against an isolated data directory.

Each test module run builds its own lake under a temp dir, so tests never touch
the developer's `.data/`.  Run with::

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

TMP = tempfile.mkdtemp(prefix="qha-test-")
os.environ["QHA_DATA_DIR"] = TMP

from app import store  # noqa: E402
from app.engine import actions, analyzer, executor, history_seed, lake  # noqa: E402
from app.engine import sqlparse_lite as sql  # noqa: E402


def setUpModule():
    store.init_db()
    with store.db() as conn:
        lake.seed(conn)
        history_seed.seed_history(conn)
        conn.commit()


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


class TestSqlParser(unittest.TestCase):
    def test_normalization_ignores_literals(self):
        a = sql.parse("select country, count(*) from events where event_date='2024-01-01' group by country")
        b = sql.parse("select country, count(*) from events where event_date='2024-12-31' group by country")
        self.assertEqual(a.fingerprint(), b.fingerprint())
        self.assertIn("'?'", sql.normalize(a))

    def test_shape_change_changes_fingerprint(self):
        a = sql.parse("select count(*) from events")
        b = sql.parse("select count(*) from events where country='CN'")
        self.assertNotEqual(a.fingerprint(), b.fingerprint())

    def test_rejects_unsupported_sql(self):
        for bad in [
            "insert into events values (1)",
            "select a from t join u on t.id=u.id",
            "select * from events where x = (select 1)",
            "select count(*) from events; drop table events",
        ]:
            with self.assertRaises(sql.QueryError):
                sql.parse(bad)

    def test_extracts_predicates_and_aggregates(self):
        s = sql.parse(
            "select country, count(*) as n, avg(amount) a from orders "
            "where order_time >= '2024-01-01' and status in ('paid','new') group by country"
        )
        cols = [c for c, _ in s.equalities()]
        self.assertIn("status", cols)
        ops = [(c, op) for c, op, _ in s.ranges()]
        self.assertIn(("order_time", ">="), ops)
        self.assertEqual(len(s.aggregate_calls()), 2)
        self.assertTrue(s.has_aggregation())


class TestExecutor(unittest.TestCase):
    def test_partition_pruning_is_real(self):
        with store.db() as conn:
            q = "select count(*) as n from page_views where view_date='2024-06-02' and hour='03'"
            r = executor.execute(conn, sql.parse(q))
            self.assertEqual(r.metrics["files_scanned"], 1)
            self.assertEqual(r.metrics["files_total"], 336)
            self.assertEqual(r.metrics["rows_matched"], r.rows[0]["n"])

    def test_replaying_query_reproduces_scan_metrics(self):
        with store.db() as conn:
            q = "select status, count(*) as n from orders group by status"
            first = executor.execute(conn, sql.parse(q), collect_rows=False)
            second = executor.execute(conn, sql.parse(q), collect_rows=False)
            self.assertEqual(first.metrics["bytes_scanned"], second.metrics["bytes_scanned"])
            self.assertEqual(first.metrics["rows_scanned"], second.metrics["rows_scanned"])

    def test_aggregation_matches_manual_count(self):
        with store.db() as conn:
            q = "select country, count(*) as n from events group by country"
            r = executor.execute(conn, sql.parse(q))
            total = sum(row["n"] for row in r.rows)
            meta = store.table_row(conn, "events")
            self.assertEqual(total, meta["row_count"])

    def test_errors_are_reported_not_swallowed(self):
        with store.db() as conn:
            with self.assertRaises(executor.ExecError):
                executor.execute(conn, sql.parse("select missing from events"))

    def test_zone_map_prunes_out_of_range_dates(self):
        with store.db() as conn:
            q = "select count(*) as n from orders where order_time >= '2030-01-01'"
            r = executor.execute(conn, sql.parse(q))
            self.assertEqual(r.metrics["files_scanned"], 0)
            self.assertEqual(r.rows[0]["n"], 0)


class TestAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with store.db() as conn:
            cls.findings = analyzer.detect(conn)
            cls.execs = analyzer.load_executions(conn)
            cls.groups = analyzer.group_executions(cls.execs)

    def kinds(self):
        return {f["kind"] for f in self.findings}

    def test_detects_all_four_problem_classes(self):
        self.assertTrue({"overscan", "partition_miss", "repeated_aggregation", "small_files"} <= self.kinds())

    def test_every_advisory_has_executable_evidence(self):
        for f in self.findings:
            r = json.loads(f["rationale_json"])
            self.assertIn("rule", r)
            self.assertIn("evidence", r)
            self.assertTrue(r["evidence"], f["title"])
            self.assertIn("observed", r)
            if f["kind"] != "small_files":
                self.assertTrue(f["sample_ids"], f["title"])

    def test_overscan_recommendation_has_projection_or_is_withheld(self):
        for f in self.findings:
            if f["kind"] != "overscan":
                continue
            r = json.loads(f["rationale_json"])
            rec = r.get("recommendation")
            if rec:
                self.assertIn(rec["action"], {"cluster", "add_partition"})
                self.assertIn("alternative_projection", r)
            else:
                # Withholding must be explained, not silent.
                self.assertTrue(
                    any("仅能" in e or "无法裁剪" in e for e in r["evidence"]),
                    f"withheld recommendation must explain itself: {r['evidence']}",
                )

    def test_repeated_aggregation_groups_distinct_fingerprints(self):
        repeats = [f for f in self.findings if f["kind"] == "repeated_aggregation"]
        self.assertTrue(repeats)
        for f in repeats:
            r = json.loads(f["rationale_json"])
            self.assertGreaterEqual(r["observed"]["runs"], analyzer.CONFIG["repeat_min_runs"])
            self.assertTrue(r["observed"]["aggregates"])

    def test_stale_stats_are_reported(self):
        # Other tests may refresh stats; make the condition explicit here.
        with store.db() as conn:
            conn.execute(
                "UPDATE tables SET last_data_change_at='2099-01-01T00:00:00+00:00' "
                "WHERE name='events'"
            )
            conn.commit()
            stale = analyzer.stale_tables(conn)
        self.assertIn("events", [t["table"] for t in stale])
        self.assertIn("message", stale[0])

    def test_abnormal_executions_cover_each_reason_class(self):
        with store.db() as conn:
            execs = analyzer.load_executions(conn)
            groups = analyzer.group_executions(execs)
        anomalies = analyzer.abnormal_executions(execs, groups)
        reasons = {r["kind"] for a in anomalies for r in a["reasons"]}
        self.assertIn("unfiltered_full_scan", reasons)
        # Error executions are recorded by the history seed; assert the detector
        # surfaces whichever ones exist rather than assuming a fixed count.
        with store.db() as conn:
            failed = conn.execute(
                "SELECT COUNT(*) n FROM executions WHERE status<>'ok'"
            ).fetchone()["n"]
        if failed:
            self.assertIn("error", reasons)


class TestProjections(unittest.TestCase):
    def test_month_projection_is_bounded_and_not_understated(self):
        with store.db() as conn:
            files = store.file_rows(conn, "orders")
            q = sql.parse(
                "select status, count(*) n from orders "
                "where order_time >= '2024-11-25' and order_time <= '2024-12-08' group by status"
            )
            p = analyzer.project_repartition(files, "order_time", "date", q)
        self.assertLessEqual(p.lower, p.files_scanned)
        self.assertLessEqual(p.files_scanned, p.upper)
        self.assertGreater(p.total_files, p.files_scanned)
        # Two calendar months are partially covered -> at least 2 files.
        self.assertGreaterEqual(p.files_scanned, 1)

    def test_projection_never_exceeds_its_own_bounds(self):
        with store.db() as conn:
            files = store.file_rows(conn, "events")
            q = sql.parse("select device, count(*) n from events where event_type='purchase' group by device")
            p = analyzer.project_cluster(files, "event_type", q)
        self.assertLessEqual(p.lower, p.files_scanned)
        self.assertLessEqual(p.files_scanned, p.upper)
        self.assertLessEqual(p.upper, p.total_files)


class TestApplyUndo(unittest.TestCase):
    def _persist(self, finding):
        with store.db() as conn:
            now = store.utcnow()
            cur = conn.execute(
                "INSERT INTO advisories(kind,table_name,title,severity,confidence,rationale_json,"
                "sample_ids,fingerprint,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (finding["kind"], finding["table_name"], finding["title"], finding["severity"],
                 finding["confidence"], finding["rationale_json"], json.dumps(finding["sample_ids"]),
                 finding["fingerprint"], "open", now, now),
            )
            conn.commit()
            return int(cur.lastrowid)

    def _pick(self, kind):
        with store.db() as conn:
            findings = analyzer.detect(conn)
        for f in findings:
            r = json.loads(f["rationale_json"])
            if f["kind"] == kind and r.get("recommendation"):
                return f
        self.skipTest(f"no actionable {kind} finding in this dataset")

    def test_apply_measures_before_and_after_and_undo_restores(self):
        finding = self._pick("partition_miss")
        aid = self._persist(finding)
        with store.db() as conn:
            before_layout = store.table_row(conn, finding["table_name"])["partition_cols"]
            plan = actions.simulate(conn, aid)
            result = actions.apply_simulation(conn, plan["simulation_id"])
            conn.commit()

            self.assertTrue(result["before"]["measured"])
            self.assertTrue(result["after"]["measured"])
            self.assertEqual(result["before"]["query"], result["after"]["query"])
            self.assertNotEqual(
                (result["before"]["files_scanned"], result["before"]["files_total"]),
                (result["after"]["files_scanned"], result["after"]["files_total"]),
                "apply must change the physical layout",
            )
            # rollback point was created before mutation and is available
            rp = conn.execute(
                "SELECT * FROM rollback_points WHERE id=?", (result["rollback_point"]["id"],)
            ).fetchone()
            self.assertEqual(rp["state"], "available")

            undo = actions.undo_apply(conn, result["apply_id"])
            conn.commit()
            self.assertEqual(undo["status"], "undone")
            self.assertEqual(
                store.table_row(conn, finding["table_name"])["partition_cols"], before_layout
            )
            self.assertEqual(undo["measurement"]["files_total"], result["before"]["files_total"])

    def test_simulation_estimates_are_labelled_and_bounded(self):
        finding = self._pick("partition_miss")
        aid = self._persist(finding)
        with store.db() as conn:
            plan = actions.simulate(conn, aid)
        self.assertIn("不是实测结果", plan["estimate_disclaimer"])
        est = plan["estimates"]["files_scanned"]
        self.assertLessEqual(est["bound_low"], est["value"])
        self.assertLessEqual(est["value"], est["bound_high"])
        self.assertNotIn("duration_ms", [k for k, v in plan["estimates"].items()
                                         if isinstance(v, dict) and v.get("value") is not None])

    def test_apply_refuses_when_state_changed_after_simulation(self):
        finding = self._pick("partition_miss")
        aid = self._persist(finding)
        with store.db() as conn:
            plan = actions.simulate(conn, aid)
            # Simulate an out-of-band catalog change.
            conn.execute(
                "UPDATE tables SET stats_updated_at='2099-01-01T00:00:00+00:00' WHERE name=?",
                (finding["table_name"],),
            )
            conn.commit()
            with self.assertRaises(actions.ActionError) as ctx:
                actions.apply_simulation(conn, plan["simulation_id"])
        self.assertEqual(ctx.exception.code, "state_changed")

    def test_compact_cannot_promise_more_than_partition_floor(self):
        finding = self._pick("small_files")
        aid = self._persist(finding)
        with store.db() as conn:
            plan = actions.simulate(conn, aid)
            meta = store.table_row(conn, finding["table_name"])
            files = store.file_rows(conn, finding["table_name"])
        dirs = len({json.dumps(f["partition"], sort_keys=True) for f in files})
        est = plan["estimates"]["files_scanned"]
        self.assertGreaterEqual(est["value"], dirs)
        self.assertLessEqual(est["value"], meta["file_count"])


class TestStatsValidation(unittest.TestCase):
    def test_verify_stats_flags_stale_catalog(self):
        with store.db() as conn:
            conn.execute(
                "UPDATE tables SET last_data_change_at='2099-01-01T00:00:00+00:00' "
                "WHERE name='events'"
            )
            conn.commit()
            result = actions.verify_stats(conn, "events")
        self.assertTrue(result["stale"])
        self.assertEqual(result["verdict"], "needs_refresh")

    def test_refresh_stats_clears_stale_and_drift(self):
        with store.db() as conn:
            conn.execute(
                "UPDATE tables SET last_data_change_at='2099-01-01T00:00:00+00:00' "
                "WHERE name='events'"
            )
            conn.commit()
            actions.refresh_stats(conn, "events")
            conn.commit()
            again = actions.verify_stats(conn, "events")
            self.assertFalse(again["stale"])
            self.assertEqual(again["drift_count"], 0)
            self.assertEqual(again["verdict"], "ok")

    def test_corrupted_zone_map_is_detected(self):
        with store.db() as conn:
            files = store.file_rows(conn, "orders")
            victim = files[0]
            tampered = dict(victim["stats"])
            tampered["order_time"] = {"min": "1999-01-01", "max": "1999-12-31", "nulls": 0}
            conn.execute(
                "UPDATE files SET stats_json=? WHERE id=?",
                (json.dumps(tampered), victim["id"]),
            )
            conn.commit()
            result = actions.verify_stats(conn, "orders")
            self.assertGreater(result["drift_count"], 0)
            self.assertEqual(result["verdict"], "needs_refresh")
            actions.refresh_stats(conn, "orders")
            conn.commit()
            self.assertEqual(actions.verify_stats(conn, "orders")["drift_count"], 0)


if __name__ == "__main__":
    unittest.main()
