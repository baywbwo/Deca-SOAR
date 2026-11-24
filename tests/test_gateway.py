from hypersoar import ledger
from hypersoar.gateway.service import MAX_ATTEMPTS, DeliveryError, forward_once

from helpers import ingest, waf_alert, write_ndjson


def test_pull_dedups_and_is_idempotent(pool, settings, tmp_path, conn):
    rows = [waf_alert(), waf_alert(ts="2026-11-24T03:02:00Z", events=5), waf_alert(ip="203.0.113.99"),
            "{not json", "[1,2]", {"source": "waf", "rule_id": ""}]
    r = ingest(pool, settings, tmp_path, rows)
    assert (r.pulled, r.new, r.merged, r.rejected) == (6, 2, 1, 3)
    again = ingest(pool, settings, tmp_path, [])  # same file, cursor at end
    assert (again.pulled, again.new) == (0, 0)
    counts = conn.execute("SELECT event_count FROM gateway.inbox_event ORDER BY event_count").fetchall()
    assert [c["event_count"] for c in counts] == [40, 45]
    # Raw PII never lands in the inbox or ledger.
    dump = str(conn.execute("SELECT json_agg(alert) AS a FROM gateway.inbox_event").fetchone()["a"])
    dump += str(conn.execute("SELECT json_agg(canonical) AS a FROM ledger.entry").fetchone()["a"])
    assert "203.0.113.7" not in dump and "a@b.co" not in dump
    assert ledger.verify(conn).ok


def test_forward_success_and_retry_then_dead(pool, settings, tmp_path, conn):
    ingest(pool, settings, tmp_path, [waf_alert(), waf_alert(ip="203.0.113.50")])
    seen = []

    def ok(alert):
        seen.append(alert)
        return f"alert-{alert['alert_id']}/run-1"

    res = forward_once(pool, ok)
    assert res.sent == 2 and len(seen) == 2
    assert all(a["counts"]["events"] == 40 and a["entities"]["src_ip"].startswith("tok_ip_") for a in seen)
    st = conn.execute("SELECT status, downstream_ref, alert_id FROM gateway.inbox_event").fetchall()
    assert {(s["status"], s["downstream_ref"]) for s in st} == {
        ("forwarded", f"alert-{s['alert_id']}/run-1") for s in st
    }

    ingest(pool, settings, tmp_path, [waf_alert(ip="203.0.113.60")], name="other")

    def down(alert):
        raise DeliveryError("temporal UNAVAILABLE")

    res = forward_once(pool, down)
    assert res.failed == 1
    with conn.transaction():
        conn.execute("UPDATE gateway.inbox_event SET attempts = %s, next_attempt_at = now()"
                     " WHERE status = 'pending'", (MAX_ATTEMPTS - 1,))
    res = forward_once(pool, down)
    assert res.dead == 1
    row = conn.execute("SELECT status, last_error FROM gateway.inbox_event WHERE status = 'dead'").fetchone()
    assert row["last_error"] == "temporal UNAVAILABLE"
    assert ledger.verify(conn).ok


def test_forward_unexpected_error_keeps_only_class_name(pool, settings, tmp_path, conn):
    ingest(pool, settings, tmp_path, [waf_alert()])

    def boom(alert):
        raise RuntimeError("dial tcp temporal.internal:7233 secret-ish detail")

    assert forward_once(pool, boom).failed == 1
    row = conn.execute("SELECT status, last_error FROM gateway.inbox_event").fetchone()
    assert (row["status"], row["last_error"]) == ("pending", "RuntimeError")
