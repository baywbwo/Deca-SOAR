import httpx

from deca_soar import ledger
from deca_soar.gateway.service import MAX_ATTEMPTS, forward_once

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

    def ok(req: httpx.Request):
        seen.append(req)
        return httpx.Response(200, json={"wf_exec_id": "wf-1/exec-1"})

    with httpx.Client(transport=httpx.MockTransport(ok)) as c:
        res = forward_once(pool, c, "http://tracecat.invalid/webhook/secret-path")
    assert res.sent == 2 and len(seen) == 2
    st = conn.execute("SELECT status, downstream_ref FROM gateway.inbox_event").fetchall()
    assert {(s["status"], s["downstream_ref"]) for s in st} == {("forwarded", "wf-1/exec-1")}

    ingest(pool, settings, tmp_path, [waf_alert(ip="203.0.113.60")], name="other")

    def fail(req):
        return httpx.Response(503)

    with httpx.Client(transport=httpx.MockTransport(fail)) as c:
        res = forward_once(pool, c, "http://tracecat.invalid/webhook/secret-path")
        assert res.failed == 1
        with conn.transaction():
            conn.execute("UPDATE gateway.inbox_event SET attempts = %s, next_attempt_at = now()"
                         " WHERE status = 'pending'", (MAX_ATTEMPTS - 1,))
        res = forward_once(pool, c, "http://tracecat.invalid/webhook/secret-path")
    assert res.dead == 1
    row = conn.execute("SELECT status, last_error FROM gateway.inbox_event WHERE status = 'dead'").fetchone()
    assert row["last_error"] == "http 503"
    assert "secret-path" not in str(conn.execute("SELECT json_agg(canonical) a FROM ledger.entry").fetchone())
    assert ledger.verify(conn).ok
