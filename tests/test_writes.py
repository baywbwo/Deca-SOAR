"""v0.8 human writes through the broker: re-authentication, the L3 rule, idempotency, audit trail,
case triage (assign, open/waiting/closed, comments) and early revoke."""

import uuid

from hypersoar import ledger
from hypersoar.broker import writes

from helpers import PW, ingest, waf_alert
from test_broker_api import _alert, body, client, env, principals  # noqa: F401  (fixtures)


def _ledger(conn, event_type):
    return [r["payload"] for r in conn.execute(
        "SELECT payload FROM ledger.entry WHERE event_type = %s ORDER BY seq", (event_type,)).fetchall()]


def _l2(client, principals, pool, settings, tmp_path, conn, key="LTAI5tWRITEWRITEWRIT"):
    ingest(pool, settings, tmp_path, [{"source": "actiontrail", "rule_id": "ram.ak.geo", "severity_hint": "high",
                                       "detected_at": "2026-11-24T03:00:00Z", "access_key_id": key}])
    aid, alert = _alert(conn)
    r = client.post("/v1/actions/requests", headers=principals["analyst1"],
                    json=body(aid, action="ram.access_key.disable", conf=0.9,
                              params={"access_key_token": alert["entities"]["access_key_token"]}))
    j = r.json()
    assert j["status"] == "pending_approval", j
    return j


def _case(pool, settings, tmp_path, conn):
    ingest(pool, settings, tmp_path, [waf_alert()])
    return conn.execute("SELECT case_id FROM gateway.alert_case ORDER BY case_no DESC LIMIT 1").fetchone()["case_id"]


def test_approval_without_reauth_is_rejected(client, principals, pool, settings, tmp_path, conn):
    j = _l2(client, principals, pool, settings, tmp_path, conn)
    url = f"/v1/actions/requests/{j['request_id']}/approval"
    r = client.post(url, headers=principals["approver1"], json={"approve": True})
    assert r.status_code == 403 and "re-authentication" in r.text
    r = client.post(url, headers=principals["approver1"], json={"approve": True, "password": "wrong password!!"})
    assert r.status_code == 403
    assert len(_ledger(conn, "auth.reauth_failed")) == 2
    assert conn.execute("SELECT status FROM broker.action_request WHERE request_id = %s",
                        (j["request_id"],)).fetchone()["status"] == "pending_approval"
    ok = client.post(url, headers=principals["approver1"], json={"approve": True, "password": PW})
    assert ok.status_code == 200 and ok.json()["status"] == "validated"
    entry = _ledger(conn, "action.approved")[-1]
    assert entry["via"] == "console" and entry["approver"]
    assert PW not in str(conn.execute("SELECT json_agg(canonical) a FROM ledger.entry").fetchone())


def test_human_without_reauth_hash_cannot_write(client, principals, pool, settings, tmp_path, conn):
    j = _l2(client, principals, pool, settings, tmp_path, conn)
    conn.execute("UPDATE broker.principal SET reauth_hash = NULL WHERE name = 'approver1'")
    r = client.post(f"/v1/actions/requests/{j['request_id']}/approval", headers=principals["approver1"],
                    json={"approve": True, "password": PW})
    assert r.status_code == 403


def test_l3_has_no_fast_path(client, principals, pool, settings, tmp_path, conn):
    j = _l2(client, principals, pool, settings, tmp_path, conn)
    conn.execute("UPDATE broker.action_request SET level = 'L3' WHERE request_id = %s", (j["request_id"],))
    url = f"/v1/actions/requests/{j['request_id']}/approval"
    # Re-authenticated but no reason: refused.
    r = client.post(url, headers=principals["approver1"], json={"approve": True, "password": PW})
    assert r.status_code == 403 and "reason" in r.text
    # Service principals never approve, whatever the level.
    assert client.post(url, headers=principals["svc-admin"],
                       json={"approve": True, "password": PW, "reason": "x"}).status_code == 403
    # The service layer refuses any channel other than the console (Lark one-click, API without re-auth).
    from hypersoar.broker import service
    req = conn.execute("SELECT * FROM broker.action_request WHERE request_id = %s", (j["request_id"],)).fetchone()
    try:
        service._decide(conn, None, req, True, approver_id=None, approver_ref="lark:ou_x", actor="lark:ou_x",
                        via="lark", extra={"reason": "looks bad"})
        raise AssertionError("L3 approved from Lark")
    except PermissionError as e:
        assert "console" in str(e)
    ok = client.post(url, headers=principals["approver1"],
                     json={"approve": True, "password": PW, "reason": "confirmed with the account owner"})
    assert ok.status_code == 200 and ok.json()["status"] == "validated"
    row = conn.execute("SELECT decision_reason FROM broker.action_request WHERE request_id = %s",
                       (j["request_id"],)).fetchone()
    assert row["decision_reason"] == "confirmed with the account owner"
    assert _ledger(conn, "action.approved")[-1]["reason"] == "confirmed with the account owner"


def test_l3_catalog_entry_cannot_be_auto():
    import pytest

    from hypersoar.broker.catalog import CatalogError, parse_catalog
    with pytest.raises(CatalogError, match="approval"):
        parse_catalog({"version": 1, "actions": {"x.y": {
            "level": "L3", "mode": "auto", "sources": ["waf"], "params": {}, "allowed_verdicts": ["malicious"],
            "min_confidence": 0.9, "rate_limit": {"per_hour": 1}}}})


def test_kill_switch_needs_reauth_and_reason(client, principals, conn):
    ks = {"scope": "global", "engaged": True}
    assert client.post("/v1/kill-switch", headers=principals["admin1"], json=ks).status_code == 422  # no reason
    ks["reason"] = "suspected bad rule"
    assert client.post("/v1/kill-switch", headers=principals["admin1"], json=ks).status_code == 403  # no password
    ks["password"] = PW
    r = client.post("/v1/kill-switch", headers={**principals["admin1"], "Idempotency-Key": "ks-on-00000001"}, json=ks)
    assert r.status_code == 200 and r.json()["engaged"] is True and r.json()["idempotent_replay"] is False
    again = client.post("/v1/kill-switch", headers={**principals["admin1"], "Idempotency-Key": "ks-on-00000001"},
                        json=ks)
    assert again.status_code == 200 and again.json()["idempotent_replay"] is True
    assert len(_ledger(conn, "kill_switch.changed")) == 1
    assert _ledger(conn, "kill_switch.changed")[0]["reason"] == "suspected bad rule"
    other = client.post("/v1/kill-switch", headers={**principals["admin1"], "Idempotency-Key": "ks-on-00000001"},
                        json={**ks, "engaged": False})
    assert other.status_code == 409
    row = conn.execute("SELECT engaged, reason FROM broker.kill_switch WHERE scope = 'global'").fetchone()
    assert row["engaged"] is True and row["reason"] == "suspected bad rule"
    assert client.post("/v1/kill-switch", headers={**principals["admin1"], "Idempotency-Key": "bad key!"},
                       json=ks).status_code == 422


def test_case_assign_status_comment(client, principals, pool, settings, tmp_path, conn):
    cid = _case(pool, settings, tmp_path, conn)
    h = principals["analyst1"]
    assert client.post(f"/v1/cases/{cid}/assign", headers=h, json={"assignee": "admin1"}).json()["assignee"] == "admin1"
    assert client.post(f"/v1/cases/{cid}/assign", headers=h, json={"assignee": "worker-svc"}).status_code == 422
    assert client.post(f"/v1/cases/{cid}/assign", headers=h, json={"assignee": "nobody"}).status_code == 422
    for st in ("waiting", "closed", "open"):
        r = client.post(f"/v1/cases/{cid}/status", headers=h, json={"status": st, "reason": "triage"})
        assert r.status_code == 200 and r.json()["status"] == st, r.text
        assert conn.execute("SELECT status FROM gateway.alert_case WHERE case_id = %s", (cid,)).fetchone()["status"] == st
    assert client.post(f"/v1/cases/{cid}/status", headers=h, json={"status": "deleted"}).status_code == 422
    hk = {**h, "Idempotency-Key": "comment-0000001"}
    c1 = client.post(f"/v1/cases/{cid}/comments", headers=hk, json={"body": "Checked the WAF log, real scan."})
    c2 = client.post(f"/v1/cases/{cid}/comments", headers=hk, json={"body": "Checked the WAF log, real scan."})
    assert c1.status_code == 201 and c2.json()["idempotent_replay"] is True
    assert c1.json()["comment_id"] == c2.json()["comment_id"]
    assert conn.execute("SELECT count(*) n FROM broker.case_comment WHERE case_id = %s", (cid,)).fetchone()["n"] == 1
    # Service principals and viewers do not triage; unknown cases are 404.
    assert client.post(f"/v1/cases/{cid}/comments", headers=principals["worker-svc"],
                       json={"body": "x"}).status_code == 403
    assert client.post(f"/v1/cases/{cid}/comments", headers=principals["viewer1"], json={"body": "x"}).status_code == 403
    assert client.post("/v1/cases/CS-999999/status", headers=h, json={"status": "closed"}).status_code == 404
    assert client.post("/v1/cases/x'--/status", headers=h, json={"status": "closed"}).status_code == 404
    events = [r["event_type"] for r in conn.execute(
        "SELECT event_type FROM ledger.entry WHERE event_type LIKE 'case.%%' ORDER BY seq").fetchall()]
    assert events.count("case.assigned") == 1 and events.count("case.status_changed") == 3
    assert events.count("case.commented") == 1
    assert "real scan" not in str(_ledger(conn, "case.commented"))
    assert ledger.verify(conn).ok


def test_waiting_case_keeps_correlating(client, principals, pool, settings, tmp_path, conn):
    cid = _case(pool, settings, tmp_path, conn)
    client.post(f"/v1/cases/{cid}/status", headers=principals["analyst1"], json={"status": "waiting"})
    ingest(pool, settings, tmp_path, [waf_alert(ts="2026-11-24T03:06:00Z")], name="second")
    rows = conn.execute("SELECT case_id, status, alert_count FROM gateway.alert_case").fetchall()
    assert len(rows) == 1 and rows[0]["status"] == "waiting" and rows[0]["alert_count"] == 2


def test_revoke_time_boxed_action(client, principals, pool, settings, tmp_path, conn):
    ingest(pool, settings, tmp_path, [waf_alert()])
    aid, alert = _alert(conn)
    j = client.post("/v1/actions/requests", headers=principals["worker-svc"],
                    json=body(aid, params={"ip_token": alert["entities"]["src_ip"], "waf_instance": "w1",
                                           "ttl_s": 3600})).json()
    assert j["status"] == "validated" and j["rollback_at"]
    url = f"/v1/actions/requests/{j['request_id']}/revoke"
    assert client.post(url, headers=principals["analyst1"], json={"password": PW, "reason": "false positive"}).status_code == 403
    assert client.post(url, headers=principals["approver1"], json={"reason": "false positive"}).status_code == 403
    r = client.post(url, headers=principals["approver1"], json={"password": PW, "reason": "false positive"})
    assert r.status_code == 200 and r.json()["status"] == "rolled_back"
    row = conn.execute("SELECT status, revoked_by, revoked_at FROM broker.action_request WHERE request_id = %s",
                       (j["request_id"],)).fetchone()
    assert row["status"] == "rolled_back" and row["revoked_by"] == "principal:approver1" and row["revoked_at"]
    assert client.post(url, headers=principals["approver1"],
                       json={"password": PW, "reason": "again"}).status_code == 409
    assert _ledger(conn, "action.revoked")[0]["reason"] == "false positive"
    assert client.post(f"/v1/actions/requests/{uuid.uuid4()}/revoke", headers=principals["approver1"],
                       json={"password": PW, "reason": "not needed"}).status_code == 404


def test_body_sha_ignores_password():
    assert writes.body_sha("op", {"a": 1, "password": "x"}) == writes.body_sha("op", {"a": 1, "password": "y"})
    assert writes.body_sha("op", {"a": 1}) != writes.body_sha("op2", {"a": 1})
