"""v0.8 console writes: the browser-facing checks (session, same origin, CSRF token, JSON, Idempotency-Key,
re-auth rate limit) and the whole path through the real broker app: approve, L3, kill switch, case triage,
revoke, audit trail. Production has no scenario page."""

import json
import secrets

import httpx
import pytest
from fastapi.testclient import TestClient

from hypersoar.broker import service
from hypersoar.broker import writes as bw
from hypersoar.common.config import ConfigError
from hypersoar.console import writes as cw

from helpers import ingest, waf_alert
from test_broker_api import _alert, body, client, env, principals  # noqa: F401  (fixtures)
from test_console import ORIGIN, PASSWORD, _login, console, console_env, pw_hash, viewer  # noqa: F401  (fixtures)

WRITES = [("/api/approvals/{request_id}/ask-ai", "POST"), ("/api/approvals/{request_id}/decision", "POST"),
          ("/api/cases/{case_id}/assign", "POST"), ("/api/cases/{case_id}/comments", "POST"),
          ("/api/cases/{case_id}/status", "POST"), ("/api/kill-switch", "POST"),
          ("/api/requests/{request_id}/revoke", "POST"), ("/login", "POST"), ("/logout", "POST")]


def _ledger(conn, event_type):
    return [r for r in conn.execute("SELECT actor, payload FROM ledger.entry WHERE event_type = %s ORDER BY seq",
                                    (event_type,)).fetchall()]


@pytest.fixture
def owner(conn, pw_hash):
    """The broker's human principal the console user acts as: same name, admin, re-auth = console password."""
    tok = secrets.token_urlsafe(24)
    with conn.transaction():
        service.create_principal(conn, "owner", "human", "admin", tok, "test")
        bw.set_reauth_hash(conn, "owner", pw_hash, "test")
    return tok


@pytest.fixture
def wired(client, owner, console):
    """Console logged in, its broker client pointed at the real broker app (in-process)."""
    from hypersoar.console.app import fastapi_app
    st = fastapi_app.state
    st.broker = cw.BrokerClient("http://testserver", owner, transport=client._transport)
    assert _login(console).status_code == 303
    csrf = console.get("/api/shell").json()["meta"]["csrf"]
    yield console, csrf
    st.broker.close()
    st.broker = None


def _w(c, csrf, path, payload, key=None, **hdr):
    h = {"content-type": "application/json", "x-hypersoar-csrf": csrf, "idempotency-key": key or secrets.token_hex(8),
         **ORIGIN, **hdr}
    return c.post(path, content=json.dumps(payload), headers=h)


def _l2(client, principals, pool, settings, tmp_path, conn):
    ingest(pool, settings, tmp_path, [{"source": "actiontrail", "rule_id": "ram.ak.geo", "severity_hint": "high",
                                       "detected_at": "2026-11-24T03:00:00Z", "access_key_id": "LTAI5tCONSOLECONSOLE"}])
    aid, alert = _alert(conn)
    j = client.post("/v1/actions/requests", headers=principals["analyst1"],
                    json=body(aid, action="ram.access_key.disable", conf=0.9,
                              params={"access_key_token": alert["entities"]["access_key_token"]})).json()
    assert j["status"] == "pending_approval", j
    return j["request_id"]


def test_write_routes_are_exactly_these():
    from hypersoar.console.app import fastapi_app
    got = sorted((r.path, m) for r in fastapi_app.routes for m in getattr(r, "methods", set()) - {"GET", "HEAD"})
    assert got == WRITES


def test_browser_checks_before_the_broker(wired):
    c, csrf = wired
    path, ok = "/api/kill-switch", {"engaged": True, "password": PASSWORD, "reason": "test"}
    assert _w(c, "", path, ok).status_code == 403
    assert _w(c, "x" * 43, path, ok).status_code == 403
    assert _w(c, csrf, path, ok, origin="https://evil.example").status_code == 403
    assert _w(c, csrf, path, ok, origin="http://testserver").status_code == 403
    assert _w(c, csrf, path, ok, **{"content-type": "text/plain"}).status_code == 415
    assert _w(c, csrf, path, ok, key="bad key!").status_code == 422
    assert _w(c, csrf, path, {**ok, "scope": "global"}).status_code == 422  # extra fields refused
    assert _w(c, csrf, "/api/cases/CS-1;drop/status", {"status": "closed"}).status_code == 404
    assert _w(c, csrf, "/api/approvals/not-a-uuid/decision", {"approve": True, "password": "x"}).status_code == 404
    c.post("/logout", headers=ORIGIN)
    assert _w(c, csrf, path, ok).status_code == 401


def test_writes_off_without_broker_settings(console):
    assert _login(console).status_code == 303
    meta = console.get("/api/shell").json()["meta"]
    assert meta["writes"] is False and len(meta["csrf"]) >= 40 and "read_only" not in meta
    r = _w(console, meta["csrf"], "/api/cases/CS-1001/comments", {"body": "x"})
    assert r.status_code == 503


def test_approve_through_the_broker_needs_the_password(wired, client, principals, pool, settings, tmp_path, conn):
    c, csrf = wired
    rid = _l2(client, principals, pool, settings, tmp_path, conn)
    url = f"/api/approvals/{rid}/decision"
    assert _w(c, csrf, url, {"approve": True}).status_code == 422  # no password: refused before the broker
    r = _w(c, csrf, url, {"approve": True, "password": "not the password"})
    assert r.status_code == 403 and "re-authentication" in r.json()["detail"]
    assert conn.execute("SELECT status FROM broker.action_request WHERE request_id = %s",
                        (rid,)).fetchone()["status"] == "pending_approval"
    key = "approve-0000001"
    ok = _w(c, csrf, url, {"approve": True, "password": PASSWORD}, key=key)
    assert ok.status_code == 200 and ok.json()["status"] == "validated", ok.text
    again = _w(c, csrf, url, {"approve": True, "password": PASSWORD}, key=key)
    assert again.status_code == 200 and again.json()["idempotent_replay"] is True
    approved = _ledger(conn, "action.approved")
    assert len(approved) == 1 and approved[0]["payload"]["via"] == "console"
    assert [x["actor"] for x in _ledger(conn, "auth.reauth_failed")] == ["principal:owner"]
    assert PASSWORD not in str(conn.execute("SELECT json_agg(canonical) a FROM ledger.entry").fetchone())
    assert c.get("/api/approvals").json()["pending"] == []


def test_l3_needs_a_reason_from_the_console_too(wired, client, principals, pool, settings, tmp_path, conn):
    c, csrf = wired
    rid = _l2(client, principals, pool, settings, tmp_path, conn)
    conn.execute("UPDATE broker.action_request SET level = 'L3' WHERE request_id = %s", (rid,))
    url = f"/api/approvals/{rid}/decision"
    r = _w(c, csrf, url, {"approve": True, "password": PASSWORD})
    assert r.status_code == 403 and "reason" in r.json()["detail"]
    ok = _w(c, csrf, url, {"approve": True, "password": PASSWORD, "reason": "owner confirmed the key leaked"})
    assert ok.status_code == 200 and ok.json()["status"] == "validated"
    assert _ledger(conn, "action.approved")[-1]["payload"]["reason"] == "owner confirmed the key leaked"


def test_reject_from_the_console(wired, client, principals, pool, settings, tmp_path, conn):
    c, csrf = wired
    rid = _l2(client, principals, pool, settings, tmp_path, conn)
    r = _w(c, csrf, f"/api/approvals/{rid}/decision", {"approve": False, "password": PASSWORD, "reason": "benign"})
    assert r.status_code == 200 and r.json()["status"] == "rejected", r.text
    recent = c.get("/api/approvals").json()["recent"]
    assert recent[0]["status"] == "rejected"


def test_kill_switch_from_the_console(wired, conn):
    c, csrf = wired
    on = {"engaged": True, "password": PASSWORD, "reason": "bad rule firing"}
    assert _w(c, csrf, "/api/kill-switch", {**on, "reason": "x"}).status_code == 422
    r = _w(c, csrf, "/api/kill-switch", on, key="ks-console-01")
    assert r.status_code == 200 and r.json()["engaged"] is True
    assert c.get("/api/shell").json()["kill_switch"]["global_engaged"] is True
    assert _w(c, csrf, "/api/kill-switch", on, key="ks-console-01").json()["idempotent_replay"] is True
    off = _w(c, csrf, "/api/kill-switch", {"engaged": False, "password": PASSWORD, "reason": "rule fixed"})
    assert off.status_code == 200 and c.get("/api/shell").json()["kill_switch"]["global_engaged"] is False
    changes = _ledger(conn, "kill_switch.changed")
    assert [x["payload"]["reason"] for x in changes] == ["bad rule firing", "rule fixed"]
    assert {x["actor"] for x in changes} == {"principal:owner"}


def test_case_triage_from_the_console(wired, pool, settings, tmp_path, conn):
    c, csrf = wired
    ingest(pool, settings, tmp_path, [waf_alert()])
    cid = conn.execute("SELECT case_id FROM gateway.alert_case").fetchone()["case_id"]
    d = c.get(f"/api/cases/{cid}").json()
    assert "owner" in d["people"] and "worker-svc" not in d["people"] and d["case"]["assignee"] is None
    assert _w(c, csrf, f"/api/cases/{cid}/assign", {"assignee": "owner"}).json()["assignee"] == "owner"
    assert _w(c, csrf, f"/api/cases/{cid}/assign", {"assignee": "worker-svc"}).status_code == 422
    assert _w(c, csrf, f"/api/cases/{cid}/status", {"status": "waiting"}).json()["status"] == "waiting"
    assert [x["case_id"] for x in c.get("/api/cases?status=waiting").json()["cases"]] == [cid]
    assert [x["case_id"] for x in c.get("/api/cases?status=open").json()["cases"]] == [cid]
    assert c.get("/api/shell").json()["open_cases"] == 1
    key = "comment-console-1"
    first = _w(c, csrf, f"/api/cases/{cid}/comments", {"body": "Scanner from a known VPS range."}, key=key)
    assert first.status_code == 201
    assert _w(c, csrf, f"/api/cases/{cid}/comments", {"body": "Scanner from a known VPS range."},
              key=key).json()["idempotent_replay"] is True
    assert _w(c, csrf, f"/api/cases/{cid}/comments", {"body": "x" * 2001}).status_code == 422
    assert _w(c, csrf, f"/api/cases/{cid}/status", {"status": "closed", "reason": "scanner"}).status_code == 200
    d = c.get(f"/api/cases/{cid}").json()
    assert d["case"]["status"] == "closed" and d["case"]["assignee"] == "owner"
    assert d["case"]["status_by"] == "principal:owner" and d["case"]["close_reason"] == "scanner"
    assert [m["body"] for m in d["comments"]] == ["Scanner from a known VPS range."]
    assert [x["case_id"] for x in c.get("/api/cases?status=closed").json()["cases"]] == [cid]
    assert c.get("/api/cases?status=open").json()["cases"] == []
    events = [r["event_type"] for r in conn.execute(
        "SELECT event_type FROM ledger.entry WHERE event_type LIKE 'case.%%' AND actor = 'principal:owner'"
        " ORDER BY seq").fetchall()]
    assert events == ["case.assigned", "case.status_changed", "case.commented", "case.status_changed"]


def test_revoke_from_the_automation_screen(wired, client, principals, pool, settings, tmp_path, conn):
    c, csrf = wired
    ingest(pool, settings, tmp_path, [waf_alert()])
    aid, alert = _alert(conn)
    j = client.post("/v1/actions/requests", headers=principals["worker-svc"],
                    json=body(aid, params={"ip_token": alert["entities"]["src_ip"], "waf_instance": "w1",
                                           "ttl_s": 3600})).json()
    exp = c.get("/api/automation").json()["expiring"]
    assert [x["id"] for x in exp] == [j["request_id"]]
    url = f"/api/requests/{j['request_id']}/revoke"
    assert _w(c, csrf, url, {"password": PASSWORD}).status_code == 422  # reason required
    r = _w(c, csrf, url, {"password": PASSWORD, "reason": "false positive"})
    assert r.status_code == 200 and r.json()["status"] == "rolled_back", r.text
    assert c.get("/api/automation").json()["expiring"] == []
    assert _w(c, csrf, url, {"password": PASSWORD, "reason": "again"}).status_code == 409
    assert _ledger(conn, "action.revoked")[0]["actor"] == "principal:owner"


def test_wrong_reauth_passwords_are_rate_limited(wired):
    c, csrf = wired
    bad = {"engaged": True, "password": "wrong wrong wrong", "reason": "test"}
    for _ in range(5):
        assert _w(c, csrf, "/api/kill-switch", bad).status_code == 403
    r = _w(c, csrf, "/api/kill-switch", {**bad, "password": PASSWORD})
    assert r.status_code == 429
    # Non re-auth writes are not blocked by it.
    assert _w(c, csrf, "/api/cases/CS-999999/status", {"status": "closed"}).status_code == 404


def test_ask_ai_sends_the_alert_from_the_database(wired, client, principals, pool, settings, tmp_path, conn):
    c, csrf = wired
    rid = _l2(client, principals, pool, settings, tmp_path, conn)
    alert_id = str(conn.execute("SELECT alert_id FROM broker.action_request WHERE request_id = %s",
                                (rid,)).fetchone()["alert_id"])
    seen = []

    def handler(req: httpx.Request):
        seen.append((req.url.path, json.loads(req.content), req.headers.get("authorization")))
        return httpx.Response(200, json={"alert_id": alert_id, "verdict": "malicious", "confidence": 0.91})

    from hypersoar.console.app import fastapi_app
    real = fastapi_app.state.broker
    fastapi_app.state.broker = cw.BrokerClient("https://broker.test", "tok", transport=httpx.MockTransport(handler))
    try:
        assert _w(c, csrf, f"/api/approvals/{rid}/ask-ai", {"alert_id": "smuggled"}).status_code == 422
        r = _w(c, csrf, f"/api/approvals/{rid}/ask-ai", {}, key="ask-ai-0001")
        assert r.status_code == 200 and r.json()["verdict"] == "malicious"
        assert _w(c, csrf, f"/api/approvals/{rid}/ask-ai", {}, key="ask-ai-0001").json()["idempotent_replay"] is True
        assert seen == [("/v1/triage", {"alert_id": alert_id}, "Bearer tok")]
    finally:
        fastapi_app.state.broker.close()
        fastapi_app.state.broker = real


def test_broker_client_maps_errors():
    def handler(req):
        return {"/401": httpx.Response(401, json={"detail": "bad token"}),
                "/500": httpx.Response(500, text="boom"),
                "/409": httpx.Response(409, json={"detail": "x" * 1000})}[req.url.path]

    b = cw.BrokerClient("https://broker.test", "t", transport=httpx.MockTransport(handler))
    assert b.post("/401", {}, "k" * 8) == (502, {"detail": "broker answered 401"})
    assert b.post("/500", {}, "k" * 8) == (502, {"detail": "broker answered 500"})
    st, d = b.post("/409", {}, "k" * 8)
    assert st == 409 and len(d["detail"]) == 300

    def down(req):
        raise httpx.ConnectError("no route")
    assert cw.BrokerClient("https://b.test", "t", transport=httpx.MockTransport(down)).post("/x", {}, None)[0] == 502


def test_broker_client_settings(monkeypatch, tmp_path):
    monkeypatch.delenv("HYPERSOAR_BROKER_URL", raising=False)
    assert cw.BrokerClient.from_env("production") is None
    monkeypatch.setenv("HYPERSOAR_BROKER_URL", "http://broker:8200")
    with pytest.raises(ConfigError, match="https"):
        cw.BrokerClient.from_env("production")
    monkeypatch.setenv("HYPERSOAR_BROKER_URL", "https://broker:8200")
    monkeypatch.delenv("HYPERSOAR_BROKER_TOKEN", raising=False)
    monkeypatch.delenv("HYPERSOAR_BROKER_TOKEN_FILE", raising=False)
    with pytest.raises(ConfigError, match="TOKEN"):
        cw.BrokerClient.from_env("sandbox")


def test_production_has_no_scenario_page(console):
    from hypersoar.console.app import fastapi_app
    assert _login(console).status_code == 303
    inst = fastapi_app.state.install
    real = inst.get
    inst.get = lambda pool: {**real(pool), "mode": "production"}
    try:
        assert console.get("/scenarios").status_code == 404
        assert console.get("/api/scenarios").status_code == 404
        page = console.get("/cases").text
        assert '<body class="app prod" data-screen="cases"' in page
        assert console.get("/api/shell").json()["mode"] == "production"
    finally:
        inst.get = real
    assert console.get("/scenarios").status_code == 200


def test_scenario_cli_refuses_production_before_touching_the_database(monkeypatch, tmp_path):
    from hypersoar import cli
    monkeypatch.setenv("HYPERSOAR_MODE", "production")
    monkeypatch.setenv("HYPERSOAR_DB_URL", "postgresql://nobody@127.0.0.1:1/none")  # never reached
    with pytest.raises(ConfigError, match="sandbox only"):
        cli.main(["scenario", "run", "--replay", str(tmp_path / "x.ndjson"), "--actor", "t"])
    with pytest.raises(RuntimeError, match="HYPERSOAR_MODE=sandbox"):
        cli.main(["synth-alerts", "--out", str(tmp_path / "y.ndjson"), "--count", "1"])
