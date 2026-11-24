"""Lark / Jira / 9router integrations: secrets, callbacks, ladder, Jira dedup, AI fallback, production rules."""

import json
import logging
import secrets
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from hypersoar import ledger
from hypersoar.broker import service
from hypersoar.broker.integrations import ai as ai_mod
from hypersoar.broker.integrations import config as int_config
from hypersoar.broker.integrations import hub as hub_mod
from hypersoar.broker.integrations import lark, secretbox
from hypersoar.common import entity as entity_mod
from hypersoar.common.config import ConfigError
from hypersoar.console.auth import hash_password

from helpers import ingest

KEY_HEX = "11" * 32
ADMIN_PW = "integration-admin-pw-for-tests"
LARK = {"app_secret": "lark-app-secret-VALUE-9f3a", "verification_token": "lark-vtoken-VALUE-77c1",
        "encrypt_key": "lark-encrypt-VALUE-0b5e"}


@pytest.fixture(scope="module")
def admin_hash():
    return hash_password(ADMIN_PW)


@pytest.fixture
def env(monkeypatch, settings, roles, admin_hash):
    monkeypatch.setenv("HYPERSOAR_DB_URL", roles["broker"])
    monkeypatch.setenv("HYPERSOAR_VAULT_PRIVATE_KEY", settings.vault_private_key.hex())
    monkeypatch.setenv("HYPERSOAR_ALLOW_TEST_NETS", "1")
    monkeypatch.setenv("HYPERSOAR_POLICY_DIR", str(settings.policy_dir))
    monkeypatch.setenv("HYPERSOAR_INTEGRATION_KEY", KEY_HEX)
    monkeypatch.setenv("HYPERSOAR_INTEGRATION_ADMIN_PASSWORD_HASH", admin_hash)
    monkeypatch.setenv("HYPERSOAR_SYNC", "0")
    for n in ("ALIBABA_CLOUD_ACCESS_KEY_ID", "HYPERSOAR_ENV", "HYPERSOAR_MODE", "HYPERSOAR_INTEGRATION_WRITES",
              "HYPERSOAR_JIRA_INBOUND"):
        monkeypatch.delenv(n, raising=False)
    return monkeypatch


@pytest.fixture
def principals(conn):
    toks = {}
    with conn.transaction():
        for name, kind, role in [("worker-svc", "service", "analyst"), ("svc-admin", "service", "admin"),
                                 ("analyst1", "human", "analyst"), ("approver1", "human", "approver"),
                                 ("admin1", "human", "admin")]:
            t = secrets.token_urlsafe(24)
            service.create_principal(conn, name, kind, role, t, "test")
            toks[name] = {"Authorization": f"Bearer {t}"}
    return toks


@pytest.fixture
def client(env, principals):
    from hypersoar.broker.app import app
    with TestClient(app) as c:
        c.broker = app.state.broker
        c.pool = app.state.pool
        yield c


@pytest.fixture
def box():
    return secretbox.SecretBox(bytes.fromhex(KEY_HEX))


def _lark_secrets(conn, box):
    with conn.transaction():
        for k, v in LARK.items():
            secretbox.set_secret(conn, box, "dob", "lark", "sandbox", k, v, "test")


def _ak_alert(pool, settings, tmp_path, conn, key="LTAI5tSyntheticKey7Q2F"):
    ingest(pool, settings, tmp_path, [{"source": "actiontrail", "rule_id": "actiontrail.ak_unusual_ip",
                                       "severity_hint": "critical", "detected_at": "2026-11-24T03:00:00Z",
                                       "src_ip": "203.0.113.5", "principal": "svc-settlement-report",
                                       "access_key_id": key}], name=f"ak{secrets.token_hex(3)}")
    r = conn.execute("SELECT alert_id, alert FROM gateway.inbox_event ORDER BY ingested_at DESC LIMIT 1").fetchone()
    return str(r["alert_id"]), r["alert"]


def _l2(client, principals, aid, alert):
    r = client.post("/v1/actions/requests", headers=principals["analyst1"], json={
        "alert_id": aid, "action": "ram.access_key.disable",
        "params": {"access_key_token": alert["entities"]["access_key_token"]},
        "decision": {"verdict": "malicious", "confidence": 0.9, "source": "rule"}})
    j = r.json()
    assert j["status"] == "pending_approval", j
    return j


def _callback(event: dict, *, key=LARK["encrypt_key"], ts=None, tamper=False):
    body = json.dumps({"encrypt": lark.encrypt(key, json.dumps(event).encode(), secrets.token_bytes(16))}).encode()
    ts = str(int(ts if ts is not None else time.time()))
    nonce = secrets.token_hex(8)
    sig = lark.sign(ts, nonce, key, body)
    if tamper:
        body = body[:-2] + b" }"
    return body, {"X-Lark-Request-Timestamp": ts, "X-Lark-Request-Nonce": nonce, "X-Lark-Signature": sig,
                  "Content-Type": "application/json"}


def _click(open_id, request_id, approve=True, token=LARK["verification_token"]):
    return {"schema": "2.0", "header": {"event_type": "card.action.trigger", "token": token},
            "event": {"operator": {"open_id": open_id}, "action": {"value": {"request_id": request_id,
                                                                            "approve": approve}}}}


def _ledger(conn, type_):
    return [r["payload"] for r in conn.execute(
        "SELECT canonical::jsonb -> 'payload' AS payload FROM ledger.entry WHERE event_type = %s ORDER BY seq",
        (type_,))]


# -- secrets -----------------------------------------------------------------------
def test_secret_is_write_only_and_never_logged(client, principals, conn, env, caplog):
    caplog.set_level(logging.DEBUG)
    url = "/v1/integrations/jira/secrets/api_token"
    value = "jira-token-VALUE-never-leaves-4d2c"
    put = {"value": value, "password": ADMIN_PW}
    assert client.put(url, headers=principals["admin1"], json=put).status_code == 403  # writes flag off
    env.setenv("HYPERSOAR_INTEGRATION_WRITES", "1")
    assert client.put(url, headers=principals["approver1"], json=put).status_code == 403
    assert client.put(url, headers=principals["svc-admin"], json=put).status_code == 403
    r = client.put(url, headers=principals["admin1"], json={**put, "password": "wrong-password-here"})
    assert r.status_code == 403 and "re-authentication" in r.text
    assert client.put(url, headers=principals["admin1"], json=put).status_code == 204
    assert client.put("/v1/integrations/jira/secrets/password", headers=principals["admin1"],
                      json=put).status_code == 422
    listing = client.get("/v1/integrations", headers=principals["approver1"])
    assert listing.status_code == 200 and value not in listing.text
    jira = next(i for i in listing.json()["integrations"] if i["integration"] == "jira")
    st = jira["secrets"]["api_token"]
    assert st["set"] is True and st["rotated_by"] == "principal:admin1" and st["rotated_at"]
    assert set(st) <= {"set", "rotated_at", "rotated_by", "expires_at", "required"}
    db = json.dumps([dict(r) for r in conn.execute("SELECT * FROM broker.integration_secret")], default=str)
    assert value not in db
    led = json.dumps([r["canonical"] for r in conn.execute("SELECT canonical FROM ledger.entry")], default=str)
    assert value not in led and "api_token" in led
    assert value not in caplog.text and ADMIN_PW not in caplog.text
    with conn.transaction():  # only the broker key opens it
        assert secretbox.get_secrets(conn, secretbox.SecretBox(bytes.fromhex(KEY_HEX)), "dob", "jira",
                                     "sandbox")["api_token"] == value
        with pytest.raises(ConfigError):
            secretbox.get_secrets(conn, secretbox.SecretBox(b"\x22" * 32), "dob", "jira", "sandbox")


def test_viewer_role_cannot_read_ciphertext(roles):
    import psycopg
    auditor = roles["auditor"]
    with psycopg.connect(auditor) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("SELECT ciphertext FROM broker.integration_secret").fetchall()


# -- config versions ------------------------------------------------------------------
def test_config_save_history_and_rollback(client, principals, conn, env):
    env.setenv("HYPERSOAR_INTEGRATION_WRITES", "1")
    cur = client.get("/v1/integrations", headers=principals["admin1"]).json()
    ai_view = next(i for i in cur["integrations"] if i["integration"] == "ai")
    assert ai_view["version"] == 1 and ai_view["target"] == "mock"
    s = dict(ai_view["settings"], timeout_s=30)
    r = client.put("/v1/integrations/ai", headers=principals["admin1"],
                   json={"target": "mock", "settings": s, "password": ADMIN_PW, "note": "slower model"})
    assert r.status_code == 200 and r.json()["version"] == 2, r.text
    bad = client.put("/v1/integrations/ai", headers=principals["admin1"],
                     json={"target": "mock", "settings": {**s, "api_key": "x"}, "password": ADMIN_PW})
    assert bad.status_code == 422
    hist = client.get("/v1/integrations/ai/history", headers=principals["admin1"]).json()["versions"]
    assert [h["version"] for h in hist] == [2, 1]
    rb = client.post("/v1/integrations/ai/rollback", headers=principals["admin1"],
                     json={"version": 1, "password": ADMIN_PW})
    assert rb.status_code == 200 and rb.json()["version"] == 3
    assert int_config.get(conn, "dob", "ai", "sandbox")["settings"]["timeout_s"] == 20
    changed = _ledger(conn, "integration.config_changed")
    assert [c["version"] for c in changed][-2:] == [2, 3] and "timeout_s" in changed[-2]["changed_fields"]


# -- production rules ----------------------------------------------------------------
def test_production_rejects_mock():
    ent = entity_mod.load(mode="sandbox")
    ai = ent.integrations["ai"]
    with pytest.raises(int_config.ConfigInvalid, match="mock"):
        int_config.validate("ai", "production", "mock", ai.settings)
    with pytest.raises(int_config.ConfigInvalid):
        int_config.validate("ai", "production", "live", {**ai.settings, "mock_fault": "invalid_json"})
    import yaml
    from pathlib import Path
    doc = yaml.safe_load(Path("entities/dob.yaml").read_text())
    doc["targets"]["production"]["jira"]["target"] = "mock"
    with pytest.raises(ConfigError, match="mock"):
        entity_mod.parse(doc, "production")


# -- Lark callback --------------------------------------------------------------------
def test_lark_callback_rejects_bad_signature_token_and_age(client, principals, pool, settings, tmp_path, conn, box):
    _lark_secrets(conn, box)
    aid, alert = _ak_alert(pool, settings, tmp_path, conn)
    req = _l2(client, principals, aid, alert)
    ev = _click("ou_sandboxrina", req["request_id"])
    for body, headers in [_callback(ev, tamper=True), _callback(ev, key="some-other-encrypt-key"),
                          _callback(ev, ts=time.time() - 3600),
                          _callback(_click("ou_sandboxrina", req["request_id"], token="forged-token"))]:
        r = client.post("/hooks/lark/card", content=body, headers=headers)
        assert r.status_code == 401, r.text
    no_sig = client.post("/hooks/lark/card", json={"encrypt": "AAAA"})
    assert no_sig.status_code == 401
    st = conn.execute("SELECT status FROM broker.action_request WHERE request_id = %s",
                      (req["request_id"],)).fetchone()["status"]
    assert st == "pending_approval"


def test_lark_callback_url_verification(client, conn, box):
    _lark_secrets(conn, box)
    body, h = _callback({"type": "url_verification", "challenge": "abc123", "token": LARK["verification_token"]})
    assert client.post("/hooks/lark/card", content=body, headers=h).json() == {"challenge": "abc123"}


def test_lark_click_outside_ladder_is_refused(client, principals, pool, settings, tmp_path, conn, box):
    _lark_secrets(conn, box)
    aid, alert = _ak_alert(pool, settings, tmp_path, conn)
    req = _l2(client, principals, aid, alert)
    body, h = _callback(_click("ou_intruder", req["request_id"]))
    r = client.post("/hooks/lark/card", content=body, headers=h)
    assert r.status_code == 403
    assert conn.execute("SELECT status FROM broker.action_request WHERE request_id = %s",
                        (req["request_id"],)).fetchone()["status"] == "pending_approval"
    ref = _ledger(conn, "approval.refused")
    assert ref and ref[-1]["lark_user"] == "ou_intruder" and "ladder" in ref[-1]["reason"]


def test_lark_click_on_ladder_approves_in_shadow(client, principals, pool, settings, tmp_path, conn, box):
    _lark_secrets(conn, box)
    aid, alert = _ak_alert(pool, settings, tmp_path, conn)
    req = _l2(client, principals, aid, alert)
    assert req["case_id"] and req["expires_at"] and req["impact"] and req["rollback_plan"]
    body, h = _callback(_click("ou_sandboxbayu", req["request_id"]))
    r = client.post("/hooks/lark/card", content=body, headers=h)
    assert r.status_code == 200 and r.json()["status"] == "validated", r.text
    row = conn.execute("SELECT * FROM broker.action_request WHERE request_id = %s", (req["request_id"],)).fetchone()
    assert row["approver_ref"] == "lark:ou_sandboxbayu" and row["executed_at"] is None
    ok = _ledger(conn, "action.approved")[-1]
    assert ok["via"] == "lark" and ok["ladder_step"] == 1 and ok["role"] == "SOC lead"
    body, h = _callback(_click("ou_sandboxrina", req["request_id"], approve=False))
    assert client.post("/hooks/lark/card", content=body, headers=h).status_code == 409  # already decided
    assert ledger.verify(conn).ok


def test_lark_cannot_approve_non_l2(client, principals, pool, settings, tmp_path, conn, box):
    """L1 is validated by policy, never pending; anything that is not L2 (L3 included) is refused."""
    _lark_secrets(conn, box)
    aid, alert = _ak_alert(pool, settings, tmp_path, conn)
    req = _l2(client, principals, aid, alert)
    conn.execute("UPDATE broker.action_request SET level = 'L3' WHERE request_id = %s", (req["request_id"],))
    body, h = _callback(_click("ou_sandboxandi", req["request_id"]))
    assert client.post("/hooks/lark/card", content=body, headers=h).status_code == 403
    assert conn.execute("SELECT status FROM broker.action_request WHERE request_id = %s",
                        (req["request_id"],)).fetchone()["status"] == "pending_approval"


def test_lark_click_after_ttl_expires(client, principals, pool, settings, tmp_path, conn, box):
    _lark_secrets(conn, box)
    aid, alert = _ak_alert(pool, settings, tmp_path, conn)
    req = _l2(client, principals, aid, alert)
    conn.execute("UPDATE broker.action_request SET expires_at = now() - interval '1 second' WHERE request_id = %s",
                 (req["request_id"],))
    body, h = _callback(_click("ou_sandboxrina", req["request_id"]))
    r = client.post("/hooks/lark/card", content=body, headers=h)
    assert r.status_code == 409 and "expired" in r.text
    assert conn.execute("SELECT status FROM broker.action_request WHERE request_id = %s",
                        (req["request_id"],)).fetchone()["status"] == "expired"


# -- escalation ladder ---------------------------------------------------------------
def test_escalation_on_call_lead_head_then_expire(client, principals, pool, settings, tmp_path, conn):
    aid, alert = _ak_alert(pool, settings, tmp_path, conn)
    req = _l2(client, principals, aid, alert)
    hub = client.broker.hub
    created = conn.execute("SELECT created_at, expires_at FROM broker.action_request WHERE request_id = %s",
                           (req["request_id"],)).fetchone()
    # dob ladder: on-call 5 min, lead 10 min, Head of IT 15 min = 30 min = the TTL cap.
    assert abs(created["expires_at"] - created["created_at"] - timedelta(minutes=30)) < timedelta(seconds=2)
    levels = []
    for minutes in (1, 6, 16, 29):
        hub_mod.escalate_due(pool, hub, created["created_at"] + timedelta(minutes=minutes))
        levels.append(conn.execute("SELECT escalation_level FROM broker.action_request WHERE request_id = %s",
                                   (req["request_id"],)).fetchone()["escalation_level"])
    assert levels == [0, 1, 2, 2]
    out = hub_mod.escalate_due(pool, hub, created["created_at"] + timedelta(minutes=31))
    assert out == [{"request_id": req["request_id"], "event": "expired"}]
    assert [e["role"] for e in _ledger(conn, "action.escalated")] == ["SOC lead", "Head of IT"]
    cards = conn.execute("SELECT payload FROM broker.integration_outbox WHERE operation = 'lark.approval_card'"
                         " ORDER BY outbox_id").fetchall()
    assert [c["payload"]["step"] for c in cards] == [0, 1, 2]
    # Mock Lark sends each card to the approvers of that step.
    res = hub_mod.tick(pool, hub)
    assert res["ops"] and all(o["outcome"] == "done" for o in res["ops"]), res


# -- Jira -------------------------------------------------------------------------------
def test_jira_mock_never_duplicates(client, principals, pool, settings, tmp_path, conn):
    aid, alert = _ak_alert(pool, settings, tmp_path, conn)
    case_id = conn.execute("SELECT case_id FROM gateway.case_alert WHERE alert_id = %s", (aid,)).fetchone()["case_id"]
    hub = client.broker.hub
    for _ in range(3):
        with pool.connection() as c, c.transaction():
            hub_mod.enqueue(c, "dob", "jira", "jira.ensure_issue", case_id=case_id)
    hub_mod.tick(pool, hub)
    with pool.connection() as c, c.transaction():
        status, key = hub_mod.ensure_jira_issue(c, hub, case_id)
    assert status == "duplicate" and key == "SEC-101"
    creates = conn.execute("SELECT count(*) n FROM broker.integration_call WHERE operation = 'jira.create'"
                           " AND case_id = %s", (case_id,)).fetchone()["n"]
    assert creates == 1
    linked = _ledger(conn, "jira.issue_linked")
    assert linked[0] == {"case_id": case_id, "issue_key": "SEC-101", "found_existing": False}


def _live_jira(conn, monkeypatch_hub, transport):
    with conn.transaction():
        row = int_config.get(conn, "dob", "jira", "sandbox")
        int_config.save(conn, "dob", "jira", "sandbox", "live", True, row["settings"], "test")
        secretbox.set_secret(conn, secretbox.SecretBox(bytes.fromhex(KEY_HEX)), "dob", "jira", "sandbox",
                             "api_token", "jira-live-token-VALUE", "test")
    monkeypatch_hub.transports["jira"] = transport


def test_jira_live_finds_existing_issue_by_label(client, principals, pool, settings, tmp_path, conn):
    aid, _ = _ak_alert(pool, settings, tmp_path, conn)
    case_id = conn.execute("SELECT case_id FROM gateway.case_alert WHERE alert_id = %s", (aid,)).fetchone()["case_id"]
    seen = []

    def handler(req: httpx.Request):
        seen.append((req.method, req.url.path, dict(req.url.params)))
        if req.url.path == "/rest/api/3/search/jql":
            return httpx.Response(200, json={"issues": [{"key": "SEC-7"}]})
        return httpx.Response(500)

    hub = client.broker.hub
    _live_jira(conn, hub, httpx.MockTransport(handler))
    with pool.connection() as c, c.transaction():
        assert hub_mod.ensure_jira_issue(c, hub, case_id) == ("duplicate", "SEC-7")
    assert [s[0] for s in seen] == ["GET"] and f"hypersoar-{case_id.lower()}" in seen[0][2]["jql"].lower()


def test_jira_live_creates_once_with_priority_and_tokens_only(client, principals, pool, settings, tmp_path, conn):
    aid, _ = _ak_alert(pool, settings, tmp_path, conn)
    case_id = conn.execute("SELECT case_id FROM gateway.case_alert WHERE alert_id = %s", (aid,)).fetchone()["case_id"]
    created = []

    def handler(req: httpx.Request):
        if req.url.path == "/rest/api/3/search/jql":
            return httpx.Response(200, json={"issues": []})
        if req.url.path == "/rest/api/3/issue" and req.method == "POST":
            created.append(json.loads(req.content))
            return httpx.Response(201, json={"key": "SEC-42"})
        return httpx.Response(404)

    hub = client.broker.hub
    _live_jira(conn, hub, httpx.MockTransport(handler))
    for _ in range(2):
        with pool.connection() as c, c.transaction():
            hub_mod.ensure_jira_issue(c, hub, case_id)
    assert len(created) == 1
    f = created[0]["fields"]
    assert f["priority"] == {"name": "Highest"} and f["project"] == {"key": "SEC"}
    assert f"hypersoar-{case_id.lower()}" in [x.lower() for x in f["labels"]]
    text = json.dumps(created)
    for raw in ("203.0.113.5", "LTAI5tSyntheticKey7Q2F", "svc-settlement-report"):
        assert raw not in text


def test_jira_failure_retries_then_records_error(client, principals, pool, settings, tmp_path, conn):
    aid, _ = _ak_alert(pool, settings, tmp_path, conn)
    case_id = conn.execute("SELECT case_id FROM gateway.case_alert WHERE alert_id = %s", (aid,)).fetchone()["case_id"]
    hub = client.broker.hub
    _live_jira(conn, hub, httpx.MockTransport(lambda r: httpx.Response(503)))
    with pool.connection() as c, c.transaction():
        hub_mod.enqueue(c, "dob", "jira", "jira.ensure_issue", case_id=case_id)
    now = datetime.now(UTC)
    for i in range(hub_mod.MAX_ATTEMPTS):
        r = hub_mod.process_one(pool, hub, now + timedelta(hours=i))
        assert r and r["status"] == "error"
    assert r["outcome"] == "error"
    assert conn.execute("SELECT 1 FROM broker.jira_issue WHERE case_id = %s", (case_id,)).fetchone() is None
    assert _ledger(conn, "integration.failed")[-1]["attempts"] == hub_mod.MAX_ATTEMPTS


def test_jira_issue_closes_when_case_closes(client, principals, pool, settings, tmp_path, conn):
    aid, _ = _ak_alert(pool, settings, tmp_path, conn)
    case_id = conn.execute("SELECT case_id FROM gateway.case_alert WHERE alert_id = %s", (aid,)).fetchone()["case_id"]
    hub = client.broker.hub
    with pool.connection() as c, c.transaction():
        hub_mod.ensure_jira_issue(c, hub, case_id)
    conn.execute("UPDATE gateway.alert_case SET status = 'closed', closed_at = now() WHERE case_id = %s", (case_id,))
    hub_mod.tick(pool, hub)
    hub_mod.tick(pool, hub)
    assert conn.execute("SELECT status FROM broker.jira_issue WHERE case_id = %s",
                        (case_id,)).fetchone()["status"] == "closed"
    assert conn.execute("SELECT count(*) n FROM broker.integration_outbox WHERE operation = 'jira.close'"
                        ).fetchone()["n"] == 1


def test_jira_inbound_is_off_by_default(client):
    assert client.post("/hooks/jira", json={}).status_code == 404


# -- 9router -----------------------------------------------------------------------------
def _set_ai(conn, **changes):
    with conn.transaction():
        row = int_config.get(conn, "dob", "ai", "sandbox")
        target = changes.pop("target", row["target"])
        int_config.save(conn, "dob", "ai", "sandbox", target, True, {**row["settings"], **changes}, "test")


def test_triage_mock_returns_verdict_and_trace(client, principals, pool, settings, tmp_path, conn):
    aid, _ = _ak_alert(pool, settings, tmp_path, conn)
    r = client.post("/v1/triage", headers=principals["worker-svc"], json={"alert_id": aid})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["verdict"] in ("malicious", "suspicious") and j["source"] == "llm" and not j["escalated"]
    tr = _ledger(conn, "ai.triage")[-1]
    assert tr["alert_id"] == aid and tr["prompt_sha"] and tr["attempts"][0]["ok"]
    assert conn.execute("SELECT sum(calls) n FROM broker.ai_usage").fetchone()["n"] == 1
    ops = {r["operation"] for r in conn.execute("SELECT operation FROM broker.integration_outbox")}
    assert {"jira.ensure_issue", "lark.case_notify"} <= ops


def test_triage_broken_json_falls_back_then_escalates(client, principals, pool, settings, tmp_path, conn):
    aid, _ = _ak_alert(pool, settings, tmp_path, conn)
    _set_ai(conn, mock_fault="invalid_json_primary")
    j = client.post("/v1/triage", headers=principals["worker-svc"], json={"alert_id": aid}).json()
    assert j["fallback_used"] is True and j["model"] == "deca-lite" and j["verdict"] != "unknown"
    _set_ai(conn, mock_fault="invalid_json")
    j = client.post("/v1/triage", headers=principals["worker-svc"], json={"alert_id": aid}).json()
    assert j["verdict"] == "unknown" and j["escalated"] and j["confidence"] == 0.0
    esc = _ledger(conn, "ai.escalated")[-1]
    assert esc["reason"] == "AI answer unusable"
    assert conn.execute("SELECT count(*) n FROM broker.integration_outbox WHERE operation = 'lark.notice'"
                        ).fetchone()["n"] >= 1


def test_triage_live_bad_schema_and_token_limit(client, principals, pool, settings, tmp_path, conn):
    aid, _ = _ak_alert(pool, settings, tmp_path, conn)
    sent = []

    def handler(req: httpx.Request):
        body = json.loads(req.content)
        sent.append(body)
        content = '{"verdict": "pwned", "confidence": 2}' if body["model"] == "deca-triage-v2" else "not json"
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}],
                                         "usage": {"prompt_tokens": 500, "completion_tokens": 100}})

    _set_ai(conn, target="live")
    with conn.transaction():
        secretbox.set_secret(conn, secretbox.SecretBox(bytes.fromhex(KEY_HEX)), "dob", "ai", "sandbox", "api_key",
                             "router-key-VALUE", "test")
    client.broker.hub.transports["ai"] = httpx.MockTransport(handler)
    j = client.post("/v1/triage", headers=principals["worker-svc"], json={"alert_id": aid}).json()
    assert j["verdict"] == "unknown" and j["escalated"]
    assert [b["model"] for b in sent] == ["deca-triage-v2", "deca-lite"]
    user_msg = sent[0]["messages"][1]["content"]
    for raw in ("203.0.113.5", "LTAI5tSyntheticKey7Q2F", "svc-settlement-report"):
        assert raw not in user_msg
    assert sent[0]["temperature"] == 0 and sent[0]["response_format"] == {"type": "json_object"}
    _set_ai(conn, daily_token_limit=1000)
    before = len(sent)
    j = client.post("/v1/triage", headers=principals["worker-svc"], json={"alert_id": aid}).json()
    assert j["verdict"] == "unknown" and j["escalated"] and len(sent) == before
    assert "token limit" in _ledger(conn, "ai.escalated")[-1]["reason"]


def test_ai_refuses_untokenised_input():
    assert ai_mod.raw_values_in('{"x":"203.0.113.9"}') and ai_mod.raw_values_in('{"k":"LTAI5tAbCdEfGhIjKlMn"}')
    assert not ai_mod.raw_values_in('{"x":"tok_ip_0123456789abcdef"}')


# -- connection tests -------------------------------------------------------------------
def test_connection_test_per_integration(client, principals, conn):
    for name in ("lark", "jira", "ai"):
        r = client.post(f"/v1/integrations/{name}/test", headers=principals["admin1"])
        assert r.status_code == 200 and r.json()["status"] == "pass", r.text
        assert all(s["ok"] for s in r.json()["steps"])
    assert client.post("/v1/integrations/ai/test", headers=principals["svc-admin"]).status_code == 403
    assert client.post("/v1/integrations/nope/test", headers=principals["admin1"]).status_code == 404
    runs = conn.execute("SELECT integration, status FROM broker.integration_test_run ORDER BY started_at").fetchall()
    assert [(r["integration"], r["status"]) for r in runs] == [("lark", "pass"), ("jira", "pass"), ("ai", "pass")]
    view = client.get("/v1/integrations", headers=principals["admin1"]).json()
    assert {i["integration"]: i["state"] for i in view["integrations"]}["ai"] in ("connected", "warning")


def test_jira_done_closes_case_only_when_enabled(client, principals, pool, settings, tmp_path, conn, env, box):
    aid, _ = _ak_alert(pool, settings, tmp_path, conn)
    case_id = conn.execute("SELECT case_id FROM gateway.case_alert WHERE alert_id = %s", (aid,)).fetchone()["case_id"]
    hub = client.broker.hub
    with pool.connection() as c, c.transaction():
        _, key = hub_mod.ensure_jira_issue(c, hub, case_id)
    hook_secret = "jira-hook-VALUE-31ab"
    with conn.transaction():
        secretbox.set_secret(conn, box, "dob", "jira", "sandbox", "webhook_secret", hook_secret, "test")
        row = int_config.get(conn, "dob", "jira", "sandbox")
        s = {**row["settings"], "sync": {**row["settings"]["sync"], "close_case_on_done": True}}
        int_config.save(conn, "dob", "jira", "sandbox", "mock", True, s, "test")
    event = {"issue": {"key": key, "fields": {"labels": [f"hypersoar-{case_id}"],
                                              "status": {"statusCategory": {"key": "done"}}}}}
    raw = json.dumps(event).encode()
    import hashlib
    import hmac as hmac_mod
    sig = "sha256=" + hmac_mod.new(hook_secret.encode(), raw, hashlib.sha256).hexdigest()
    assert client.post("/hooks/jira", content=raw, headers={"X-Hub-Signature": sig}).status_code == 404  # flag off
    hub.jira_inbound = True
    try:
        assert client.post("/hooks/jira", content=raw, headers={"X-Hub-Signature": "sha256=00"}).status_code == 401
        r = client.post("/hooks/jira", content=raw, headers={"X-Hub-Signature": sig})
        assert r.status_code == 200 and r.json() == {"case_id": case_id, "close_requested": True}, r.text
    finally:
        hub.jira_inbound = False
    ingest(pool, settings, tmp_path, [], name="empty")
    c = conn.execute("SELECT status, close_reason FROM gateway.alert_case WHERE case_id = %s", (case_id,)).fetchone()
    assert (c["status"], c["close_reason"]) == ("closed", "jira:done")


def test_cli_set_secret_reads_stdin_and_never_prints_it(client, conn, env, box, monkeypatch, capsys):
    import io

    from hypersoar import cli

    value = "cli-secret-VALUE-9e1f"
    monkeypatch.setattr("sys.stdin", io.StringIO(value + "\n"))
    assert cli.main(["integration", "set-secret", "--integration", "ai", "--name", "api_key",
                     "--actor", "ops"]) == 0
    out = capsys.readouterr()
    assert value not in out.out + out.err and '"set": true' in out.out
    assert secretbox.get_secrets(conn, box, "dob", "ai", "sandbox")["api_key"] == value
    assert value not in json.dumps(_ledger(conn, "integration.secret_rotated"))
    monkeypatch.setattr("sys.stdin", io.StringIO("\n"))
    assert cli.main(["integration", "set-secret", "--integration", "ai", "--name", "api_key", "--actor", "ops"]) == 2
    assert cli.main(["integration", "test", "--actor", "ops"]) == 0
    lines = [json.loads(x) for x in capsys.readouterr().out.splitlines() if x.startswith("{")]
    assert [(r["integration"], r["status"]) for r in lines] == [("lark", "pass"), ("jira", "pass"), ("ai", "pass")]
