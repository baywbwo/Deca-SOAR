import hashlib
import secrets

import pytest
from fastapi.testclient import TestClient

from deca_soar import ledger
from deca_soar.broker import service
from deca_soar.common.config import ConfigError

from helpers import ingest, waf_alert


@pytest.fixture
def env(monkeypatch, settings):
    monkeypatch.setenv("DECA_DB_URL", settings.db_url)
    monkeypatch.setenv("DECA_TOKENIZATION_KEY", settings.tokenization_key.hex())
    monkeypatch.setenv("DECA_VAULT_KEY", settings.vault_key.hex())
    monkeypatch.setenv("DECA_POLICY_DIR", str(settings.policy_dir))
    for n in ("ALIBABA_CLOUD_ACCESS_KEY_ID", "DECA_ENV"):
        monkeypatch.delenv(n, raising=False)
    return monkeypatch


@pytest.fixture
def principals(conn):
    toks = {}
    with conn.transaction():
        for name, kind, role in [("tracecat", "service", "analyst"), ("svc-admin", "service", "admin"),
                                 ("viewer1", "human", "viewer"), ("analyst1", "human", "analyst"),
                                 ("approver1", "human", "approver"), ("admin1", "human", "admin")]:
            t = secrets.token_urlsafe(24)
            service.create_principal(conn, name, kind, role, t, "test")
            toks[name] = {"Authorization": f"Bearer {t}"}
    return toks


@pytest.fixture
def client(env, principals):
    from deca_soar.broker.app import app
    with TestClient(app) as c:
        yield c


def _alert(conn, **kw):
    r = conn.execute("SELECT alert_id, alert FROM gateway.inbox_event ORDER BY ingested_at DESC LIMIT 1").fetchone()
    return str(r["alert_id"]), r["alert"]


def body(alert_id, action="waf.ip_blacklist.add", params=None, verdict="malicious", conf=0.95, **kw):
    b = {"alert_id": alert_id, "action": action, "params": params or {},
         "decision": {"verdict": verdict, "confidence": conf, "source": "rule"}}
    b.update(kw)
    return b


@pytest.fixture
def waf(pool, settings, tmp_path, conn):
    ingest(pool, settings, tmp_path, [waf_alert()])
    aid, alert = _alert(conn)
    return aid, alert["entities"]["src_ip"]


def test_auth_required(client):
    assert client.get("/v1/catalog").status_code == 401
    assert client.get("/v1/catalog", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_valid_l1_request_is_validated_in_shadow(client, principals, waf, conn):
    aid, ip_tok = waf
    r = client.post("/v1/actions/requests", headers=principals["tracecat"],
                    json=body(aid, params={"ip_token": ip_tok, "waf_instance": "waf-prod-1"}))
    assert r.status_code == 201, r.text
    j = r.json()
    assert j["status"] == "validated" and j["mode"] == "shadow" and j["executed_at"] is None
    assert j["params"]["ttl_s"] == 86400 and ip_tok in j["would_execute"]
    assert "203.0.113.7" not in r.text
    again = client.post("/v1/actions/requests", headers=principals["tracecat"],
                        json=body(aid, params={"ip_token": ip_tok, "waf_instance": "waf-prod-1"}))
    assert again.status_code == 200 and again.json()["idempotent_replay"] is True
    assert again.json()["request_id"] == j["request_id"]
    clash = client.post("/v1/actions/requests", headers=principals["tracecat"],
                        json=body(aid, params={"ip_token": ip_tok, "waf_instance": "waf-prod-2"},
                                  idempotency_key=j["idempotency_key"]))
    assert clash.status_code == 409
    v = client.get("/v1/ledger/verify", headers=principals["viewer1"]).json()
    assert v["ok"] and v["entries"] >= 3
    types = [r["event_type"] for r in conn.execute("SELECT event_type FROM ledger.entry ORDER BY seq")]
    assert types[-2:] == ["policy.decision", "action.requested"]


@pytest.mark.parametrize("ip,reason", [("198.51.100.20", "protected"), ("192.0.2.5", "protected")])
def test_protected_target_rejected(client, principals, pool, settings, tmp_path, conn, ip, reason):
    ingest(pool, settings, tmp_path, [waf_alert(ip=ip)])
    aid, alert = _alert(conn)
    r = client.post("/v1/actions/requests", headers=principals["tracecat"],
                    json=body(aid, params={"ip_token": alert["entities"]["src_ip"], "waf_instance": "w1"}))
    j = r.json()
    assert j["status"] == "rejected" and any(reason in x for x in j["reasons"])
    assert ip not in r.text


def test_target_must_come_from_evidence(client, principals, waf, settings):
    aid, _ = waf
    from deca_soar.common.pii import Tokenizer
    forged = Tokenizer(settings.tokenization_key).token("ip", "203.0.113.200")
    j = client.post("/v1/actions/requests", headers=principals["tracecat"],
                    json=body(aid, params={"ip_token": forged, "waf_instance": "w1"})).json()
    assert j["status"] == "rejected" and "target not in alert evidence" in j["reasons"]


@pytest.mark.parametrize("kw,reason", [
    ({"conf": 0.5}, "confidence below"),
    ({"verdict": "suspicious"}, "verdict suspicious not allowed"),
    ({"params": {"ip_token": "IPTOK", "waf_instance": "w1", "ttl_s": 999999999}}, "ttl_s out of range"),
    ({"params": {"ip_token": "IPTOK", "waf_instance": "w1;rm -rf"}}, "waf_instance invalid"),
    ({"params": {"ip_token": "IPTOK", "waf_instance": "w1", "extra": 1}}, "not allowed"),
    ({"params": {"ip_token": "203.0.113.7", "waf_instance": "w1"}}, "must be a token"),
    ({"action": "ram.access_key.disable", "params": {"access_key_token": "IPTOK"}}, "source waf"),
    ({"action": "shell.exec"}, "action not in catalog"),
])
def test_validation_rejections(client, principals, waf, kw, reason):
    aid, ip_tok = waf
    kw = dict(kw)
    if "params" in kw:
        kw["params"] = {k: (ip_tok if v == "IPTOK" else v) for k, v in kw["params"].items()}
    else:
        kw.setdefault("params", {"ip_token": ip_tok, "waf_instance": "w1"})
    j = client.post("/v1/actions/requests", headers=principals["tracecat"], json=body(aid, **kw)).json()
    assert j["status"] == "rejected", j
    assert any(reason in x for x in j["reasons"]), j["reasons"]


def test_rate_limit(client, principals, pool, settings, tmp_path, conn):
    # 50 new IPs per hour per WAF instance (design 6.3); the 51st is rejected.
    ingest(pool, settings, tmp_path, [waf_alert(ip=f"203.0.113.{i}") for i in range(1, 52)])
    rows = conn.execute("SELECT alert_id, alert FROM gateway.inbox_event").fetchall()
    statuses = []
    for r in rows:
        j = client.post("/v1/actions/requests", headers=principals["tracecat"],
                        json=body(str(r["alert_id"]), params={"ip_token": r["alert"]["entities"]["src_ip"],
                                                               "waf_instance": "w1"})).json()
        statuses.append(j["status"])
    assert statuses.count("validated") == 50 and statuses.count("rejected") == 1


def test_l2_approval_flow(client, principals, pool, settings, tmp_path, conn):
    ingest(pool, settings, tmp_path, [{"source": "actiontrail", "rule_id": "ram.ak.geo", "severity_hint": "high",
                                       "detected_at": "2026-11-24T03:00:00Z", "principal": "ops-bot",
                                       "access_key_id": "LTAI5tAbCdEfGhIjKlMn"}])
    aid, alert = _alert(conn)
    r = client.post("/v1/actions/requests", headers=principals["analyst1"],
                    json=body(aid, action="ram.access_key.disable", verdict="suspicious", conf=0.8,
                              params={"access_key_token": alert["entities"]["access_key_token"]}))
    j = r.json()
    assert j["status"] == "pending_approval" and j["level"] == "L2", j
    url = f"/v1/actions/requests/{j['request_id']}/approval"
    assert client.post(url, headers=principals["tracecat"], json={"approve": True}).status_code == 403
    assert client.post(url, headers=principals["svc-admin"], json={"approve": True}).status_code == 403
    assert client.post(url, headers=principals["viewer1"], json={"approve": True}).status_code == 403
    r2 = client.post(url, headers=principals["approver1"], json={"approve": True})
    assert r2.status_code == 200 and r2.json()["status"] == "validated" and r2.json()["executed_at"] is None
    assert client.post(url, headers=principals["approver1"], json={"approve": True}).status_code == 409
    assert "LTAI5tAbCdEfGhIjKlMn" not in str(conn.execute("SELECT json_agg(canonical) a FROM ledger.entry")
                                             .fetchone())


def test_self_approval_forbidden(client, principals, pool, settings, tmp_path, conn):
    ingest(pool, settings, tmp_path, [{"source": "actiontrail", "rule_id": "ram.ak.geo", "severity_hint": "high",
                                       "detected_at": "2026-11-24T03:00:00Z", "access_key_id": "LTAI5tZZZZZZZZZZZZZZ"}])
    aid, alert = _alert(conn)
    j = client.post("/v1/actions/requests", headers=principals["approver1"],
                    json=body(aid, action="ram.access_key.disable", conf=0.9,
                              params={"access_key_token": alert["entities"]["access_key_token"]})).json()
    r = client.post(f"/v1/actions/requests/{j['request_id']}/approval", headers=principals["approver1"],
                    json={"approve": True})
    assert r.status_code == 403 and "own request" in r.text


def test_role_permissions(client, principals, waf):
    aid, ip_tok = waf
    req = body(aid, params={"ip_token": ip_tok, "waf_instance": "w1"})
    assert client.post("/v1/actions/requests", headers=principals["viewer1"], json=req).status_code == 403
    ks = {"scope": "global", "engaged": True}
    for who in ("viewer1", "analyst1", "approver1", "tracecat", "svc-admin"):
        assert client.post("/v1/kill-switch", headers=principals[who], json=ks).status_code == 403, who
    assert client.post("/v1/kill-switch", headers=principals["admin1"], json=ks).status_code == 200
    j = client.post("/v1/actions/requests", headers=principals["tracecat"], json=req).json()
    assert j["mode"] == "shadow"
    assert client.get("/v1/whoami", headers=principals["tracecat"]).json()["permissions"] == ["read",
                                                                                              "request_action"]


def test_unknown_alert_and_bad_body(client, principals):
    r = client.post("/v1/actions/requests", headers=principals["tracecat"],
                    json=body("00000000-0000-0000-0000-000000000000"))
    assert r.status_code == 404
    bad = body("00000000-0000-0000-0000-000000000000")
    bad["decision"]["confidence"] = 7
    assert client.post("/v1/actions/requests", headers=principals["tracecat"], json=bad).status_code == 422
    bad = body("00000000-0000-0000-0000-000000000000", sneaky=True)
    assert client.post("/v1/actions/requests", headers=principals["tracecat"], json=bad).status_code == 422


def test_refuses_to_start_with_write_credentials(env, principals):
    env.setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "x")
    from deca_soar.broker.app import app
    with pytest.raises(ConfigError):
        with TestClient(app):
            pass


def test_refuses_production_with_placeholder_allowlist(env, principals):
    env.setenv("DECA_ENV", "production")
    from deca_soar.broker.app import app
    with pytest.raises(ConfigError):
        with TestClient(app):
            pass


def test_token_stored_hashed(conn, principals):
    tok = principals["tracecat"]["Authorization"].split()[1]
    assert conn.execute("SELECT count(*) n FROM broker.principal WHERE token_sha256 = %s",
                        (hashlib.sha256(tok.encode()).hexdigest(),)).fetchone()["n"] == 1
    assert ledger.verify(conn).ok
