"""Data-source connectors: field mapping, CEF, webhook HMAC, SLS pull, the spool, the gateway's
restricted view of source settings, the broker connection tests and the production rules."""

import json
import time
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlsplit

import httpx
import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.rows import dict_row

from hypersoar.broker.integrations import config as int_config
from hypersoar.broker.integrations import secretbox
from hypersoar.common.config import ConfigError
from hypersoar.common.db import make_pool
from hypersoar.gateway import app as gw_app
from hypersoar.gateway.connectors import Connectors
from hypersoar.gateway.service import pull_once
from hypersoar.sources import cef, connection_test, mapping, spool, webhook
from hypersoar.sources.models import SlsSettings, SyslogSettings, WebhookSettings
from hypersoar.sources.sls import SlsClient, SlsSource, signature

from helpers import PW
from test_integrations import KEY_HEX, _as, box, client, env, principals  # noqa: F401  (fixtures)

SECRET = "w" * 40
WEBHOOK = {"source_type": "siem", "rule_prefix": "wazuh.",
           "fields": {"rule_id": "rule.id", "severity": "rule.level", "detected_at": "timestamp",
                      "src_ip": "data.srcip", "dst_asset": "agent.name"}}
SLS = {"source_type": "waf", "endpoint": "https://ap-southeast-5.log.aliyuncs.com", "project": "dob-waf",
       "logstore": "waf-alerts", "fields": {"rule_id": "rule", "severity": "level", "detected_at": "__time__",
                                            "src_ip": "real_client_ip"}, "window_s": 60, "lag_s": 30}


# -- mapping and CEF --------------------------------------------------------------------------
def test_mapping_reads_only_the_field_map():
    s = WebhookSettings.model_validate(WEBHOOK)
    rec = {"rule": {"id": "5710", "level": 10}, "rule.id": None, "timestamp": "1764032523000",
           "data": {"srcip": "203.0.113.50"}, "agent": {"name": "portal-01"}, "evil": {"source": "waf"}}
    rec.pop("rule.id")
    raw = mapping.to_raw(rec, s, "webhook://1")
    assert raw["source"] == "siem" and raw["rule_id"] == "wazuh.5710" and raw["severity_hint"] == "critical"
    assert raw["detected_at"].startswith("2025-11-25T01:02:03") and raw["src_ip"] == "203.0.113.50"
    assert raw["dst_asset"] == "portal-01" and "evil" not in raw and raw["raw_ref"] == "webhook://1"
    assert mapping.severity("3", {}) == "low" and mapping.severity("Very-High", {}) == "critical"
    assert mapping.severity("P1", {"p1": "high"}) == "high" and mapping.severity(None, {}) == "medium"
    # A host name is not a blockable address; a missing rule id is refused.
    assert "src_ip" not in mapping.to_raw({"rule": {"id": "1"}, "data": {"srcip": "evil.example"}}, s, "x")
    with pytest.raises(mapping.MappingError):
        mapping.to_raw({"data": {}}, s, "x")
    with pytest.raises(mapping.MappingError):
        mapping.to_raw({"rule": {"id": "x" * 80}}, s, "x")


def test_cef_parse():
    rec = cef.parse(r"<134>Nov 25 01:02:03 fw CEF:0|Fortinet|FortiGate|7.4|13056|SQL inj\|ection|8|"
                    r"src=203.0.113.9 dhost=portal request=/login?q\=1 msg=a b c cnt=4")
    assert rec["device_vendor"] == "Fortinet" and rec["signature_id"] == "13056" and rec["name"] == "SQL inj|ection"
    assert rec["src"] == "203.0.113.9" and rec["request"] == "/login?q=1" and rec["msg"] == "a b c"
    raw = mapping.to_raw(rec, SyslogSettings(allowed_senders=("10.0.0.0/8",), rule_prefix="forti."), "syslog://1")
    assert raw["rule_id"] == "forti.13056" and raw["severity_hint"] == "high" and raw["events"] == 4
    for bad in ("hello", "CEF:0|a|b", "CEF:" + "x|" * 7 + "a=" + "b" * 9000):
        with pytest.raises(cef.CefError):
            cef.parse(bad)


def test_settings_validation():
    with pytest.raises(ValueError, match="whole internet"):
        SyslogSettings(allowed_senders=("0.0.0.0/0",))
    with pytest.raises(ValueError):
        SlsSettings.model_validate({**SLS, "endpoint": "https://evil.example.com"})
    with pytest.raises(int_config.ConfigInvalid, match="no mock target"):
        int_config.validate("webhook", "sandbox", "mock", WEBHOOK)
    int_config.validate("webhook", "production", "live", WEBHOOK)


# -- webhook ---------------------------------------------------------------------------------
def test_webhook_signature_rules():
    body, seen, now = b'{"rule": {"id": "1"}}', webhook.SeenSignatures(), 1_800_000_000
    sig = webhook.sign(SECRET, now, body)
    webhook.verify(SECRET, str(now), sig, body, 300, seen, now=now)
    for secret, ts, s, b, status in [
        (SECRET, str(now), sig, body, 409),                                   # replayed
        (SECRET, str(now), webhook.sign(SECRET, now, b"{}"), body, 401),      # body changed
        (SECRET, str(now - 301), webhook.sign(SECRET, now - 301, body), body, 401),  # too old
        (SECRET, None, sig, body, 401),
        ("short", str(now), sig, body, 503),
    ]:
        with pytest.raises(webhook.Rejected) as e:
            webhook.verify(secret, ts, s, b, 300, seen, now=now)
        assert e.value.status == status
    assert len(webhook.records(b'{"alerts": [{"a": 1}, {"b": 2}]}')) == 2
    with pytest.raises(webhook.Rejected):
        webhook.records(b"[1, 2]")


def _gateway_login(roles):
    return make_pool(roles["gateway"], max_size=2)


def _configure(conn, box, name, settings, secrets=None, mode="sandbox", enabled=True, activate=True):
    with conn.transaction():
        v = int_config.save(conn, "dob", name, mode, "live", enabled, settings, "test")
        if activate:  # as a passed connection test would
            int_config.activate(conn, "dob", name, mode, v, "test")
        for k, v in (secrets or {}).items():
            secretbox.set_secret(conn, box, "dob", name, mode, k, v, "test")


def test_webhook_end_to_end_through_the_gateway(conn, roles, settings, box):
    _configure(conn, box, "webhook", WEBHOOK, {"hmac_secret": SECRET})
    _configure(conn, box, "lark", {"app_id": "cli_abcdefgh12", "routing": {s: {} for s in
               ("critical", "high", "medium", "low")}, "ladder": [{"role": "x", "timeout_min": 5,
               "approvers": [{"name": "a", "lark_user_id": "ou_a"}]}]}, {"app_secret": "LARK-SECRET-VALUE"})
    gpool = _gateway_login(roles)
    try:
        conns = Connectors(gpool, "dob", "sandbox", box)
        # The gateway login sees data-source settings and secrets only.
        with gpool.connection() as g:
            assert {r["integration"] for r in g.execute("SELECT integration FROM broker.source_secret")} == {"webhook"}
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                g.execute("SELECT 1 FROM broker.integration_secret")
        app = gw_app.app
        app.state.pool, app.state.entity_id, app.state.connectors = gpool, "dob", conns
        app.state.seen = webhook.SeenSignatures()
        c = TestClient(app)
        alerts = [{"rule": {"id": "5710", "level": 12}, "timestamp": "2026-11-25T01:00:00Z",
                   "data": {"srcip": "203.0.113.77"}}, {"no": "rule"}]
        body = json.dumps({"alerts": alerts}).encode()
        ts = str(int(time.time()))
        h = {"content-type": "application/json", "x-hypersoar-timestamp": ts,
             "x-hypersoar-signature": webhook.sign(SECRET, ts, body)}
        r = c.post("/v1/ingest/webhook", content=body, headers=h)
        assert r.status_code == 202 and r.json() == {"accepted": 2}
        assert c.post("/v1/ingest/webhook", content=body, headers=h).status_code == 409
        assert c.post("/v1/ingest/webhook", content=body, headers={**h, "x-hypersoar-signature": "sha256=00"}
                      ).status_code == 401
        [src] = conns.pull_sources()
        res = pull_once(gpool, src, settings)
        assert (res.pulled, res.new, res.rejected) == (2, 1, 1)
        row = conn.execute("SELECT source, rule_id, alert FROM gateway.inbox_event").fetchone()
        assert row["source"] == "siem" and row["rule_id"] == "wazuh.5710"
        assert row["alert"]["entities"]["src_ip"].startswith("tok_ip_") and "203.0.113.77" not in json.dumps(row["alert"])
        assert conn.execute("SELECT count(*) n FROM gateway.source_spool").fetchone()["n"] == 0
        # Disabled: the endpoint closes within one refresh.
        _configure(conn, box, "webhook", WEBHOOK, enabled=False)
        conns.refresh(force=True)
        assert c.post("/v1/ingest/webhook", content=body, headers=h).status_code == 404
    finally:
        gpool.close()


def test_spool_is_bounded(conn, monkeypatch):
    monkeypatch.setattr(spool, "MAX_PENDING", 3)
    spool.put(conn, "dob", "webhook", [{"a": 1}, {"a": 2}])
    with pytest.raises(spool.SpoolFull):
        spool.put(conn, "dob", "webhook", [{"a": 3}, {"a": 4}])


def test_syslog_handler(conn, roles, box):
    _configure(conn, box, "syslog", {"allowed_senders": ["10.20.0.0/16"]})
    gpool = _gateway_login(roles)
    try:
        counters = {"accepted": 0, "dropped": 0, "unparsed": 0}
        on_line = gw_app.syslog_handler(gpool, "dob", Connectors(gpool, "dob", "sandbox", box), counters)
        on_line("10.20.3.4", "<134>Nov 25 01:02:03 fw CEF:0|V|P|1|42|x|5|src=203.0.113.1")
        on_line("::ffff:10.20.3.4", "<134>Nov 25 01:02:03 fw CEF:0|V|P|1|43|x|5|src=203.0.113.1")
        on_line("192.0.2.1", "<134>Nov 25 01:02:03 fw CEF:0|V|P|1|42|x|5|src=203.0.113.1")
        on_line("10.20.3.4", "not cef")
        assert counters == {"accepted": 2, "dropped": 1, "unparsed": 1}
    finally:
        gpool.close()


# -- SLS ------------------------------------------------------------------------------------
class FakeSls:
    def __init__(self, logs_by_window, incomplete=()):
        self.logs, self.incomplete, self.calls = logs_by_window, set(incomplete), []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        u = urlsplit(str(request.url))
        params = dict(parse_qsl(u.query))
        auth = request.headers["authorization"]
        hdrs = {k: v for k, v in request.headers.items() if k.startswith("x-log-")}
        expected = signature("sk-secret", "GET", request.headers["date"], hdrs, u.path, params)
        assert u.hostname == "dob-waf.ap-southeast-5.log.aliyuncs.com" and auth == f"LOG ak-id:{expected}"
        frm, off, line = int(params["from"]), int(params["offset"]), int(params["line"])
        self.calls.append((frm, off, line))
        logs = self.logs.get(frm, [])[off:off + line]
        return httpx.Response(200, json=logs, headers={
            "x-log-progress": "Incomplete" if frm in self.incomplete else "Complete"})


def test_sls_pull_windows_and_cursor():
    s = SlsSettings.model_validate({**SLS, "page": 10})
    t0 = 1_800_000_000
    logs = {t0: [{"rule": "waf.sqli.burst", "level": "high", "__time__": str(t0 + i), "real_client_ip": "203.0.113.9"}
                 for i in range(12)], t0 + 60: [{"rule": "waf.scan.path_enum", "__time__": str(t0 + 61)}]}
    fake = FakeSls(logs, incomplete={t0 + 120})
    clock = [t0 + 60 + 30]  # window [t0, t0+60) is complete, the next one is not yet
    src = SlsSource(SlsClient(s, {"access_key_id": "ak-id", "access_key_secret": "sk-secret"},
                              httpx.MockTransport(fake)), clock=lambda: clock[0])
    out, cur = src.pull(f"{t0}:0", 500)
    assert len(out) == 12 and cur == f"{t0 + 60}:0" and out[0]["rule_id"] == "waf.sqli.burst"
    assert out[0]["source"] == "waf" and out[0]["raw_ref"] == f"sls://dob-waf/waf-alerts/{t0}/0"
    assert src.pull(cur, 500) == ([], cur)  # nothing new until the next window has ended
    clock[0] = t0 + 180 + 30
    out, cur2 = src.pull(cur, 500)
    assert len(out) == 1 and cur2 == f"{t0 + 120}:0"  # stops at the window SLS still indexes
    # A limit smaller than the window keeps the offset in the cursor.
    out, cur3 = SlsSource(src.client, clock=lambda: t0 + 90).pull(f"{t0}:0", 5)
    assert len(out) == 5 and cur3 == f"{t0}:5"


def test_sls_connection_test_reports_errors_without_secrets():
    s = SlsSettings.model_validate(SLS)
    assert connection_test("sls", s, {})[-1] == {"step": "secrets set", "ok": False,
                                                  "detail": "access_key_id, access_key_secret"}
    deny = httpx.MockTransport(lambda r: httpx.Response(401, json={"errorCode": "Unauthorized",
                                                                   "errorMessage": "sk-secret is wrong"}))
    steps = connection_test("sls", s, {"access_key_id": "ak-id", "access_key_secret": "sk-secret"}, deny)
    assert steps[-1]["ok"] is False and steps[-1]["detail"] == "HTTP 401 Unauthorized"
    assert "sk-secret" not in json.dumps(steps)


def test_source_connection_tests_through_the_broker(client, principals, conn, box, env):
    _configure(conn, box, "webhook", WEBHOOK, {"hmac_secret": SECRET})
    _configure(conn, box, "syslog", {"allowed_senders": ["10.0.0.0/8"]})
    env.setenv("HYPERSOAR_INTEGRATION_WRITES", "1")
    for name in ("webhook", "syslog"):
        r = client.post(f"/v1/integrations/{name}/test", headers=_as(principals, "admin1"), json={"password": PW})
        assert r.status_code == 200 and r.json()["status"] == "pass", r.text
    assert client.post("/v1/integrations/sls/test", headers=_as(principals, "admin1"),
                       json={"password": PW}).json()["status"] == "fail"
    view = {i["integration"]: i for i in client.get("/v1/integrations", headers=principals["admin1"]).json()
            ["integrations"]}
    assert view["webhook"]["category"] == "source" and view["webhook"]["state"] == "connected"
    assert view["webhook"]["secrets"]["hmac_secret"]["set"] is True and SECRET not in json.dumps(view)
    assert view["lark"]["category"] == "notify" and view["sls"]["state"] == "not_configured"


# -- production -----------------------------------------------------------------------------
def test_production_gateway_refuses_the_replay_file(monkeypatch, tmp_path):
    monkeypatch.setenv("HYPERSOAR_GATEWAY_SOURCE", "replay")
    monkeypatch.setenv("HYPERSOAR_REPLAY_FILE", str(tmp_path / "a.ndjson"))
    with pytest.raises(ConfigError, match="sandbox only"):
        gw_app.replay_source("production")
    assert gw_app.replay_source("sandbox") is not None
    monkeypatch.setenv("HYPERSOAR_GATEWAY_SOURCE", "connectors")
    assert gw_app.replay_source("production") is None
    monkeypatch.delenv("HYPERSOAR_GATEWAY_SOURCE")
    assert gw_app.replay_source("production") is None


def test_production_connectors_are_separate_from_sandbox(conn, roles, box):
    _configure(conn, box, "webhook", WEBHOOK, {"hmac_secret": SECRET}, mode="sandbox")
    gpool = _gateway_login(roles)
    try:
        assert Connectors(gpool, "dob", "production", box).pull_sources() == []
        assert [s.name for s in Connectors(gpool, "dob", "sandbox", box).pull_sources()] == ["webhook"]
    finally:
        gpool.close()
