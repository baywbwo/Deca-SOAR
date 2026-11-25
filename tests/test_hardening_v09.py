"""v0.9 hardening (review of v0.8, findings 1-6 and LOW): egress allowlist and public-address check,
secrets bound to their host, active-after-test, re-authenticated integration writes, separate gateway
key, explicit mode, syslog transport rules, webhook replay across processes."""

import asyncio
import base64
import json
import socket

import httpx
import pytest

from hypersoar.broker.integrations import config as int_config
from hypersoar.broker.integrations import secretbox
from hypersoar.common import egress, entity
from hypersoar.common.config import ConfigError, Settings
from hypersoar.common.db import make_pool
from hypersoar.sources import syslog, webhook
from hypersoar.workflows import worker

from helpers import PW
from test_preflight import _live_stub
from test_integrations import KEY_HEX, _as, _host, box, client, env, principals  # noqa: F401  (fixtures)

MASTER = bytes.fromhex(KEY_HEX)
TOKEN_A, TOKEN_B = "jira-token-for-site-A-VALUE", "jira-token-for-site-B-VALUE"


def _ledger(conn, event_type):
    return [r["payload"] for r in conn.execute(
        "SELECT payload FROM ledger.entry WHERE event_type = %s ORDER BY seq", (event_type,)).fetchall()]


# -- 1. egress --------------------------------------------------------------------------------
@pytest.mark.parametrize("host", ["169.254.169.254", "127.0.0.1", "10.0.0.5", "[::1]", "::ffff:127.0.0.1",
                                  "2130706433", "0x7f.1", "127.1", "1.2.3.4."])
def test_ip_literal_hosts_are_refused(host):
    with pytest.raises(egress.EgressDenied, match="IP address"):
        egress.check_host("jira", host)


@pytest.mark.parametrize("integration,host", [("jira", "evil.example.com"), ("jira", "atlassian.net.evil.com"),
                                              ("jira", "atlassian.net"), ("lark", "open.larksuite.com.evil.io"),
                                              ("sls", "log.aliyuncs.com"), ("ai", "9router.sandbox.invalid")])
def test_hosts_off_the_allowlist_are_refused(integration, host, monkeypatch):
    monkeypatch.delenv("HYPERSOAR_AI_HOSTS", raising=False)  # live AI is refused until its host is designated
    with pytest.raises(egress.EgressDenied):
        egress.check_host(integration, host)


def test_allowlisted_hosts_pass(monkeypatch):
    monkeypatch.setenv("HYPERSOAR_AI_HOSTS", "router.deca.example")
    assert egress.check_host("jira", "Deca.Atlassian.NET") == "deca.atlassian.net"
    assert egress.check_host("lark", "open.larksuite.com") == "open.larksuite.com"
    assert egress.check_host("sls", "ap-southeast-5.log.aliyuncs.com")
    assert egress.check_host("ai", "router.deca.example") == "router.deca.example"


@pytest.mark.parametrize("url", ["http://deca.atlassian.net", "https://deca.atlassian.net:8443",
                                 "https://user:pw@deca.atlassian.net", "https://169.254.169.254/latest"])
def test_only_plain_https_urls(url):
    with pytest.raises(egress.EgressDenied):
        egress.host_of("jira", url)


@pytest.mark.parametrize("ip", ["10.1.2.3", "127.0.0.1", "169.254.169.254", "100.100.100.200", "100.64.0.1",
                                "172.16.0.1", "192.168.1.1", "::1", "fe80::1", "fd00:ec2::254", "::ffff:10.0.0.1",
                                "0.0.0.0"])
def test_names_resolving_to_internal_or_metadata_addresses_are_refused(fake_dns, ip):
    fake_dns["rebind.atlassian.net"] = ["93.184.215.14", ip]  # one bad answer is enough
    with pytest.raises(egress.EgressDenied, match="non-public"):
        egress.resolve("rebind.atlassian.net")


def test_guarded_transport_never_connects_inward(fake_dns, monkeypatch):
    fake_dns["rebind.atlassian.net"] = ["169.254.169.254"]
    connected = []
    monkeypatch.setattr("httpcore.SyncBackend.connect_tcp", lambda *a, **k: connected.append(a) or 1 / 0)
    with httpx.Client(transport=egress.transport("jira")) as c:
        with pytest.raises(httpx.ConnectError, match="egress denied"):
            c.get("https://rebind.atlassian.net/rest/api/3/myself")
        with pytest.raises(httpx.ConnectError, match="egress denied"):
            c.get("https://169.254.169.254/latest/meta-data/")
        with pytest.raises(httpx.ConnectError, match="egress denied"):
            c.get("https://evil.example.com/")
    assert connected == []


def test_internal_site_cannot_be_saved(client, principals, conn, env):
    env.setenv("HYPERSOAR_INTEGRATION_WRITES", "1")
    row = int_config.get(conn, "dob", "jira", "sandbox")
    for site in ("https://169.254.169.254", "https://10.0.0.8", "https://jira.internal.corp"):
        r = client.put("/v1/integrations/jira", headers=_as(principals, "admin1"),
                       json={"target": "live", "settings": {**row["settings"], "site": site}, "password": PW})
        assert r.status_code == 422, (site, r.text)
    assert int_config.get(conn, "dob", "jira", "sandbox")["version"] == row["version"]


def test_live_ai_needs_a_designated_host(client, conn, env):
    env.delenv("HYPERSOAR_AI_HOSTS")
    row = int_config.get(conn, "dob", "ai", "sandbox")
    with pytest.raises(int_config.ConfigInvalid, match="no host is allowed"):
        int_config.validate("ai", "sandbox", "live", row["settings"])


def test_connection_test_refuses_a_host_that_resolves_inward(client, principals, conn, env, fake_dns):
    env.setenv("HYPERSOAR_INTEGRATION_WRITES", "1")
    fake_dns["inward.atlassian.net"] = ["10.9.8.7"]
    row = int_config.get(conn, "dob", "jira", "sandbox")
    with conn.transaction():
        int_config.save(conn, "dob", "jira", "sandbox", "live", True,
                        {**row["settings"], "site": "https://inward.atlassian.net"}, "test")
    r = client.post("/v1/integrations/jira/test", headers=_as(principals, "admin1"), json={"password": PW})
    assert r.status_code == 200 and r.json()["status"] == "fail"
    assert r.json()["steps"][0] == {"step": "host is allowed and public", "ok": False,
                                    "detail": "'inward.atlassian.net' resolves to a non-public address"}
    assert int_config.get(conn, "dob", "jira", "sandbox")["active_version"] != r.json()["config_version"]


# -- 1. secrets bound to their host; active only after a passing test -------------------------
def _site(conn, site):
    row = int_config.get(conn, "dob", "jira", "sandbox")
    with conn.transaction():
        return int_config.save(conn, "dob", "jira", "sandbox", "live", True, {**row["settings"], "site": site}, "test")


def _captured(seen):
    out = []
    for req in seen:
        auth = req.headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            auth += " " + base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8", "replace")
        out.append(f"{req.url} {auth} {req.content.decode('utf-8', 'replace')}")
    return "\n".join(out)


def test_no_secret_is_sent_after_a_host_change_or_rollback(client, principals, conn, box, env):
    env.setenv("HYPERSOAR_INTEGRATION_WRITES", "1")
    seen = []

    def handler(req):
        seen.append(req)
        return _live_stub(req)

    hub = client.broker.hub
    hub.transports["jira"] = httpx.MockTransport(handler)
    v_a = _site(conn, "https://site-a.atlassian.net")
    with conn.transaction():
        secretbox.set_secret(conn, box, "dob", "jira", "sandbox", "api_token", TOKEN_A, "test")
    # The token for site A goes to site A only.
    assert client.post("/v1/integrations/jira/test", headers=_as(principals, "admin1"),
                       json={"password": PW}).json()["status"] == "pass"
    assert TOKEN_A in _captured(seen) and all(r.url.host == "site-a.atlassian.net" for r in seen)

    # Host change: the token for A is deleted, the test of B runs without it.
    seen.clear()
    _site(conn, "https://site-b.atlassian.net")
    assert _ledger(conn, "integration.secrets_cleared")[-1] == {
        "integration": "jira", "mode": "sandbox", "names": ["api_token"], "reason": "host_changed"}
    r = client.post("/v1/integrations/jira/test", headers=_as(principals, "admin1"), json={"password": PW}).json()
    assert r["status"] == "fail" and TOKEN_A not in _captured(seen)
    # The runtime still uses active version A, which now has no token: nothing to send.
    assert secretbox.get_secrets(conn, box, "dob", "jira", "sandbox", "site-a.atlassian.net") == {}

    # Token for B, then roll back to A: B's token is deleted, A has none.
    with conn.transaction():
        secretbox.set_secret(conn, box, "dob", "jira", "sandbox", "api_token", TOKEN_B, "test")
    seen.clear()
    rb = client.post("/v1/integrations/jira/rollback", headers=_as(principals, "admin1"),
                     json={"version": v_a, "password": PW})
    assert rb.status_code == 200, rb.text
    assert _host(conn, "jira") == "site-a.atlassian.net"
    client.post("/v1/integrations/jira/test", headers=_as(principals, "admin1"), json={"password": PW})
    text = _captured(seen)
    assert TOKEN_A not in text and TOKEN_B not in text
    assert conn.execute("SELECT count(*) n FROM broker.integration_secret WHERE integration = 'jira'"
                        ).fetchone()["n"] == 0


def test_a_secret_does_not_open_for_another_host(client, conn, box):
    _site(conn, "https://site-a.atlassian.net")
    with conn.transaction():
        secretbox.set_secret(conn, box, "dob", "jira", "sandbox", "api_token", TOKEN_A, "test")
    # Even if the row's host column were rewritten, the host is part of the sealed data.
    conn.execute("UPDATE broker.integration_secret SET host = 'site-b.atlassian.net' WHERE integration = 'jira'")
    with pytest.raises(ConfigError, match="does not open"):
        secretbox.get_secrets(conn, box, "dob", "jira", "sandbox", "site-b.atlassian.net")


def test_a_live_version_is_active_only_after_its_test_passes(conn, client, principals, env):
    env.setenv("HYPERSOAR_INTEGRATION_WRITES", "1")
    hub = client.broker.hub
    hub.transports["jira"] = httpx.MockTransport(lambda r: httpx.Response(401))
    before = int_config.get(conn, "dob", "jira", "sandbox")["active_version"]
    v = _site(conn, "https://site-c.atlassian.net")
    row, model = int_config.settings_of(conn, "dob", "jira", "sandbox")
    assert row["version"] == before and model is not None and model.site != "https://site-c.atlassian.net"
    assert client.post("/v1/integrations/jira/test", headers=_as(principals, "admin1"),
                       json={"password": PW}).json()["status"] == "fail"
    assert int_config.get(conn, "dob", "jira", "sandbox")["active_version"] == before
    with conn.transaction():
        secretbox.set_secret(conn, secretbox.SecretBox.from_master(MASTER), "dob", "jira", "sandbox", "api_token",
                             TOKEN_A, "test")
    hub.transports["jira"] = httpx.MockTransport(_live_stub)
    r = client.post("/v1/integrations/jira/test", headers=_as(principals, "admin1"), json={"password": PW}).json()
    assert r["status"] == "pass", r["steps"]
    assert int_config.get(conn, "dob", "jira", "sandbox")["active_version"] == v
    assert _ledger(conn, "integration.activated")[-1]["version"] == v


# -- 2. integration writes: per-person re-auth, limiter, ledger, idempotency -------------------
def test_failed_reauth_on_an_integration_write_is_in_the_ledger_and_limited(client, principals, conn, env):
    env.setenv("HYPERSOAR_INTEGRATION_WRITES", "1")
    url = "/v1/integrations/jira/secrets/api_token"
    for _ in range(5):
        r = client.put(url, headers=_as(principals, "admin1"), json={"value": "x" * 20, "password": "wrong-pw-xx"})
        assert r.status_code == 403
    fails = _ledger(conn, "auth.reauth_failed")
    assert len(fails) == 5 and "wrong-pw-xx" not in json.dumps(fails)
    # Locked out now, even with the right password.
    assert client.put(url, headers=_as(principals, "admin1"), json={"value": "x" * 20, "password": PW}
                      ).status_code == 429
    assert conn.execute("SELECT count(*) n FROM broker.integration_secret WHERE name = 'api_token'"
                        ).fetchone()["n"] == 0


def test_integration_write_replays_with_the_same_key(client, principals, conn, env):
    env.setenv("HYPERSOAR_INTEGRATION_WRITES", "1")
    row = int_config.get(conn, "dob", "ai", "sandbox")
    h = _as(principals, "admin1")
    t = 30 if row["settings"].get("timeout_s") != 30 else 10
    body = {"target": "mock", "settings": {**row["settings"], "timeout_s": t}, "password": PW}
    first = client.put("/v1/integrations/ai", headers=h, json=body)
    again = client.put("/v1/integrations/ai", headers=h, json=body)
    assert first.status_code == again.status_code == 200, first.text
    assert again.json().get("idempotent_replay") is True
    assert int_config.get(conn, "dob", "ai", "sandbox")["version"] == row["version"] + 1
    other = client.put("/v1/integrations/ai", headers=h,
                       json={**body, "settings": {**body["settings"], "timeout_s": 20}})
    assert other.status_code == 409


# -- 4. the gateway holds the data-source key only ---------------------------------------------
def test_gateway_key_cannot_open_outbound_secrets(client, conn, box, monkeypatch, tmp_path):
    _site(conn, "https://site-a.atlassian.net")
    with conn.transaction():
        secretbox.set_secret(conn, box, "dob", "jira", "sandbox", "api_token", TOKEN_A, "test")
    f = tmp_path / "source.key"
    f.write_text(base64.urlsafe_b64encode(secretbox.derive(MASTER, "source")).decode())
    monkeypatch.setenv("HYPERSOAR_SOURCE_KEY_FILE", str(f))
    gw = secretbox.SecretBox.source_from_env()
    assert set(gw.keys) == {"source"} and MASTER not in gw.keys.values()
    with pytest.raises(ConfigError, match="no key for jira"):
        secretbox.get_secrets(conn, gw, "dob", "jira", "sandbox", "site-a.atlassian.net")
    # Even a source key passed off as the outbound one does not open it.
    forged = secretbox.SecretBox({"outbound": gw.keys["source"]})
    with pytest.raises(ConfigError, match="does not open"):
        secretbox.get_secrets(conn, forged, "dob", "jira", "sandbox", "site-a.atlassian.net")
    assert secretbox.derive(MASTER, "source") != secretbox.derive(MASTER, "outbound")


def test_gateway_refuses_the_integration_master_key(monkeypatch):
    monkeypatch.setenv("HYPERSOAR_INTEGRATION_KEY", KEY_HEX)
    with pytest.raises(ConfigError, match="HYPERSOAR_INTEGRATION_KEY"):
        Settings.for_gateway()
    monkeypatch.delenv("HYPERSOAR_INTEGRATION_KEY")
    monkeypatch.setenv("HYPERSOAR_INTEGRATION_KEY_FILE", "/run/secrets/deca_integration_key")
    with pytest.raises(ConfigError, match="HYPERSOAR_INTEGRATION_KEY"):
        Settings.for_gateway()


# -- 6. explicit mode and install check -------------------------------------------------------
def test_no_explicit_mode_refuses_to_start(monkeypatch):
    monkeypatch.delenv("HYPERSOAR_MODE", raising=False)
    for env_name in ("production", "lab", None):
        if env_name:
            monkeypatch.setenv("HYPERSOAR_ENV", env_name)
        else:
            monkeypatch.delenv("HYPERSOAR_ENV", raising=False)
        with pytest.raises(ConfigError, match="HYPERSOAR_MODE is not set"):
            entity.current_mode()
    monkeypatch.setenv("HYPERSOAR_ENV", "production")
    monkeypatch.setenv("HYPERSOAR_MODE", "sandbox")
    with pytest.raises(ConfigError, match="requires HYPERSOAR_MODE=production"):
        entity.current_mode()


def test_gateway_without_mode_refuses_to_start(monkeypatch):
    from fastapi.testclient import TestClient

    from hypersoar.gateway import app as gw_app
    monkeypatch.delenv("HYPERSOAR_MODE", raising=False)
    with pytest.raises(ConfigError, match="HYPERSOAR_MODE"):
        with TestClient(gw_app.app):
            pass


def test_worker_checks_the_install_through_the_broker(monkeypatch):
    class Fake:
        def __init__(self, inst):
            self.inst = inst

        async def install(self):
            return self.inst

    asyncio.run(worker.check_install(Fake({"mode": "sandbox", "entity_id": "dob"}), "sandbox", "dob"))
    with pytest.raises(ConfigError, match="production install"):
        asyncio.run(worker.check_install(Fake({"mode": "production", "entity_id": "dob"}), "sandbox", "dob"))
    with pytest.raises(ConfigError, match="another entity"):
        asyncio.run(worker.check_install(Fake({"mode": "sandbox", "entity_id": "xyz"}), "sandbox", "dob"))
    monkeypatch.delenv("HYPERSOAR_MODE", raising=False)
    with pytest.raises(ConfigError, match="HYPERSOAR_MODE"):
        asyncio.run(worker.run())


def test_broker_whoami_reports_its_install(client, principals):
    j = client.get("/v1/whoami", headers=principals["worker-svc"]).json()
    assert j["install"] == {"mode": "sandbox", "entity_id": "dob"} and j["channel"] == "api"


# -- 5. syslog --------------------------------------------------------------------------------
def test_production_syslog_is_tcp_with_tls_only():
    with pytest.raises(ConfigError, match="UDP"):
        syslog.listen_config("production", {"HYPERSOAR_SYSLOG_PORT": "6514", "HYPERSOAR_SYSLOG_UDP": "1"})
    with pytest.raises(ConfigError, match="needs TLS"):
        syslog.listen_config("production", {"HYPERSOAR_SYSLOG_PORT": "6514"})
    with pytest.raises(ConfigError, match="both"):
        syslog.listen_config("sandbox", {"HYPERSOAR_SYSLOG_PORT": "6514", "HYPERSOAR_SYSLOG_TLS_CERT_FILE": "/x"})
    cfg = syslog.listen_config("sandbox", {"HYPERSOAR_SYSLOG_PORT": "5514"})
    assert cfg.tls is None and cfg.udp is False and cfg.port == 5514
    assert syslog.listen_config("sandbox", {}) is None


def test_syslog_refuses_senders_at_connect_and_bounds_the_queue(monkeypatch):
    monkeypatch.setattr(syslog, "QUEUE_MAX", 3)
    got, counters, accepted = [], {}, {"ok": False}

    async def main():
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        def on_line(sender, line):
            got.append(line)

        objs = await syslog.serve(syslog.Listen("127.0.0.1", port, None, False), on_line,
                                  lambda ip: accepted["ok"], counters)
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"CEF:0|refused\n")
            await w.drain()
            try:  # closed before anything was read
                assert await asyncio.wait_for(r.read(), 5) == b""
            except ConnectionResetError:
                pass
            w.close()
            accepted["ok"] = True
            # Hold the worker so the queue fills: 3 lines queue, the rest are dropped and counted.
            objs[0].task.cancel()
            await asyncio.sleep(0)
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"".join(b"CEF:0|line%d\n" % i for i in range(10)))
            await w.drain()
            for _ in range(50):
                if counters["queue_full"] >= 7:
                    break
                await asyncio.sleep(0.02)
            w.close()
        finally:
            for o in objs:
                o.close()
    asyncio.run(main())
    assert counters["denied"] == 1 and counters["queue_full"] == 7
    assert "CEF:0|refused" not in got


# -- LOW: webhook replay across processes ------------------------------------------------------
def test_webhook_signature_is_refused_by_another_gateway_process(roles):
    p1, p2 = make_pool(roles["gateway"], max_size=1), make_pool(roles["gateway"], max_size=1)
    try:
        a, b = webhook.DbSeen(p1, "dob"), webhook.DbSeen(p2, "dob")
        assert a.first_time("sha256=abc", 300) is True
        assert b.first_time("sha256=abc", 300) is False  # another replica, or after a restart
        assert a.first_time("sha256=abc", 300) is False
        assert webhook.DbSeen(p1, "other").first_time("sha256=abc", 300) is True
        secret, ts, body = "w" * 40, "1800000000", b"{}"
        sig = webhook.sign(secret, ts, body)
        webhook.verify(secret, ts, sig, body, 300, a, now=1800000000)
        with pytest.raises(webhook.Rejected) as e:
            webhook.verify(secret, ts, sig, body, 300, b, now=1800000000)
        assert e.value.status == 409
    finally:
        p1.close()
        p2.close()


def test_generated_source_key_is_the_source_subkey_of_the_generated_master():
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location("gen_secrets", Path(__file__).parents[1] / "scripts/gen_secrets.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    keys = mod.generate()
    from hypersoar.broker.integrations.secretbox import derive

    assert bytes.fromhex(keys["deca_source_key"]) == derive(bytes.fromhex(keys["deca_integration_key"]), "source")
    assert keys["deca_source_key"] != keys["deca_integration_key"]


def test_gateway_readyz_answers_internal_callers_only_never_through_the_proxy(conn, roles):
    from fastapi.testclient import TestClient

    from hypersoar.common.db import make_pool
    from hypersoar.gateway import app as gw_app

    gpool = make_pool(roles["gateway"], max_size=2)
    try:
        gw_app.app.state.pool, gw_app.app.state.syslog = gpool, {"accepted": 0}
        inside = TestClient(gw_app.app, client=("127.0.0.1", 50000))
        assert inside.get("/readyz").status_code == 200
        for h in ({"x-forwarded-for": "198.51.100.7"}, {"forwarded": "for=198.51.100.7"}, {"x-real-ip": "10.0.0.1"}):
            assert inside.get("/readyz", headers=h).status_code == 404, h
        assert TestClient(gw_app.app, client=("198.51.100.7", 50000)).get("/readyz").status_code == 404
        assert inside.get("/healthz").status_code == 200
    finally:
        gpool.close()


def test_cli_derive_source_key_writes_the_source_subkey_once(tmp_path, monkeypatch):
    import base64

    from hypersoar import cli
    from hypersoar.broker.integrations.secretbox import derive

    master = bytes(range(32))
    monkeypatch.setenv("HYPERSOAR_INTEGRATION_KEY", master.hex())
    out = tmp_path / "deca_source_key"
    assert cli.main(["integration", "derive-source-key", "--out", str(out)]) == 0
    raw = out.read_text().strip()
    assert base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)) == derive(master, "source")
    assert out.stat().st_mode & 0o777 == 0o600
    assert cli.main(["integration", "derive-source-key", "--out", str(out)]) == 2  # never overwrites
