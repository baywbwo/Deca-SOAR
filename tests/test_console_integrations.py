"""The Integrations screen: the console reads settings, secret status, schemas and versions through the broker
and writes them with CSRF + re-auth; a secret value never comes back. Production edits live settings only."""

import json
import secrets

import pytest

from hypersoar.broker import service
from hypersoar.broker import writes as bw
from hypersoar.broker.integrations import NAMES
from hypersoar.broker.integrations import config as int_config
from hypersoar.console import writes as cw

from test_console import ORIGIN, PASSWORD, _login, console, console_env, pw_hash, viewer  # noqa: F401  (fixtures)
from test_integrations import client, env, principals  # noqa: F401  (fixtures)


@pytest.fixture
def wired(client, conn, pw_hash, console):
    """Console logged in as owner (admin, re-auth = console password), its broker client on the in-process broker
    with the integration master key mounted."""
    from hypersoar.console.app import fastapi_app
    tok = secrets.token_urlsafe(24)
    with conn.transaction():
        service.create_principal(conn, "owner", "human", "admin", tok, "test", channel="console")
        bw.set_reauth_hash(conn, "owner", pw_hash, "test")
    st = fastapi_app.state
    st.broker = cw.BrokerClient("http://testserver", tok, transport=client._transport)
    assert _login(console).status_code == 303
    csrf = console.get("/api/shell").json()["meta"]["csrf"]
    yield console, csrf
    st.broker.close()
    st.broker = None


def _send(c, csrf, method, path, payload):
    h = {"content-type": "application/json", "x-hypersoar-csrf": csrf, "idempotency-key": secrets.token_hex(8), **ORIGIN}
    return c.request(method, path, content=json.dumps(payload), headers=h)


def test_screen_and_reads_need_a_session(console):
    assert console.get("/integrations", follow_redirects=False).headers["location"] == "/login"
    for path in ("/api/integrations", "/api/integrations/lark/history"):
        r = console.get(path)
        assert r.status_code == 401 and r.json() == {"detail": "login required"}, path


def test_reads_without_a_broker_say_so(console):
    assert _login(console).status_code == 303
    assert '<body class="app" data-screen="integrations"' in console.get("/integrations").text
    r = console.get("/api/integrations")
    assert r.status_code == 503 and "broker" in r.json()["detail"]


def test_listing_carries_schemas_and_secret_status_only(wired, env):
    c, csrf = wired
    env.setenv("HYPERSOAR_INTEGRATION_WRITES", "1")
    j = c.get("/api/integrations").json()
    assert j["mode"] == "sandbox" and j["writes_enabled"] is True
    assert [i["integration"] for i in j["integrations"]] == list(NAMES)
    assert set(j["schemas"]) == set(NAMES)
    assert j["schemas"]["jira"] == int_config.MODELS["jira"].model_json_schema()
    lark = next(i for i in j["integrations"] if i["integration"] == "lark")
    for st in lark["secrets"].values():
        assert set(st) <= {"set", "required", "rotated_at", "rotated_by", "expires_at"}
    assert c.get("/api/integrations/Bad;name/history").status_code == 404
    assert c.get("/api/integrations/nope/history").status_code == 404  # the broker does not know it


def test_save_secret_test_and_rollback_from_the_screen(wired, env, conn):
    c, csrf = wired
    env.setenv("HYPERSOAR_INTEGRATION_WRITES", "1")
    ai = next(i for i in c.get("/api/integrations").json()["integrations"] if i["integration"] == "ai")
    v0 = ai["version"]
    s = dict(ai["settings"], timeout_s=30)
    body = {"target": "mock", "enabled": True, "settings": s, "note": "from the screen"}
    assert _send(c, csrf, "PUT", "/api/integrations/ai", {**body, "password": "wrong password"}).status_code == 403
    assert _send(c, csrf, "PUT", "/api/integrations/ai", {**body, "password": PASSWORD, "reason": "x"}).status_code == 422
    r = _send(c, csrf, "PUT", "/api/integrations/ai", {**body, "password": PASSWORD})
    assert r.status_code == 200 and r.json()["version"] == v0 + 1, r.text

    value = "ai-key-VALUE-typed-in-the-screen-7e1"
    r = _send(c, csrf, "PUT", "/api/integrations/ai/secrets/api_key",
              {"value": value, "expires_at": "2027-02-18", "password": PASSWORD})
    assert r.status_code == 200 and value not in r.text, r.text
    listing = c.get("/api/integrations")
    assert value not in listing.text
    st = next(i for i in listing.json()["integrations"] if i["integration"] == "ai")["secrets"]["api_key"]
    assert st["set"] is True and st["rotated_by"] == "principal:owner" and st["expires_at"].startswith("2027-02-18")

    t = _send(c, csrf, "POST", "/api/integrations/ai/test", {"password": PASSWORD})
    assert t.status_code == 200 and t.json()["status"] == "pass", t.text
    after = next(i for i in c.get("/api/integrations").json()["integrations"] if i["integration"] == "ai")
    assert after["active_version"] == v0 + 1 and after["state"] == "connected"
    assert after["last_test"]["config_version"] == v0 + 1

    hist = c.get("/api/integrations/ai/history").json()["versions"]
    assert [h["version"] for h in hist][:2] == [v0 + 1, v0] and hist[0]["note"] == "from the screen"
    rb = _send(c, csrf, "POST", "/api/integrations/ai/rollback", {"version": v0, "password": PASSWORD})
    assert rb.status_code == 200 and rb.json()["version"] == v0 + 2
    assert int_config.get(conn, "dob", "ai", "sandbox")["settings"]["timeout_s"] == ai["settings"]["timeout_s"]
    led = json.dumps([r["canonical"] for r in conn.execute("SELECT canonical FROM ledger.entry")], default=str)
    assert value not in led and PASSWORD not in led
    assert {r["actor"] for r in conn.execute(
        "SELECT actor FROM ledger.entry WHERE event_type LIKE 'integration.%%'")} >= {"principal:owner"}


def test_production_shows_the_screen_read_only(wired, env):
    c, csrf = wired
    from hypersoar.console.app import fastapi_app
    inst = fastapi_app.state.install
    real = inst.get
    inst.get = lambda pool: {**real(pool), "mode": "production"}
    try:
        page = c.get("/integrations")
        assert page.status_code == 200 and '<body class="app prod" data-screen="integrations"' in page.text
        j = c.get("/api/integrations").json()
        assert j["writes_enabled"] is False  # HYPERSOAR_INTEGRATION_WRITES unset, as in production
        r = _send(c, csrf, "POST", "/api/integrations/ai/test", {"password": PASSWORD})
        assert r.status_code == 403
    finally:
        inst.get = real


def _ai(c):
    return next(i for i in c.get("/api/integrations").json()["integrations"] if i["integration"] == "ai")


def test_writes_without_csrf_reauth_or_idempotency_are_refused(wired, env):
    c, csrf = wired
    env.setenv("HYPERSOAR_INTEGRATION_WRITES", "1")
    ai = _ai(c)
    body = json.dumps({"target": "mock", "enabled": True, "settings": ai["settings"], "password": PASSWORD})
    base = {"content-type": "application/json", "idempotency-key": secrets.token_hex(8), **ORIGIN}
    for path, method in (("/api/integrations/ai", "PUT"), ("/api/integrations/ai/test", "POST"),
                         ("/api/integrations/ai/rollback", "POST"), ("/api/integrations/ai/secrets/api_key", "PUT")):
        r = c.request(method, path, content=body, headers=base)
        assert r.status_code == 403 and "CSRF" in r.json()["detail"], path
        r = c.request(method, path, content=body, headers={**base, "x-hypersoar-csrf": "x" * len(csrf)})
        assert r.status_code == 403, path
        r = c.request(method, path, content=body, headers={**base, "x-hypersoar-csrf": csrf, "origin": "https://evil.example"})
        assert r.status_code == 403, path
        h = {k: v for k, v in base.items() if k != "idempotency-key"}
        assert c.request(method, path, content=body, headers={**h, "x-hypersoar-csrf": csrf}).status_code == 422, path
    no_pw = {"target": "mock", "enabled": True, "settings": ai["settings"]}
    r = _send(c, csrf, "PUT", "/api/integrations/ai", no_pw)
    assert r.status_code in (403, 422), r.text
    assert _ai(c)["version"] == ai["version"]  # nothing was saved by any of them


@pytest.mark.parametrize("name,patch,why", [
    ("ai", {"base_url": "https://10.0.0.5/v1"}, "IP address"),
    ("ai", {"base_url": "https://127.0.0.1:8443/v1"}, "IP address"),
    ("ai", {"base_url": "https://llm.internal.corp/v1"}, "allowlist"),
    ("jira", {"site": "https://192.168.1.20"}, "IP address"),
    ("jira", {"site": "https://jira.internal.corp"}, "allowlist"),
    ("lark", {"base_url": "https://169.254.169.254"}, "IP address"),
])
def test_live_targets_on_internal_or_unlisted_hosts_are_refused(wired, env, name, patch, why):
    c, csrf = wired
    env.setenv("HYPERSOAR_INTEGRATION_WRITES", "1")
    item = next(i for i in c.get("/api/integrations").json()["integrations"] if i["integration"] == name)
    settings = dict(item["settings"] or {}, **patch)
    r = _send(c, csrf, "PUT", f"/api/integrations/{name}",
              {"target": "live", "enabled": True, "settings": settings, "password": PASSWORD})
    assert r.status_code == 422 and why in r.json()["detail"], r.text
    after = next(i for i in c.get("/api/integrations").json()["integrations"] if i["integration"] == name)
    assert after["version"] == item["version"]


def test_secrets_are_deleted_when_the_host_changes(wired, env):
    c, csrf = wired
    env.setenv("HYPERSOAR_INTEGRATION_WRITES", "1")
    ai = _ai(c)
    r = _send(c, csrf, "PUT", "/api/integrations/ai/secrets/api_key", {"value": "k-" + "a" * 30, "password": PASSWORD})
    assert r.status_code == 200, r.text
    assert _ai(c)["secrets"]["api_key"]["set"] is True
    same = dict(ai["settings"], timeout_s=10)  # same host: the key stays
    assert _send(c, csrf, "PUT", "/api/integrations/ai",
                 {"target": "mock", "enabled": True, "settings": same, "password": PASSWORD}).status_code == 200
    assert _ai(c)["secrets"]["api_key"]["set"] is True
    moved = dict(same, base_url="https://other-llm.example.com/v1")  # mock target: any host, but the key is not carried over
    r = _send(c, csrf, "PUT", "/api/integrations/ai", {"target": "mock", "enabled": True, "settings": moved, "password": PASSWORD})
    assert r.status_code == 200, r.text
    assert _ai(c)["secrets"]["api_key"]["set"] is False


@pytest.fixture
def production(wired, client):
    """Console and broker both in production mode, as on the deca-prod stack."""
    from hypersoar.console.app import fastapi_app
    inst = fastapi_app.state.install
    real = inst.get
    inst.get = lambda pool: {**real(pool), "mode": "production"}
    hub = client.broker.hub
    hub.mode = "production"
    try:
        yield wired
    finally:
        inst.get = real
        hub.mode = "sandbox"


def _item(c, name):
    return next(i for i in c.get("/api/integrations").json()["integrations"] if i["integration"] == name)


def test_production_without_the_write_flag_refuses_every_integration_write(production, env, conn):
    c, csrf = production
    ai = _ai(c)
    live = int_config.get(conn, "dob", "ai", "sandbox")["settings"]
    for method, path, body in (
            ("PUT", "/api/integrations/ai", {"target": "live", "enabled": True, "settings": live}),
            ("PUT", "/api/integrations/ai/secrets/api_key", {"value": "k-" + "b" * 30}),
            ("POST", "/api/integrations/ai/rollback", {"version": 1}),
            ("POST", "/api/integrations/ai/test", {})):
        r = _send(c, csrf, method, path, {**body, "password": PASSWORD})
        assert r.status_code == 403 and "disabled" in r.json()["detail"], (path, r.text)
    assert _ai(c)["version"] == ai["version"] and _ai(c)["secrets"]["api_key"]["set"] is False


JIRA = {"site": "https://deca-a.atlassian.net", "email": "soc@example.com", "project": "SOC", "issue_type": "Task",
        "priority_map": {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}}


def _ledger(conn, event_type):
    return [r["canonical"] for r in conn.execute(
        "SELECT canonical FROM ledger.entry WHERE event_type = %s ORDER BY seq", (event_type,))]


def test_production_edits_live_settings_with_every_guard(production, env, conn):
    """Owner decision 2026-11-25: production settings are edited from the console. Live targets only, hosts on
    the allowlist, secrets bound to the host, the person's password, CSRF and an Idempotency-Key."""
    c, csrf = production
    env.setenv("HYPERSOAR_INTEGRATION_WRITES", "1")
    j = c.get("/api/integrations").json()
    assert j["mode"] == "production" and j["writes_enabled"] is True
    put = lambda s, target="live", pw=PASSWORD: _send(  # noqa: E731
        c, csrf, "PUT", "/api/integrations/jira", {"target": target, "enabled": True, "settings": s, "password": pw})

    # Refused, and nothing saved: mock target, IP literal, internal and metadata addresses, hosts off the allowlist.
    for s, target, why in (
            (JIRA, "mock", "production cannot use a mock target"),
            ({**JIRA, "site": "https://10.0.0.5"}, "live", "IP address"),
            ({**JIRA, "site": "https://169.254.169.254"}, "live", "IP address"),
            ({**JIRA, "site": "https://[::1]"}, "live", "site: String should match pattern"),
            ({**JIRA, "site": "https://jira.internal.corp"}, "live", "allowlist"),
            ({**JIRA, "site": "https://deca.atlassian.net.evil.example"}, "live", "allowlist")):
        r = put(s, target)
        assert r.status_code == 422 and why in r.json()["detail"], (s["site"], r.text)
    assert not _item(c, "jira")["version"]
    ai = int_config.get(conn, "dob", "ai", "sandbox")["settings"]
    r = _send(c, csrf, "PUT", "/api/integrations/ai", {"target": "live", "enabled": True, "password": PASSWORD,
                                                       "settings": {**ai, "mock_fault": "timeout"}})
    assert r.status_code == 422 and "sandbox only" in r.json()["detail"], r.text

    # Without CSRF, without the password, or with a wrong one: refused; a wrong password goes into the ledger.
    h = {"content-type": "application/json", "idempotency-key": secrets.token_hex(8), **ORIGIN}
    body = json.dumps({"target": "live", "enabled": True, "settings": JIRA, "password": PASSWORD})
    assert c.put("/api/integrations/jira", content=body, headers=h).status_code == 403
    r = _send(c, csrf, "PUT", "/api/integrations/jira", {"target": "live", "enabled": True, "settings": JIRA})
    assert r.status_code in (403, 422), r.text
    before = len(_ledger(conn, "auth.reauth_failed"))
    assert put(JIRA, pw="not the password").status_code == 403
    failed = _ledger(conn, "auth.reauth_failed")
    assert len(failed) == before + 1 and "integration.save:jira" in json.dumps(failed[-1], default=str)
    assert not _item(c, "jira")["version"]

    # Saved on an allowed host; a secret is bound to it and goes when the host changes, by a save or a rollback.
    assert put(JIRA).status_code == 200
    v1 = _item(c, "jira")["version"]
    token = lambda: _send(c, csrf, "PUT", "/api/integrations/jira/secrets/api_token",  # noqa: E731
                          {"value": "qa-not-a-real-token-" + secrets.token_hex(8), "password": PASSWORD})
    assert token().status_code == 200 and _item(c, "jira")["secrets"]["api_token"]["set"] is True
    assert put({**JIRA, "site": "https://deca-b.atlassian.net"}).status_code == 200
    jira = _item(c, "jira")
    assert jira["version"] == v1 + 1 and jira["secrets"]["api_token"]["set"] is False
    assert token().status_code == 200
    rb = _send(c, csrf, "POST", "/api/integrations/jira/rollback", {"version": v1, "password": PASSWORD})
    assert rb.status_code == 200, rb.text
    jira = _item(c, "jira")
    assert jira["settings"]["site"] == JIRA["site"] and jira["secrets"]["api_token"]["set"] is False
    cleared = _ledger(conn, "integration.secrets_cleared")
    assert len(cleared) >= 2 and all("api_token" in json.dumps(x, default=str) for x in cleared[-2:])
    # A live version is not active before its connection test passes: nothing is sent to Jira yet.
    assert jira["active_version"] is None


def test_listing_carries_allowlist_presets_and_source_health(wired, env):
    from hypersoar.sources import presets
    c, csrf = wired
    j = c.get("/api/integrations").json()
    assert j["allowed_hosts"] == {"lark": ["open.larksuite.com"], "jira": [".atlassian.net"],
                                  "sls": [".log.aliyuncs.com"], "ai": ["9router.sandbox.invalid"]}
    assert set(j["presets"]) == set(presets.PRESETS) and all("sample" not in p for p in j["presets"].values())
    assert j["tokenized"] == ["src_ip", "principal", "access_key_id"]
    assert set(j["health"]) == {"sls", "webhook", "syslog"}
    assert all(set(h) == {"alerts_24h", "last_alert"} for h in j["health"].values())


def test_every_preset_validates_and_maps_its_sample():
    from hypersoar.sources import mapping, models, presets
    base = {"webhook": {}, "sls": {"endpoint": "https://ap-southeast-5.log.aliyuncs.com", "project": "p-1",
                                   "logstore": "waf-logstore"}}
    for name, p in presets.PRESETS.items():
        s = presets.apply(name, base[p["connector"]])
        model = {"webhook": models.WebhookSettings, "sls": models.SlsSettings}[p["connector"]].model_validate(s)
        raw = mapping.to_raw(p["sample"], model, f"{p['connector']}://t")
        assert raw["rule_id"] and raw["rule_id"].startswith(s["rule_prefix"]), name
        assert raw.get("src_ip") == "203.0.113.9", name
        assert set(p["settings"]["fields"]) == set(models.FieldMap.model_fields), name
