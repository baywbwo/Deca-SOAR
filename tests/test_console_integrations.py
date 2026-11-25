"""The Integrations screen: the console reads settings, secret status, schemas and versions through the broker
and writes them with CSRF + re-auth; a secret value never comes back. Production shows the screen read-only."""

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
