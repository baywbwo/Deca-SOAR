"""Read-only SOC console (lab): login, rate limit, viewer DB role, no write endpoints, synthetic alerts."""

import ipaddress
import json
import random

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import errors
from psycopg.rows import dict_row

from hypersoar import synth
from hypersoar.common.config import ConfigError
from hypersoar.common.dbguard import login_problems
from hypersoar.common.pii import Tokenizer
from hypersoar.console import auth
from hypersoar.gateway.normalize import normalize

from conftest import make_login
from helpers import ingest, waf_alert
from test_broker_api import _alert, body, client, env, principals  # noqa: F401  (fixtures)

PASSWORD = "correct horse battery staple 42"
ORIGIN = {"origin": "https://testserver"}


@pytest.fixture(scope="module")
def pw_hash():
    return auth.hash_password(PASSWORD)


# Auth building blocks -----------------------------------------------------------------------------

def test_hash_roundtrip_and_format(pw_hash):
    assert pw_hash.startswith("scrypt$32768$8$1$") and PASSWORD not in pw_hash
    h = auth.PasswordHash.parse(pw_hash)
    assert h.verify(PASSWORD) and not h.verify(PASSWORD + "x") and not h.verify("")


def test_short_password_refused():
    with pytest.raises(ValueError):
        auth.hash_password("short")


@pytest.mark.parametrize("value", ["", "plain", "scrypt$1024$8$1$AAAAAAAAAAAAAAAAAAAAAA$" + "A" * 43,
                                   "bcrypt$x$y$z$a$b", "scrypt$x$8$1$a$b"])
def test_weak_or_malformed_hash_refused(value):
    with pytest.raises(ConfigError):
        auth.PasswordHash.parse(value)


def test_limiter_per_client_and_reset():
    lim = auth.LoginLimiter(per_client=3, window_s=60, global_per_min=100)
    for _ in range(3):
        assert lim.allow("a")
        lim.failed("a")
    assert not lim.allow("a")
    assert lim.allow("b")
    lim.succeeded("a")
    assert lim.allow("a")


def test_limiter_global_cap():
    lim = auth.LoginLimiter(per_client=100, global_per_min=4)
    assert all(lim.allow(f"c{i}") for i in range(4))
    assert not lim.allow("fresh-client")


def test_client_address_trusts_only_the_connector():
    trusted = [ipaddress.ip_network("172.30.124.30/32")]
    hdr = {"cf-connecting-ip": "203.0.113.9"}
    assert auth.client_address("172.30.124.30", hdr, trusted) == "203.0.113.9"
    assert auth.client_address("172.30.124.31", hdr, trusted) == "172.30.124.31"
    assert auth.client_address("172.30.124.30", {"cf-connecting-ip": "not-an-ip"}, trusted) == "172.30.124.30"


def test_session_idle_expiry(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(auth.time, "monotonic", lambda: clock[0])
    s = auth.SessionStore(idle_s=10, absolute_s=100)
    t = s.create("owner")
    assert s.get(t).user == "owner"
    clock[0] += 11
    assert s.get(t) is None
    assert s.get("x" * 500) is None


# Viewer DB role -----------------------------------------------------------------------------------

@pytest.fixture
def viewer(pg_server, db_url):
    return make_login(pg_server, db_url, "deca_soar_viewer")


def _problems(url, service):
    with psycopg.connect(url, row_factory=dict_row) as c:
        return login_problems(c, service)


def test_viewer_login_passes_console_guard(viewer):
    assert _problems(viewer, "console") == []


def test_other_logins_refused_as_console(roles, db_url):
    assert any("not a member of deca_soar_viewer" in p for p in _problems(roles["broker"], "console"))
    assert any("SUPERUSER" in p for p in _problems(db_url, "console"))


def test_viewer_refused_as_service(viewer):
    assert any("not a member of deca_soar_auditor" in p for p in _problems(viewer, "auditor"))


@pytest.mark.parametrize("sql", [
    "INSERT INTO broker.kill_switch (scope, engaged, changed_by) VALUES ('global', true, gen_random_uuid())",
    "UPDATE gateway.inbox_event SET status = 'dead'",
    "SELECT * FROM vault.token_map",
    "SELECT * FROM broker.principal",
    "SELECT * FROM gateway.ingest_cursor",
])
def test_viewer_cannot_write_or_read_secrets(viewer, sql):
    with psycopg.connect(viewer) as c, pytest.raises(errors.InsufficientPrivilege):
        c.execute(sql)


def test_extra_grant_to_viewer_refused(viewer, conn):
    conn.execute("GRANT UPDATE ON broker.kill_switch TO deca_soar_viewer")
    assert any("UPDATE on broker.kill_switch" in p for p in _problems(viewer, "console"))


# Console app --------------------------------------------------------------------------------------

@pytest.fixture
def console_env(monkeypatch, tmp_path, viewer, pw_hash):
    f = tmp_path / "console.hash"
    f.write_text(pw_hash + "\n")
    monkeypatch.setenv("HYPERSOAR_DB_URL", viewer)
    monkeypatch.setenv("HYPERSOAR_CONSOLE_PASSWORD_HASH_FILE", str(f))
    monkeypatch.setenv("HYPERSOAR_CONSOLE_USER", "owner")
    monkeypatch.setenv("HYPERSOAR_CONSOLE_SYNTHETIC", "1")
    monkeypatch.setenv("HYPERSOAR_GIT_SHA", "abc1234")
    monkeypatch.delenv("HYPERSOAR_CONSOLE_TRUSTED_PROXIES", raising=False)
    return monkeypatch


@pytest.fixture
def console(console_env):
    from hypersoar.console.app import app
    with TestClient(app, base_url="https://testserver") as c:
        yield c


def _login(c, user="owner", password=PASSWORD, headers=ORIGIN):
    return c.post("/login", content=f"username={user}&password={password.replace(' ', '+')}",
                  headers={"content-type": "application/x-www-form-urlencoded", **headers}, follow_redirects=False)


def test_unauthenticated_access_is_redirected_or_401(console):
    assert console.get("/", follow_redirects=False).status_code == 303
    assert console.get("/api/state").status_code == 401
    assert console.get("/healthz").json() == {"ok": True}


def test_login_flow_and_cookie_flags(console):
    r = _login(console)
    assert r.status_code == 303 and r.headers["location"] == "/"
    cookie = r.headers["set-cookie"]
    assert cookie.startswith("__Host-hypersoar_console=")
    for flag in ("HttpOnly", "Secure", "SameSite=strict", "Path=/"):
        assert flag.lower() in cookie.lower()
    assert console.get("/").status_code == 200
    s = console.get("/api/state").json()
    assert s["meta"] == {"synthetic": True, "sha": "abc1234", "user": "owner", "mode": "shadow", "read_only": True}
    assert s["ledger"]["ok"] is True
    out = console.post("/logout", headers=ORIGIN, follow_redirects=False)
    assert out.status_code == 303
    assert console.get("/api/state").status_code == 401


@pytest.mark.parametrize("headers", [{}, {"origin": "https://evil.example"}, {"origin": "http://testserver"}])
def test_login_requires_same_origin(console, headers):
    assert _login(console, headers=headers).status_code == 403


def test_wrong_credentials_then_rate_limited(console):
    assert _login(console, password="wrong password here!!").status_code == 401
    assert _login(console, user="admin").status_code == 401
    for _ in range(3):
        assert _login(console, password="still wrong password").status_code == 401
    r = _login(console)
    assert r.status_code == 429 and "set-cookie" not in r.headers


def test_security_headers(console):
    r = console.get("/login")
    h = r.headers
    assert "script-src 'self'" in h["content-security-policy"] and "unsafe-inline" not in h["content-security-policy"]
    assert h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff"
    assert h["referrer-policy"] == "same-origin" and h["cache-control"] == "no-store"
    assert "strict-transport-security" in h
    assert "<script" not in r.text and "style=" not in r.text


def test_static_has_no_inline_code_and_unknown_files_404(console):
    from hypersoar.console.app import STATIC
    page = (STATIC / "index.html").read_text()
    assert "<script>" not in page and "style=" not in page and "onclick" not in page
    js = (STATIC / "console.js").read_text()
    assert "innerHTML" not in js and "eval(" not in js
    assert console.get("/static/console.js").status_code == 200
    assert console.get("/static/../app.py").status_code == 404
    assert console.get("/static/index.html").status_code == 404


def test_no_write_endpoints():
    from hypersoar.console.app import fastapi_app
    writes = sorted((r.path, m) for r in fastapi_app.routes for m in getattr(r, "methods", set()) - {"GET", "HEAD"})
    assert writes == [("/login", "POST"), ("/logout", "POST")]


def test_body_limit(console):
    r = console.post("/login", content="a" * 10_000, headers={"content-type": "application/x-www-form-urlencoded",
                                                             **ORIGIN})
    assert r.status_code == 413


def test_refuses_to_start_with_broker_login(console_env, roles):
    console_env.setenv("HYPERSOAR_DB_URL", roles["broker"])
    from hypersoar.console.app import app
    with pytest.raises(ConfigError, match="console database login has more privilege"):
        with TestClient(app, base_url="https://testserver"):
            pass


def test_state_shows_alert_verdict_and_shadow_decision(client, principals, pool, settings, tmp_path, conn,
                                                       console_env, viewer):
    ingest(pool, settings, tmp_path, [waf_alert(ip="203.0.113.44"), waf_alert(ip="198.51.100.7")])
    rows = conn.execute("SELECT alert_id, alert FROM gateway.inbox_event").fetchall()
    for r in rows:
        tok = r["alert"]["entities"]["src_ip"]
        resp = client.post("/v1/actions/requests", headers=principals["worker-svc"],
                           json=body(str(r["alert_id"]), params={"ip_token": tok, "waf_instance": "waf-lab"}))
        assert resp.status_code == 201
    from hypersoar.console.app import app
    with TestClient(app, base_url="https://testserver") as c:
        assert _login(c).status_code == 303
        r = c.get("/api/state")
    s = r.json()
    assert s["counts"]["alerts_total"] == 2 and s["counts"]["decisions"] == 2
    statuses = sorted(a["broker"]["status"] for a in s["feed"])
    assert statuses == ["rejected", "validated"]
    assert all(a["triage"]["verdict"] == "malicious" and a["broker"]["mode"] == "shadow" for a in s["feed"])
    assert s["ledger"]["ok"] and s["ledger"]["entries"] >= 6 and s["ledger"]["tail"]
    assert s["kill_switch"]["any_engaged"] is False
    assert "203.0.113.44" not in r.text and "198.51.100.7" not in r.text


# Synthetic generator ------------------------------------------------------------------------------

def test_synthetic_alerts_normalize_and_are_marked(tmp_path):
    rng = random.Random(1)
    tok = Tokenizer(b"\x01" * 32)
    for kind, _ in synth.MIX:
        raw = synth.make_alert(kind, rng)
        assert raw["raw_ref"] == "synthetic://lab"
        assert ipaddress.ip_address(raw["src_ip"]) in ipaddress.ip_network(
            "198.51.100.0/24" if kind == "waf_protected" else "203.0.113.0/24")
        normalize(raw, tok, source_name="synthetic")


def test_synthetic_run_appends_whole_lines(tmp_path):
    out = tmp_path / "alerts.ndjson"
    n = synth.run(out, 0, 6, seed=3, log=lambda m: None)
    lines = out.read_text().splitlines()
    assert n == 6 and len(lines) == 6
    assert {json.loads(x)["rule_id"] for x in lines[:4]} == {"waf.sqli.burst", "waf.scan.path_enum", "sas.bruteforce"}
