"""Read-only SOC console (lab): login, rate limit, viewer DB role, no write endpoints, synthetic alerts."""

import ipaddress
import json
import random
from datetime import UTC, datetime

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
    assert s["meta"] == {"synthetic": True, "sha": "abc1234", "user": "owner"}
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
    assert "font-src 'self';" in h["content-security-policy"] and "default-src 'none'" in h["content-security-policy"]


PAGES = {"/": "overview", "/map": "map", "/cases": "cases", "/approvals": "approvals",
         "/automation": "automation", "/integrations": "integrations"}


def test_static_has_no_inline_code_and_unknown_files_404(console):
    from hypersoar.console.app import STATIC
    for name in PAGES.values():
        page = (STATIC / f"{name}.html").read_text()
        assert "<script>" not in page and "style=" not in page and "onclick" not in page, name
        assert page.count("<script") == 1 and '<script src="/static/console.js" defer></script>' in page, name
        assert f'data-screen="{name}"' in page and "http" not in page.replace('xmlns="http://www.w3.org/2000/svg"', "")
    js = (STATIC / "console.js").read_text()
    assert "innerHTML" not in js and "eval(" not in js and "new Function" not in js and "outerHTML" not in js
    css = (STATIC / "console.css").read_text()
    assert "url(#" not in css and "@import" not in css and "url(http" not in css
    assert console.get("/static/console.js").status_code == 200
    assert console.get("/static/../app.py").status_code == 404
    assert console.get("/static/index.html").status_code == 404
    for name, mime in [("intercept.svg", "image/svg+xml"), ("worldmap.svg", "image/svg+xml"), ("icon.svg", "image/svg+xml"),
                       ("geist-sans.woff2", "font/woff2"), ("geist-mono.woff2", "font/woff2")]:
        r = console.get(f"/static/{name}")
        assert r.status_code == 200 and r.headers["content-type"].startswith(mime)
    for name in ("intercept.svg", "worldmap.svg", "icon.svg"):
        art = (STATIC / name).read_text()
        assert "<script" not in art and "href=\"http" not in art and "url(http" not in art and " on" not in art.lower()


def test_pages_and_api_need_a_session(console):
    for path in PAGES:
        r = console.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login", path
    for path in ("/api/shell", "/api/overview", "/api/map?w=1h", "/api/cases", "/api/cases/CS-1001",
                 "/api/approvals", "/api/automation", "/api/state"):
        r = console.get(path)
        assert r.status_code == 401 and r.json() == {"detail": "login required"}, path


def test_pages_render_with_csp_and_sandbox_marker(console):
    assert _login(console).status_code == 303
    for path, name in PAGES.items():
        r = console.get(path)
        assert r.status_code == 200 and f'<body class="app" data-screen="{name}"' in r.text, path
        assert "unsafe-inline" not in r.headers["content-security-policy"]
    assert console.get("/api/map?w=2d").status_code == 422
    assert console.get("/api/cases?status=all").status_code == 422
    assert console.get("/api/cases/CS-9999").status_code == 404
    assert console.get("/api/cases/1;drop").status_code == 404


def test_production_marks_pages_and_has_no_scenarios(console):
    from hypersoar.console.app import STATIC, fastapi_app
    assert _login(console).status_code == 303
    # The scenario screen left the console in both modes (the CLI still runs them in the sandbox).
    assert console.get("/scenarios").status_code == 404 and console.get("/api/scenarios").status_code == 404
    assert not (STATIC / "scenarios.html").exists() and "/scenarios" not in (STATIC / "console.js").read_text()
    console_env_install = fastapi_app.state.install
    real = console_env_install.get
    console_env_install.get = lambda pool: {"mode": "production", "entity_id": "dob"}
    try:
        assert console.get("/scenarios").status_code == 404
        assert console.get("/api/scenarios").status_code == 404
        assert '<body class="app prod" data-screen="overview"' in console.get("/").text
        assert console.get("/api/shell").json()["mode"] == "production"
    finally:
        console_env_install.get = real


def test_console_without_explicit_mode_refuses_to_start(console_env):
    # Lab containers carry HYPERSOAR_ENV=production; without an explicit HYPERSOAR_MODE nothing guesses.
    console_env.setenv("HYPERSOAR_ENV", "production")
    console_env.delenv("HYPERSOAR_MODE", raising=False)
    from hypersoar.console.app import app
    with pytest.raises(ConfigError, match="HYPERSOAR_MODE"):
        with TestClient(app, base_url="https://testserver"):
            pass


def test_entity_names_follow_the_install_mode_not_the_container_env(console_env):
    console_env.setenv("HYPERSOAR_ENV", "lab")
    console_env.setenv("HYPERSOAR_MODE", "sandbox")
    from hypersoar.console.app import app
    with TestClient(app, base_url="https://testserver") as c:
        assert "Security orchestration console · PT Delta Omega Beta" in c.get("/login").text
        assert _login(c).status_code == 303
        ent = c.get("/api/shell").json()["entity"]
    assert ent["name"] == "PT Delta Omega Beta" and ent["id"] == "dob"
    assert ent["region_label"] == "Alibaba Cloud Jakarta" and ent["region"] == "ap-southeast-5"
    assert ent["assets"] == 7 and set(ent) == {"id", "name", "short", "timezone", "region", "region_label",
                                               "map_xy", "assets"}


def test_evidence_counts_alerts_in_the_right_number():
    from hypersoar.console.views import _evidence
    assert _evidence({"alert_ids": ["a"]}) == ["1 alert in the case"]
    assert _evidence({"alert_ids": ["a", "b"]}) == ["2 alerts in the case"]


def test_write_endpoints_are_listed_in_test_console_writes():
    from test_console_writes import WRITES

    from hypersoar.console.app import fastapi_app
    writes = sorted((r.path, m) for r in fastapi_app.routes for m in getattr(r, "methods", set()) - {"GET", "HEAD"})
    assert writes == WRITES


def test_body_limit(console):
    r = console.post("/login", content="a" * 20_000, headers={"content-type": "application/x-www-form-urlencoded",
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
    assert len(s["timeline"]) == 24 and sum(h["high"] for h in s["timeline"]) == 2
    assert s["top_rules"] == [{"rule_id": "waf.sqli.burst", "source": "waf", "n": 2, "severity": "high"}]
    assert "203.0.113.44" not in r.text and "198.51.100.7" not in r.text


def test_new_api_shapes_and_no_raw_addresses(client, principals, pool, settings, tmp_path, conn,
                                             console_env, viewer):
    ips = ("203.0.113.44", "198.51.100.7")
    ingest(pool, settings, tmp_path, [waf_alert(ip=ip) for ip in ips])
    for r in conn.execute("SELECT alert_id, alert FROM gateway.inbox_event").fetchall():
        tok = r["alert"]["entities"]["src_ip"]
        resp = client.post("/v1/actions/requests", headers=principals["worker-svc"],
                           json=body(str(r["alert_id"]), params={"ip_token": tok, "waf_instance": "waf-lab"}))
        assert resp.status_code == 201
    from hypersoar.console.app import app
    with TestClient(app, base_url="https://testserver") as c:
        assert _login(c).status_code == 303
        out = {p: c.get(p) for p in ("/api/shell", "/api/overview", "/api/map?w=15m", "/api/map?w=24h",
                                     "/api/cases?status=open", "/api/cases?status=closed", "/api/approvals",
                                     "/api/automation")}
        assert all(r.status_code == 200 for r in out.values()), {p: r.status_code for p, r in out.items()}
        cases = out["/api/cases?status=open"].json()["cases"]
        details = [c.get(f"/api/cases/{x['case_id']}") for x in cases]
    shell = out["/api/shell"].json()
    assert shell["meta"]["writes"] is False and shell["meta"]["csrf"] and shell["mode"] == "sandbox" and shell["ledger"]["ok"] is True
    assert shell["kill_switch"]["global_engaged"] is False
    ov = out["/api/overview"].json()
    assert ov["stats"]["alerts_24h"] == 2 and len(ov["timeline"]) == 24
    m = out["/api/map?w=24h"].json()
    assert m["window"] == "24h" and m["total"] == 2 and len(m["arcs"]) <= 200
    assert {a["sev"] for a in m["arcs"]} <= {"critical", "high", "medium", "low", "info"}
    assert cases and all(d.status_code == 200 for d in details)
    d = details[0].json()
    assert {"case", "alerts", "steps", "ai", "trace", "requests", "calls", "also_in"} <= set(d)
    ap = out["/api/approvals"].json()
    assert all("would_execute" in x for x in ap["recent"])
    auto = out["/api/automation"].json()
    assert auto["catalog_loaded"] is True and auto["ledger"]["tail"]
    for p, r in [*out.items(), *(("detail", x) for x in details)]:
        for ip in ips:
            assert ip not in r.text, (p, ip)


# Synthetic generator ------------------------------------------------------------------------------

def test_seeding_campaigns_normalize_into_mitre_chains(tmp_path):
    rng = random.Random(1)
    tok = Tokenizer(b"\x01" * 32)
    seed_net = ipaddress.ip_network("203.0.113.0/24")
    for kind in synth.CAMPAIGNS:
        c = synth.Campaign.start(kind, rng, 0)
        tactics = []
        while not c.done:
            raw = c.next_alert(rng, datetime.now(UTC))
            assert raw["raw_ref"] == "synthetic://lab"
            ip = ipaddress.ip_address(raw["src_ip"])
            if kind == "protected_source":
                assert ip in ipaddress.ip_network("198.51.100.0/25")
            else:  # never the 203.0.113.208/28+ blocks kept for scenario runs
                assert ip in seed_net and int(str(ip).rsplit(".", 1)[1]) < 208
            na = normalize(raw, tok, source_name="synthetic", keep_truth=True)
            assert na.alert["synthetic_truth"] == synth.TRUTH.get(kind, "malicious")
            tactics.append(na.alert["attack"]["tactic"])
        if kind == "ak_lateral":
            assert tactics == ["TA0001", "TA0007", "TA0008", "TA0009"]


def test_seeding_bot_refuses_production(tmp_path):
    with pytest.raises(RuntimeError, match="sandbox"):
        synth.run(tmp_path / "a.ndjson", 0, 1, seed=1, mode="production")
    assert not (tmp_path / "a.ndjson").exists()


def test_seeding_bot_paces_the_l2_access_key_chain():
    s = synth.Seeder(5, step_gap_s=120)
    starts = []
    t = 0.0
    while t < 6 * 3600:
        starts += [t for a in s.tick(t) if a["rule_id"] == "actiontrail.ak_unusual_ip"]
        t += 120
    assert len(starts) == 3 and all(b - a >= synth.AK_EVERY_S for a, b in zip(starts, starts[1:]))
    assert starts[0] >= synth.AK_FIRST_S  # never at start-up


def test_synthetic_run_appends_whole_lines(tmp_path):
    out = tmp_path / "alerts.ndjson"
    n = synth.run(out, 0, 6, seed=3, log=lambda m: None)
    lines = out.read_text().splitlines()
    assert n == 6 and len(lines) == 6
    # No AccessKey chain at start-up: its 1/hour quota stays free for a scenario run after a deploy.
    assert "ak_lateral" not in {json.loads(x)["campaign"] for x in lines}


def test_expiring_shows_the_target_not_the_whole_call():
    from hypersoar.console.views import _target
    assert _target("waf.ip_blacklist.add(ip_token=tok_ip_98fd, ttl_s=86400, waf_instance=waf-jkt-01)") == "tok_ip_98fd"
    assert _target("noop") == "noop" and _target(None) is None


def test_every_page_links_the_icon_so_the_browser_never_asks_for_favicon_ico(console):
    from hypersoar.console.app import STATIC
    link = '<link rel="icon" href="/static/icon.svg" type="image/svg+xml">'
    for name in PAGES.values():
        assert link in (STATIC / f"{name}.html").read_text()
    assert link in console.get("/login").text
