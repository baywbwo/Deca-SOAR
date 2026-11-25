"""SOC console process. Run with uvicorn over TLS behind the tunnel connector:

    uvicorn hypersoar.console.app:app --host 0.0.0.0 --port 8300 --no-proxy-headers \
        --ssl-certfile ... --ssl-keyfile ...

Settings: HYPERSOAR_DB_URL(_FILE) is a deca_soar_viewer login; HYPERSOAR_CONSOLE_PASSWORD_HASH_FILE holds the
scrypt hash from `hypersoar console-hash`; HYPERSOAR_CONSOLE_USER (default `owner`);
HYPERSOAR_CONSOLE_TRUSTED_PROXIES lists the connector's addresses whose CF-Connecting-IP is believed;
HYPERSOAR_CONSOLE_SYNTHETIC=1 labels the data as synthetic; HYPERSOAR_GIT_SHA is shown in the footer.
Reads use the read-only viewer login. Writes (approve, kill switch, case triage, revoke) are posted to the
broker; see console/writes.py for HYPERSOAR_BROKER_URL / _TOKEN(_FILE) / _CA_FILE.
"""

from __future__ import annotations

import hmac
import html
import json
import logging
import os
import re
import threading
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from starlette.concurrency import run_in_threadpool

from hypersoar.broker import catalog as catalog_mod
from hypersoar.common import entity as entity_mod
from hypersoar.common.config import ConfigError, _cidrs, read_secret
from hypersoar.common.dbguard import assert_least_privilege_login
from hypersoar.common.http import BodyLimit
from hypersoar.console import queries, views
from hypersoar.console import writes as cw
from hypersoar.console.auth import LoginLimiter, PasswordHash, SessionStore, client_address

log = logging.getLogger("hypersoar.console")

STATIC = Path(__file__).resolve().parent / "static"
COOKIE = "__Host-hypersoar_console"
MAX_BODY = 16384  # a 2000-character comment in any script, plus JSON
# Screens of the v3 console. Each is a static page with no inline code, filled by console.js from /api/*.
PAGES = {"/": "overview.html", "/map": "map.html", "/cases": "cases.html", "/approvals": "approvals.html",
         "/automation": "automation.html", "/scenarios": "scenarios.html"}
# Sandbox tools: production answers 404 for these, so they are not just hidden but absent.
SANDBOX_ONLY = {"/scenarios", "/api/scenarios"}
STATIC_FILES = {"console.css": "text/css; charset=utf-8", "console.js": "text/javascript; charset=utf-8",
                "intercept.svg": "image/svg+xml", "worldmap.svg": "image/svg+xml", "icon.svg": "image/svg+xml",
                "geist-sans.woff2": "font/woff2", "geist-mono.woff2": "font/woff2"}
CASE_ID = re.compile(r"^CS-[0-9]{1,9}$")

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';"
       " connect-src 'self';"
       " form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
SECURITY_HEADERS = {
    "content-security-policy": CSP,
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    # same-origin, not no-referrer: with no-referrer browsers send "Origin: null" on form POSTs, which
    # the same-origin check on /login and /logout must reject. Cross-origin requests still get no referrer.
    "referrer-policy": "same-origin",
    "strict-transport-security": "max-age=31536000",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "cache-control": "no-store",
}


def _configure(conn) -> None:
    # Defence in depth on top of the viewer grants: every transaction of this pool is read-only.
    conn.execute("SET default_transaction_read_only = on")
    conn.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    raw_hash = read_secret("HYPERSOAR_CONSOLE_PASSWORD_HASH")
    assert raw_hash is not None
    app.state.password = PasswordHash.parse(raw_hash)
    app.state.user = os.environ.get("HYPERSOAR_CONSOLE_USER", "owner").strip()
    if not app.state.user:
        raise ConfigError("HYPERSOAR_CONSOLE_USER must not be empty")
    app.state.trusted = _cidrs(os.environ.get("HYPERSOAR_CONSOLE_TRUSTED_PROXIES", ""))
    app.state.synthetic = os.environ.get("HYPERSOAR_CONSOLE_SYNTHETIC") == "1"
    app.state.sha = os.environ.get("HYPERSOAR_GIT_SHA", "unknown")[:40]
    app.state.sessions = SessionStore()
    app.state.limiter = LoginLimiter()
    # Wrong passwords on re-authenticated writes: 5 per 15 minutes per person and address.
    app.state.reauth_limiter = LoginLimiter(per_client=5, window_s=900, global_per_min=60)
    app.state.ask_ai = AskAiReplay()
    # Ask AI spends model tokens: at most 10 runs per person per 10 minutes.
    app.state.ask_ai_rate = UserRate(10, 600)
    app.state.ledger = queries.LedgerStatus()
    app.state.install = InstallInfo()
    app.state.entity = {}
    app.state.catalog = _catalog_public()
    db_url = read_secret("HYPERSOAR_DB_URL")
    pool = ConnectionPool(db_url, min_size=1, max_size=4, configure=_configure,
                          kwargs={"row_factory": dict_row, "autocommit": False}, open=True)
    try:
        mode = entity_mod.current_mode()
        with pool.connection() as conn:
            assert_least_privilege_login(conn, "console")
            entity_mod.assert_install(conn, mode, entity_mod.load(mode=mode).id)
    except BaseException:
        pool.close()
        raise
    app.state.pool = pool
    try:
        app.state.broker = cw.BrokerClient.from_env(app.state.install.get(pool)["mode"])
    except BaseException:
        pool.close()
        raise
    if app.state.broker is None:
        log.warning("console: HYPERSOAR_BROKER_URL not set; every write answers 503")
    yield
    if app.state.broker is not None:
        app.state.broker.close()
    pool.close()


class UserRate:
    """At most `limit` calls per user in a sliding window."""

    def __init__(self, limit: int, window_s: float) -> None:
        self.limit, self.window_s, self._d, self._lock = limit, window_s, {}, threading.Lock()

    def allow(self, user: str) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._d.setdefault(user, deque())
            while q and now - q[0] > self.window_s:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


class AskAiReplay:
    """The broker's triage endpoint has no Idempotency-Key, so a retried "Ask AI" click with the same key
    returns the first answer from here instead of calling the model twice."""

    def __init__(self, ttl_s: float = 600, max_items: int = 256) -> None:
        self.ttl_s, self.max_items, self._d, self._lock = ttl_s, max_items, {}, threading.Lock()

    def get(self, key: tuple) -> tuple[int, dict] | None:
        with self._lock:
            v = self._d.get(key)
            if v is None or time.monotonic() - v[0] > self.ttl_s:
                return None
            return v[1], {**v[2], "idempotent_replay": True}

    def put(self, key: tuple, status: int, body: dict) -> None:
        with self._lock:
            if len(self._d) >= self.max_items:
                del self._d[min(self._d, key=lambda k: self._d[k][0])]
            self._d[key] = (time.monotonic(), status, body)


class InstallInfo:
    """Mode and entity of this install (public.hypersoar_install), re-read at most once a minute."""

    def __init__(self, ttl_s: float = 60) -> None:
        self.ttl_s, self._at, self._value, self._lock = ttl_s, -1e9, None, threading.Lock()

    def get(self, pool) -> dict:
        with self._lock:
            if self._value is None or time.monotonic() - self._at >= self.ttl_s:
                with pool.connection() as conn:
                    self._value = views.install(conn)
                self._at = time.monotonic()
            return self._value


def _entity_public(cache: dict, mode: str) -> dict | None:
    """Display fields of the entity file, read for the install's mode (the database marker, not HYPERSOAR_MODE:
    the console has no mode of its own). No targets, accounts or integration settings leave here."""
    if mode not in cache:
        try:
            e = entity_mod.load(mode=mode)
        except ConfigError as exc:
            log.warning("console: entity file not loaded (%s); header shows the entity id only", exc)
            cache[mode] = None
        else:
            cache[mode] = {"id": e.id, "name": e.name, "short": e.short, "timezone": e.timezone,
                           "region": e.region, "region_label": e.region_label, "map_xy": list(e.map_xy),
                           "assets": len(e.assets)}
    return cache[mode]


def _catalog_public() -> list[dict] | None:
    try:
        cat, _ = catalog_mod.load(Path(os.environ.get("HYPERSOAR_POLICY_DIR", "policy")))
    except (OSError, ConfigError, ValueError) as exc:
        log.warning("console: action catalog not loaded (%s)", exc)
        return None
    return [a.public() for a in cat.values()]


fastapi_app = FastAPI(title="HyperSoar Console", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@fastapi_app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response


def _session(request: Request):
    return request.app.state.sessions.get(request.cookies.get(COOKIE))


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin", "")
    host = request.headers.get("host", "")
    if not origin or not host:
        return False
    parts = urlsplit(origin)
    return parts.scheme == "https" and parts.netloc.lower() == host.lower()


def _client(request: Request) -> str:
    peer = request.client.host if request.client else None
    return client_address(peer, {k.lower(): v for k, v in request.headers.items()}, request.app.state.trusted)


LOGIN_MESSAGES = {
    None: "",
    "bad": "Wrong username or password",
    "limit": "Too many attempts. Wait a few minutes and try again",
    "origin": "Request rejected. Reload this page and try again",
}


def _login_page(request: Request, status: int = 200, msg: str | None = None) -> HTMLResponse:
    text = html.escape(LOGIN_MESSAGES[msg])
    st = request.app.state
    try:
        mode = st.install.get(st.pool)["mode"]
    except Exception:  # the sign-in page must render even when the database is away
        mode = "sandbox"
    name = html.escape((_entity_public(st.entity, mode) or {}).get("name") or "")
    eyebrow = "Security orchestration console" + (f" · {name}" if name else "")
    flags = ('<span class="flag">Synthetic data</span>' if st.synthetic else "") + (
        '<span class="env prd">Production</span>' if mode == "production" else '<span class="env sbx">Sandbox</span>')
    body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · HyperSoar Console</title><link rel="icon" href="/static/icon.svg" type="image/svg+xml"><link rel="stylesheet" href="/static/console.css"></head>
<body class="gate">
<div class="art" aria-hidden="true"></div>
<main class="gate-panel">
<div class="gate-top"><span class="word">HyperSoar</span>{flags}</div>
<div class="gate-copy">
<p class="eyebrow">{eyebrow}</p>
<h1 class="display">Watch every<br>decision<span class="cut">.</span></h1>
<p class="lede">Cases, approvals and the kill switch of the gateway, triage and action broker. Every change asks for your password again and goes into the audit trail.</p>
</div>
<form method="post" action="/login" class="gate-form">
<label for="username">Username</label>
<input id="username" name="username" autocomplete="username" required maxlength="64" autofocus>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required maxlength="256">
<p class="err" role="alert">{text}</p>
<button type="submit" class="btn pri">Sign in</button>
</form>
<p class="gate-foot">Owner access only. Sessions end after 8 hours, or 30 minutes idle</p>
</main></body></html>"""
    return HTMLResponse(body, status_code=status)


@fastapi_app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@fastapi_app.get("/login")
def login_form(request: Request):
    if _session(request):
        return RedirectResponse("/", status_code=303)
    return _login_page(request)


@fastapi_app.post("/login")
async def login(request: Request):
    if not _same_origin(request):
        return _login_page(request, 403, "origin")
    client = _client(request)
    limiter: LoginLimiter = request.app.state.limiter
    if not limiter.allow(client):
        log.warning("console login rate-limited client=%s", client)
        return _login_page(request, 429, "limit")
    form = parse_qs((await request.body()).decode("utf-8", "replace"), max_num_fields=4)
    user = (form.get("username") or [""])[0]
    password = (form.get("password") or [""])[0]
    # Always run scrypt so a wrong user name takes as long as a wrong password.
    password_ok = await run_in_threadpool(request.app.state.password.verify, password)
    user_ok = hmac.compare_digest(user.encode(), request.app.state.user.encode())
    if not (password_ok and user_ok):
        limiter.failed(client)
        log.warning("console login failed client=%s", client)
        return _login_page(request, 401, "bad")
    limiter.succeeded(client)
    request.app.state.sessions.drop(request.cookies.get(COOKIE))
    token = request.app.state.sessions.create(request.app.state.user)
    log.info("console login ok client=%s", client)
    r = RedirectResponse("/", status_code=303)
    r.set_cookie(COOKIE, token, httponly=True, secure=True, samesite="strict", path="/",
                 max_age=int(request.app.state.sessions.absolute_s))
    return r


@fastapi_app.post("/logout")
def logout(request: Request):
    if not _same_origin(request):
        return Response(status_code=403)
    request.app.state.sessions.drop(request.cookies.get(COOKIE))
    r = RedirectResponse("/login", status_code=303)
    r.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return r


def _production(request: Request) -> bool:
    return request.app.state.install.get(request.app.state.pool)["mode"] == "production"


def _page(request: Request, path: str, name: str):
    if not _session(request):
        return RedirectResponse("/login", status_code=303)
    page = (STATIC / name).read_text()
    # Production hides sandbox-only parts server side, so they never flash before console.js runs.
    if _production(request):
        if path in SANDBOX_ONLY:
            return Response(status_code=404)
        page = page.replace('<body class="app"', '<body class="app prod"', 1)
    return HTMLResponse(page)


def _page_route(path: str, name: str):
    def route(request: Request):
        return _page(request, path, name)
    return route


for _path, _name in PAGES.items():
    fastapi_app.add_api_route(_path, _page_route(_path, _name), methods=["GET"], include_in_schema=False)


@fastapi_app.get("/static/{name}")
def static(name: str):
    if name not in STATIC_FILES:
        return Response(status_code=404)
    return FileResponse(STATIC / name, media_type=STATIC_FILES[name])


def _api(request: Request, fn):
    """Session check, one read-only connection, the install row: every /api/* GET goes through here."""
    s = _session(request)
    if not s:
        return JSONResponse({"detail": "login required"}, status_code=401)
    st = request.app.state
    inst = st.install.get(st.pool)
    with st.pool.connection() as conn:
        return fn(conn, inst, s)


@fastapi_app.get("/api/shell")
def api_shell(request: Request):
    st = request.app.state

    def build(conn, inst, s):
        return {**views.shell(conn, inst), "mode": inst["mode"], "entity_id": inst["entity_id"],
                "entity": ent if (ent := _entity_public(st.entity, inst["mode"])) and ent["id"] == inst["entity_id"] else None,
                "kill_switch": queries.kill_switch(conn), "ledger": st.ledger.get(conn),
                "meta": {"synthetic": st.synthetic, "sha": st.sha, "user": s.user, "csrf": s.csrf,
                         "writes": st.broker is not None},
                "now": views.now_iso()}
    return _api(request, build)


@fastapi_app.get("/api/overview")
def api_overview(request: Request):
    return _api(request, lambda conn, inst, s: {**views.overview(conn, inst), "timeline": queries.timeline(conn),
                                                "top_rules": queries.top_rules(conn)})


@fastapi_app.get("/api/map")
def api_map(request: Request, w: str = "1h"):
    if w not in views.WINDOWS:
        return JSONResponse({"detail": "w must be 15m, 1h or 24h"}, status_code=422)
    return _api(request, lambda conn, inst, s: {**views.threat_map(conn, inst, w), "feed": views.feed(conn, inst)})


@fastapi_app.get("/api/cases")
def api_cases(request: Request, status: str = "open"):
    if status not in ("open", "waiting", "closed"):
        return JSONResponse({"detail": "status must be open, waiting or closed"}, status_code=422)
    return _api(request, lambda conn, inst, s: {"status": status, "cases": views.case_list(conn, inst, status)})


@fastapi_app.get("/api/cases/{case_id}")
def api_case(request: Request, case_id: str):
    if not CASE_ID.match(case_id):
        return JSONResponse({"detail": "not found"}, status_code=404)

    def build(conn, inst, s):
        d = views.case_detail(conn, inst, case_id)
        return {**d, "people": views.people(conn, inst)} if d is not None else JSONResponse(
            {"detail": "not found"}, status_code=404)
    return _api(request, build)


@fastapi_app.get("/api/approvals")
def api_approvals(request: Request):
    return _api(request, lambda conn, inst, s: views.approvals(conn, inst))


@fastapi_app.get("/api/automation")
def api_automation(request: Request):
    st = request.app.state
    return _api(request, lambda conn, inst, s: {**views.automation(conn, inst, st.catalog),
                                                "ledger": {**st.ledger.get(conn), "tail": queries.ledger_tail(conn)}})


@fastapi_app.get("/api/scenarios")
def api_scenarios(request: Request):
    # Scenario tests are a sandbox tool: production has no such endpoint.
    return _api(request, lambda conn, inst, s: JSONResponse({"detail": "not found"}, status_code=404)
                if inst["mode"] != "sandbox" else views.scenarios(conn, inst))


@fastapi_app.get("/api/state")
def api_state(request: Request):
    s = _session(request)
    if not s:
        return JSONResponse({"detail": "login required"}, status_code=401)
    with request.app.state.pool.connection() as conn:
        data = queries.state(conn, request.app.state.ledger)
    data["meta"] = {"synthetic": request.app.state.synthetic, "sha": request.app.state.sha, "user": s.user}
    return data


# -- writes: checked here for the browser, decided by the broker --------------------------------------
def _deny(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)


async def _write(request: Request, plan):
    """Session, same origin, CSRF token, JSON body, Idempotency-Key; then the broker decides."""
    st = request.app.state
    s = _session(request)
    if not s:
        return _deny(401, "login required")
    if not _same_origin(request):
        return _deny(403, "cross-origin request refused")
    if not hmac.compare_digest(request.headers.get(cw.CSRF_HEADER, "").encode(), s.csrf.encode()):
        return _deny(403, "missing or wrong CSRF token; reload the page")
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        return _deny(415, "send JSON")
    key = request.headers.get("idempotency-key", "")
    if not cw.IDEMPOTENCY_KEY.match(key):
        return _deny(422, "Idempotency-Key must be 8-128 letters, digits, - or _")
    if st.broker is None:
        return _deny(503, "writes are not configured on this console")
    def build(data):
        inst = st.install.get(st.pool)
        with st.pool.connection() as conn:
            return plan(data, conn, inst)

    try:
        p = await run_in_threadpool(build, json.loads(await request.body() or b"null"))
    except (ValueError, UnicodeDecodeError) as e:
        detail = str(e) if isinstance(e, cw.BadInput) else "body must be JSON"
        return _deny(404 if detail == "not found" else 422, detail)
    bucket = f"{s.user}|{_client(request)}"
    if p.reauth and not st.reauth_limiter.allow(bucket):
        log.warning("console re-auth rate-limited user=%s", s.user)
        return _deny(429, "too many wrong passwords; wait a few minutes")
    replay_key = (s.user, key) if p.path == "/v1/triage" else None
    if replay_key and (prev := st.ask_ai.get(replay_key)):
        return JSONResponse(prev[1], status_code=prev[0])
    if replay_key and not st.ask_ai_rate.allow(s.user):
        return _deny(429, "Ask AI was used too often; wait a few minutes")
    status, out = await run_in_threadpool(st.broker.send, p.method, p.path, p.body, key)
    if p.reauth:
        if status == 403 and "re-authentication" in str(out.get("detail", "")):
            st.reauth_limiter.failed(bucket)
        elif status < 300:
            st.reauth_limiter.succeeded(bucket)
    if replay_key and status < 300:
        st.ask_ai.put(replay_key, status, out)
    log.info("console write path=%s status=%s user=%s", p.path.split("/")[2] if p.path.count("/") > 1 else p.path,
             status, s.user)
    return JSONResponse(out, status_code=status)


@fastapi_app.post("/api/approvals/{request_id}/decision")
async def w_decision(request: Request, request_id: str):
    return await _write(request, lambda d, conn, inst: cw.decision(request_id, d))


@fastapi_app.post("/api/approvals/{request_id}/ask-ai")
async def w_ask_ai(request: Request, request_id: str):
    return await _write(request, lambda d, conn, inst: cw.ask_ai(conn, inst["entity_id"], request_id, d))


@fastapi_app.post("/api/requests/{request_id}/revoke")
async def w_revoke(request: Request, request_id: str):
    return await _write(request, lambda d, conn, inst: cw.revoke(request_id, d))


@fastapi_app.post("/api/kill-switch")
async def w_kill_switch(request: Request):
    return await _write(request, lambda d, conn, inst: cw.kill_switch(d))


@fastapi_app.post("/api/cases/{case_id}/assign")
async def w_assign(request: Request, case_id: str):
    return await _write(request, lambda d, conn, inst: cw.assign(case_id, d))


@fastapi_app.post("/api/cases/{case_id}/status")
async def w_status(request: Request, case_id: str):
    return await _write(request, lambda d, conn, inst: cw.status(case_id, d))


@fastapi_app.post("/api/cases/{case_id}/comments")
async def w_comment(request: Request, case_id: str):
    return await _write(request, lambda d, conn, inst: cw.comment(case_id, d))


@fastapi_app.put("/api/integrations/{name}")
async def w_integration_save(request: Request, name: str):
    return await _write(request, lambda d, conn, inst: cw.integration_save(name, d))


@fastapi_app.post("/api/integrations/{name}/rollback")
async def w_integration_rollback(request: Request, name: str):
    return await _write(request, lambda d, conn, inst: cw.integration_rollback(name, d))


@fastapi_app.put("/api/integrations/{name}/secrets/{secret}")
async def w_integration_secret(request: Request, name: str, secret: str):
    return await _write(request, lambda d, conn, inst: cw.integration_secret(name, secret, d))


@fastapi_app.post("/api/integrations/{name}/test")
async def w_integration_test(request: Request, name: str):
    return await _write(request, lambda d, conn, inst: cw.integration_test(name, d))


app = BodyLimit(fastapi_app, MAX_BODY)
