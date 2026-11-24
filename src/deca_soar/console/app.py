"""SOC console process (read-only). Run with uvicorn over TLS behind the tunnel connector:

    uvicorn deca_soar.console.app:app --host 0.0.0.0 --port 8300 --no-proxy-headers \
        --ssl-certfile ... --ssl-keyfile ...

Settings: DECA_DB_URL(_FILE) is a deca_soar_viewer login; DECA_CONSOLE_PASSWORD_HASH_FILE holds the
scrypt hash from `deca-soar console-hash`; DECA_CONSOLE_USER (default `owner`);
DECA_CONSOLE_TRUSTED_PROXIES lists the connector's addresses whose CF-Connecting-IP is believed;
DECA_CONSOLE_SYNTHETIC=1 labels the data as synthetic; DECA_GIT_SHA is shown in the footer.
"""

from __future__ import annotations

import hmac
import html
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from starlette.concurrency import run_in_threadpool

from deca_soar.common.config import ConfigError, _cidrs, read_secret
from deca_soar.common.dbguard import assert_least_privilege_login
from deca_soar.common.http import BodyLimit
from deca_soar.console import queries
from deca_soar.console.auth import LoginLimiter, PasswordHash, SessionStore, client_address

log = logging.getLogger("deca_soar.console")

STATIC = Path(__file__).resolve().parent / "static"
COOKIE = "__Host-deca_console"
MAX_BODY = 4096

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self';"
       " form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
SECURITY_HEADERS = {
    "content-security-policy": CSP,
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
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
    raw_hash = read_secret("DECA_CONSOLE_PASSWORD_HASH")
    assert raw_hash is not None
    app.state.password = PasswordHash.parse(raw_hash)
    app.state.user = os.environ.get("DECA_CONSOLE_USER", "owner").strip()
    if not app.state.user:
        raise ConfigError("DECA_CONSOLE_USER must not be empty")
    app.state.trusted = _cidrs(os.environ.get("DECA_CONSOLE_TRUSTED_PROXIES", ""))
    app.state.synthetic = os.environ.get("DECA_CONSOLE_SYNTHETIC") == "1"
    app.state.sha = os.environ.get("DECA_GIT_SHA", "unknown")[:40]
    app.state.sessions = SessionStore()
    app.state.limiter = LoginLimiter()
    app.state.ledger = queries.LedgerStatus()
    db_url = read_secret("DECA_DB_URL")
    pool = ConnectionPool(db_url, min_size=1, max_size=4, configure=_configure,
                          kwargs={"row_factory": dict_row, "autocommit": False}, open=True)
    try:
        with pool.connection() as conn:
            assert_least_privilege_login(conn, "console")
    except BaseException:
        pool.close()
        raise
    app.state.pool = pool
    yield
    pool.close()


fastapi_app = FastAPI(title="DECA SOC Console", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


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
    "bad": "Nama pengguna atau kata sandi salah.",
    "limit": "Terlalu banyak percobaan. Coba lagi beberapa menit lagi.",
    "origin": "Permintaan ditolak. Muat ulang halaman ini lalu coba lagi.",
}


def _login_page(request: Request, status: int = 200, msg: str | None = None) -> HTMLResponse:
    text = html.escape(LOGIN_MESSAGES[msg])
    synthetic = '<p class="chip sample">Data sintetis</p>' if request.app.state.synthetic else ""
    body = f"""<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Masuk · DECA SOC Console</title><link rel="stylesheet" href="/static/console.css"></head>
<body class="login-body"><main class="login">
<div class="brand"><span class="logo" aria-hidden="true">D</span><span class="t1">DECA</span><span class="t2">SOC Console</span></div>
{synthetic}
<form method="post" action="/login" class="login-form">
<h1>Masuk</h1>
<p class="small">Tampilan baca saja untuk pemilik. Tidak ada tombol aksi.</p>
<label for="username">Nama pengguna</label>
<input id="username" name="username" autocomplete="username" required maxlength="64" autofocus>
<label for="password">Kata sandi</label>
<input id="password" name="password" type="password" autocomplete="current-password" required maxlength="256">
<p class="err" role="alert">{text}</p>
<button type="submit" class="btn pri">Masuk</button>
</form></main></body></html>"""
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


@fastapi_app.get("/")
def index(request: Request):
    if not _session(request):
        return RedirectResponse("/login", status_code=303)
    return FileResponse(STATIC / "index.html", media_type="text/html; charset=utf-8")


@fastapi_app.get("/static/{name}")
def static(name: str):
    files = {"console.css": "text/css; charset=utf-8", "console.js": "text/javascript; charset=utf-8"}
    if name not in files:
        return Response(status_code=404)
    return FileResponse(STATIC / name, media_type=files[name])


@fastapi_app.get("/api/state")
def api_state(request: Request):
    s = _session(request)
    if not s:
        return JSONResponse({"detail": "login required"}, status_code=401)
    with request.app.state.pool.connection() as conn:
        data = queries.state(conn, request.app.state.ledger)
    data["meta"] = {"synthetic": request.app.state.synthetic, "sha": request.app.state.sha,
                    "user": s.user, "mode": "shadow", "read_only": True}
    return data


app = BodyLimit(fastapi_app, MAX_BODY)
