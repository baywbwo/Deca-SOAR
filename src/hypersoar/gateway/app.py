"""Gateway process: a background pull/forward loop, the push receivers of the data-source connectors
(generic webhook, syslog/CEF) and internal health endpoints.

Sources: the data-source connectors configured on the integration screen for this entity and mode
(hypersoar.sources), plus, in sandbox only, the replay file the seeding bot writes. A production
gateway refuses to start with a replay file: synthetic alerts never reach a production install.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from hypersoar.broker.integrations.secretbox import SecretBox
from hypersoar.common import entity as entity_mod
from hypersoar.common.config import DEFAULT_INTERNAL_CIDRS, ConfigError, Settings
from hypersoar.common.db import make_pool
from hypersoar.common.dbguard import assert_least_privilege_login
from hypersoar.common.http import BodyLimit
from hypersoar.gateway.connectors import Connectors
from hypersoar.gateway.service import Deliver, forward_once, pull_once
from hypersoar.gateway.sources import ReplayFileSource
from hypersoar.gateway.starter import TemporalStarter
from hypersoar.sources import cef, spool, syslog, webhook
from hypersoar.workflows.config import TemporalSettings

log = logging.getLogger("hypersoar.gateway")
MAX_WEBHOOK_BODY = 1024 * 1024


def replay_source(mode: str):
    """The sandbox replay file, or None. HYPERSOAR_GATEWAY_SOURCE=connectors (the default) reads only the
    configured data sources; =replay adds the replay file, which production refuses."""
    kind = os.environ.get("HYPERSOAR_GATEWAY_SOURCE", "connectors")
    if kind not in ("connectors", "replay"):
        raise ConfigError(f"unsupported HYPERSOAR_GATEWAY_SOURCE {kind[:20]!r} (connectors or replay)")
    if kind == "connectors":
        return None
    if mode != "sandbox":
        raise ConfigError("the replay file holds synthetic alerts and is sandbox only; production reads the"
                          " data sources configured on the integration screen")
    return ReplayFileSource(Path(os.environ["HYPERSOAR_REPLAY_FILE"]),
                            name=os.environ.get("HYPERSOAR_SOURCE_NAME", "replay"))


def run_loop(stop: threading.Event, pool, settings: Settings, fixed: list, connectors: Connectors | None,
             deliver: Deliver, interval_s: float) -> None:
    while not stop.is_set():
        try:
            dynamic = connectors.pull_sources() if connectors else []
        except Exception as e:
            log.error("source config error: %s", type(e).__name__)
            dynamic = []
        for source in fixed + dynamic:
            try:
                p = pull_once(pool, source, settings)
                if p.pulled:
                    log.info("pull %s pulled=%d new=%d merged=%d rejected=%d", source.name, p.pulled, p.new,
                             p.merged, p.rejected)
            except Exception as e:  # one broken source never stops the others
                log.error("pull %s error: %s", source.name, type(e).__name__)
        try:
            f = forward_once(pool, deliver)
            if f.sent or f.failed or f.dead:
                log.info("forward sent=%d failed=%d dead=%d", f.sent, f.failed, f.dead)
        except Exception as e:  # keep the loop alive; the inbox makes retries safe
            log.error("forward error: %s", type(e).__name__)
        stop.wait(interval_s)


def syslog_accept(connectors: Connectors):
    """Checked when a connection or datagram arrives, from the last loaded settings (no DB call)."""
    def accept(sender: str) -> bool:
        a = connectors.peek("syslog")
        return a is not None and syslog.allowed(sender, a.settings.allowed_senders)
    return accept


def syslog_handler(pool, entity_id: str, connectors: Connectors, counters: dict):
    def on_line(sender: str, line: str) -> None:
        a = connectors.get("syslog")
        if a is None or not syslog.allowed(sender, a.settings.allowed_senders):
            counters["dropped"] += 1
            return
        try:
            rec = cef.parse(line)
        except cef.CefError:
            counters["unparsed"] += 1
            return
        try:
            with pool.connection() as conn:
                spool.put(conn, entity_id, "syslog", [rec])
            counters["accepted"] += 1
        except spool.SpoolFull:
            counters["dropped"] += 1
        except Exception as e:
            counters["dropped"] += 1
            log.error("syslog spool error: %s", type(e).__name__)
    return on_line


@asynccontextmanager
async def lifespan(app: FastAPI):
    mode = entity_mod.current_mode()  # first: nothing starts without an explicit mode
    settings = Settings.for_gateway()
    fixed = [s for s in (replay_source(mode),) if s is not None]
    ent = entity_mod.load(mode=mode)
    pool = make_pool(settings.db_url)
    try:
        with pool.connection() as conn:
            assert_least_privilege_login(conn, "gateway")
            entity_mod.assert_install(conn, mode, ent.id)
    except BaseException:
        pool.close()
        raise
    # The source subkey only: Lark/Jira/AI secrets are sealed under another key the gateway never holds.
    connectors = Connectors(pool, ent.id, mode, SecretBox.source_from_env())
    starter = TemporalStarter(TemporalSettings.from_env(), identity=f"deca-gateway@{os.uname().nodename}")
    stop = threading.Event()
    t = threading.Thread(
        target=run_loop,
        args=(stop, pool, settings, fixed, connectors, starter, float(os.environ.get("HYPERSOAR_PULL_INTERVAL_S", "15"))),
        name="gateway-loop",
        daemon=True,
    )
    t.start()
    app.state.pool = pool
    app.state.entity_id = ent.id
    app.state.connectors = connectors
    app.state.seen = webhook.DbSeen(pool, ent.id)
    app.state.syslog = {"accepted": 0, "dropped": 0, "unparsed": 0}
    listeners = []
    listen = syslog.listen_config(mode)
    if listen is not None:
        await asyncio.to_thread(connectors.refresh, True)
        listeners = await syslog.serve(listen, syslog_handler(pool, ent.id, connectors, app.state.syslog),
                                       syslog_accept(connectors), app.state.syslog)
    yield
    for srv in listeners:
        srv.close()
    stop.set()
    t.join(timeout=15)
    if not t.is_alive():
        starter.close()
    pool.close()


app = FastAPI(title="HyperSoar Ingest Gateway", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(BodyLimit, max_bytes=MAX_WEBHOOK_BODY)


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


PROXY_HEADERS = ("forwarded", "x-forwarded-for", "x-real-ip")


def _internal_caller(request: Request) -> bool:
    """A direct caller on an internal network: not a request relayed by the public proxy/SLB."""
    if any(h in request.headers for h in PROXY_HEADERS):
        return False
    try:
        ip = ipaddress.ip_address(request.client.host if request.client else "")
    except ValueError:
        return False
    cidrs = os.environ.get("HYPERSOAR_INTERNAL_CIDRS", DEFAULT_INTERNAL_CIDRS)
    return any(ip in ipaddress.ip_network(c.strip(), strict=False) for c in cidrs.split(",") if c.strip())


@app.get("/readyz")
def readyz(request: Request) -> dict:
    # Inbox and syslog counters are for operators: not answered through the public webhook proxy.
    if not _internal_caller(request):
        raise HTTPException(404)
    with app.state.pool.connection() as conn:
        rows = conn.execute("SELECT status, count(*) AS n FROM gateway.inbox_event GROUP BY status").fetchall()
    return {"ok": True, "inbox": {r["status"]: r["n"] for r in rows}, "syslog": app.state.syslog}


@app.post("/v1/ingest/webhook", status_code=202)
async def ingest_webhook(request: Request):
    """Generic webhook (hypersoar.sources.webhook): HMAC-signed JSON alerts from any SIEM."""
    st = request.app.state
    a = await asyncio.to_thread(st.connectors.get, "webhook")
    if a is None:
        raise HTTPException(404, "the webhook data source is not enabled")
    body = await request.body()
    if len(body) > a.settings.max_body_kb * 1024:
        raise HTTPException(413, "request body too large")
    try:
        await asyncio.to_thread(
            webhook.verify, a.secrets.get("hmac_secret"), request.headers.get("x-hypersoar-timestamp"),
            request.headers.get("x-hypersoar-signature"), body, a.settings.max_skew_s, st.seen)
        recs = webhook.records(body)
    except webhook.Rejected as e:
        return JSONResponse({"detail": str(e)}, status_code=e.status)

    def put():
        with st.pool.connection() as conn:
            return spool.put(conn, st.entity_id, "webhook", recs)
    try:
        n = await asyncio.to_thread(put)
    except spool.SpoolFull:
        return JSONResponse({"detail": "the gateway is behind; retry later"}, status_code=429,
                            headers={"Retry-After": "60"})
    return {"accepted": n}
