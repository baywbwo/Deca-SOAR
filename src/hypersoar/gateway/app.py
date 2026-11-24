"""Gateway process: a background pull/forward loop plus internal health endpoints.

It has no ingest endpoint: alerts are pulled (design 6.1), so nothing here accepts data from outside.
"""

from __future__ import annotations

import logging
import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from hypersoar.common.config import Settings
from hypersoar.common.db import make_pool
from hypersoar.common.dbguard import assert_least_privilege_login
from hypersoar.gateway.service import Deliver, forward_once, pull_once
from hypersoar.gateway.sources import ReplayFileSource
from hypersoar.gateway.starter import TemporalStarter
from hypersoar.workflows.config import TemporalSettings

log = logging.getLogger("hypersoar.gateway")


def build_source():
    kind = os.environ.get("HYPERSOAR_GATEWAY_SOURCE", "replay")
    if kind == "replay":
        return ReplayFileSource(Path(os.environ["HYPERSOAR_REPLAY_FILE"]), name=os.environ.get("HYPERSOAR_SOURCE_NAME", "replay"))
    raise RuntimeError(f"unsupported source {kind!r} (SLS source is phase 1)")


def run_loop(stop: threading.Event, pool, settings: Settings, source, deliver: Deliver, interval_s: float) -> None:
    while not stop.is_set():
        try:
            p = pull_once(pool, source, settings)
            f = forward_once(pool, deliver)
            if p.pulled or f.sent or f.failed or f.dead:
                log.info(
                    "cycle pulled=%d new=%d merged=%d rejected=%d sent=%d failed=%d dead=%d",
                    p.pulled, p.new, p.merged, p.rejected, f.sent, f.failed, f.dead,
                )
        except Exception as e:  # keep the loop alive; the inbox makes retries safe
            log.error("cycle error: %s", type(e).__name__)
        stop.wait(interval_s)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings.for_gateway()
    pool = make_pool(settings.db_url)
    try:
        with pool.connection() as conn:
            assert_least_privilege_login(conn, "gateway")
    except BaseException:
        pool.close()
        raise
    starter = TemporalStarter(TemporalSettings.from_env(), identity=f"deca-gateway@{os.uname().nodename}")
    stop = threading.Event()
    t = threading.Thread(
        target=run_loop,
        args=(stop, pool, settings, build_source(), starter, float(os.environ.get("HYPERSOAR_PULL_INTERVAL_S", "15"))),
        name="gateway-loop",
        daemon=True,
    )
    t.start()
    app.state.pool = pool
    yield
    stop.set()
    t.join(timeout=15)
    if not t.is_alive():
        starter.close()
    pool.close()


app = FastAPI(title="HyperSoar Ingest Gateway", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.get("/readyz")
def readyz() -> dict:
    with app.state.pool.connection() as conn:
        rows = conn.execute("SELECT status, count(*) AS n FROM gateway.inbox_event GROUP BY status").fetchall()
    return {"ok": True, "inbox": {r["status"]: r["n"] for r in rows}}
