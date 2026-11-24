"""Gateway process: a background pull/forward loop plus internal health endpoints.

It has no ingest endpoint: alerts are pulled (design 6.1), so nothing here accepts data from outside.
"""

from __future__ import annotations

import logging
import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI

from deca_soar.common.config import Settings, read_secret
from deca_soar.common.db import make_pool
from deca_soar.gateway.service import forward_once, pull_once
from deca_soar.gateway.sources import ReplayFileSource

log = logging.getLogger("deca_soar.gateway")
# httpx logs request URLs at INFO; the Tracecat webhook URL embeds its secret.
logging.getLogger("httpx").setLevel(logging.WARNING)


def build_source():
    kind = os.environ.get("DECA_GATEWAY_SOURCE", "replay")
    if kind == "replay":
        return ReplayFileSource(Path(os.environ["DECA_REPLAY_FILE"]), name=os.environ.get("DECA_SOURCE_NAME", "replay"))
    raise RuntimeError(f"unsupported source {kind!r} (SLS source is phase 1)")


def run_loop(
    stop: threading.Event, pool, settings: Settings, source, webhook_url: str, interval_s: float,
    api_key: str | None = None,
) -> None:
    with httpx.Client(timeout=httpx.Timeout(10.0), follow_redirects=False) as client:
        while not stop.is_set():
            try:
                p = pull_once(pool, source, settings)
                f = forward_once(pool, client, webhook_url, api_key=api_key)
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
    webhook_url = read_secret("DECA_TRACECAT_WEBHOOK_URL")
    # Tracecat webhook API key (x-tracecat-api-key); production sets it, the URL secret alone is weaker.
    api_key = read_secret("DECA_TRACECAT_WEBHOOK_API_KEY", required=os.environ.get("DECA_ENV") == "production")
    stop = threading.Event()
    t = threading.Thread(
        target=run_loop,
        args=(stop, pool, settings, build_source(), webhook_url, float(os.environ.get("DECA_PULL_INTERVAL_S", "15")),
              api_key),
        name="gateway-loop",
        daemon=True,
    )
    t.start()
    app.state.pool = pool
    yield
    stop.set()
    t.join(timeout=15)
    pool.close()


app = FastAPI(title="DECA SOAR Ingest Gateway", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.get("/readyz")
def readyz() -> dict:
    with app.state.pool.connection() as conn:
        rows = conn.execute("SELECT status, count(*) AS n FROM gateway.inbox_event GROUP BY status").fetchall()
    return {"ok": True, "inbox": {r["status"]: r["n"] for r in rows}}
