"""Worker process: runs AlertShadowWorkflow and its activities.

  HYPERSOAR_BROKER_URL             broker base URL (https required with HYPERSOAR_ENV=production)
  HYPERSOAR_BROKER_TOKEN(_FILE)    service principal token, role analyst
  HYPERSOAR_BROKER_CA_FILE         CA bundle for the broker's TLS cert (optional)
  plus the HYPERSOAR_TEMPORAL_* settings in hypersoar.workflows.config.

The worker holds no database URL and no vault or tokenisation key: it only ever sees tokens.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal

from temporalio.worker import Worker

from hypersoar.common import entity as entity_mod
from hypersoar.common.config import ConfigError, assert_no_write_credentials, read_secret
from hypersoar.workflows.activities import BrokerSubmitter
from hypersoar.workflows.config import TemporalSettings
from hypersoar.workflows.shadow import AlertShadowWorkflow

log = logging.getLogger("hypersoar.worker")
logging.getLogger("httpx").setLevel(logging.WARNING)
WORKER_FORBIDDEN_ENV = ("HYPERSOAR_DB_URL", "HYPERSOAR_VAULT_PRIVATE_KEY", "HYPERSOAR_VAULT_KEY", "HYPERSOAR_TOKENIZATION_KEY")


def broker_from_env() -> BrokerSubmitter:
    url = os.environ.get("HYPERSOAR_BROKER_URL", "").strip()
    if not url:
        raise ConfigError("HYPERSOAR_BROKER_URL is required")
    if os.environ.get("HYPERSOAR_ENV") == "production" and not url.startswith("https://"):
        raise ConfigError("production requires an https:// HYPERSOAR_BROKER_URL")
    token = read_secret("HYPERSOAR_BROKER_TOKEN")
    assert token is not None
    return BrokerSubmitter(url, token, verify=os.environ.get("HYPERSOAR_BROKER_CA_FILE") or True)


def check_env() -> None:
    assert_no_write_credentials()
    bad = [n for n in WORKER_FORBIDDEN_ENV if os.environ.get(n) or os.environ.get(f"{n}_FILE")]
    if bad:
        raise ConfigError("worker must not hold database or vault credentials (found: " + ", ".join(bad) + ")")


async def check_install(broker: BrokerSubmitter, mode: str, entity_id: str) -> None:
    """The worker has no database, so it checks the install through the broker it will post to."""
    inst = await broker.install()
    if inst.get("mode") != mode:
        raise ConfigError(f"the broker serves a {inst.get('mode')} install; this worker runs in {mode} mode")
    if inst.get("entity_id") != entity_id:
        raise ConfigError("the broker serves another entity")


async def run() -> None:
    check_env()
    mode = entity_mod.current_mode()
    ts = TemporalSettings.from_env()
    broker = broker_from_env()
    await check_install(broker, mode, entity_mod.load(mode=mode).id)
    client = await ts.connect(identity=f"deca-worker@{os.uname().nodename}")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    worker = Worker(
        client,
        task_queue=ts.task_queue,
        workflows=[AlertShadowWorkflow],
        activities=[broker.triage, broker.submit],
        max_concurrent_activities=int(os.environ.get("HYPERSOAR_WORKER_MAX_ACTIVITIES", "20")),
    )
    log.info("worker ready: namespace=%s task_queue=%s tls=%s", ts.namespace, ts.task_queue, ts.tls is not None)
    async with worker:
        await stop.wait()
    await broker.aclose()
    log.info("worker stopped")


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
