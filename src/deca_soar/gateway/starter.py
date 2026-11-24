"""Starts one AlertShadowWorkflow per alert. Used from the gateway's (synchronous) loop thread."""

from __future__ import annotations

import asyncio
from datetime import timedelta

from temporalio.client import Client
from temporalio.common import WorkflowIDConflictPolicy, WorkflowIDReusePolicy
from temporalio.exceptions import WorkflowAlreadyStartedError
from temporalio.service import RPCError

from deca_soar.gateway.service import DeliveryError
from deca_soar.workflows import WORKFLOW_NAME, workflow_id
from deca_soar.workflows.config import TemporalSettings

RPC_TIMEOUT = timedelta(seconds=10)


class TemporalStarter:
    """Owns a private event loop so the blocking gateway loop can call it like a function."""

    def __init__(self, settings: TemporalSettings, *, identity: str = "deca-gateway") -> None:
        self._settings = settings
        self._identity = identity
        self._loop = asyncio.new_event_loop()
        self._client: Client | None = None

    def __call__(self, alert: dict) -> str | None:
        return self._loop.run_until_complete(self._start(alert))

    async def _start(self, alert: dict) -> str | None:
        try:
            if self._client is None:
                self._client = await self._settings.connect(identity=self._identity)
            handle = await self._client.start_workflow(
                WORKFLOW_NAME,
                alert,
                id=workflow_id(alert["alert_id"]),
                task_queue=self._settings.task_queue,
                # Running: attach to it. Closed: refuse a second run for the same alert.
                id_conflict_policy=WorkflowIDConflictPolicy.USE_EXISTING,
                id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
                rpc_timeout=RPC_TIMEOUT,
            )
            return f"{handle.id}/{handle.result_run_id or handle.run_id}"
        except WorkflowAlreadyStartedError:
            # Started before a crash lost our commit, and already finished: delivered.
            return f"{workflow_id(alert['alert_id'])}/existing"
        except RPCError as e:
            self._client = None if e.status.name in ("UNAVAILABLE", "UNAUTHENTICATED") else self._client
            raise DeliveryError(f"temporal {e.status.name}") from None
        except RuntimeError as e:
            # Client.connect reports connection failures as RuntimeError; its text can include the address only.
            self._client = None
            raise DeliveryError("temporal connect failed") from e

    def close(self) -> None:
        self._loop.close()
