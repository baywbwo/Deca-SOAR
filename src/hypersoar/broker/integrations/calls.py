"""integration_call rows: every outbound call the broker makes (or the mock stands in for). The
detail holds operation facts only (ids, status codes, step names), never a secret or a raw value."""

from __future__ import annotations

import time
import uuid

from psycopg.types.json import Jsonb

DETAIL_MAX = 2000


class IntegrationError(RuntimeError):
    """A failed call. The message is safe to store and show: no URL query, body or secret."""


def record(conn, entity_id: str, integration: str, operation: str, target: str, status: str, *,
           case_id=None, alert_id=None, request_id=None, external_ref=None, detail=None,
           duration_ms: int | None = None) -> str:
    call_id = str(uuid.uuid4())
    d = dict(detail or {})
    if len(str(d)) > DETAIL_MAX:
        d = {"truncated": True}
    conn.execute(
        "INSERT INTO broker.integration_call (call_id, entity_id, integration, operation, target, status, case_id,"
        " alert_id, request_id, external_ref, detail, duration_ms) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,"
        " %s, %s)",
        (call_id, entity_id, integration, operation[:40], target, status, case_id, alert_id, request_id,
         (external_ref or None) and str(external_ref)[:120], Jsonb(d), duration_ms),
    )
    return call_id


class Timer:
    def __enter__(self):
        self.t0 = time.monotonic()
        return self

    def __exit__(self, *exc):
        self.ms = int((time.monotonic() - self.t0) * 1000)
        return False
