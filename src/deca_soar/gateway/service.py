"""Ingest gateway: pull -> normalise/tokenise -> dedup into a durable inbox -> forward to Tracecat."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from deca_soar import ledger
from deca_soar.common.config import Settings
from deca_soar.common.pii import Tokenizer, Vault
from deca_soar.gateway.normalize import NormalizeError, normalize
from deca_soar.gateway.sources import AlertSource

ACTOR = "service:gateway"
MAX_ATTEMPTS = 12


@dataclass
class PullResult:
    pulled: int = 0
    new: int = 0
    merged: int = 0
    rejected: int = 0
    cursor: str = ""


def pull_once(pool: ConnectionPool, source: AlertSource, settings: Settings, *, limit: int = 500) -> PullResult:
    """One pull cycle. Inbox rows, vault entries, ledger entries and the cursor commit together,
    so a crash either keeps the whole batch or none of it (no event lost, none double-counted)."""
    vault = Vault(settings.vault_key, settings.vault_key_id)
    res = PullResult()
    with pool.connection() as conn, conn.transaction():
        row = conn.execute(
            "SELECT cursor FROM gateway.ingest_cursor WHERE source_name = %s FOR UPDATE", (source.name,)
        ).fetchone()
        cursor = row["cursor"] if row else None
        raws, new_cursor = source.pull(cursor, limit)
        res.pulled = len(raws)
        for raw in raws:
            try:
                if raw.get("_invalid"):
                    raise NormalizeError("invalid JSON line")
                tok = Tokenizer(settings.tokenization_key, settings.internal_cidrs)
                na = normalize(raw, tok, source_name=source.name)
            except (NormalizeError, KeyError, TypeError, ValueError) as e:
                res.rejected += 1
                ledger.append(conn, "ingest.rejected", ACTOR, {"source": source.name, "reason": str(e)[:200]})
                continue
            vault.store(conn, na.found)
            ins = conn.execute(
                "INSERT INTO gateway.inbox_event (alert_id, fingerprint, source, rule_id, severity_hint,"
                " detected_at, event_count, alert, evidence_tokens)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (fingerprint) DO UPDATE SET event_count = gateway.inbox_event.event_count"
                "   + EXCLUDED.event_count, last_seen_at = now()"
                " RETURNING alert_id, (xmax = 0) AS inserted",
                (
                    na.alert_id, na.fingerprint, na.source, na.rule_id, na.severity_hint, na.detected_at,
                    na.event_count, Jsonb(na.alert), na.evidence_tokens,
                ),
            ).fetchone()
            if ins["inserted"]:
                res.new += 1
                ledger.append(
                    conn,
                    "alert.ingested",
                    ACTOR,
                    {
                        "alert_id": str(ins["alert_id"]),
                        "fingerprint": na.fingerprint,
                        "rule_id": na.rule_id,
                        "source": na.source,
                        "severity_hint": na.severity_hint,
                    },
                )
            else:
                res.merged += 1
        conn.execute(
            "INSERT INTO gateway.ingest_cursor (source_name, cursor) VALUES (%s, %s)"
            " ON CONFLICT (source_name) DO UPDATE SET cursor = EXCLUDED.cursor, updated_at = now()",
            (source.name, new_cursor),
        )
        res.cursor = new_cursor
    return res


@dataclass
class ForwardResult:
    sent: int = 0
    failed: int = 0
    dead: int = 0


def _backoff(attempts: int) -> timedelta:
    return timedelta(seconds=min(300, 2 ** min(attempts, 8)))


def forward_once(
    pool: ConnectionPool, client: httpx.Client, webhook_url: str, *, batch: int = 50, api_key: str | None = None
) -> ForwardResult:
    """Deliver pending alerts to the Tracecat webhook. At-least-once; Tracecat sees alert_id for dedup."""
    res = ForwardResult()
    with pool.connection() as conn:
        with conn.transaction():
            rows = conn.execute(
                "SELECT alert_id, alert, event_count, attempts FROM gateway.inbox_event"
                " WHERE status = 'pending' AND next_attempt_at <= now()"
                " ORDER BY next_attempt_at LIMIT %s FOR UPDATE SKIP LOCKED",
                (batch,),
            ).fetchall()
            for r in rows:
                body = dict(r["alert"])
                body["counts"] = {**body.get("counts", {}), "events": r["event_count"]}
                try:
                    headers = {"x-tracecat-api-key": api_key} if api_key else None
                    resp = client.post(webhook_url, json=body, headers=headers)
                    resp.raise_for_status()
                    ref = _downstream_ref(resp)
                    conn.execute(
                        "UPDATE gateway.inbox_event SET status = 'forwarded', forwarded_at = now(),"
                        " attempts = attempts + 1, downstream_ref = %s, last_error = NULL WHERE alert_id = %s",
                        (ref, r["alert_id"]),
                    )
                    ledger.append(
                        conn, "alert.forwarded", ACTOR, {"alert_id": str(r["alert_id"]), "downstream_ref": ref}
                    )
                    res.sent += 1
                except httpx.HTTPError as e:
                    attempts = r["attempts"] + 1
                    # Status code or exception class only: the URL carries the webhook secret.
                    err = (
                        f"http {e.response.status_code}"
                        if isinstance(e, httpx.HTTPStatusError)
                        else type(e).__name__
                    )
                    dead = attempts >= MAX_ATTEMPTS
                    conn.execute(
                        "UPDATE gateway.inbox_event SET attempts = %s, last_error = %s,"
                        " next_attempt_at = %s, status = %s WHERE alert_id = %s",
                        (attempts, err, datetime.now(UTC) + _backoff(attempts),
                         "dead" if dead else "pending", r["alert_id"]),
                    )
                    if dead:
                        res.dead += 1
                        ledger.append(conn, "alert.dead_letter", ACTOR, {"alert_id": str(r["alert_id"]), "error": err})
                    else:
                        res.failed += 1
    return res


def _downstream_ref(resp: httpx.Response) -> str | None:
    try:
        data = resp.json()
    except ValueError:
        return None
    if isinstance(data, dict):
        for k in ("wf_exec_id", "workflow_execution_id", "id"):
            if data.get(k):
                return str(data[k])[:200]
    return None
