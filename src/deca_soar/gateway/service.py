"""Ingest gateway: pull -> normalise/tokenise -> dedup into a durable inbox -> start the alert workflow."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from deca_soar import ledger
from deca_soar.common.config import Settings
from deca_soar.common.pii import Tokenizer, VaultWriter
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
    vault = VaultWriter(settings.vault_public_key, settings.vault_key_id)
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


class DeliveryError(Exception):
    """A failed hand-off. The message is stored in the inbox, so it must not carry secrets."""


Deliver = Callable[[dict], "str | None"]


def forward_once(pool: ConnectionPool, deliver: Deliver, *, batch: int = 50) -> ForwardResult:
    """Hand pending alerts to the workflow engine. At-least-once; the workflow id derives from alert_id,
    so a redelivery after a crash attaches to the same workflow instead of starting a second one."""
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
                    ref = deliver(body)
                except Exception as e:  # noqa: BLE001 - any failure means "retry later"
                    attempts = r["attempts"] + 1
                    err = str(e)[:200] if isinstance(e, DeliveryError) else type(e).__name__
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
                    continue
                ref = str(ref)[:200] if ref else None
                conn.execute(
                    "UPDATE gateway.inbox_event SET status = 'forwarded', forwarded_at = now(),"
                    " attempts = attempts + 1, downstream_ref = %s, last_error = NULL WHERE alert_id = %s",
                    (ref, r["alert_id"]),
                )
                ledger.append(conn, "alert.forwarded", ACTOR, {"alert_id": str(r["alert_id"]), "downstream_ref": ref})
                res.sent += 1
    return res
