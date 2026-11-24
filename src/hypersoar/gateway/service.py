"""Ingest gateway: pull -> normalise/tokenise -> dedup into a durable inbox -> start the alert workflow."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from hypersoar import ledger
from hypersoar.common import entity as entity_mod
from hypersoar.common.config import Settings
from hypersoar.common.entity import Entity
from hypersoar.common.pii import Tokenizer, VaultWriter
from hypersoar.gateway import cases
from hypersoar.gateway.normalize import NormalizeError, normalize
from hypersoar.gateway.sources import AlertSource

ACTOR = "service:gateway"
MAX_ATTEMPTS = 12


@dataclass
class PullResult:
    pulled: int = 0
    new: int = 0
    merged: int = 0
    rejected: int = 0
    closed: int = 0
    cursor: str = ""


def pull_once(pool: ConnectionPool, source: AlertSource, settings: Settings, *, limit: int = 500,
              entity: Entity | None = None) -> PullResult:
    """One pull cycle. Inbox rows, cases, vault entries, ledger entries and the cursor commit together,
    so a crash either keeps the whole batch or none of it (no event lost, none double-counted)."""
    entity = entity or entity_mod.load()
    eid = entity.id
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
                na = normalize(raw, tok, source_name=source.name, keep_truth=entity.mode == "sandbox")
            except (NormalizeError, KeyError, TypeError, ValueError) as e:
                res.rejected += 1
                ledger.append(conn, "ingest.rejected", ACTOR, {"source": source.name, "reason": str(e)[:200]}, eid)
                continue
            vault.store(conn, na.found)
            ins = conn.execute(
                "INSERT INTO gateway.inbox_event (entity_id, alert_id, fingerprint, source, rule_id, severity_hint,"
                " detected_at, event_count, alert, evidence_tokens)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (entity_id, fingerprint) DO UPDATE SET event_count = gateway.inbox_event.event_count"
                "   + EXCLUDED.event_count, last_seen_at = now()"
                " RETURNING alert_id, (xmax = 0) AS inserted",
                (
                    eid, na.alert_id, na.fingerprint, na.source, na.rule_id, na.severity_hint, na.detected_at,
                    na.event_count, Jsonb(na.alert), na.evidence_tokens,
                ),
            ).fetchone()
            if ins["inserted"]:
                res.new += 1
                case_id = cases.attach(conn, entity, na.alert, na.detected_at, na.event_count)
                conn.execute(
                    "UPDATE gateway.inbox_event SET alert = alert || jsonb_build_object('case_id', %s::text)"
                    " WHERE alert_id = %s",
                    (case_id, ins["alert_id"]),
                )
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
                        "case_id": case_id,
                    },
                    eid,
                )
            else:
                res.merged += 1
                cases.add_events(conn, eid, ins["alert_id"], na.event_count)
        conn.execute(
            "INSERT INTO gateway.ingest_cursor (source_name, cursor) VALUES (%s, %s)"
            " ON CONFLICT (source_name) DO UPDATE SET cursor = EXCLUDED.cursor, updated_at = now()",
            (source.name, new_cursor),
        )
        res.closed = len(cases.close_idle(conn, entity))
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
                "SELECT entity_id, alert_id, alert, event_count, attempts FROM gateway.inbox_event"
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
                        ledger.append(conn, "alert.dead_letter", ACTOR, {"alert_id": str(r["alert_id"]), "error": err},
                                      r["entity_id"])
                    else:
                        res.failed += 1
                    continue
                ref = str(ref)[:200] if ref else None
                conn.execute(
                    "UPDATE gateway.inbox_event SET status = 'forwarded', forwarded_at = now(),"
                    " attempts = attempts + 1, downstream_ref = %s, last_error = NULL WHERE alert_id = %s",
                    (ref, r["alert_id"]),
                )
                ledger.append(conn, "alert.forwarded", ACTOR, {"alert_id": str(r["alert_id"]), "downstream_ref": ref},
                              r["entity_id"])
                res.sent += 1
    return res
