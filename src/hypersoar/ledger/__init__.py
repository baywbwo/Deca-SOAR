"""Append-only audit ledger with a SHA-256 hash chain (design 6.5).

Each entry stores the exact canonical JSON it was hashed over, and
hash = SHA-256(prev_hash_bytes || canonical_utf8). The first entry links to GENESIS.
Appends are serialised with a transaction-scoped advisory lock so the chain never forks.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

GENESIS = "0" * 64
_LOCK_KEY = 0x0DECA5_0A_1ED  # constant advisory lock id for the ledger


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def chain_hash(prev_hash: str, canonical: str) -> str:
    return hashlib.sha256(bytes.fromhex(prev_hash) + canonical.encode("utf-8")).hexdigest()


def envelope(event_type: str, actor: str, payload: dict, recorded_at: datetime) -> dict:
    return {
        "v": 1,
        "event_type": event_type,
        "actor": actor,
        "recorded_at": recorded_at.astimezone(UTC).isoformat(),
        "payload": payload,
    }


@dataclass(frozen=True)
class Appended:
    seq: int
    hash: str


def append(conn: psycopg.Connection, event_type: str, actor: str, payload: dict) -> Appended:
    """Append one entry inside the caller's transaction."""
    conn.execute("SELECT pg_advisory_xact_lock(%s)", (_LOCK_KEY,))
    row = conn.execute("SELECT hash FROM ledger.entry ORDER BY seq DESC LIMIT 1").fetchone()
    prev = _col(row, "hash", 0) if row else GENESIS
    recorded_at = datetime.now(UTC)
    canonical = canonical_json(envelope(event_type, actor, payload, recorded_at))
    digest = chain_hash(prev, canonical)
    out = conn.execute(
        "INSERT INTO ledger.entry (recorded_at, event_type, actor, payload, canonical, prev_hash, hash)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING seq",
        (recorded_at, event_type, actor, Jsonb(payload), canonical, prev, digest),
    ).fetchone()
    return Appended(seq=_col(out, "seq", 0), hash=digest)


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    head_seq: int | None
    head_hash: str
    errors: list[str] = field(default_factory=list)


def verify(conn: psycopg.Connection, *, max_errors: int = 20) -> VerifyResult:
    """Walk the whole chain and recompute every link."""
    prev = GENESIS
    count = 0
    head_seq: int | None = None
    errors: list[str] = []
    with conn.transaction(), conn.cursor(name="ledger_verify") as cur:
        cur.execute(
            "SELECT seq, recorded_at, event_type, actor, payload, canonical, prev_hash, hash"
            " FROM ledger.entry ORDER BY seq"
        )
        for r in cur:
            seq, recorded_at, event_type, actor, payload, canonical, prev_hash, digest = (
                r[k] for k in ("seq", "recorded_at", "event_type", "actor", "payload", "canonical", "prev_hash", "hash")
            ) if isinstance(r, dict) else r
            count += 1
            head_seq = seq
            if prev_hash != prev:
                errors.append(f"seq {seq}: prev_hash does not link to previous entry")
            if chain_hash(prev_hash, canonical) != digest:
                errors.append(f"seq {seq}: hash mismatch")
            try:
                env = json.loads(canonical)
                if (
                    env.get("event_type") != event_type
                    or env.get("actor") != actor
                    or env.get("payload") != payload
                    or datetime.fromisoformat(env.get("recorded_at")) != recorded_at
                ):
                    errors.append(f"seq {seq}: stored columns differ from hashed canonical")
            except (ValueError, TypeError):
                errors.append(f"seq {seq}: canonical is not valid JSON")
            prev = digest
            if len(errors) >= max_errors:
                break
    return VerifyResult(ok=not errors, entries=count, head_seq=head_seq, head_hash=prev, errors=errors)


def _col(row: Any, name: str, idx: int) -> Any:
    return row[name] if isinstance(row, dict) else row[idx]


def anchor_record(conn: psycopg.Connection) -> tuple[VerifyResult, dict]:
    """Verify the chain and describe its head for an external anchor (design 6.5, review F3).

    An anchor kept outside the database the apps write to is what makes an owner-level rewrite
    detectable: recomputing the chain after an edit changes every later hash, including the head.
    """
    r = verify(conn)
    rec = {
        "v": 1,
        "head_seq": r.head_seq,
        "head_hash": r.head_hash,
        "entries": r.entries,
        "anchored_at": datetime.now(UTC).isoformat(),
    }
    return r, rec


def check_anchors(conn: psycopg.Connection, anchors: list[dict]) -> list[str]:
    """Every anchored head must still be in the ledger with the same hash."""
    errors: list[str] = []
    for a in anchors:
        seq = a.get("head_seq")
        if seq is None:
            continue
        row = conn.execute("SELECT hash FROM ledger.entry WHERE seq = %s", (seq,)).fetchone()
        if row is None:
            errors.append(f"anchor seq {seq}: entry missing (ledger truncated?)")
        elif _col(row, "hash", 0) != a.get("head_hash"):
            errors.append(f"anchor seq {seq}: hash differs from anchored head (ledger rewritten?)")
    return errors
