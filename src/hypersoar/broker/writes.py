"""Human writes from the SOC console: case triage, approvals, the kill switch and early revokes.

Every write here is made by a human principal who typed their password again (re-authentication,
checked against broker.principal.reauth_hash), carries an Idempotency-Key, and leaves a ledger entry.
A retried write with the same key and body returns the first answer; the same key with another body
is a conflict. Only successful writes are remembered, so a typo in the password can be retried.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime

from psycopg.types.json import Jsonb

from hypersoar import ledger
from hypersoar.broker.roles import Principal

CASE_STATUSES = ("open", "waiting", "closed")
COMMENT_MAX = 2000
REASON_MAX = 500


class ReauthFailed(PermissionError):
    pass


class WriteConflict(RuntimeError):
    pass


def set_reauth_hash(conn, name: str, hash_text: str, actor: str) -> None:
    from hypersoar.console.auth import PasswordHash
    PasswordHash.parse(hash_text)
    r = conn.execute("UPDATE broker.principal SET reauth_hash = %s WHERE name = %s AND kind = 'human'"
                     " RETURNING principal_id", (hash_text, name)).fetchone()
    if r is None:
        raise LookupError("no human principal with that name")
    ledger.append(conn, "principal.reauth_set", actor, {"principal_id": str(r["principal_id"]), "name": name})


def check_reauth(conn, who: Principal, password: str | None) -> None:
    """A human write needs that person's password again. Service principals never pass."""
    from hypersoar.console.auth import PasswordHash
    if who.kind != "human":
        raise ReauthFailed("only a person can make this change")
    if not password:
        raise ReauthFailed("re-authentication required")
    r = conn.execute("SELECT reauth_hash FROM broker.principal WHERE principal_id = %s AND active",
                     (who.principal_id,)).fetchone()
    if r is None or not r["reauth_hash"] or not PasswordHash.parse(r["reauth_hash"]).verify(password):
        raise ReauthFailed("re-authentication failed")


def body_sha(operation: str, body: dict) -> str:
    """Hash of what the write asks for. The password is never part of it."""
    clean = {k: v for k, v in body.items() if k != "password"}
    return hashlib.sha256(f"{operation}|{ledger.canonical_json(clean)}".encode()).hexdigest()


def replay(conn, who: Principal, key: str, operation: str, sha: str) -> dict | None:
    """The stored answer for this key, or None. Serialises writes with the same key."""
    conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"{who.principal_id}|{key}",))
    r = conn.execute("SELECT operation, request_sha256, response FROM broker.write_op"
                     " WHERE principal_id = %s AND idempotency_key = %s", (who.principal_id, key)).fetchone()
    if r is None:
        return None
    if r["operation"] != operation or r["request_sha256"] != sha:
        raise WriteConflict("idempotency key reused for a different change")
    return {**r["response"], "idempotent_replay": True}


def remember(conn, who: Principal, key: str, operation: str, sha: str, response: dict) -> dict:
    conn.execute("INSERT INTO broker.write_op (principal_id, idempotency_key, operation, request_sha256,"
                 " status_code, response) VALUES (%s, %s, %s, %s, 200, %s)",
                 (who.principal_id, key, operation, sha, Jsonb(response)))
    return {**response, "idempotent_replay": False}


# -- cases ----------------------------------------------------------------------------------
def _case(conn, entity_id: str, case_id: str) -> dict:
    r = conn.execute("SELECT case_id, status, assignee FROM gateway.alert_case WHERE entity_id = %s AND case_id = %s"
                     " FOR UPDATE", (entity_id, case_id)).fetchone()
    if r is None:
        raise LookupError("case")
    return r


def assign_case(conn, entity_id: str, who: Principal, case_id: str, assignee: str | None) -> dict:
    c = _case(conn, entity_id, case_id)
    if assignee is not None:
        ok = conn.execute("SELECT 1 FROM broker.principal WHERE name = %s AND kind = 'human' AND active"
                          " AND entity_id = %s", (assignee, entity_id)).fetchone()
        if ok is None:
            raise ValueError("assignee is not an active person on this install")
    conn.execute("UPDATE gateway.alert_case SET assignee = %s, updated_at = now() WHERE entity_id = %s"
                 " AND case_id = %s", (assignee, entity_id, case_id))
    ledger.append(conn, "case.assigned", f"principal:{who.name}",
                  {"case_id": case_id, "from": c["assignee"], "to": assignee}, entity_id)
    return {"case_id": case_id, "assignee": assignee}


def set_case_status(conn, entity_id: str, who: Principal, case_id: str, status: str, reason: str | None) -> dict:
    if status not in CASE_STATUSES:
        raise ValueError("status must be open, waiting or closed")
    c = _case(conn, entity_id, case_id)
    if c["status"] == status:
        return {"case_id": case_id, "status": status, "changed": False}
    if status == "closed":
        conn.execute("UPDATE gateway.alert_case SET status = 'closed', closed_at = now(), close_reason = %s,"
                     " status_by = %s, updated_at = now() WHERE entity_id = %s AND case_id = %s",
                     ((reason or "closed by analyst")[:REASON_MAX], f"principal:{who.name}", entity_id, case_id))
    else:
        conn.execute("UPDATE gateway.alert_case SET status = %s, closed_at = NULL, close_reason = NULL,"
                     " status_by = %s, updated_at = now() WHERE entity_id = %s AND case_id = %s",
                     (status, f"principal:{who.name}", entity_id, case_id))
    ledger.append(conn, "case.status_changed", f"principal:{who.name}",
                  {"case_id": case_id, "from": c["status"], "to": status, "reason": (reason or "")[:REASON_MAX]},
                  entity_id)
    return {"case_id": case_id, "status": status, "changed": True}


def comment_case(conn, entity_id: str, who: Principal, case_id: str, body: str) -> dict:
    body = body.strip()
    if not body or len(body) > COMMENT_MAX:
        raise ValueError(f"comment must be 1 to {COMMENT_MAX} characters")
    _case(conn, entity_id, case_id)
    cid = str(uuid.uuid4())
    row = conn.execute("INSERT INTO broker.case_comment (comment_id, entity_id, case_id, author, body)"
                       " VALUES (%s, %s, %s, %s, %s) RETURNING created_at",
                       (cid, entity_id, case_id, who.name, body)).fetchone()
    # The ledger keeps who and when; the text stays in the case (it may name people).
    ledger.append(conn, "case.commented", f"principal:{who.name}",
                  {"case_id": case_id, "comment_id": cid, "chars": len(body)}, entity_id)
    return {"case_id": case_id, "comment_id": cid, "created_at": row["created_at"].isoformat()}


# -- early revoke of a time-boxed action ------------------------------------------------------
def revoke(conn, entity_id: str, who: Principal, request_id: str, reason: str) -> dict:
    r = conn.execute("SELECT request_id, status, rollback_at, case_id, action FROM broker.action_request"
                     " WHERE request_id = %s AND entity_id = %s FOR UPDATE", (request_id, entity_id)).fetchone()
    if r is None:
        raise LookupError("request")
    if r["status"] not in ("validated", "executed") or r["rollback_at"] is None:
        raise WriteConflict(f"request is {r['status']} and has no expiry to revoke")
    if r["rollback_at"] <= datetime.now(UTC):
        raise WriteConflict("already expired")
    conn.execute("UPDATE broker.action_request SET status = 'rolled_back', revoked_at = now(), revoked_by = %s,"
                 " rollback_at = now() WHERE request_id = %s", (f"principal:{who.name}", request_id))
    ledger.append(conn, "action.revoked", f"principal:{who.name}",
                  {"request_id": request_id, "case_id": r["case_id"], "action": r["action"],
                   "reason": reason[:REASON_MAX]}, entity_id)
    return {"request_id": request_id, "status": "rolled_back"}
