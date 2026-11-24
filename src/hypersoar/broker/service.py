"""Broker DB layer: action requests, approvals, kill switch. Shadow-only: nothing is ever executed."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import psycopg
from psycopg.types.json import Jsonb

from hypersoar import ledger
from hypersoar.broker import policy
from hypersoar.broker.catalog import ActionSpec, Protected
from hypersoar.broker.roles import Principal
from hypersoar.common.pii import Vault

APPROVAL_TTL = timedelta(minutes=30)
RATIONALE_MAX = 500


class NotFound(LookupError):
    pass


class Conflict(RuntimeError):
    pass


@dataclass
class Broker:
    catalog: dict[str, ActionSpec]
    protected: Protected
    vault: Vault
    internal_cidrs: list = field(default_factory=list)
    allow_test_nets: bool = False


def principal_by_token(conn: psycopg.Connection, token: str) -> Principal | None:
    digest = hashlib.sha256(token.encode()).hexdigest()
    r = conn.execute(
        "SELECT principal_id, name, kind, role FROM broker.principal WHERE token_sha256 = %s AND active",
        (digest,),
    ).fetchone()
    return Principal(str(r["principal_id"]), r["name"], r["kind"], r["role"]) if r else None


def create_principal(conn: psycopg.Connection, name: str, kind: str, role: str, token: str, actor: str) -> str:
    pid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO broker.principal (principal_id, name, kind, role, token_sha256) VALUES (%s, %s, %s, %s, %s)",
        (pid, name, kind, role, hashlib.sha256(token.encode()).hexdigest()),
    )
    ledger.append(conn, "principal.created", actor, {"principal_id": pid, "name": name, "kind": kind, "role": role})
    return pid


def default_idempotency_key(alert_id: str, action: str, params: dict) -> str:
    return hashlib.sha256(f"{alert_id}|{action}|{ledger.canonical_json(params)}".encode()).hexdigest()


def kill_switch_state(conn: psycopg.Connection, action: str) -> bool:
    r = conn.execute(
        "SELECT bool_or(engaged) AS on FROM broker.kill_switch WHERE scope IN ('global', %s)", (action,)
    ).fetchone()
    return bool(r and r["on"])


def _request_view(r: dict) -> dict:
    return {
        "request_id": str(r["request_id"]),
        "idempotency_key": r["idempotency_key"],
        "decision_id": str(r["decision_id"]),
        "alert_id": str(r["alert_id"]),
        "action": r["action"],
        "params": r["params"],
        "level": r["level"],
        "mode": r["mode"],
        "status": r["status"],
        "reasons": r["reasons"],
        "would_execute": r["would_execute"],
        "approver": str(r["approver"]) if r["approver"] else None,
        "rollback_at": r["rollback_at"].isoformat() if r["rollback_at"] else None,
        "executed_at": None,
        "created_at": r["created_at"].isoformat(),
    }


def get_request(conn: psycopg.Connection, request_id: str) -> dict:
    r = conn.execute("SELECT * FROM broker.action_request WHERE request_id = %s", (request_id,)).fetchone()
    if r is None:
        raise NotFound("request")
    return _request_view(r)


def submit(conn: psycopg.Connection, b: Broker, who: Principal, body: dict) -> tuple[dict, bool]:
    """Validate and record one action request. Returns (view, replayed). Runs in the caller's transaction."""
    action = body["action"]
    alert_id = body["alert_id"]
    raw_params = body.get("params") or {}
    d = body["decision"]
    idem = body.get("idempotency_key") or default_idempotency_key(alert_id, action, raw_params)
    req_hash = hashlib.sha256(
        ledger.canonical_json({"alert_id": alert_id, "action": action, "params": raw_params}).encode()
    ).hexdigest()

    # Scoped per principal (review F6): another caller's key never replays someone else's request.
    existing = conn.execute(
        "SELECT * FROM broker.action_request WHERE requested_by = %s AND idempotency_key = %s",
        (who.principal_id, idem),
    ).fetchone()
    if existing is not None:
        if existing["request_sha256"] != req_hash:
            raise Conflict("idempotency key reused for a different request")
        return _request_view(existing), True

    alert = conn.execute(
        "SELECT alert_id, source, severity_hint, evidence_tokens FROM gateway.inbox_event WHERE alert_id = %s",
        (alert_id,),
    ).fetchone()
    if alert is None:
        raise NotFound("alert")

    spec = b.catalog.get(action)
    decision = policy.Decision(verdict=d["verdict"], confidence=float(d["confidence"]), source=d["source"])
    if spec is None:
        reasons, params, level, scope, intent = ["action not in catalog"], {}, "L3", None, None
        target_mode = None
    else:
        view = policy.AlertView(
            alert_id=alert_id,
            source=alert["source"],
            severity_hint=alert["severity_hint"],
            evidence_tokens=frozenset(alert["evidence_tokens"]),
        )
        st = policy.check_static(spec, view, decision, raw_params)
        reasons, params, level, target_mode = list(st.reasons), st.params, spec.level, spec.mode
        if st.ok and st.target_token:
            value = b.vault.reveal(conn, st.target_token)
            reasons += policy.check_target(
                spec.target_kind, value, b.protected, b.internal_cidrs, allow_test_nets=b.allow_test_nets
            )
        scope = policy.rate_scope(spec, params)
        if not reasons and spec.rate_per_hour:
            # Serialise per scope so two concurrent requests cannot both squeeze under the limit.
            conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (scope,))
            n = conn.execute(
                "SELECT count(*) AS n FROM broker.action_request WHERE action = %s AND rate_scope = %s"
                " AND status IN ('validated', 'pending_approval') AND created_at > now() - interval '1 hour'",
                (action, scope),
            ).fetchone()["n"]
            if n >= spec.rate_per_hour:
                reasons.append(f"rate limit {spec.rate_per_hour}/hour reached")
        intent = policy.would_execute(spec, params) if not reasons else None

    killed = kill_switch_state(conn, action)
    if killed:
        # An engaged kill switch blocks the request outright, shadow or not (review F6).
        reasons.append("kill switch engaged")
        intent = None
    if reasons:
        status = "rejected"
    elif target_mode == "approval":
        status = "pending_approval"
    else:
        status = "validated"

    decision_id = str(uuid.uuid4())
    record = {
        "decision_id": decision_id,
        "alert_id": alert_id,
        "case_id": body.get("case_id"),
        "deterministic_signals": d.get("deterministic_signals") or {},
        "ai": {
            "model": d.get("model"),
            "prompt_version": d.get("prompt_version"),
            "verdict": decision.verdict,
            "confidence": decision.confidence,
            "rationale_summary": (d.get("rationale_summary") or "")[:RATIONALE_MAX],
            "evidence_refs": [str(x)[:80] for x in (d.get("evidence_refs") or [])][:20],
            "source": decision.source,
        },
        "policy": {
            "result": "request_action",
            "rule_matched": action,
            "reasons": reasons,
            "effective_mode": "shadow",
            "target_mode": target_mode,
            "kill_switch": killed,
        },
    }
    conn.execute(
        "INSERT INTO broker.decision_record (decision_id, alert_id, case_id, record) VALUES (%s, %s, %s, %s)",
        (decision_id, alert_id, body.get("case_id"), Jsonb(record)),
    )
    request_id = str(uuid.uuid4())
    rollback_at = None
    if status != "rejected" and "ttl_s" in params:
        rollback_at = datetime.now(UTC) + timedelta(seconds=params["ttl_s"])
    row = conn.execute(
        "INSERT INTO broker.action_request (request_id, idempotency_key, request_sha256, decision_id, alert_id,"
        " action, params, level, mode, status, reasons, would_execute, rate_scope, requested_by, rollback_at)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'shadow', %s, %s, %s, %s, %s, %s) RETURNING *",
        (request_id, idem, req_hash, decision_id, alert_id, action[:128], Jsonb(params), level, status, Jsonb(reasons),
         intent, scope, who.principal_id, rollback_at),
    ).fetchone()
    ledger.append(conn, "policy.decision", f"principal:{who.name}", {
        "decision_id": decision_id, "alert_id": alert_id, "verdict": decision.verdict,
        "confidence": decision.confidence, "decision_source": decision.source,
    })
    ledger.append(conn, "action.requested", f"principal:{who.name}", {
        "request_id": request_id, "decision_id": decision_id, "alert_id": alert_id, "action": action[:128],
        "params": params, "status": status, "mode": "shadow", "target_mode": target_mode,
        "reasons": reasons, "would_execute": intent, "kill_switch": killed,
    })
    return _request_view(row), False


def decide_approval(conn: psycopg.Connection, who: Principal, request_id: str, approve: bool) -> dict:
    """Record an approver decision. In shadow mode an approval still executes nothing."""
    r = conn.execute(
        "SELECT * FROM broker.action_request WHERE request_id = %s FOR UPDATE", (request_id,)
    ).fetchone()
    if r is None:
        raise NotFound("request")
    if r["status"] != "pending_approval":
        raise Conflict(f"request is {r['status']}")
    if str(r["requested_by"]) == who.principal_id:
        raise PermissionError("requester cannot approve their own request")
    if approve and kill_switch_state(conn, r["action"]):
        raise Conflict("kill switch engaged")
    if datetime.now(UTC) - r["created_at"] > APPROVAL_TTL:
        conn.execute("UPDATE broker.action_request SET status = 'expired' WHERE request_id = %s", (request_id,))
        ledger.append(conn, "action.expired", f"principal:{who.name}", {"request_id": request_id})
        raise Conflict("approval window expired")
    status = "validated" if approve else "rejected"
    row = conn.execute(
        "UPDATE broker.action_request SET status = %s, approver = %s WHERE request_id = %s RETURNING *",
        (status, who.principal_id, request_id),
    ).fetchone()
    ledger.append(conn, "action.approved" if approve else "action.denied", f"principal:{who.name}", {
        "request_id": request_id, "approver": who.principal_id, "role": who.role, "mode": "shadow",
    })
    return _request_view(row)


def set_kill_switch(conn: psycopg.Connection, who_id: str, actor: str, scope: str, engaged: bool) -> None:
    conn.execute(
        "INSERT INTO broker.kill_switch (scope, engaged, changed_by) VALUES (%s, %s, %s)"
        " ON CONFLICT (scope) DO UPDATE SET engaged = EXCLUDED.engaged, changed_by = EXCLUDED.changed_by,"
        " changed_at = now()",
        (scope, engaged, who_id),
    )
    ledger.append(conn, "kill_switch.changed", actor, {"scope": scope, "engaged": engaged})
