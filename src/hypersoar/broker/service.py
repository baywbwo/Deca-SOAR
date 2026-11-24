"""Broker DB layer: action requests, approvals, kill switch. Shadow-only: nothing is ever executed."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import psycopg
from psycopg.types.json import Jsonb

from hypersoar import ledger
from hypersoar.broker import policy
from hypersoar.broker.catalog import ActionSpec, Protected
from hypersoar.broker.roles import Principal
from hypersoar.common.pii import Vault

if TYPE_CHECKING:
    from hypersoar.broker.integrations.hub import Hub

APPROVAL_TTL = timedelta(minutes=30)
RATIONALE_MAX = 500


class NotFound(LookupError):
    pass


class Expired(RuntimeError):
    """The approval window passed. Raised before anything is written: the caller's transaction rolls
    back, so it records the expiry with mark_expired in a transaction of its own."""


class Conflict(RuntimeError):
    pass


@dataclass
class Broker:
    catalog: dict[str, ActionSpec]
    protected: Protected
    vault: Vault
    internal_cidrs: list = field(default_factory=list)
    allow_test_nets: bool = False
    hub: Hub | None = None

    @property
    def entity_id(self) -> str:
        return self.hub.entity_id if self.hub else "dob"


# What the approver sees on the card and in the console, per catalog action. Shadow mode: these
# describe what WOULD happen; nothing runs.
IMPACT = {
    "waf.ip_blacklist.add": "Blocks the source IP at WAF {waf_instance} for {ttl_s}s.",
    "waf.rate_limit.tighten": "Tightens the WAF rate limit on {domain}.",
    "ram.access_key.disable": "Disables AccessKey {access_key_token}; anything using it stops working until"
                              " it is re-enabled.",
    "ram.policy.detach": "Detaches policy {policy_name} from {principal_token}.",
    "ecs.security_group.isolate": "Moves {instance_id} into the isolation security group; its services go"
                                  " offline.",
}


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


def kill_switch_state(conn: psycopg.Connection, action: str, entity_id: str = "dob") -> bool:
    r = conn.execute(
        "SELECT bool_or(engaged) AS on FROM broker.kill_switch WHERE entity_id = %s AND scope IN ('global', %s)",
        (entity_id, action),
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
        "entity_id": r["entity_id"],
        "case_id": r["case_id"],
        "expires_at": r["expires_at"].isoformat() if r["expires_at"] else None,
        "escalation_level": r["escalation_level"],
        "approver_ref": r["approver_ref"],
        "impact": r["impact"],
        "rollback_plan": r["rollback_plan"],
        "evidence": r["evidence"],
    }


def _impact(action: str, params: dict) -> str:
    tpl = IMPACT.get(action)
    if tpl is None:
        return f"Runs {action[:80]}."
    try:
        return tpl.format(**{k: v for k, v in params.items()})[:300]
    except (KeyError, IndexError, ValueError):
        return tpl.split(" {")[0][:300]


def _rollback(spec: ActionSpec | None) -> str | None:
    if spec is None or not spec.rollback:
        return None
    return f"{spec.rollback} (one click in the console; recorded in the ledger)"[:300]


def _expires_at(b: Broker, conn, now: datetime) -> datetime:
    ladder = b.hub.ladder(conn) if b.hub else None
    minutes = sum(s.timeout_min for s in ladder) if ladder else None
    ttl = min(APPROVAL_TTL, timedelta(minutes=minutes)) if minutes else APPROVAL_TTL
    return now + ttl


def _notify(conn, b: Broker, op_jira: str | None, text: str, case_id: str | None, request_id: str | None,
            lark_op: str | None = None, payload: dict | None = None) -> None:
    if b.hub is None:
        return
    from hypersoar.broker.integrations import hub as hub_mod
    if case_id and op_jira:
        hub_mod.enqueue(conn, b.entity_id, "jira", op_jira, case_id=case_id, request_id=request_id,
                        payload={"text": text})
    if lark_op:
        hub_mod.enqueue(conn, b.entity_id, "lark", lark_op, case_id=case_id, request_id=request_id,
                        payload=payload or {})


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
        "SELECT e.alert_id, e.source, e.severity_hint, e.evidence_tokens, e.entity_id, a.case_id"
        " FROM gateway.inbox_event e LEFT JOIN gateway.case_alert a USING (alert_id) WHERE e.alert_id = %s",
        (alert_id,),
    ).fetchone()
    if alert is None or alert["entity_id"] != b.entity_id:
        raise NotFound("alert")
    # The case comes from the gateway's correlation, never from the caller.
    case_id = alert["case_id"]

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
                "SELECT count(*) AS n FROM broker.action_request WHERE entity_id = %s AND action = %s"
                " AND rate_scope = %s AND status IN ('validated', 'pending_approval')"
                " AND created_at > now() - interval '1 hour'",
                (b.entity_id, action, scope),
            ).fetchone()["n"]
            if n >= spec.rate_per_hour:
                reasons.append(f"rate limit {spec.rate_per_hour}/hour reached")
        intent = policy.would_execute(spec, params) if not reasons else None

    killed = kill_switch_state(conn, action, b.entity_id)
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
        "case_id": case_id,
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
        "INSERT INTO broker.decision_record (decision_id, alert_id, case_id, record, entity_id)"
        " VALUES (%s, %s, %s, %s, %s)",
        (decision_id, alert_id, case_id, Jsonb(record), b.entity_id),
    )
    request_id = str(uuid.uuid4())
    now = datetime.now(UTC)
    rollback_at = None
    if status != "rejected" and "ttl_s" in params:
        rollback_at = now + timedelta(seconds=params["ttl_s"])
    expires_at = _expires_at(b, conn, now) if status == "pending_approval" else None
    evidence = {"alert_ids": [alert_id], "tokens": sorted(alert["evidence_tokens"])[:20]}
    if case_id:
        evidence["alert_ids"] = [str(r["alert_id"]) for r in conn.execute(
            "SELECT alert_id FROM gateway.case_alert WHERE entity_id = %s AND case_id = %s LIMIT 20",
            (b.entity_id, case_id)).fetchall()]
    row = conn.execute(
        "INSERT INTO broker.action_request (request_id, idempotency_key, request_sha256, decision_id, alert_id,"
        " action, params, level, mode, status, reasons, would_execute, rate_scope, requested_by, rollback_at,"
        " entity_id, case_id, expires_at, impact, rollback_plan, evidence)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'shadow', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        " RETURNING *",
        (request_id, idem, req_hash, decision_id, alert_id, action[:128], Jsonb(params), level, status, Jsonb(reasons),
         intent, scope, who.principal_id, rollback_at, b.entity_id, case_id, expires_at,
         _impact(action, params) if spec else None, _rollback(spec), Jsonb(evidence)),
    ).fetchone()
    ledger.append(conn, "policy.decision", f"principal:{who.name}", {
        "decision_id": decision_id, "alert_id": alert_id, "case_id": case_id, "verdict": decision.verdict,
        "confidence": decision.confidence, "decision_source": decision.source,
    }, b.entity_id)
    ledger.append(conn, "action.requested", f"principal:{who.name}", {
        "request_id": request_id, "decision_id": decision_id, "alert_id": alert_id, "case_id": case_id,
        "action": action[:128], "params": params, "status": status, "mode": "shadow", "target_mode": target_mode,
        "reasons": reasons, "would_execute": intent, "kill_switch": killed,
        "expires_at": expires_at.isoformat() if expires_at else None,
    }, b.entity_id)
    if status == "pending_approval":
        _notify(conn, b, "jira.comment", f"Approval requested for {action} (level {level}). Nothing runs until an"
                f" approver on the ladder answers; expires {expires_at:%H:%M} UTC.", case_id, request_id,
                "lark.approval_card", {"step": 0})
    elif status == "validated":
        _notify(conn, b, "jira.comment", f"Shadow: HyperSoar would run {action} ({level}). Nothing was executed.",
                case_id, request_id)
    return _request_view(row), False


def _decide(conn: psycopg.Connection, b: Broker | None, r: dict, approve: bool, *, approver_id: str | None,
            approver_ref: str | None, actor: str, via: str, extra: dict) -> dict:
    """Checks shared by every approval path (API and Lark). The broker decides, not the channel."""
    request_id = str(r["request_id"])
    entity_id = r["entity_id"]
    if r["status"] != "pending_approval":
        raise Conflict(f"request is {r['status']}")
    if r["level"] not in ("L2", "L3"):
        raise PermissionError(f"level {r['level']} cannot be approved here")
    if r["level"] == "L3" and approve:
        # L3 has no fast path: never auto, never a one-click channel (Lark). Only a person who
        # re-authenticated in the console, with a written reason.
        if via != "console":
            raise PermissionError("L3 needs a re-authenticated approver in the console")
        if not (extra.get("reason") or "").strip():
            raise PermissionError("L3 approval needs a reason")
    if approve and kill_switch_state(conn, r["action"], entity_id):
        raise Conflict("kill switch engaged")
    expires = r["expires_at"] or (r["created_at"] + APPROVAL_TTL)
    if datetime.now(UTC) >= expires:
        raise Expired("approval window expired")
    status = "validated" if approve else "rejected"
    reason = (extra.get("reason") or "")[:500] or None
    row = conn.execute(
        "UPDATE broker.action_request SET status = %s, approver = %s, approver_ref = %s, decision_reason = %s"
        " WHERE request_id = %s RETURNING *",
        (status, approver_id, approver_ref, reason, request_id),
    ).fetchone()
    ledger.append(conn, "action.approved" if approve else "action.denied", actor, {
        "request_id": request_id, "case_id": r["case_id"], "approver": approver_id, "approver_ref": approver_ref,
        "via": via, "mode": "shadow", **extra,
    }, entity_id)
    if b is not None:
        verb = "approved" if approve else "rejected"
        _notify(conn, b, "jira.comment", f"{r['action']} {verb} via {via} by {approver_ref or actor}. Shadow mode:"
                " nothing was executed.", r["case_id"], request_id, "lark.notice",
                {"title": f"Request {verb}", "text": f"{r['action']} {verb} via {via}. Shadow mode: nothing ran.",
                 "severity": "medium"})
    return _request_view(row)


def mark_expired(conn: psycopg.Connection, request_id: str, actor: str) -> bool:
    """Expire a pending request whose window has passed. True if this call expired it."""
    r = conn.execute(
        "UPDATE broker.action_request SET status = 'expired' WHERE request_id = %s AND status = 'pending_approval'"
        " AND coalesce(expires_at, created_at + %s) <= now() RETURNING entity_id, case_id",
        (request_id, APPROVAL_TTL),
    ).fetchone()
    if r is None:
        return False
    ledger.append(conn, "action.expired", actor, {"request_id": request_id, "case_id": r["case_id"],
                                                  "reason": "approval window passed"}, r["entity_id"])
    return True


def decide_approval(conn: psycopg.Connection, who: Principal, request_id: str, approve: bool,
                    b: Broker | None = None, *, via: str = "api", reason: str | None = None) -> dict:
    """Record an approver decision. In shadow mode an approval still executes nothing."""
    r = conn.execute(
        "SELECT * FROM broker.action_request WHERE request_id = %s FOR UPDATE", (request_id,)
    ).fetchone()
    if r is None or (b is not None and r["entity_id"] != b.entity_id):
        raise NotFound("request")
    if str(r["requested_by"]) == who.principal_id:
        raise PermissionError("requester cannot approve their own request")
    extra = {"role": who.role}
    if reason:
        extra["reason"] = reason[:500]
    return _decide(conn, b, r, approve, approver_id=who.principal_id, approver_ref=None,
                   actor=f"principal:{who.name}", via=via, extra=extra)


def decide_from_lark(conn: psycopg.Connection, b: Broker, lark_user_id: str, request_id: str, approve: bool) -> dict:
    """An Approve/Reject click on a Lark card, already signature-checked. The clicker must be on this
    entity's approver ladder; everything else is the same check as the API path."""
    try:
        request_id = str(uuid.UUID(request_id))
    except ValueError:
        raise NotFound("request") from None
    ladder = b.hub.ladder(conn) if b.hub else None
    step = next((i for i, s in enumerate(ladder or ()) for a in s.approvers if a.lark_user_id == lark_user_id), None)
    if step is None:
        raise PermissionError("not on the approver ladder")
    r = conn.execute(
        "SELECT * FROM broker.action_request WHERE request_id = %s FOR UPDATE", (request_id,)
    ).fetchone()
    if r is None or r["entity_id"] != b.entity_id:
        raise NotFound("request")
    return _decide(conn, b, r, approve, approver_id=None, approver_ref=f"lark:{lark_user_id[:80]}",
                   actor=f"lark:{lark_user_id[:80]}", via="lark", extra={"ladder_step": step,
                                                                        "role": ladder[step].role})


def record_refusal(conn: psycopg.Connection, b: Broker, lark_user_id: str, request_id: str, reason: str) -> None:
    """Own transaction, after the refused one rolled back: a signed click from someone who may not
    approve is worth a trace."""
    ledger.append(conn, "approval.refused", "service:lark", {
        "request_id": str(request_id)[:40], "lark_user": lark_user_id[:80], "reason": reason[:120]}, b.entity_id)


def set_kill_switch(conn: psycopg.Connection, who_id: str, actor: str, scope: str, engaged: bool,
                    entity_id: str = "dob", reason: str | None = None) -> None:
    reason = (reason or "").strip()[:500] or None
    conn.execute(
        "INSERT INTO broker.kill_switch (entity_id, scope, engaged, changed_by, reason) VALUES (%s, %s, %s, %s, %s)"
        " ON CONFLICT (entity_id, scope) DO UPDATE SET engaged = EXCLUDED.engaged, changed_by = EXCLUDED.changed_by,"
        " reason = EXCLUDED.reason, changed_at = now()",
        (entity_id, scope, engaged, who_id, reason),
    )
    ledger.append(conn, "kill_switch.changed", actor, {"scope": scope, "engaged": engaged, "reason": reason},
                  entity_id)
