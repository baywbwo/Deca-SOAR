"""Broker-side triage (POST /v1/triage): the broker loads the alert itself, asks 9router (outside
any transaction), records the work trace (G4) and queues the Jira issue and Lark notification.

The worker only passes an alert id; it never sees or sends alert content to the AI itself.
"""

from __future__ import annotations

from datetime import UTC, datetime

from hypersoar import ledger
from hypersoar.broker.integrations import calls, config
from hypersoar.broker.integrations import hub as hub_mod
from hypersoar.broker.integrations.ai import TriageResult
from hypersoar.broker.service import Broker, NotFound

ACTOR = "service:broker"


def _load(conn, b: Broker, alert_id: str):
    alert = conn.execute(
        "SELECT e.alert_id, e.entity_id, e.source, e.rule_id, e.severity_hint, e.event_count, e.alert,"
        " e.evidence_tokens, a.case_id FROM gateway.inbox_event e LEFT JOIN gateway.case_alert a USING (alert_id)"
        " WHERE e.alert_id = %s", (alert_id,),
    ).fetchone()
    if alert is None or alert["entity_id"] != b.entity_id:
        raise NotFound("alert")
    case = None
    if alert["case_id"]:
        case = conn.execute(
            "SELECT case_id, alert_count, tactics, max_severity FROM gateway.alert_case WHERE entity_id = %s"
            " AND case_id = %s", (b.entity_id, alert["case_id"]),
        ).fetchone()
    return dict(alert), (dict(case) if case else None)


def triage(pool, b: Broker, alert_id: str, actor: str) -> dict:
    hub = b.hub
    with pool.connection() as conn:
        alert, case = _load(conn, b, alert_id)
        client, target, error = None, "mock", None
        try:
            client, _, row = hub.ai(conn)
            target = row["target"]
        except (hub_mod.NotConfigured, config.ConfigInvalid) as e:
            error = str(e)[:200]
        used = conn.execute(
            "SELECT coalesce(sum(tokens_in + tokens_out), 0) AS n FROM broker.ai_usage WHERE entity_id = %s"
            " AND day = current_date", (b.entity_id,),
        ).fetchone()["n"]
    if client is None:
        res = TriageResult("unknown", 0.0, f"AI not available: {error}", [], None, "none", target,
                           escalate="AI not configured")
    else:
        res = client.triage(alert, case, int(used))
    case_id = alert["case_id"]
    with pool.connection() as conn, conn.transaction():
        for a in res.attempts:
            conn.execute(
                "INSERT INTO broker.ai_usage (entity_id, day, model, calls, failures, tokens_in, tokens_out)"
                " VALUES (%s, current_date, %s, 1, %s, %s, %s) ON CONFLICT (entity_id, day, model) DO UPDATE SET"
                " calls = broker.ai_usage.calls + 1, failures = broker.ai_usage.failures + EXCLUDED.failures,"
                " tokens_in = broker.ai_usage.tokens_in + EXCLUDED.tokens_in,"
                " tokens_out = broker.ai_usage.tokens_out + EXCLUDED.tokens_out",
                (b.entity_id, a.model[:64], 0 if a.ok else 1, a.tokens_in, a.tokens_out),
            )
        ok = any(a.ok for a in res.attempts)
        calls.record(conn, b.entity_id, "ai", "ai.triage", target, "ok" if ok else ("skipped" if not res.attempts
                                                                                    else "error"),
                     case_id=case_id, alert_id=alert_id, detail={
                         "verdict": res.verdict, "model": res.model, "fallback_used": res.fallback_used,
                         "attempts": [{"model": a.model, "ok": a.ok, "error": a.error, "latency_ms": a.latency_ms,
                                       "tokens": a.tokens_in + a.tokens_out} for a in res.attempts],
                         "escalated": res.escalate},
                     duration_ms=sum(a.latency_ms for a in res.attempts))
        ledger.append(conn, "ai.triage", actor, {"alert_id": alert_id, "case_id": case_id, **res.trace()},
                      b.entity_id)
        if res.escalate:
            ledger.append(conn, "ai.escalated", ACTOR, {"alert_id": alert_id, "case_id": case_id,
                                                       "reason": res.escalate}, b.entity_id)
            hub_mod.enqueue(conn, b.entity_id, "lark", "lark.notice", case_id=case_id, payload={
                "title": f"Analyst needed{' · ' + case_id if case_id else ''}",
                "text": f"AI could not triage alert {alert['rule_id']}: {res.escalate}. Verdict Unknown; an analyst"
                        " decides. Nothing runs automatically.",
                "severity": (case or {}).get("max_severity") or alert["severity_hint"], "oncall": True})
        if case_id and res.verdict in hub_mod.NOTIFY_VERDICTS:
            has_issue = conn.execute("SELECT 1 FROM broker.jira_issue WHERE entity_id = %s AND case_id = %s",
                                     (b.entity_id, case_id)).fetchone()
            if not has_issue:
                hub_mod.enqueue(conn, b.entity_id, "jira", "jira.ensure_issue", case_id=case_id, once=True)
            hub_mod.enqueue(conn, b.entity_id, "lark", "lark.case_notify", case_id=case_id, once=True,
                            payload={"verdict": res.verdict})
            hub_mod.enqueue(conn, b.entity_id, "jira", "jira.comment", case_id=case_id, payload={
                "text": f"New alert {alert['rule_id']} ({alert['severity_hint']}, {alert['event_count']} events). "
                        f"AI verdict {res.verdict} ({res.confidence:.2f}) by {res.model or 'none'}"
                        f"{' via fallback' if res.fallback_used else ''}."})
    return {
        "alert_id": alert_id, "case_id": case_id, "verdict": res.verdict, "confidence": res.confidence,
        "source": "llm", "model": res.model, "prompt_version": res.prompt_version,
        "rationale_summary": res.rationale_summary, "evidence_refs": res.evidence_refs,
        "escalated": res.escalate, "fallback_used": res.fallback_used,
        # The entity's own WAF instance, so the worker never needs entity config to build a request.
        "waf_instance": b.hub.entity.waf_instance,
        "triaged_at": datetime.now(UTC).isoformat(),
    }
