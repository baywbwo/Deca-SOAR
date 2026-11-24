"""AlertShadowWorkflow: deterministic orchestration only. No I/O, clocks or randomness here."""

from __future__ import annotations

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from hypersoar.workflows import WORKFLOW_NAME
    from hypersoar.workflows.activities import BrokerSubmitter

# Unlimited attempts within schedule_to_close: an outage of the broker (or of the worker that runs
# the activity) delays the request but never drops it.
ACTIVITY_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=2),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(minutes=5),
    non_retryable_error_types=["BrokerRejected"],
)
START_TO_CLOSE = timedelta(seconds=30)
SCHEDULE_TO_CLOSE = timedelta(hours=24)
WAF_INSTANCE = "waf-jkt-01"
BLOCK_ACTION = "waf.ip_blacklist.add"
AK_DISABLE = "ram.access_key.disable"
# ActionTrail rules where a leaked or misused AccessKey is the thing to stop (L2: an approver decides).
AK_RULES = frozenset({"actiontrail.ak_unusual_ip", "actiontrail.oss.bulk_read"})
DECISION_FIELDS = ("verdict", "confidence", "source", "model", "prompt_version", "rationale_summary",
                   "evidence_refs", "deterministic_signals")
ACTIONABLE = frozenset({"suspicious", "malicious"})


def build_request(alert: dict, decision: dict) -> dict | None:
    """The one action this alert type maps to, or None. Unknown or benign never submits: an Unknown
    verdict has already been escalated to an analyst by the broker."""
    if decision.get("verdict") not in ACTIONABLE:
        return None
    ents = alert.get("entities") or {}
    if alert.get("source") == "waf" and ents.get("src_ip"):
        action = BLOCK_ACTION
        params = {"ip_token": ents["src_ip"], "waf_instance": decision.get("waf_instance") or WAF_INSTANCE}
    elif alert.get("source") == "actiontrail" and alert.get("rule_id") in AK_RULES and ents.get("access_key_token"):
        action = AK_DISABLE
        params = {"access_key_token": ents["access_key_token"]}
    else:
        return None
    return {
        "alert_id": alert["alert_id"],
        "action": action,
        "params": params,
        "decision": {k: decision[k] for k in DECISION_FIELDS if decision.get(k) is not None},
        "idempotency_key": f"wf-{alert['alert_id']}",
    }


@workflow.defn(name=WORKFLOW_NAME)
class AlertShadowWorkflow:
    @workflow.run
    async def run(self, alert: dict) -> dict:
        decision = await workflow.execute_activity_method(
            BrokerSubmitter.triage,
            alert,
            start_to_close_timeout=START_TO_CLOSE,
            schedule_to_close_timeout=SCHEDULE_TO_CLOSE,
            retry_policy=ACTIVITY_RETRY,
        )
        request = build_request(alert, decision)
        if request is None:
            return {"outcome": "escalated" if decision.get("escalated") else "no_action",
                    "alert_id": alert.get("alert_id"), "verdict": decision["verdict"]}
        result = await workflow.execute_activity_method(
            BrokerSubmitter.submit,
            request,
            start_to_close_timeout=START_TO_CLOSE,
            schedule_to_close_timeout=SCHEDULE_TO_CLOSE,
            retry_policy=ACTIVITY_RETRY,
        )
        return {"outcome": "submitted", "alert_id": alert["alert_id"], "verdict": decision["verdict"], **result}
