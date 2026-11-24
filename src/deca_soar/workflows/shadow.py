"""AlertShadowWorkflow: deterministic orchestration only. No I/O, clocks or randomness here."""

from __future__ import annotations

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from deca_soar.workflows import WORKFLOW_NAME
    from deca_soar.workflows.activities import BrokerSubmitter, triage_mock

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


def build_request(alert: dict, decision: dict) -> dict | None:
    src_ip = (alert.get("entities") or {}).get("src_ip")
    if alert.get("source") != "waf" or not src_ip:
        return None
    return {
        "alert_id": alert["alert_id"],
        "action": BLOCK_ACTION,
        "params": {"ip_token": src_ip, "waf_instance": WAF_INSTANCE},
        "decision": decision,
        "idempotency_key": f"wf-{alert['alert_id']}",
    }


@workflow.defn(name=WORKFLOW_NAME)
class AlertShadowWorkflow:
    @workflow.run
    async def run(self, alert: dict) -> dict:
        decision = await workflow.execute_activity(
            triage_mock,
            alert,
            start_to_close_timeout=START_TO_CLOSE,
            schedule_to_close_timeout=SCHEDULE_TO_CLOSE,
            retry_policy=ACTIVITY_RETRY,
        )
        request = build_request(alert, decision)
        if request is None:
            return {"outcome": "no_action", "alert_id": alert.get("alert_id"), "verdict": decision["verdict"]}
        result = await workflow.execute_activity_method(
            BrokerSubmitter.submit,
            request,
            start_to_close_timeout=START_TO_CLOSE,
            schedule_to_close_timeout=SCHEDULE_TO_CLOSE,
            retry_policy=ACTIVITY_RETRY,
        )
        return {"outcome": "submitted", "alert_id": alert["alert_id"], "verdict": decision["verdict"], **result}
