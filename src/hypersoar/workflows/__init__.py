"""Alert workflows on Temporal (MIT, self-hosted): workflow-as-code replacing the phase-0 webhook pipeline.

alert (gateway) -> triage (mock in phase 0) -> action broker (shadow) -> ledger (written by the broker).
"""

TASK_QUEUE = "deca-soar-alerts"
WORKFLOW_NAME = "AlertShadowWorkflow"


def workflow_id(alert_id: str) -> str:
    """One workflow per alert: restarting the gateway can never start a second run for it."""
    return f"alert-{alert_id}"
