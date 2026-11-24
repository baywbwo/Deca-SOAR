"""Activities: everything with side effects or non-determinism lives here, never in the workflow."""

from __future__ import annotations

import httpx
from temporalio import activity
from temporalio.exceptions import ApplicationError

# Offline stand-in for the broker's triage, registered under the same activity name by tests that
# run a worker without a broker. The deployed worker uses BrokerSubmitter.triage (9router via the broker).
TRIAGE_MODEL = "mock-phase0"
TRIAGE_RATIONALE = "phase-0 mock triage; LLM not tested"
RETRYABLE_STATUS = frozenset({408, 425, 429})


@activity.defn(name="triage")
async def triage_mock(alert: dict) -> dict:
    severity = alert.get("severity_hint", "medium")
    src_ip = (alert.get("entities") or {}).get("src_ip")
    return {
        "verdict": "malicious" if severity in ("high", "critical") else "suspicious",
        "confidence": 0.95,
        "source": "rule",
        "model": TRIAGE_MODEL,
        "prompt_version": "none",
        "rationale_summary": TRIAGE_RATIONALE,
        "evidence_refs": [src_ip] if src_ip else [],
        "deterministic_signals": {
            "rule_id": alert.get("rule_id"),
            "events": (alert.get("counts") or {}).get("events"),
            "severity_hint": severity,
        },
        "escalated": None,
        "waf_instance": "waf-jkt-01",
    }


class BrokerSubmitter:
    """Posts an action request to the broker as a service principal (role analyst).

    The broker re-derives everything that matters (evidence, target, policy) from its own database,
    so a compromised worker can at most ask; it cannot widen what is allowed.
    """

    def __init__(self, base_url: str, token: str, *, verify: str | bool = True, transport=None) -> None:
        self._url = base_url.rstrip("/") + "/v1/actions/requests"
        self._triage_url = base_url.rstrip("/") + "/v1/triage"
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            follow_redirects=False,
            verify=verify,
            headers={"Authorization": f"Bearer {token}"},
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _post(self, url: str, body: dict) -> httpx.Response:
        try:
            resp = await self._client.post(url, json=body)
        except httpx.TransportError as e:
            # Retryable: the broker may be restarting. Class name only, never the URL or token.
            raise ApplicationError(f"broker unreachable ({type(e).__name__})", type="BrokerUnavailable") from None
        if resp.status_code in (200, 201):
            return resp
        retryable = resp.status_code >= 500 or resp.status_code in RETRYABLE_STATUS
        raise ApplicationError(
            f"broker http {resp.status_code}",
            _detail(resp),
            type="BrokerUnavailable" if retryable else "BrokerRejected",
            non_retryable=not retryable,
        )

    @activity.defn(name="triage")
    async def triage(self, alert: dict) -> dict:
        """The broker loads the alert and asks 9router; the worker sends only the alert id."""
        return (await self._post(self._triage_url, {"alert_id": alert["alert_id"]})).json()

    @activity.defn(name="submit_to_broker")
    async def submit(self, request: dict) -> dict:
        resp = await self._post(self._url, request)
        if resp.status_code in (200, 201):
            data = resp.json()
            return {
                "request_id": data.get("request_id"),
                "status": data.get("status"),
                "reasons": data.get("reasons") or [],
                "idempotent_replay": bool(data.get("idempotent_replay")),
            }
        raise ApplicationError(f"broker http {resp.status_code}", type="BrokerRejected", non_retryable=True)


def _detail(resp: httpx.Response) -> str:
    try:
        d = resp.json().get("detail")
    except (ValueError, AttributeError):
        return ""
    return str(d)[:300] if d is not None else ""
