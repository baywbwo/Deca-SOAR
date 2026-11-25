"""Console writes. The console has no write grant on the database: every change is posted to the action
broker, which checks the role, the re-authentication, the policy and the idempotency key and writes the
audit trail. The console only adds what a browser needs: the session, a same-origin check, a per-session
CSRF token and a rate limit on wrong re-auth passwords.

Settings: HYPERSOAR_BROKER_URL (https), HYPERSOAR_BROKER_TOKEN(_FILE) the bearer token of the human
principal the console user signs in as (same name as HYPERSOAR_CONSOLE_USER, role admin), and
HYPERSOAR_BROKER_CA_FILE for the broker's private CA.
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from hypersoar.common.config import ConfigError, read_secret

CSRF_HEADER = "x-hypersoar-csrf"
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
CASE_ID = re.compile(r"^CS-[0-9]{1,9}$")
INTEGRATION = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
SECRET_NAME = re.compile(r"^[a-z][a-z0-9_]{0,39}$")


class BrokerClient:
    def __init__(self, url: str, token: str, *, verify: str | bool = True, transport=None) -> None:
        self._client = httpx.Client(base_url=url.rstrip("/"), timeout=httpx.Timeout(15.0), follow_redirects=False,
                                    verify=verify, headers={"Authorization": f"Bearer {token}"}, transport=transport)

    @classmethod
    def from_env(cls, mode: str) -> BrokerClient | None:
        url = os.environ.get("HYPERSOAR_BROKER_URL", "").strip()
        if not url:
            return None
        if mode == "production" and not url.startswith("https://"):
            raise ConfigError("production requires an https:// HYPERSOAR_BROKER_URL")
        token = read_secret("HYPERSOAR_BROKER_TOKEN")
        if not token:
            raise ConfigError("HYPERSOAR_BROKER_URL is set but HYPERSOAR_BROKER_TOKEN(_FILE) is empty")
        return cls(url, token, verify=os.environ.get("HYPERSOAR_BROKER_CA_FILE") or True)

    def close(self) -> None:
        self._client.close()

    def post(self, path: str, body: dict, key: str | None) -> tuple[int, dict]:
        return self.send("POST", path, body, key)

    def send(self, method: str, path: str, body: dict | None, key: str | None) -> tuple[int, dict]:
        """(status, JSON) as the browser should see it. The broker's 401 and 5xx become 502: they are this
        console's problem (token, broker down), not the person's session."""
        try:
            r = self._client.request(method, path, json=body,
                                     headers={"Idempotency-Key": key} if key else {})
        except httpx.TransportError as e:
            return 502, {"detail": f"broker unreachable ({type(e).__name__})"}
        try:
            data = r.json()
        except ValueError:
            data = {}
        if r.status_code == 401 or r.status_code >= 500:
            return 502, {"detail": f"broker answered {r.status_code}"}
        if r.status_code >= 400:
            detail = data.get("detail") if isinstance(data, dict) else None
            return r.status_code, {"detail": str(detail)[:300] if detail else f"broker answered {r.status_code}"}
        return r.status_code, data if isinstance(data, dict) else {}


# -- what the browser may send, per write ----------------------------------------------------------------
class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DecisionIn(_In):
    approve: bool
    password: str = Field(min_length=1, max_length=1024)
    reason: str | None = Field(default=None, max_length=500)


class KillSwitchIn(_In):
    engaged: bool
    password: str = Field(min_length=1, max_length=1024)
    reason: str = Field(min_length=3, max_length=500)


class RevokeIn(_In):
    password: str = Field(min_length=1, max_length=1024)
    reason: str = Field(min_length=3, max_length=500)


class AssignIn(_In):
    assignee: str | None = Field(default=None, min_length=1, max_length=80)


class StatusIn(_In):
    status: Literal["open", "waiting", "closed"]
    reason: str | None = Field(default=None, max_length=500)


class CommentIn(_In):
    body: str = Field(min_length=1, max_length=2000)


class Empty(_In):
    pass


class IntegrationSaveIn(_In):
    password: str = Field(min_length=1, max_length=1024)
    target: Literal["mock", "live"]
    enabled: bool = True
    settings: dict
    note: str = Field(default="", max_length=200)


class IntegrationRollbackIn(_In):
    password: str = Field(min_length=1, max_length=1024)
    version: int = Field(ge=1)


class IntegrationSecretIn(_In):
    password: str = Field(min_length=1, max_length=1024)
    value: str = Field(min_length=1, max_length=4096)
    expires_at: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")


class Reauth(_In):
    password: str = Field(min_length=1, max_length=1024)


@dataclass(frozen=True)
class Plan:
    path: str
    body: dict
    reauth: bool
    method: str = "POST"


class BadInput(ValueError):
    pass


def _uuid(v: str) -> str:
    try:
        return str(uuid.UUID(v))
    except ValueError:
        raise BadInput("not found") from None


def _case(v: str) -> str:
    if not CASE_ID.match(v):
        raise BadInput("not found")
    return v


def parse(model: type[_In], data) -> _In:
    if not isinstance(data, dict):
        raise BadInput("body must be a JSON object")
    try:
        return model.model_validate(data)
    except ValidationError as e:
        first = e.errors()[0]
        raise BadInput(f"{'.'.join(str(x) for x in first['loc']) or 'body'}: {first['msg']}") from None


def decision(request_id: str, data) -> Plan:
    b = parse(DecisionIn, data)
    return Plan(f"/v1/actions/requests/{_uuid(request_id)}/approval", b.model_dump(exclude_none=True), True)


def revoke(request_id: str, data) -> Plan:
    return Plan(f"/v1/actions/requests/{_uuid(request_id)}/revoke", parse(RevokeIn, data).model_dump(), True)


def kill_switch(data) -> Plan:
    return Plan("/v1/kill-switch", {"scope": "global", **parse(KillSwitchIn, data).model_dump()}, True)


def assign(case_id: str, data) -> Plan:
    return Plan(f"/v1/cases/{_case(case_id)}/assign", parse(AssignIn, data).model_dump(), False)


def status(case_id: str, data) -> Plan:
    return Plan(f"/v1/cases/{_case(case_id)}/status", parse(StatusIn, data).model_dump(exclude_none=True), False)


def comment(case_id: str, data) -> Plan:
    return Plan(f"/v1/cases/{_case(case_id)}/comments", parse(CommentIn, data).model_dump(), False)


def ask_ai(conn, entity_id: str, request_id: str, data) -> Plan:
    """Run AI triage again on the alert behind an approval request. The alert comes from the database,
    never from the browser."""
    parse(Empty, data)
    r = conn.execute("SELECT alert_id FROM broker.action_request WHERE request_id = %s AND entity_id = %s",
                     (_uuid(request_id), entity_id)).fetchone()
    if r is None:
        raise BadInput("not found")
    return Plan("/v1/triage", {"alert_id": str(r["alert_id"])}, False)


# -- integration settings (the Integrations screen). The broker keeps them off unless
# HYPERSOAR_INTEGRATION_WRITES=1 and checks the person's password, the role and the Idempotency-Key.
def _integration(name: str) -> str:
    if not INTEGRATION.match(name):
        raise BadInput("not found")
    return name


def integration_save(name: str, data) -> Plan:
    return Plan(f"/v1/integrations/{_integration(name)}", parse(IntegrationSaveIn, data).model_dump(), True, "PUT")


def integration_rollback(name: str, data) -> Plan:
    return Plan(f"/v1/integrations/{_integration(name)}/rollback", parse(IntegrationRollbackIn, data).model_dump(),
                True)


def integration_secret(name: str, secret: str, data) -> Plan:
    if not SECRET_NAME.match(secret):
        raise BadInput("not found")
    return Plan(f"/v1/integrations/{_integration(name)}/secrets/{secret}",
                parse(IntegrationSecretIn, data).model_dump(exclude_none=True), True, "PUT")


def integration_test(name: str, data) -> Plan:
    return Plan(f"/v1/integrations/{_integration(name)}/test", parse(Reauth, data).model_dump(), True)
