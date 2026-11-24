"""Integration settings per entity and mode (screen 08). Non-secret fields only; secrets are in
secretbox. entities/<id>.yaml seeds the first version; after that the database is the source.

Every save writes a new version (the previous one stays for one-click rollback) and a ledger entry
with the names of the fields that changed, never their values.
"""

from __future__ import annotations

import string
from typing import Literal

from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from hypersoar import ledger
from hypersoar.broker.integrations import LABELS, NAMES, secretbox

SEVERITIES = ("critical", "high", "medium", "low")
TITLE_FIELDS = frozenset({"severity", "case_id", "case_title", "asset"})
MAX_LADDER_MIN = 60
HTTPS = r"^https://[A-Za-z0-9.-]+(:[0-9]{2,5})?(/[A-Za-z0-9._~/-]*)?$"


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LarkRoute(_M):
    chat_id: str | None = Field(default=None, pattern=r"^oc_[A-Za-z0-9]{1,64}$")
    chat_name: str = Field(default="", max_length=80)
    oncall_dm: bool = False
    delivery: Literal["now", "digest_30m", "daily_0800", "off"] = "now"


class LarkApprover(_M):
    name: str = Field(min_length=1, max_length=80)
    lark_user_id: str = Field(pattern=r"^ou_[A-Za-z0-9]{1,64}$")


class LarkStep(_M):
    role: str = Field(min_length=1, max_length=40)
    approvers: tuple[LarkApprover, ...] = Field(min_length=1, max_length=5)
    timeout_min: Literal[5, 10, 15, 30]


class LarkSettings(_M):
    base_url: str = Field(default="https://open.larksuite.com", pattern=HTTPS)
    app_id: str = Field(pattern=r"^cli_[A-Za-z0-9]{8,40}$")
    routing: dict[Literal["critical", "high", "medium", "low"], LarkRoute]
    ladder: tuple[LarkStep, ...] = Field(min_length=1, max_length=3)

    @model_validator(mode="after")
    def _check(self):
        if set(self.routing) != set(SEVERITIES):
            raise ValueError("routing needs critical, high, medium and low")
        if sum(s.timeout_min for s in self.ladder) > MAX_LADDER_MIN:
            raise ValueError(f"the approval ladder may last at most {MAX_LADDER_MIN} minutes")
        ids = [a.lark_user_id for s in self.ladder for a in s.approvers]
        if len(ids) != len(set(ids)):
            raise ValueError("a Lark user can be on only one ladder step")
        return self

    def approver_step(self, lark_user_id: str) -> int | None:
        return next((i for i, s in enumerate(self.ladder) for a in s.approvers if a.lark_user_id == lark_user_id),
                    None)

    def ladder_minutes(self) -> int:
        return sum(s.timeout_min for s in self.ladder)


class JiraSync(_M):
    comment_on_update: bool = True
    done_on_close: bool = True
    # Inbound: also needs HYPERSOAR_JIRA_INBOUND=1 on the broker, which stays off until reviewed.
    close_case_on_done: bool = False


class JiraSettings(_M):
    site: str = Field(pattern=HTTPS)
    email: str = Field(pattern=r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", max_length=120)
    project: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,9}$")
    issue_type: str = Field(min_length=1, max_length=40)
    title_template: str = Field(default="[{severity}] {case_id} {case_title}", min_length=1, max_length=200)
    priority_map: dict[Literal["critical", "high", "medium", "low"], str]
    sync: JiraSync = JiraSync()

    @field_validator("title_template")
    @classmethod
    def _fields(cls, v: str) -> str:
        used = {f for _, f, _, _ in string.Formatter().parse(v) if f}
        if not used <= TITLE_FIELDS:
            raise ValueError(f"title may only use {sorted(TITLE_FIELDS)}")
        return v

    @field_validator("priority_map")
    @classmethod
    def _prio(cls, v: dict) -> dict:
        if set(v) != set(SEVERITIES) or not all(isinstance(x, str) and 0 < len(x) <= 30 for x in v.values()):
            raise ValueError("priority_map needs critical, high, medium and low")
        return v


class AiSettings(_M):
    base_url: str = Field(pattern=HTTPS)
    triage_model: str = Field(pattern=r"^[A-Za-z0-9._:/-]{1,64}$")
    fallback_model: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._:/-]{1,64}$")
    timeout_s: Literal[10, 20, 30] = 20
    daily_token_limit: int = Field(default=2_000_000, ge=1_000, le=100_000_000)
    max_tokens: int = Field(default=400, ge=64, le=2000)
    prompt_version: str = Field(default="triage-v1", pattern=r"^[a-z0-9.-]{1,32}$")
    # Sandbox mock only: makes the mock answer badly so the guardrails can be exercised.
    mock_fault: Literal["none", "invalid_json", "invalid_json_primary", "timeout"] = "none"


MODELS = {"lark": LarkSettings, "jira": JiraSettings, "ai": AiSettings}


class ConfigInvalid(ValueError):
    pass


def validate(integration: str, mode: str, target: str, settings: dict):
    if integration not in NAMES:
        raise ConfigInvalid("unknown integration")
    if target not in ("mock", "live"):
        raise ConfigInvalid("target must be mock or live")
    if mode == "production" and target != "live":
        raise ConfigInvalid("production cannot use a mock target")
    try:
        model = MODELS[integration].model_validate(settings)
    except ValidationError as e:
        # Field locations and messages only; pydantic's input echo is dropped.
        raise ConfigInvalid("; ".join(f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors())[:600]) \
            from None
    if integration == "ai" and mode == "production" and model.mock_fault != "none":
        raise ConfigInvalid("mock_fault is for sandbox only")
    return model


def _changed(a, b, prefix: str = "") -> list[str]:
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            out += _changed(a.get(k), b.get(k), f"{prefix}{k}.")
        return out
    return [prefix.rstrip(".")] if a != b else []


def get(conn, entity_id: str, integration: str, mode: str) -> dict | None:
    return conn.execute(
        "SELECT * FROM broker.integration_config WHERE entity_id = %s AND integration = %s AND mode = %s",
        (entity_id, integration, mode),
    ).fetchone()


def settings_of(conn, entity_id: str, integration: str, mode: str):
    """(row, validated settings model) or (None, None) when the integration is not configured."""
    row = get(conn, entity_id, integration, mode)
    if row is None or not row["enabled"]:
        return row, None
    return row, validate(integration, mode, row["target"], row["settings"])


def _write(conn, entity_id, integration, mode, target, enabled, settings, actor, note, previous):
    version = (previous["version"] + 1) if previous else 1
    if previous:
        conn.execute(
            "UPDATE broker.integration_config SET target = %s, enabled = %s, settings = %s, version = %s,"
            " updated_by = %s, updated_at = now() WHERE entity_id = %s AND integration = %s AND mode = %s",
            (target, enabled, Jsonb(settings), version, actor[:120], entity_id, integration, mode),
        )
    else:
        conn.execute(
            "INSERT INTO broker.integration_config (entity_id, integration, mode, target, enabled, settings, version,"
            " updated_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (entity_id, integration, mode, target, enabled, Jsonb(settings), version, actor[:120]),
        )
    conn.execute(
        "INSERT INTO broker.integration_config_version (entity_id, integration, mode, version, target, enabled,"
        " settings, changed_by, note) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (entity_id, integration, mode, version, target, enabled, Jsonb(settings), actor[:120], (note or "")[:200]),
    )
    fields = _changed({"target": previous["target"], "enabled": previous["enabled"], **previous["settings"]}
                      if previous else {}, {"target": target, "enabled": enabled, **settings})
    ledger.append(conn, "integration.config_changed", actor[:120], {
        "integration": integration, "mode": mode, "version": version, "changed_fields": fields[:60],
        "note": (note or "")[:200],
    }, entity_id)
    return version


def save(conn, entity_id: str, integration: str, mode: str, target: str, enabled: bool, settings: dict,
         actor: str, note: str = "") -> int:
    model = validate(integration, mode, target, settings)
    clean = model.model_dump(mode="json")
    conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"hypersoar-int:{entity_id}:{integration}:{mode}",))
    prev = get(conn, entity_id, integration, mode)
    if prev and prev["target"] == target and prev["enabled"] == enabled and prev["settings"] == clean:
        return prev["version"]
    return _write(conn, entity_id, integration, mode, target, enabled, clean, actor, note, prev)


def rollback(conn, entity_id: str, integration: str, mode: str, version: int, actor: str) -> int:
    old = conn.execute(
        "SELECT * FROM broker.integration_config_version WHERE entity_id = %s AND integration = %s AND mode = %s"
        " AND version = %s", (entity_id, integration, mode, version),
    ).fetchone()
    if old is None:
        raise LookupError("version not found")
    return save(conn, entity_id, integration, mode, old["target"], old["enabled"], old["settings"], actor,
                f"rollback to v{version}")


def seed(conn, entity, actor: str = "service:broker") -> list[str]:
    """First start: copy entities/<id>.yaml settings into the database. Never overwrites."""
    seeded = []
    for name, raw in entity.integrations.items():
        if get(conn, entity.id, name, entity.mode) is None:
            save(conn, entity.id, name, entity.mode, raw.target, True, raw.settings, actor, "seeded from entity file")
            seeded.append(name)
    return seeded


def last_test(conn, entity_id: str, integration: str, mode: str) -> dict | None:
    return conn.execute(
        "SELECT run_id, status, steps, config_version, target, finished_at, actor FROM broker.integration_test_run"
        " WHERE entity_id = %s AND integration = %s AND mode = %s ORDER BY finished_at DESC LIMIT 1",
        (entity_id, integration, mode),
    ).fetchone()


def view(conn, entity_id: str, integration: str, mode: str) -> dict:
    row = get(conn, entity_id, integration, mode)
    secrets = secretbox.status(conn, entity_id, integration, mode)
    t = last_test(conn, entity_id, integration, mode)
    errors = conn.execute(
        "SELECT count(*) AS n FROM broker.integration_call WHERE entity_id = %s AND integration = %s"
        " AND status = 'error' AND created_at > now() - interval '24 hours'", (entity_id, integration),
    ).fetchone()["n"]
    if row is None:
        state = "not_configured"
    elif not row["enabled"]:
        state = "disabled"
    elif t is None or t["config_version"] != row["version"]:
        state = "not_tested"
    elif t["status"] != "pass":
        state = "error"
    elif errors or (row["target"] == "live" and not all(s["set"] for s in secrets.values() if s["required"])):
        state = "warning"
    else:
        state = "connected"
    return {
        "integration": integration, "label": LABELS[integration], "mode": mode,
        "target": row["target"] if row else None, "enabled": row["enabled"] if row else False,
        "version": row["version"] if row else 0, "settings": row["settings"] if row else None,
        "updated_by": row["updated_by"] if row else None,
        "updated_at": row["updated_at"].isoformat() if row else None,
        "secrets": secrets, "errors_24h": errors, "state": state,
        "last_test": {"status": t["status"], "config_version": t["config_version"], "target": t["target"],
                      "finished_at": t["finished_at"].isoformat(), "steps": t["steps"]} if t else None,
    }
