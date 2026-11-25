"""Broker role model (design 6.9). Roles are cumulative; service principals never approve or flip the kill switch."""

from __future__ import annotations

from dataclasses import dataclass

ROLES = ("viewer", "analyst", "approver", "admin")

READ = "read"
REQUEST_ACTION = "request_action"
APPROVE = "approve"
KILL_SWITCH = "kill_switch"
MANAGE = "manage_principals"
TRIAGE = "triage_case"  # assign, change status, comment

_GRANTS = {
    "viewer": {READ},
    "analyst": {READ, REQUEST_ACTION, TRIAGE},
    "approver": {READ, REQUEST_ACTION, TRIAGE, APPROVE},
    "admin": {READ, REQUEST_ACTION, TRIAGE, APPROVE, KILL_SWITCH, MANAGE},
}
# Machines (the workflow worker, the agent) have no approver identity (design 6.3 item 6), and
# case triage is a person's call.
_HUMAN_ONLY = {APPROVE, KILL_SWITCH, MANAGE, TRIAGE}


@dataclass(frozen=True)
class Principal:
    principal_id: str
    name: str
    kind: str  # service | human
    role: str
    # Where this credential is used: 'console' is the console's own principal token for one person,
    # 'api' is any other caller. Only 'console' may approve L3 (service._decide).
    channel: str = "api"


def allowed(p: Principal, permission: str) -> bool:
    if p.role not in _GRANTS:
        return False
    if p.kind != "human" and permission in _HUMAN_ONLY:
        return False
    return permission in _GRANTS[p.role]


def can_approve(approver: Principal, requested_by: str) -> bool:
    return allowed(approver, APPROVE) and approver.principal_id != requested_by


def matrix() -> dict[str, dict[str, list[str]]]:
    perms = (READ, REQUEST_ACTION, TRIAGE, APPROVE, KILL_SWITCH, MANAGE)
    return {
        kind: {r: [x for x in perms if allowed(Principal("", "", kind, r), x)] for r in ROLES}
        for kind in ("human", "service")
    }
