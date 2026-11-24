"""Deterministic request validation (design 6.3 item 2). Pure functions: no DB, no network.

The service layer feeds in the alert as the gateway stored it and the revealed target value;
everything the caller (the workflow worker, the LLM) supplies is treated as untrusted.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from hypersoar.broker.catalog import SEVERITIES, VERDICTS, ActionSpec, Protected
from hypersoar.common.pii import canonical_ip

DECISION_SOURCES = ("rule", "llm")
TOKEN_KIND_RE = re.compile(r"^tok_([a-z]+)_[0-9a-f]{16}$")
# RFC 5737 / RFC 3849 documentation ranges. Not globally routable, so rejected as block targets,
# except in tests and the disposable e2e stack (never with HYPERSOAR_ENV=production).
TEST_NETS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


@dataclass
class AlertView:
    alert_id: str
    source: str
    severity_hint: str
    evidence_tokens: frozenset[str]


@dataclass
class Decision:
    verdict: str
    confidence: float
    source: str


@dataclass
class StaticResult:
    params: dict = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    target_token: str | None = None

    @property
    def ok(self) -> bool:
        return not self.reasons


def check_params(spec: ActionSpec, raw: dict) -> tuple[dict, list[str]]:
    out: dict = {}
    reasons: list[str] = []
    if not isinstance(raw, dict):
        return {}, ["params must be an object"]
    for name in sorted(set(raw) - set(spec.params)):
        reasons.append(f"param {name[:40]!r} not allowed")
    for name, p in spec.params.items():
        if name not in raw or raw[name] is None:
            if p.required:
                reasons.append(f"param {name} required")
            elif p.default is not None:
                out[name] = p.default
            continue
        v = raw[name]
        if p.type == "int":
            if isinstance(v, bool) or not isinstance(v, int):
                reasons.append(f"param {name} must be an integer")
            elif not (p.min <= v <= p.max):
                reasons.append(f"param {name} out of range [{p.min}, {p.max}]")
            else:
                out[name] = v
        elif p.type == "string":
            if not isinstance(v, str) or len(v) > p.max_len or not p.pattern.fullmatch(v):
                reasons.append(f"param {name} invalid")
            else:
                out[name] = v
        elif p.type == "token":
            m = TOKEN_KIND_RE.match(v) if isinstance(v, str) else None
            if m is None:
                reasons.append(f"param {name} must be a token")
            elif m.group(1) != p.kind:
                reasons.append(f"param {name} must be a {p.kind} token")
            else:
                out[name] = v
    return out, reasons


def check_static(spec: ActionSpec, alert: AlertView, decision: Decision, raw_params: dict) -> StaticResult:
    """Every check that needs neither the vault nor the database."""
    res = StaticResult()
    if alert.source not in spec.sources:
        res.reasons.append(f"action not allowed for source {alert.source}")
    if decision.verdict not in VERDICTS or decision.source not in DECISION_SOURCES:
        res.reasons.append("decision invalid")
    elif decision.verdict not in spec.allowed_verdicts:
        res.reasons.append(f"verdict {decision.verdict} not allowed for this action")
    if not (0.0 <= decision.confidence <= 1.0):
        res.reasons.append("confidence out of range")
    elif decision.confidence < spec.min_confidence:
        res.reasons.append(f"confidence below {spec.min_confidence}")
    if spec.max_severity is not None and (
        alert.severity_hint not in SEVERITIES
        or SEVERITIES.index(alert.severity_hint) > SEVERITIES.index(spec.max_severity)
    ):
        res.reasons.append(f"alert severity above {spec.max_severity}")
    res.params, preasons = check_params(spec, raw_params)
    res.reasons.extend(preasons)
    if spec.target_param and spec.target_param in res.params:
        tok = res.params[spec.target_param]
        # The target must come from the source log, not from text the LLM wrote (design 6.3).
        if tok not in alert.evidence_tokens:
            res.reasons.append("target not in alert evidence")
        else:
            res.target_token = tok
    return res


def check_target(
    kind: str,
    value: str | None,
    protected: Protected,
    internal_cidrs: list,
    *,
    allow_test_nets: bool = False,
) -> list[str]:
    """Checks on the real (detokenised) target. Reasons never include the value itself."""
    if value is None:
        return ["target token unknown to vault"]
    if kind == "ip":
        try:
            ip = canonical_ip(value)
        except ValueError:
            return ["target is not an IP address"]
        # Protected first, so a protected address is reported as such whatever else it is.
        for e in protected.networks:
            if ip.version == e.network.version and ip in e.network:
                return [f"target is protected ({e.label[:60]})"]
        if (
            ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local or ip.is_reserved
            or any(ip.version == net.version and ip in net for net in internal_cidrs)
        ):
            return ["target is an internal or special-purpose address"]
        test_net = allow_test_nets and any(ip.version == n.version and ip in n for n in TEST_NETS)
        if not ip.is_global and not test_net:
            return ["target is not a globally routable address"]
        return []
    if kind in ("user", "ak"):
        return ["target is a protected principal"] if value in protected.principals else []
    return ["unsupported target kind"]


def rate_scope(spec: ActionSpec, params: dict) -> str:
    if spec.rate_scope_param:
        return f"{spec.id}:{params.get(spec.rate_scope_param, '')}"
    return spec.id


def would_execute(spec: ActionSpec, params: dict) -> str:
    """Human-readable intent with tokens only; the real value is never written to the record."""
    args = ", ".join(f"{k}={params[k]}" for k in sorted(params))
    return f"{spec.id}({args})"
