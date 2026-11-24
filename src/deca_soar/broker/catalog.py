"""Action catalog and protected-target list, loaded from policy/*.yaml and checked strictly at startup."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

LEVELS = ("L0", "L1", "L2", "L3")
MODES = ("auto", "approval")
VERDICTS = ("benign", "suspicious", "malicious", "unknown")
SEVERITIES = ("info", "low", "medium", "high", "critical")
SOURCES = ("waf", "actiontrail", "sas", "internal")
PARAM_TYPES = ("string", "int", "token")
TOKEN_KINDS = ("ip", "user", "ak")


class CatalogError(ValueError):
    pass


@dataclass(frozen=True)
class ParamSpec:
    name: str
    type: str
    required: bool = False
    kind: str | None = None
    max_len: int | None = None
    pattern: re.Pattern | None = None
    min: int | None = None
    max: int | None = None
    default: object = None


@dataclass(frozen=True)
class ActionSpec:
    id: str
    level: str
    mode: str
    sources: tuple[str, ...]
    params: dict[str, ParamSpec]
    allowed_verdicts: tuple[str, ...]
    min_confidence: float
    max_severity: str | None = None
    target_param: str | None = None
    target_kind: str | None = None
    rate_per_hour: int | None = None
    rate_scope_param: str | None = None
    rollback: str | None = None

    def public(self) -> dict:
        return {
            "id": self.id,
            "level": self.level,
            "target_mode": self.mode,
            "effective_mode": "shadow",
            "sources": list(self.sources),
            "params": {
                n: {k: v for k, v in {
                    "type": p.type, "required": p.required, "kind": p.kind, "max_len": p.max_len,
                    "pattern": p.pattern.pattern if p.pattern else None, "min": p.min, "max": p.max,
                    "default": p.default,
                }.items() if v is not None}
                for n, p in self.params.items()
            },
            "allowed_verdicts": list(self.allowed_verdicts),
            "min_confidence": self.min_confidence,
            "max_severity": self.max_severity,
            "rate_limit_per_hour": self.rate_per_hour,
            "rollback": self.rollback,
        }


@dataclass(frozen=True)
class ProtectedEntry:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    label: str
    placeholder: bool


@dataclass(frozen=True)
class Protected:
    networks: tuple[ProtectedEntry, ...] = ()
    principals: frozenset[str] = field(default_factory=frozenset)

    @property
    def has_placeholders(self) -> bool:
        return any(e.placeholder for e in self.networks)


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise CatalogError(msg)


def _param(action_id: str, name: str, raw: dict) -> ParamSpec:
    where = f"{action_id}.params.{name}"
    _need(isinstance(raw, dict), f"{where}: must be a mapping")
    unknown = set(raw) - {"type", "required", "kind", "max_len", "pattern", "min", "max", "default"}
    _need(not unknown, f"{where}: unknown keys {sorted(unknown)}")
    ptype = raw.get("type")
    _need(ptype in PARAM_TYPES, f"{where}: type must be one of {PARAM_TYPES}")
    kind = raw.get("kind")
    if ptype == "token":
        _need(kind in TOKEN_KINDS, f"{where}: token params need kind in {TOKEN_KINDS}")
    if ptype == "string":
        _need(isinstance(raw.get("max_len"), int), f"{where}: string params need max_len")
        _need(isinstance(raw.get("pattern"), str), f"{where}: string params need a pattern")
    if ptype == "int":
        _need(isinstance(raw.get("min"), int) and isinstance(raw.get("max"), int), f"{where}: int needs min/max")
    return ParamSpec(
        name=name,
        type=ptype,
        required=bool(raw.get("required", False)),
        kind=kind,
        max_len=raw.get("max_len"),
        pattern=re.compile(raw["pattern"]) if raw.get("pattern") else None,
        min=raw.get("min"),
        max=raw.get("max"),
        default=raw.get("default"),
    )


def parse_catalog(doc: dict) -> dict[str, ActionSpec]:
    _need(isinstance(doc, dict) and doc.get("version") == 1, "catalog: version 1 expected")
    actions = doc.get("actions")
    _need(isinstance(actions, dict) and actions, "catalog: actions missing")
    out: dict[str, ActionSpec] = {}
    for aid, a in actions.items():
        _need(re.fullmatch(r"[a-z0-9_]+(\.[a-z0-9_]+)+", aid) is not None, f"{aid}: invalid action id")
        _need(isinstance(a, dict), f"{aid}: must be a mapping")
        _need(a.get("level") in LEVELS, f"{aid}: level")
        _need(a.get("mode") in MODES, f"{aid}: mode")
        sources = tuple(a.get("sources") or ())
        _need(bool(sources) and all(s in SOURCES for s in sources), f"{aid}: sources")
        verdicts = tuple(a.get("allowed_verdicts") or ())
        _need(bool(verdicts) and all(v in VERDICTS for v in verdicts), f"{aid}: allowed_verdicts")
        conf = a.get("min_confidence")
        _need(isinstance(conf, (int, float)) and 0 <= conf <= 1, f"{aid}: min_confidence")
        max_sev = a.get("max_severity")
        _need(max_sev is None or max_sev in SEVERITIES, f"{aid}: max_severity")
        params = {n: _param(aid, n, p) for n, p in (a.get("params") or {}).items()}
        target = a.get("target")
        tparam = tkind = None
        if target is not None:
            tparam, tkind = target.get("param"), target.get("kind")
            _need(tparam in params and params[tparam].type == "token", f"{aid}: target must be a token param")
            _need(params[tparam].kind == tkind and params[tparam].required, f"{aid}: target kind/required")
        # Every L1+ action touching a principal/IP must name its target so evidence checks apply.
        for p in params.values():
            if p.type == "token":
                _need(p.name == tparam, f"{aid}: token param {p.name} must be the declared target")
        rate = a.get("rate_limit")
        per_hour = scope = None
        if rate is not None:
            per_hour, scope = rate.get("per_hour"), rate.get("scope_param")
            _need(isinstance(per_hour, int) and per_hour > 0, f"{aid}: rate_limit.per_hour")
            _need(scope is None or scope in params, f"{aid}: rate_limit.scope_param")
        _need(a["level"] == "L0" or rate is not None, f"{aid}: L1+ actions need a rate limit")
        _need(a["level"] in ("L0", "L1") or a["mode"] == "approval", f"{aid}: L2+ actions must require approval")
        out[aid] = ActionSpec(
            id=aid,
            level=a["level"],
            mode=a["mode"],
            sources=sources,
            params=params,
            allowed_verdicts=verdicts,
            min_confidence=float(conf),
            max_severity=max_sev,
            target_param=tparam,
            target_kind=tkind,
            rate_per_hour=per_hour,
            rate_scope_param=scope,
            rollback=a.get("rollback"),
        )
    return out


def parse_protected(doc: dict) -> Protected:
    _need(isinstance(doc, dict) and doc.get("version") == 1, "protected: version 1 expected")
    nets = []
    for e in doc.get("ip_cidrs") or []:
        try:
            net = ipaddress.ip_network(str(e["cidr"]), strict=True)
        except (KeyError, ValueError) as err:
            raise CatalogError(f"protected: invalid cidr entry {e!r}") from err
        nets.append(ProtectedEntry(net, str(e.get("label", "")), bool(e.get("placeholder", False))))
    principals = frozenset(str(p) for p in (doc.get("principals") or []))
    return Protected(tuple(nets), principals)


def load(policy_dir: Path) -> tuple[dict[str, ActionSpec], Protected]:
    with open(policy_dir / "actions.yaml") as f:
        catalog = parse_catalog(yaml.safe_load(f))
    with open(policy_dir / "protected.yaml") as f:
        protected = parse_protected(yaml.safe_load(f))
    return catalog, protected
