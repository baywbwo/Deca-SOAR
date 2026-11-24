"""Detections as code (G3): detections/<rule_id>.yaml maps a rule to its category, severity, MITRE
tactic/technique and the entity path it describes. The gateway takes these from the catalog, never
from the raw alert, and CI checks every file (tests/test_detections.py)."""

from __future__ import annotations

import os
import re
import string
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from hypersoar.common.config import ConfigError

SEVERITIES = ("info", "low", "medium", "high", "critical")
SOURCES = ("waf", "actiontrail", "sas", "internal")
KINDS = ("ip", "user", "ak", "asset")
RELS = ("targets", "authenticates_as", "uses_key", "owns_key", "moves_to")
OUTCOMES = ("attempted", "allowed", "blocked")
STEP_FIELDS = frozenset({"events", "asset", "ak"})
RULE_ID_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")
TACTIC_RE = re.compile(r"^TA00(0[1-9]|1[01]|4[023])$")
TECHNIQUE_RE = re.compile(r"^T1[0-9]{3}(\.[0-9]{3})?$")
# MITRE ATT&CK enterprise tactics in kill-chain order; the attack path lays out columns in this order.
TACTICS = {
    "TA0043": "Reconnaissance", "TA0042": "Resource development", "TA0001": "Initial access",
    "TA0002": "Execution", "TA0003": "Persistence", "TA0004": "Privilege escalation",
    "TA0005": "Defense evasion", "TA0006": "Credential access", "TA0007": "Discovery",
    "TA0008": "Lateral movement", "TA0009": "Collection", "TA0011": "Command and control",
    "TA0010": "Exfiltration", "TA0040": "Impact",
}
TACTIC_ORDER = {t: i for i, t in enumerate(TACTICS)}


@dataclass(frozen=True)
class Detection:
    id: str
    title: str
    category: str
    source: str
    severity: str
    tactic: str
    tactic_name: str
    technique: str
    technique_name: str
    path_from: str
    rel: str
    path_to: str
    outcome: str
    step: str
    tests: tuple = ()

    def step_title(self, *, events: int, asset: str | None, ak: str | None) -> str:
        return self.step.format(events=f"{events:,}", asset=asset or "an asset", ak=ak or "an AccessKey")[:200]

    def mitre(self) -> dict:
        return {"tactic": self.tactic, "tactic_name": self.tactic_name, "technique": self.technique,
                "technique_name": self.technique_name}


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise ConfigError(f"detections: {msg}")


def parse(doc: dict, filename: str | None = None) -> Detection:
    _need(isinstance(doc, dict) and doc.get("version") == 1, f"{filename}: version 1 expected")
    rid = str(doc.get("id", ""))
    _need(RULE_ID_RE.match(rid) is not None and len(rid) <= 64, f"{filename}: invalid id")
    _need(filename is None or filename == f"{rid}.yaml", f"{filename}: file name must be <id>.yaml")
    unknown = set(doc) - {"version", "id", "title", "category", "source", "severity", "mitre", "path",
                          "outcome", "step", "tests"}
    _need(not unknown, f"{rid}: unknown keys {sorted(unknown)}")
    _need(doc.get("source") in SOURCES, f"{rid}: source")
    _need(rid.split(".")[0] == doc["source"], f"{rid}: id must start with its source")
    _need(doc.get("severity") in SEVERITIES, f"{rid}: severity")
    for k in ("title", "category", "step"):
        _need(isinstance(doc.get(k), str) and 0 < len(doc[k]) <= 120, f"{rid}: {k}")
    m = doc.get("mitre") or {}
    _need(TACTIC_RE.match(str(m.get("tactic", ""))) is not None and m["tactic"] in TACTICS, f"{rid}: mitre.tactic")
    _need(m.get("tactic_name") == TACTICS[m["tactic"]], f"{rid}: mitre.tactic_name must be {TACTICS[m['tactic']]}")
    _need(TECHNIQUE_RE.match(str(m.get("technique", ""))) is not None, f"{rid}: mitre.technique")
    _need(isinstance(m.get("technique_name"), str) and m["technique_name"], f"{rid}: mitre.technique_name")
    p = doc.get("path") or {}
    _need(p.get("from") in KINDS and p.get("to") in KINDS and p.get("rel") in RELS, f"{rid}: path")
    _need(p["from"] != "asset", f"{rid}: a path starts at an actor (ip, user or ak), not an asset")
    _need(doc.get("outcome") in OUTCOMES, f"{rid}: outcome")
    fields = {f for _, f, _, _ in string.Formatter().parse(doc["step"]) if f}
    _need(fields <= STEP_FIELDS, f"{rid}: step may only use {sorted(STEP_FIELDS)}")
    tests = tuple(doc.get("tests") or ())
    _need(len(tests) >= 1, f"{rid}: at least one test fixture")
    for t in tests:
        _need(isinstance(t, dict) and isinstance(t.get("raw"), dict) and isinstance(t.get("expect"), dict),
              f"{rid}: tests need raw and expect")
        _need(t["raw"].get("rule_id") == rid and t["raw"].get("source") == doc["source"],
              f"{rid}: fixture must use this rule and source")
    return Detection(
        id=rid, title=doc["title"], category=doc["category"], source=doc["source"], severity=doc["severity"],
        tactic=m["tactic"], tactic_name=m["tactic_name"], technique=m["technique"],
        technique_name=m["technique_name"], path_from=p["from"], rel=p["rel"], path_to=p["to"],
        outcome=doc["outcome"], step=doc["step"], tests=tests,
    )


def load_dir(path: Path) -> dict[str, Detection]:
    out: dict[str, Detection] = {}
    for f in sorted(path.glob("*.yaml")):
        d = parse(yaml.safe_load(f.read_text()), f.name)
        _need(d.id not in out, f"duplicate id {d.id}")
        out[d.id] = d
    return out


@lru_cache(maxsize=4)
def load(path: str | None = None) -> dict[str, Detection]:
    p = Path(path or os.environ.get("HYPERSOAR_DETECTIONS_DIR", "detections"))
    return load_dir(p) if p.is_dir() else {}
