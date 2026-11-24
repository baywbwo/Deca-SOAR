"""Scenario runs (`hypersoar scenario run`): end-to-end checks against a running sandbox stack.

A scenario (scenarios/<id>.yaml) is a short attack written as raw detections. The runner appends them
to the gateway's replay file with raw_ref `synthetic://scenario/<run>/<id>/<n>`, then waits until the
whole pipeline has handled them (gateway case + path, worker triage, broker policy, Lark/Jira/9router
outbox) and compares what it finds with `expect`. The result, every check and how long it took go to
qa.scenario_run, which the Scenarios screen reads.

Sandbox only. Scenario alerts use 203.0.113.208-254 (and 198.51.100.129-254 for the protected case),
which the seeding bot never uses, and fresh AccessKeys and principals per run, so a run never joins a
case of the live feed or of an earlier run. Rate limits and the kill switch are not bypassed: a
scenario that needs a rate-limited action waits for its hourly quota first.
"""

from __future__ import annotations

import os
import secrets
import string
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml
from psycopg.types.json import Jsonb

from hypersoar.common.config import ConfigError

SCENARIO_HOSTS = (208, 254)
PROTECTED_HOSTS = (129, 254)
KINDS = ("pipeline", "connection_test")
EXPECT_KEYS = {"case", "relations", "requests", "ai", "lark", "jira", "connection"}
PLACEHOLDERS = {"ip", "pip", "ak", "svc", "user"}
QUOTA_STATUSES = ("validated", "pending_approval")


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise ConfigError(f"scenarios: {msg}")


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    kind: str
    alerts: tuple = ()
    expect: dict = field(default_factory=dict)
    quota: str | None = None
    timeout_s: int = 180


def parse(doc: dict, filename: str | None = None, detections: dict | None = None) -> Scenario:
    _need(isinstance(doc, dict) and doc.get("version") == 1, f"{filename}: version 1 expected")
    sid = str(doc.get("id", ""))
    _need(sid.replace("-", "").isalnum() and sid == sid.lower() and 0 < len(sid) <= 48, f"{filename}: id")
    _need(filename is None or filename == f"{sid}.yaml", f"{filename}: file name must be <id>.yaml")
    unknown = set(doc) - {"version", "id", "title", "kind", "alerts", "expect", "quota", "timeout_s"}
    _need(not unknown, f"{sid}: unknown keys {sorted(unknown)}")
    kind = doc.get("kind", "pipeline")
    _need(kind in KINDS, f"{sid}: kind")
    _need(isinstance(doc.get("title"), str) and 0 < len(doc["title"]) <= 120, f"{sid}: title")
    expect = doc.get("expect") or {}
    _need(isinstance(expect, dict) and expect and set(expect) <= EXPECT_KEYS, f"{sid}: expect")
    alerts = tuple(doc.get("alerts") or ())
    if kind == "pipeline":
        _need(0 < len(alerts) <= 10, f"{sid}: 1..10 alerts")
        _need("connection" not in expect and "case" in expect, f"{sid}: a pipeline scenario checks its case")
        for a in alerts:
            _need(isinstance(a, dict) and a.get("rule_id") and a.get("source"), f"{sid}: alert needs rule_id, source")
            _need("raw_ref" not in a and "detected_at" not in a, f"{sid}: raw_ref/detected_at are set by the runner")
            if detections is not None:
                _need(a["rule_id"] in detections, f"{sid}: {a['rule_id']} is not in detections/")
            for v in a.values():
                if isinstance(v, str) and "{" in v:
                    names = {f for _, f, _, _ in string.Formatter().parse(v) if f}
                    _need(names <= PLACEHOLDERS, f"{sid}: placeholders are {sorted(PLACEHOLDERS)}")
    else:
        _need(not alerts and set(expect) == {"connection"}, f"{sid}: a connection test has no alerts")
    timeout = int(doc.get("timeout_s", 180))
    _need(10 <= timeout <= 900, f"{sid}: timeout_s 10..900")
    return Scenario(sid, doc["title"], kind, alerts, expect, doc.get("quota"), timeout)


def load_dir(path: Path, detections: dict | None = None) -> dict[str, Scenario]:
    out: dict[str, Scenario] = {}
    for f in sorted(path.glob("*.yaml")):
        s = parse(yaml.safe_load(f.read_text()), f.name, detections)
        _need(s.id not in out, f"duplicate id {s.id}")
        out[s.id] = s
    return out


def scenarios_dir() -> Path:
    return Path(os.environ.get("HYPERSOAR_SCENARIOS_DIR", "scenarios"))


# -- values for one run -------------------------------------------------------------
def run_values(slot: int) -> dict[str, str]:
    """Fresh values per scenario per run. `slot` rotates through the scenario-only IP blocks."""
    lo, hi = SCENARIO_HOSTS
    plo, phi = PROTECTED_HOSTS
    tail = secrets.token_hex(4)
    return {
        "ip": f"203.0.113.{lo + slot % (hi - lo + 1)}",
        "pip": f"198.51.100.{plo + slot % (phi - plo + 1)}",
        "ak": "LTAI5tScn" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(13)),
        "svc": f"svc-scn-{tail}",
        "user": f"m-scn-{tail}",
    }


def render(s: Scenario, run_id: str, values: dict[str, str], now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(UTC)
    out = []
    for i, a in enumerate(s.alerts):
        raw = {k: (v.format(**values) if isinstance(v, str) else v) for k, v in a.items()}
        raw.update(raw_ref=f"synthetic://scenario/{run_id}/{s.id}/{i}",
                   detected_at=(now + timedelta(seconds=i)).isoformat())
        raw.setdefault("truth", "malicious")
        out.append(raw)
    return out


# -- what the pipeline produced -------------------------------------------------------
def observe(conn, entity_id: str, run_id: str, s: Scenario) -> dict:
    prefix = f"synthetic://scenario/{run_id}/{s.id}/"
    alerts = conn.execute(
        "SELECT e.alert_id, e.rule_id, ca.case_id FROM gateway.inbox_event e"
        " LEFT JOIN gateway.case_alert ca ON ca.alert_id = e.alert_id"
        " WHERE e.entity_id = %s AND e.alert->>'raw_ref' LIKE %s ORDER BY e.detected_at",
        (entity_id, prefix + "%"),
    ).fetchall()
    ids = [r["alert_id"] for r in alerts]
    case_ids = sorted({r["case_id"] for r in alerts if r["case_id"]})
    got: dict = {"alerts": len(alerts), "cases": case_ids}
    case_id = case_ids[0] if len(case_ids) == 1 else None
    if case_id:
        c = conn.execute(
            "SELECT category, tactics, alert_count, origin_city, origin_country, status FROM gateway.alert_case"
            " WHERE entity_id = %s AND case_id = %s", (entity_id, case_id)).fetchone()
        got["case"] = {"category": c["category"], "tactics": list(c["tactics"]), "origin": c["origin_city"],
                       "status": c["status"]}
        got["steps"] = [dict(r) for r in conn.execute(
            "SELECT tactic, technique, outcome FROM gateway.case_step WHERE entity_id = %s AND case_id = %s"
            " AND alert_id = ANY(%s) ORDER BY at, alert_id", (entity_id, case_id, ids))]
        got["relations"] = sorted({(r["src_kind"], r["rel"], r["dst_kind"]) for r in conn.execute(
            "SELECT src_kind, rel, dst_kind FROM gateway.entity_relation WHERE entity_id = %s AND case_id = %s",
            (entity_id, case_id))})
        got["lark"] = sorted({r["operation"] for r in conn.execute(
            "SELECT operation FROM broker.integration_call WHERE entity_id = %s AND case_id = %s"
            " AND integration = 'lark' AND status = 'ok'", (entity_id, case_id))})
        got["jira"] = {
            "issues": conn.execute("SELECT count(*) AS n FROM broker.jira_issue WHERE entity_id = %s AND case_id = %s"
                                   " AND issue_key IS NOT NULL", (entity_id, case_id)).fetchone()["n"],
            "creates": conn.execute("SELECT count(*) AS n FROM broker.integration_call WHERE entity_id = %s"
                                    " AND case_id = %s AND operation = 'jira.create'",
                                    (entity_id, case_id)).fetchone()["n"],
        }
    got["ai"] = [{"verdict": r["detail"].get("verdict"), "status": r["status"]} for r in conn.execute(
        "SELECT status, detail FROM broker.integration_call WHERE entity_id = %s AND integration = 'ai'"
        " AND alert_id = ANY(%s) ORDER BY created_at", (entity_id, ids))]
    got["requests"] = [{
        "action": r["action"], "status": r["status"], "level": r["level"], "reasons": r["reasons"],
        "ttl_min": round((r["expires_at"] - r["created_at"]).total_seconds() / 60) if r["expires_at"] else None,
    } for r in conn.execute(
        "SELECT action, status, level, reasons, created_at, expires_at FROM broker.action_request"
        " WHERE entity_id = %s AND alert_id = ANY(%s) ORDER BY created_at", (entity_id, ids))]
    got["triaged"] = len(got["ai"])
    return got


def evaluate(s: Scenario, got: dict) -> list[dict]:
    """One check per expectation: {name, ok, want, got}. Order follows the attack."""
    e = s.expect
    checks: list[dict] = []

    def chk(name, ok, want, have):
        checks.append({"name": name, "ok": bool(ok), "want": want, "got": have})

    n = len(s.alerts)
    chk("all alerts ingested", got["alerts"] == n, n, got["alerts"])
    chk("one case for the attack (G1)", len(got["cases"]) == 1, 1, len(got["cases"]))
    case = got.get("case") or {}
    ec = e.get("case") or {}
    if "category" in ec:
        chk("case category", case.get("category") == ec["category"], ec["category"], case.get("category"))
    if "tactics" in ec:
        have = [st["tactic"] for st in got.get("steps", [])]
        chk("attack path tactics in order (MITRE)", have == ec["tactics"], ec["tactics"], have)
    if "techniques" in ec:
        have = [st["technique"] for st in got.get("steps", [])]
        chk("MITRE techniques", have == ec["techniques"], ec["techniques"], have)
    if "outcomes" in ec:
        have = [st["outcome"] for st in got.get("steps", [])]
        chk("step outcomes", have == ec["outcomes"], ec["outcomes"], have)
    if ec.get("origin"):
        chk("geo origin on the case", bool(case.get("origin")), "a city", case.get("origin"))
    if "relations" in e:
        want = sorted(tuple(r) for r in e["relations"])
        have = got.get("relations", [])
        chk("entity relations (G2)", set(want) <= set(have), want, have)
    chk("every alert triaged", got["triaged"] >= n, n, got["triaged"])
    if "ai" in e:
        want = sorted(e["ai"]["verdicts"])
        have = sorted({a["verdict"] for a in got["ai"]})
        chk("9router verdicts", have == want and all(a["status"] == "ok" for a in got["ai"]), want, have)
    if "requests" in e:
        want = sorted(e["requests"], key=lambda r: (r["action"], r["status"]))
        have = sorted(got["requests"], key=lambda r: (r["action"], r["status"]))
        ok = len(have) == len(want)
        for w, h in zip(want, have):
            ok = ok and h["action"] == w["action"] and h["status"] == w["status"]
            ok = ok and ("level" not in w or h["level"] == w["level"])
            ok = ok and ("reason" not in w or any(w["reason"] in r for r in h["reasons"]))
            ok = ok and ("ttl_min" not in w or (h["ttl_min"] is not None and 0 < h["ttl_min"] <= w["ttl_min"]))
        chk("broker decisions (shadow)", ok, want,
            [{k: v for k, v in h.items() if k != "reasons" or v} for h in have])
    if "lark" in e:
        have = got.get("lark", [])
        chk("Lark messages", set(e["lark"]) <= set(have), e["lark"], have)
    if "jira" in e:
        have = got.get("jira") or {"issues": 0, "creates": 0}
        want = e["jira"]["issues"]
        chk("Jira: one issue per case, never a duplicate", have["issues"] == want and have["creates"] <= want,
            {"issues": want, "creates": f"<= {want}"}, have)
    return checks


# -- running ----------------------------------------------------------------------------
@dataclass
class Result:
    scenario: str
    title: str
    status: str
    checks: list
    got: dict
    duration_ms: int
    note: str = ""

    @property
    def failures(self) -> list:
        return [c for c in self.checks if not c["ok"]]


def quota_free(conn, entity_id: str, action: str, per_hour: int) -> bool:
    n = conn.execute(
        "SELECT count(*) AS n FROM broker.action_request WHERE entity_id = %s AND action = %s"
        " AND status = ANY(%s) AND created_at > now() - interval '1 hour'",
        (entity_id, action, list(QUOTA_STATUSES))).fetchone()["n"]
    return n < per_hour


def killed(conn, entity_id: str, actions: list[str]) -> bool:
    """Same scopes as the broker: global, or one of the actions this scenario expects."""
    r = conn.execute("SELECT bool_or(engaged) AS on FROM broker.kill_switch WHERE entity_id = %s"
                     " AND scope = ANY(%s)", (entity_id, ["global", *actions])).fetchone()
    return bool(r and r["on"])


def run_pipeline(connect, entity_id: str, run_id: str, s: Scenario, slot: int, inject, *,
                 rate_limits: dict, poll_s: float = 2.0, quota_wait_s: float = 2100, log=print,
                 sleep=time.sleep) -> Result:
    t0 = time.monotonic()
    with connect() as conn:
        if killed(conn, entity_id, sorted({r["action"] for r in s.expect.get("requests", [])})):
            return Result(s.id, s.title, "error", [], {}, 0, "kill switch engaged: scenario not run")
    if s.quota:
        per_hour = rate_limits.get(s.quota)
        deadline = time.monotonic() + quota_wait_s
        while per_hour:
            with connect() as conn:
                if quota_free(conn, entity_id, s.quota, per_hour):
                    break
            if time.monotonic() > deadline:
                return Result(s.id, s.title, "error", [], {}, int((time.monotonic() - t0) * 1000),
                              f"{s.quota} hourly quota still taken after {int(quota_wait_s)} s")
            log(f"{s.id}: waiting for the {s.quota} quota ({per_hour}/hour)")
            sleep(30)
    values = run_values(slot)
    inject(render(s, run_id, values))
    t_inject = time.monotonic()
    deadline = t_inject + s.timeout_s
    while True:
        with connect() as conn:
            got = observe(conn, entity_id, run_id, s)
        checks = evaluate(s, got)
        if all(c["ok"] for c in checks) or time.monotonic() > deadline:
            break
        sleep(poll_s)
    status = "pass" if all(c["ok"] for c in checks) else "fail"
    return Result(s.id, s.title, status, checks, got, int((time.monotonic() - t_inject) * 1000))


def run_connection(test_fn, s: Scenario) -> Result:
    t0 = time.monotonic()
    checks, got = [], {}
    for name, want in s.expect["connection"].items():
        r = test_fn(name)
        got[name] = {"status": r["status"],
                     "config_version": r.get("config_version"),
                     "steps": [{"step": st["step"], "ok": st["ok"]} for st in r["steps"]]}
        checks.append({"name": f"{name} connection test", "ok": r["status"] == want, "want": want,
                       "got": r["status"]})
    status = "pass" if all(c["ok"] for c in checks) else "fail"
    return Result(s.id, s.title, status, checks, got, int((time.monotonic() - t0) * 1000))


def record(conn, run_id: str, entity_id: str, r: Result, s: Scenario, started: datetime, git_sha: str | None) -> None:
    conn.execute(
        "INSERT INTO qa.scenario_run (run_id, scenario, entity_id, title, status, expected, got, failures, checks,"
        " duration_ms, git_sha, started_at, finished_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())",
        (run_id, r.scenario, entity_id, r.title, r.status, Jsonb(s.expect), Jsonb({**r.got, "note": r.note}),
         Jsonb(r.failures or ([{"name": "not run", "got": r.note}] if r.status == "error" else [])),
         Jsonb(r.checks), r.duration_ms, (git_sha or "")[:64] or None, started),
    )


def next_slot(conn) -> int:
    return conn.execute("SELECT count(*) AS n FROM qa.scenario_run").fetchone()["n"]


def new_run_id() -> str:
    return str(uuid.uuid4())
