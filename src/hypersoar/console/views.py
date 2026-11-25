"""Per-screen data for the v3 console, read through the deca_soar_viewer login only.

Every value leaving here is either a catalog field, a count, a timestamp or a token: IPs, principals and
AccessKeys stay tokenised (`ip_…`, `user_…`, `ak_…`) exactly as the gateway stored them. Free text is
clipped. Nothing in this module writes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from hypersoar.console.queries import SEVERITY_ORDER, _clip, _iso

WINDOWS = {"15m": "15 minutes", "1h": "1 hour", "24h": "24 hours"}
MAX_ARCS = 200
FEED = 18
CASE_LIST = 50
SEV_BUCKET = {"critical": "hi", "high": "hi", "medium": "md", "low": "lo", "info": "lo"}
KEY_LABEL = {"ip": "source IP", "user": "principal", "ak": "AccessKey"}
LEVEL_TEXT = {"L0": "Automatic", "L1": "Automatic, reversible", "L2": "Needs approval", "L3": "Needs signature"}


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _f(v) -> float | None:
    return None if v is None else float(v)


# -- shell: header, mode bar, footer ----------------------------------------------------------------
def install(conn) -> dict:
    r = conn.execute("SELECT mode, entity_id FROM public.hypersoar_install").fetchone()
    return {"mode": r["mode"], "entity_id": r["entity_id"]} if r else {"mode": "sandbox", "entity_id": None}


def shell(conn, inst: dict) -> dict:
    e = inst["entity_id"]
    n = conn.execute(
        "SELECT (SELECT count(*) FROM gateway.alert_case WHERE entity_id = %(e)s AND status <> 'closed') AS open_cases,"
        " (SELECT count(*) FROM broker.action_request WHERE entity_id = %(e)s AND status = 'pending_approval'"
        "   AND (expires_at IS NULL OR expires_at > now())) AS pending,"
        " (SELECT max(ingested_at) FROM gateway.inbox_event WHERE entity_id = %(e)s) AS last_ingest",
        {"e": e}).fetchone()
    ai = conn.execute(
        "SELECT target, settings ->> 'triage_model' AS model FROM broker.integration_config"
        " WHERE entity_id = %s AND integration = 'ai' AND mode = %s", (e, inst["mode"])).fetchone()
    return {
        "open_cases": n["open_cases"], "pending": n["pending"], "last_ingest": _iso(n["last_ingest"]),
        "ai": {"target": ai["target"], "model": _clip(ai["model"], 40)} if ai else None,
    }


# -- integrations: status for overview, automation, header --------------------------------------------
def integrations(conn, inst: dict) -> list[dict]:
    e, mode = inst["entity_id"], inst["mode"]
    rows = conn.execute(
        "SELECT c.integration, c.target, c.enabled, c.version, c.settings,"
        " t.status AS test_status, t.finished_at AS tested_at, t.config_version AS tested_version,"
        " l.created_at AS last_call_at, l.operation AS last_op, l.status AS last_status, l.external_ref,"
        " (SELECT count(*) FROM broker.integration_call x WHERE x.entity_id = c.entity_id"
        "   AND x.integration = c.integration AND x.status = 'error' AND x.created_at > now() - interval '24 hours')"
        "   AS errors_24h,"
        " (SELECT count(*) FROM broker.integration_call x WHERE x.entity_id = c.entity_id"
        "   AND x.integration = c.integration AND x.created_at > now() - interval '24 hours') AS calls_24h,"
        " (SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) FROM broker.integration_call x"
        "   WHERE x.entity_id = c.entity_id AND x.integration = c.integration AND x.duration_ms IS NOT NULL"
        "   AND x.created_at > now() - interval '24 hours') AS p95_ms"
        " FROM broker.integration_config c"
        " LEFT JOIN LATERAL (SELECT status, finished_at, config_version FROM broker.integration_test_run r"
        "   WHERE r.entity_id = c.entity_id AND r.integration = c.integration AND r.mode = c.mode"
        "   ORDER BY finished_at DESC LIMIT 1) t ON true"
        " LEFT JOIN LATERAL (SELECT created_at, operation, status, external_ref FROM broker.integration_call x"
        "   WHERE x.entity_id = c.entity_id AND x.integration = c.integration ORDER BY created_at DESC LIMIT 1) l"
        "   ON true"
        " WHERE c.entity_id = %s AND c.mode = %s ORDER BY array_position(ARRAY['lark','jira','ai'], c.integration), c.integration",
        (e, mode)).fetchall()
    out = []
    for r in rows:
        s = r["settings"] or {}
        if r["integration"] == "lark":
            chats = {v.get("chat_name") for v in (s.get("routing") or {}).values() if isinstance(v, dict)}
            detail = ", ".join(sorted(c for c in chats if c)) or "no chat set"
        elif r["integration"] == "jira":
            detail = f"Project {s.get('project', '?')}"
        elif r["integration"] == "webhook":
            detail = f"Signed webhook (HMAC), {s.get('source_type', 'siem')} alerts"
        elif r["integration"] == "syslog":
            detail = f"Syslog CEF from {len(s.get('allowed_senders') or [])} allowed network(s)"
        elif r["integration"] == "sls":
            detail = f"Alibaba Cloud SLS {s.get('project', '?')}/{s.get('logstore', '?')}"
        else:
            detail = s.get("triage_model") or "no model set"
        tested_ok = r["test_status"] == "pass" and r["tested_version"] == r["version"]
        health = ("off" if not r["enabled"] else "error" if r["errors_24h"] and r["last_status"] == "error"
                  else "healthy" if tested_ok or r["last_status"] in ("ok", "duplicate") else "untested")
        out.append({
            "name": r["integration"], "target": r["target"], "enabled": r["enabled"], "health": health,
            "detail": _clip(detail, 80), "version": r["version"],
            "tested": None if r["test_status"] is None else {"status": r["test_status"], "at": _iso(r["tested_at"]),
                                                             "version": r["tested_version"]},
            "last_call": None if r["last_call_at"] is None else {
                "at": _iso(r["last_call_at"]), "op": _clip(r["last_op"], 40), "status": r["last_status"],
                "ref": _clip(r["external_ref"], 40)},
            "calls_24h": r["calls_24h"], "errors_24h": r["errors_24h"],
            "p95_ms": None if r["p95_ms"] is None else int(r["p95_ms"]),
        })
    return out


# -- overview --------------------------------------------------------------------------------------------
def overview(conn, inst: dict) -> dict:
    e = inst["entity_id"]
    s = conn.execute(
        "SELECT"
        " (SELECT count(*) FROM gateway.inbox_event WHERE entity_id = %(e)s"
        "   AND ingested_at > now() - interval '24 hours') AS alerts_24h,"
        " (SELECT coalesce(sum(event_count), 0) FROM gateway.inbox_event WHERE entity_id = %(e)s"
        "   AND ingested_at > now() - interval '24 hours') AS events_24h,"
        " (SELECT count(*) FROM gateway.inbox_event WHERE entity_id = %(e)s"
        "   AND ingested_at > now() - interval '1 hour') AS alerts_1h,"
        " (SELECT count(*) FROM gateway.alert_case WHERE entity_id = %(e)s AND status <> 'closed') AS open_cases,"
        " (SELECT count(*) FROM gateway.alert_case WHERE entity_id = %(e)s AND status <> 'closed'"
        "   AND max_severity = 'critical') AS critical_cases,"
        " (SELECT coalesce(sum(alert_count), 0) FROM gateway.alert_case WHERE entity_id = %(e)s"
        "   AND status <> 'closed') AS alerts_in_open,"
        " (SELECT count(*) FROM gateway.alert_case WHERE entity_id = %(e)s"
        "   AND opened_at > now() - interval '24 hours') AS cases_24h,"
        " (SELECT count(*) FROM broker.decision_record WHERE entity_id = %(e)s"
        "   AND created_at > now() - interval '24 hours') AS decisions_24h,"
        " (SELECT count(*) FROM broker.action_request WHERE entity_id = %(e)s"
        "   AND created_at > now() - interval '24 hours' AND status = 'rejected') AS blocked_24h,"
        " (SELECT count(*) FROM broker.action_request WHERE entity_id = %(e)s"
        "   AND created_at > now() - interval '24 hours' AND status = 'executed') AS executed_24h,"
        " (SELECT count(*) FROM broker.action_request WHERE entity_id = %(e)s AND status = 'pending_approval'"
        "   AND (expires_at IS NULL OR expires_at > now())) AS pending,"
        " (SELECT min(created_at) FROM broker.action_request WHERE entity_id = %(e)s"
        "   AND status = 'pending_approval' AND (expires_at IS NULL OR expires_at > now())) AS oldest_pending,"
        " (SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM d.created_at - i.ingested_at))"
        "   FROM broker.decision_record d JOIN gateway.inbox_event i USING (alert_id)"
        "   WHERE d.entity_id = %(e)s AND d.created_at > now() - interval '24 hours') AS median_verdict_s",
        {"e": e}).fetchone()
    stats = {k: (_iso(v) if isinstance(v, datetime) else _f(v) if k == "median_verdict_s" else v)
             for k, v in dict(s).items()}
    return {"stats": stats, "open_cases": case_list(conn, inst, "open", limit=6),
            "integrations": integrations(conn, inst)}


# -- threat map ------------------------------------------------------------------------------------------
def threat_map(conn, inst: dict, window: str) -> dict:
    e, span = inst["entity_id"], WINDOWS[window]
    arcs = conn.execute(
        "SELECT i.alert_id, i.ingested_at, i.rule_id, i.severity_hint, i.alert -> 'origin' AS origin,"
        " i.alert -> 'entities' ->> 'dst_asset' AS asset, i.alert ->> 'category' AS category, a.case_id"
        " FROM gateway.inbox_event i LEFT JOIN gateway.case_alert a USING (alert_id)"
        " WHERE i.entity_id = %s AND i.ingested_at > now() - %s::interval"
        " AND jsonb_typeof(i.alert -> 'origin' -> 'xy') = 'array'"
        " ORDER BY i.ingested_at DESC LIMIT %s", (e, span, MAX_ARCS)).fetchall()
    total = conn.execute(
        "SELECT count(*) AS n, count(*) FILTER (WHERE jsonb_typeof(alert -> 'origin' -> 'xy') = 'array') AS placed"
        " FROM gateway.inbox_event WHERE entity_id = %s AND ingested_at > now() - %s::interval",
        (e, span)).fetchone()
    origins = conn.execute(
        "SELECT i.alert -> 'origin' ->> 'city' AS city, (array_agg(i.alert -> 'origin'))[1] AS origin,"
        " count(*) AS n, count(*) FILTER (WHERE i.severity_hint IN ('high', 'critical')) AS hi,"
        " count(*) FILTER (WHERE i.severity_hint = 'medium') AS md,"
        " array_remove(array_agg(DISTINCT a.case_id), NULL) AS cases"
        " FROM gateway.inbox_event i LEFT JOIN gateway.case_alert a USING (alert_id)"
        " WHERE i.entity_id = %s AND i.ingested_at > now() - %s::interval"
        " AND jsonb_typeof(i.alert -> 'origin' -> 'xy') = 'array'"
        " GROUP BY 1 ORDER BY n DESC, city LIMIT 40", (e, span)).fetchall()
    case_ids = sorted({c for o in origins for c in o["cases"]})
    cases = {r["case_id"]: r for r in conn.execute(
        "SELECT case_id, title, max_severity, priority, status FROM gateway.alert_case"
        " WHERE entity_id = %s AND case_id = ANY(%s)", (e, case_ids)).fetchall()} if case_ids else {}
    cats = conn.execute(
        "SELECT coalesce(alert ->> 'category', 'Uncatalogued') AS category, count(*) AS n,"
        " max(array_position(%s::text[], severity_hint)) AS sev"
        " FROM gateway.inbox_event WHERE entity_id = %s AND ingested_at > now() - %s::interval"
        " GROUP BY 1 ORDER BY n DESC LIMIT 6", (list(SEVERITY_ORDER), e, span)).fetchall()
    assets = conn.execute(
        "SELECT alert -> 'entities' ->> 'dst_asset' AS asset, count(*) AS n,"
        " count(*) FILTER (WHERE severity_hint IN ('high', 'critical')) AS hi"
        " FROM gateway.inbox_event WHERE entity_id = %s AND ingested_at > now() - %s::interval"
        " AND alert -> 'entities' ->> 'dst_asset' IS NOT NULL GROUP BY 1 ORDER BY n DESC LIMIT 5",
        (e, span)).fetchall()
    cat_total = sum(c["n"] for c in cats) or 1

    def org(o: dict | None) -> dict:
        o = o or {}
        xy = o.get("xy") or [0, 0]
        return {"city": _clip(o.get("city"), 40), "country": _clip(o.get("country"), 4),
                "asn": _clip(o.get("asn"), 16), "as_name": _clip(o.get("as_name"), 40), "tor": bool(o.get("tor")),
                "xy": [float(xy[0]), float(xy[1])]}

    return {
        "window": window, "total": total["n"], "placed": total["placed"],
        "arcs": [{"id": str(r["alert_id"]), "at": _iso(r["ingested_at"]), "rule": _clip(r["rule_id"], 80),
                  "sev": r["severity_hint"], "asset": _clip(r["asset"], 60), "case_id": r["case_id"],
                  **{k: v for k, v in org(r["origin"]).items() if k in ("city", "xy", "asn")}}
                 for r in arcs],
        "origins": [{**org(o["origin"]), "n": o["n"], "hi": o["hi"], "md": o["md"],
                     "cases": [{"case_id": c, "title": _clip(cases[c]["title"], 120), "sev": cases[c]["max_severity"],
                                "status": cases[c]["status"]} for c in o["cases"] if c in cases][:8]}
                    for o in origins],
        "categories": [{"category": _clip(c["category"], 60), "n": c["n"], "pct": round(100 * c["n"] / cat_total),
                        "sev": SEVERITY_ORDER[c["sev"] - 1] if c["sev"] else "info"} for c in cats],
        "assets": [{"asset": _clip(a["asset"], 60), "n": a["n"], "hi": a["hi"]} for a in assets],
    }


def feed(conn, inst: dict, limit: int = FEED) -> list[dict]:
    rows = conn.execute(
        "SELECT i.alert_id, i.ingested_at, i.rule_id, i.severity_hint, i.alert -> 'origin' ->> 'city' AS city,"
        " i.alert -> 'entities' ->> 'src_ip' AS src, i.alert -> 'entities' ->> 'dst_asset' AS asset, a.case_id"
        " FROM gateway.inbox_event i LEFT JOIN gateway.case_alert a USING (alert_id)"
        " WHERE i.entity_id = %s ORDER BY i.ingested_at DESC LIMIT %s", (inst["entity_id"], limit)).fetchall()
    return [{"id": str(r["alert_id"]), "at": _iso(r["ingested_at"]), "rule": _clip(r["rule_id"], 80),
             "sev": r["severity_hint"], "city": _clip(r["city"], 40), "src": _clip(r["src"], 16),
             "asset": _clip(r["asset"], 60), "case_id": r["case_id"]} for r in rows]


# -- cases -----------------------------------------------------------------------------------------------
def case_list(conn, inst: dict, status: str, limit: int = CASE_LIST) -> list[dict]:
    """open (everything not closed), waiting (set by an analyst, or open with a request pending approval)
    or closed."""
    where = {"open": "c.status <> 'closed'", "closed": "c.status = 'closed'",
             "waiting": "(c.status = 'waiting' OR (c.status = 'open' AND p.pending > 0))"}[status]
    rows = conn.execute(
        "SELECT c.case_id, c.title, c.category, c.status, c.max_severity, c.criticality, c.priority,"
        " c.alert_count, c.event_count, c.primary_kind, c.primary_value, c.origin_city, c.opened_at,"
        " c.last_seen_at, c.closed_at, c.close_reason, c.tactics, c.assignee, j.issue_key,"
        " coalesce(p.pending, 0) AS pending,"
        " d.verdict, d.confidence, r.action, r.status AS req_status, r.level"
        " FROM gateway.alert_case c"
        " LEFT JOIN broker.jira_issue j ON j.entity_id = c.entity_id AND j.case_id = c.case_id"
        " LEFT JOIN LATERAL (SELECT count(*) AS pending FROM broker.action_request q WHERE q.entity_id = c.entity_id"
        "   AND q.case_id = c.case_id AND q.status = 'pending_approval'"
        "   AND (q.expires_at IS NULL OR q.expires_at > now())) p ON true"
        " LEFT JOIN LATERAL (SELECT record -> 'ai' ->> 'verdict' AS verdict,"
        "   (record -> 'ai' ->> 'confidence')::float AS confidence FROM broker.decision_record x"
        "   WHERE x.entity_id = c.entity_id AND x.case_id = c.case_id ORDER BY created_at DESC LIMIT 1) d ON true"
        " LEFT JOIN LATERAL (SELECT action, status, level FROM broker.action_request q WHERE q.entity_id = c.entity_id"
        "   AND q.case_id = c.case_id ORDER BY (q.status = 'pending_approval') DESC, q.created_at DESC LIMIT 1) r"
        "   ON true"
        f" WHERE c.entity_id = %s AND {where}"
        " ORDER BY c.priority DESC, c.last_seen_at DESC LIMIT %s", (inst["entity_id"], limit)).fetchall()
    return [{
        "case_id": r["case_id"], "title": _clip(r["title"], 200), "category": _clip(r["category"], 60),
        "status": r["status"], "severity": r["max_severity"], "criticality": r["criticality"],
        "priority": r["priority"], "p": p_label(r["priority"]), "alerts": r["alert_count"], "events": r["event_count"],
        "primary": {"kind": r["primary_kind"], "value": _clip(r["primary_value"], 40)},
        "origin_city": _clip(r["origin_city"], 40), "opened_at": _iso(r["opened_at"]),
        "last_seen_at": _iso(r["last_seen_at"]), "closed_at": _iso(r["closed_at"]),
        "close_reason": _clip(r["close_reason"], 40), "tactics": list(r["tactics"]), "jira": r["issue_key"],
        "pending": r["pending"], "verdict": r["verdict"], "confidence": r["confidence"],
        "assignee": _clip(r["assignee"], 80), "broker": None if r["action"] is None else {"action": r["action"], "status": r["req_status"],
                                                    "level": r["level"]},
    } for r in rows]


def p_label(priority: int) -> str:
    """Priority 1..25 (severity rank x criticality) to the P1..P4 the analysts use."""
    return "P1" if priority >= 20 else "P2" if priority >= 12 else "P3" if priority >= 6 else "P4"


def case_detail(conn, inst: dict, case_id: str) -> dict | None:
    e = inst["entity_id"]
    c = conn.execute("SELECT * FROM gateway.alert_case WHERE entity_id = %s AND case_id = %s",
                     (e, case_id)).fetchone()
    if c is None:
        return None
    keys = conn.execute("SELECT key_kind, key_value FROM gateway.case_key WHERE entity_id = %s AND case_id = %s",
                        (e, case_id)).fetchall()
    keyset = {(k["key_kind"], k["key_value"]) for k in keys}
    alerts = conn.execute(
        "SELECT i.alert_id, i.detected_at, i.ingested_at, i.rule_id, i.source, i.severity_hint, i.event_count,"
        " i.alert -> 'entities' AS ents FROM gateway.case_alert a JOIN gateway.inbox_event i USING (alert_id)"
        " WHERE a.entity_id = %s AND a.case_id = %s ORDER BY i.detected_at, i.ingested_at LIMIT 100",
        (e, case_id)).fetchall()
    grp = []
    for a in alerts:
        ents = a["ents"] or {}
        match = [KEY_LABEL[k] for f, k in (("src_ip", "ip"), ("principal", "user"), ("access_key_token", "ak"))
                 if ents.get(f) and (k, ents[f]) in keyset]
        grp.append({"at": _iso(a["detected_at"]), "rule": _clip(a["rule_id"], 80), "source": a["source"],
                    "sev": a["severity_hint"], "events": a["event_count"], "match": match})
    steps = conn.execute(
        "SELECT at, rule_id, tactic, tactic_name, technique, title, outcome, src_kind, src_value, rel, dst_kind,"
        " dst_value, events FROM gateway.case_step WHERE entity_id = %s AND case_id = %s ORDER BY at, rule_id"
        " LIMIT 40", (e, case_id)).fetchall()
    rels = conn.execute(
        "SELECT src_kind, src_value, rel, dst_kind, dst_value, seen_count, first_seen, last_seen"
        " FROM gateway.entity_relation WHERE entity_id = %s AND case_id = %s ORDER BY first_seen LIMIT 60",
        (e, case_id)).fetchall()
    also = conn.execute(
        "SELECT DISTINCT o.case_id, o.key_kind, c.title, c.opened_at FROM gateway.case_key k"
        " JOIN gateway.case_key o ON o.entity_id = k.entity_id AND o.key_kind = k.key_kind"
        "   AND o.key_value = k.key_value AND o.case_id <> k.case_id"
        " JOIN gateway.alert_case c ON c.entity_id = o.entity_id AND c.case_id = o.case_id"
        " WHERE k.entity_id = %s AND k.case_id = %s ORDER BY c.opened_at DESC LIMIT 3", (e, case_id)).fetchall()
    decision = conn.execute(
        "SELECT record -> 'ai' AS ai, created_at FROM broker.decision_record WHERE entity_id = %s AND case_id = %s"
        " ORDER BY created_at DESC LIMIT 1", (e, case_id)).fetchone()
    trace = conn.execute(
        "SELECT seq, recorded_at, event_type, payload FROM ledger.entry WHERE entity_id = %s"
        " AND event_type IN ('ai.triage', 'ai.escalated') AND payload ->> 'case_id' = %s ORDER BY seq DESC LIMIT 8",
        (e, case_id)).fetchall()
    requests = conn.execute(
        "SELECT request_id, action, level, mode, status, reasons, would_execute, expires_at, rollback_at,"
        " created_at, escalation_level FROM broker.action_request WHERE entity_id = %s AND case_id = %s"
        " ORDER BY created_at LIMIT 30", (e, case_id)).fetchall()
    jira = conn.execute("SELECT issue_key, status FROM broker.jira_issue WHERE entity_id = %s AND case_id = %s",
                        (e, case_id)).fetchone()
    lark = conn.execute(
        "SELECT count(*) AS n, max(created_at) AS last FROM broker.integration_call WHERE entity_id = %s"
        " AND case_id = %s AND integration = 'lark' AND status = 'ok'", (e, case_id)).fetchone()
    calls = conn.execute(
        "SELECT integration, operation, target, status, external_ref, duration_ms, created_at"
        " FROM broker.integration_call WHERE entity_id = %s AND case_id = %s AND integration IN ('jira', 'lark')"
        " ORDER BY created_at LIMIT 20", (e, case_id)).fetchall()
    comments = conn.execute(
        "SELECT comment_id, author, body, created_at FROM broker.case_comment WHERE entity_id = %s AND case_id = %s"
        " ORDER BY created_at DESC LIMIT 50", (e, case_id)).fetchall()
    ai = (decision or {}).get("ai") or {}
    return {
        "case": {
            "case_id": c["case_id"], "title": _clip(c["title"], 200), "category": _clip(c["category"], 60),
            "status": c["status"], "severity": c["max_severity"], "criticality": c["criticality"],
            "priority": c["priority"], "p": p_label(c["priority"]), "alerts": c["alert_count"],
            "events": c["event_count"], "tactics": list(c["tactics"]), "sources": list(c["sources"]),
            "assets": [_clip(a, 60) for a in c["assets"]], "synthetic": c["synthetic"],
            "origin": {"city": _clip(c["origin_city"], 40), "country": _clip(c["origin_country"], 4),
                       "asn": _clip(c["origin_asn"], 16)},
            "opened_at": _iso(c["opened_at"]), "last_seen_at": _iso(c["last_seen_at"]),
            "closed_at": _iso(c["closed_at"]), "close_reason": _clip(c["close_reason"], 120),
            "assignee": _clip(c["assignee"], 80), "status_by": _clip(c["status_by"], 80),
            "keys": [{"kind": k["key_kind"], "value": _clip(k["key_value"], 40)} for k in keys],
        },
        "alerts": grp,
        "steps": [{"at": _iso(s["at"]), "rule": _clip(s["rule_id"], 80), "tactic": s["tactic"],
                   "tactic_name": _clip(s["tactic_name"], 40), "technique": _clip(s["technique"], 16),
                   "title": _clip(s["title"], 120), "outcome": s["outcome"], "events": s["events"],
                   "src": None if not s["src_kind"] else {"kind": s["src_kind"], "value": _clip(s["src_value"], 40)},
                   "rel": s["rel"],
                   "dst": None if not s["dst_kind"] else {"kind": s["dst_kind"], "value": _clip(s["dst_value"], 40)}}
                  for s in steps],
        "relations": [{"src": {"kind": r["src_kind"], "value": _clip(r["src_value"], 40)}, "rel": r["rel"],
                       "dst": {"kind": r["dst_kind"], "value": _clip(r["dst_value"], 40)}, "seen": r["seen_count"],
                       "first": _iso(r["first_seen"]), "last": _iso(r["last_seen"])} for r in rels],
        "also_in": [{"case_id": a["case_id"], "match": KEY_LABEL.get(a["key_kind"], a["key_kind"]),
                     "title": _clip(a["title"], 80), "opened_at": _iso(a["opened_at"])} for a in also],
        "ai": None if not ai else {
            "verdict": _clip(ai.get("verdict"), 20), "confidence": ai.get("confidence"),
            "model": _clip(ai.get("model"), 40), "source": _clip(ai.get("source"), 20),
            "rationale": _clip(ai.get("rationale_summary"), 500),
            "evidence_refs": [_clip(x, 80) for x in (ai.get("evidence_refs") or [])][:8],
            "at": _iso(decision["created_at"])},
        "trace": [_trace(t) for t in trace],
        "requests": [_request(r) for r in requests],
        "jira": None if not jira else {"key": jira["issue_key"], "status": jira["status"]},
        "lark": {"messages": lark["n"], "last": _iso(lark["last"])},
        "calls": [{"integration": x["integration"], "op": _clip(x["operation"], 40), "target": x["target"],
                   "status": x["status"], "ref": _clip(x["external_ref"], 40), "ms": x["duration_ms"],
                   "at": _iso(x["created_at"])} for x in calls],
        "comments": [{"id": str(m["comment_id"]), "author": _clip(m["author"], 80), "body": m["body"],
                      "at": _iso(m["created_at"])} for m in reversed(comments)],
    }


def people(conn, inst: dict) -> list[str]:
    """Who a case can be assigned to: the active people (not services) on this install."""
    return [r["name"] for r in conn.execute(
        "SELECT name FROM broker.principal WHERE entity_id = %s AND kind = 'human' AND active ORDER BY name LIMIT 100",
        (inst["entity_id"],)).fetchall()]


def _trace(t: dict) -> dict:
    p = t["payload"] or {}
    return {"seq": t["seq"], "at": _iso(t["recorded_at"]), "type": t["event_type"],
            "verdict": _clip(p.get("verdict"), 20), "confidence": p.get("confidence"), "model": _clip(p.get("model"), 40),
            "target": _clip(p.get("target"), 10), "prompt_version": _clip(p.get("prompt_version"), 20),
            "fallback_used": bool(p.get("fallback_used")), "escalated": _clip(p.get("escalated") or p.get("reason"), 120),
            "attempts": [{"model": _clip(a.get("model"), 40), "ok": bool(a.get("ok")), "error": _clip(a.get("error"), 80),
                          "ms": a.get("latency_ms"), "tokens": (a.get("tokens_in") or 0) + (a.get("tokens_out") or 0),
                          "schema_ok": bool(a.get("schema_ok"))} for a in (p.get("attempts") or [])[:4]],
            "evidence_refs": [_clip(x, 60) for x in (p.get("evidence_refs") or [])][:6]}


def _request(r: dict) -> dict:
    return {"id": str(r["request_id"]), "action": _clip(r["action"], 64), "level": r["level"],
            "level_text": LEVEL_TEXT.get(r["level"], r["level"]), "mode": r["mode"], "status": r["status"],
            "reasons": [_clip(x, 120) for x in (r["reasons"] or [])][:5], "would_execute": _clip(r["would_execute"]),
            "expires_at": _iso(r["expires_at"]), "rollback_at": _iso(r["rollback_at"]),
            "created_at": _iso(r["created_at"]), "escalation_level": r["escalation_level"]}


# -- approvals -------------------------------------------------------------------------------------------
def approvals(conn, inst: dict) -> dict:
    e = inst["entity_id"]
    pending = conn.execute(
        "SELECT q.request_id, q.action, q.level, q.mode, q.status, q.reasons, q.would_execute, q.expires_at,"
        " q.rollback_at, q.created_at, q.escalation_level, q.escalated_at, q.case_id, q.impact, q.rollback_plan,"
        " q.evidence, d.record -> 'ai' AS ai, c.title AS case_title, c.max_severity"
        " FROM broker.action_request q JOIN broker.decision_record d USING (decision_id)"
        " LEFT JOIN gateway.alert_case c ON c.entity_id = q.entity_id AND c.case_id = q.case_id"
        " WHERE q.entity_id = %s AND q.status = 'pending_approval' AND (q.expires_at IS NULL OR q.expires_at > now())"
        " ORDER BY q.expires_at NULLS LAST, q.created_at LIMIT 20", (e,)).fetchall()
    recent = conn.execute(
        "SELECT action, status, case_id, created_at, expires_at, reasons, would_execute FROM broker.action_request"
        " WHERE entity_id = %s AND level IN ('L2', 'L3')"
        " AND (status <> 'pending_approval' OR expires_at <= now())"
        " ORDER BY coalesce(expires_at, created_at) DESC LIMIT 6", (e,)).fetchall()
    lark = conn.execute(
        "SELECT settings -> 'ladder' AS ladder FROM broker.integration_config WHERE entity_id = %s"
        " AND integration = 'lark' AND mode = %s", (e, inst["mode"])).fetchone()
    ladder = [{"role": _clip(s.get("role"), 40), "timeout_min": s.get("timeout_min"),
               "approvers": [_clip(a.get("name"), 40) for a in (s.get("approvers") or [])][:4]}
              for s in ((lark or {}).get("ladder") or [])[:3]]
    out = []
    for r in pending:
        ai = r["ai"] or {}
        out.append({**_request(r), "case_id": r["case_id"], "case_title": _clip(r["case_title"], 200),
                    "severity": r["max_severity"], "impact": _clip(r["impact"], 300),
                    "rollback_plan": _clip(r["rollback_plan"], 300), "escalated_at": _iso(r["escalated_at"]),
                    "evidence": _evidence(r["evidence"]),
                    "ai": {"verdict": _clip(ai.get("verdict"), 20), "confidence": ai.get("confidence"),
                           "model": _clip(ai.get("model"), 40)}})
    return {"pending": out, "ladder": ladder,
            "recent": [{"action": _clip(r["action"], 64), "would_execute": _clip(r["would_execute"]), "case_id": r["case_id"],
                        "status": "expired" if r["status"] == "pending_approval" else r["status"],
                        "at": _iso(r["expires_at"] or r["created_at"]),
                        "reason": _clip((r["reasons"] or [None])[0], 80)} for r in recent]}


def _evidence(v) -> list[str]:
    if isinstance(v, dict):
        k = len(v.get("alert_ids") or [])
        out = [f"{k} alert{'' if k == 1 else 's'} in the case"]
        if v.get("tokens"):
            out.append("Tokens: " + ", ".join(_clip(t, 24) for t in v["tokens"][:6]))
        return out
    return [_clip(x, 160) for x in (v or [])][:6]


def _target(would_execute: str | None) -> str | None:
    """The first argument of `action(k=v, ...)`: the IP token, key or path the action is aimed at."""
    if not would_execute or "(" not in would_execute:
        return _clip(would_execute, 48)
    first = would_execute.split("(", 1)[1].rstrip(")").split(",", 1)[0]
    return _clip(first.split("=", 1)[-1].strip(), 48)


# -- automation ------------------------------------------------------------------------------------------
def automation(conn, inst: dict, catalog: list[dict] | None) -> dict:
    e = inst["entity_id"]
    per_action = {r["action"]: r for r in conn.execute(
        "SELECT action, count(*) FILTER (WHERE created_at > now() - interval '24 hours') AS n24,"
        " count(*) FILTER (WHERE status = 'validated') AS validated, count(*) FILTER (WHERE status = 'rejected')"
        " AS rejected, count(*) AS total FROM broker.action_request WHERE entity_id = %s GROUP BY action",
        (e,)).fetchall()}
    expiring = conn.execute(
        "SELECT request_id, action, case_id, would_execute, created_at, rollback_at FROM broker.action_request"
        " WHERE entity_id = %s AND status = 'validated' AND rollback_at > now() ORDER BY rollback_at LIMIT 6",
        (e,)).fetchall()
    ks = conn.execute("SELECT scope, engaged, changed_at FROM broker.kill_switch WHERE entity_id = %s ORDER BY scope",
                      (e,)).fetchall()
    changes = conn.execute(
        "SELECT integration, version, target, changed_by, changed_at, note FROM broker.integration_config_version"
        " WHERE entity_id = %s AND mode = %s ORDER BY changed_at DESC LIMIT 5", (e, inst["mode"])).fetchall()
    actions = []
    for a in catalog or []:
        n = per_action.get(a["id"]) or {}
        actions.append({"id": a["id"], "level": a["level"], "level_text": LEVEL_TEXT.get(a["level"], a["level"]),
                        "target_mode": a.get("target_mode"), "rate_per_hour": a.get("rate_limit_per_hour"),
                        "rollback": a.get("rollback"), "n24": n.get("n24", 0), "total": n.get("total", 0),
                        "passed": n.get("validated", 0), "blocked": n.get("rejected", 0)})
    return {
        "actions": actions, "catalog_loaded": catalog is not None,
        "expiring": [{"id": str(r["request_id"]), "action": _clip(r["action"], 64), "case_id": r["case_id"], "what": _target(r["would_execute"]),
                      "from": _iso(r["created_at"]), "until": _iso(r["rollback_at"])} for r in expiring],
        "kill_switch": [{"scope": _clip(r["scope"], 64), "engaged": r["engaged"], "at": _iso(r["changed_at"])}
                        for r in ks],
        "changes": [{"integration": r["integration"], "version": r["version"], "target": r["target"],
                     "by": _clip(r["changed_by"], 40), "at": _iso(r["changed_at"]), "note": _clip(r["note"], 120)}
                    for r in changes],
        "integrations": integrations(conn, inst),
    }


# -- integrations: data-source health ---------------------------------------------------------------------
SOURCE_REFS = ("sls", "webhook", "syslog")


def source_health(conn, inst: dict) -> dict:
    """Alerts each data source delivered in the last 24 hours, by the raw_ref scheme it stamps on them."""
    rows = conn.execute(
        "SELECT split_part(alert ->> 'raw_ref', '://', 1) AS src, count(*) AS n, max(ingested_at) AS last"
        " FROM gateway.inbox_event WHERE entity_id = %s AND ingested_at > now() - interval '24 hours'"
        " AND split_part(alert ->> 'raw_ref', '://', 1) = ANY(%s) GROUP BY 1",
        (inst["entity_id"], list(SOURCE_REFS))).fetchall()
    got = {r["src"]: r for r in rows}
    return {k: {"alerts_24h": got[k]["n"] if k in got else 0, "last_alert": _iso(got[k]["last"]) if k in got else None}
            for k in SOURCE_REFS}

