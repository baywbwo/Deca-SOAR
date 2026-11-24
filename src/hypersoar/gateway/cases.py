"""Case correlation (G1), entity relations (G2) and attack path steps.

Alerts that share a tokenised source IP, principal or AccessKey within the entity's correlation
window join one open case. Runs inside the gateway's pull transaction, so a crash keeps the alert,
its case link and its ledger entry together or loses all of them.
"""

from __future__ import annotations

from datetime import timedelta

from hypersoar import ledger
from hypersoar.common.entity import Entity
from hypersoar.gateway.detections import TACTIC_ORDER

SEV_RANK = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
KEY_KINDS = (("src_ip", "ip"), ("principal", "user"), ("access_key_token", "ak"))
ACTOR = "service:gateway"


def priority(severity: str, criticality: int) -> int:
    """Severity rank x asset criticality: 1..25, the number the case queue sorts on."""
    return SEV_RANK[severity] * max(1, min(5, criticality))


def _keys(alert: dict) -> list[tuple[str, str]]:
    ents = alert.get("entities") or {}
    return [(kind, ents[f]) for f, kind in KEY_KINDS if ents.get(f)]


def _find_case(conn, entity: Entity, keys: list[tuple[str, str]], at) -> str | None:
    if not keys:
        return None
    row = conn.execute(
        "SELECT k.case_id FROM gateway.case_key k JOIN gateway.alert_case c USING (entity_id, case_id)"
        " WHERE k.entity_id = %s AND c.status = 'open' AND (k.key_kind, k.key_value) IN"
        " (SELECT * FROM unnest(%s::text[], %s::text[])) AND k.last_seen_at >= %s"
        " ORDER BY k.last_seen_at DESC LIMIT 1",
        (entity.id, [k for k, _ in keys], [v for _, v in keys], at - timedelta(seconds=entity.window_s)),
    ).fetchone()
    return row["case_id"] if row else None


def _open_case(conn, entity: Entity, alert: dict, at) -> str:
    n = conn.execute(
        "SELECT coalesce(max(case_no), 1000) + 1 AS n FROM gateway.alert_case WHERE entity_id = %s", (entity.id,)
    ).fetchone()["n"]
    case_id = f"CS-{n}"
    ents = alert.get("entities") or {}
    asset = ents.get("dst_asset")
    kind, value = (_keys(alert) or [("asset", asset or alert["rule_id"])])[0]
    origin = alert.get("origin") or {}
    title = alert.get("title") or alert["rule_id"]
    if asset:
        title = f"{title} on {asset}"
    crit = entity.criticality(asset)
    conn.execute(
        "INSERT INTO gateway.alert_case (entity_id, case_id, case_no, title, category, max_severity, criticality,"
        " priority, primary_kind, primary_value, origin_city, origin_country, origin_asn, synthetic, opened_at,"
        " last_seen_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (entity.id, case_id, n, title[:200], alert.get("category") or "Uncatalogued", alert["severity_hint"], crit,
         priority(alert["severity_hint"], crit), kind, value, origin.get("city"), origin.get("country"),
         origin.get("asn"), str(alert.get("raw_ref", "")).startswith("synthetic://"), at, at),
    )
    ledger.append(conn, "case.opened", ACTOR, {"case_id": case_id, "alert_id": alert["alert_id"],
                                                "category": alert.get("category")}, entity.id)
    return case_id


def attach(conn, entity: Entity, alert: dict, at, events: int) -> str:
    """Put a newly ingested alert into a case (an existing one or a new one). Returns the case id."""
    conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"hypersoar-case:{entity.id}",))
    keys = _keys(alert)
    case_id = _find_case(conn, entity, keys, at) or _open_case(conn, entity, alert, at)
    ents = alert.get("entities") or {}
    asset = ents.get("dst_asset")
    attack = alert.get("attack") or {}
    conn.execute(
        "INSERT INTO gateway.case_alert (alert_id, entity_id, case_id) VALUES (%s, %s, %s)",
        (alert["alert_id"], entity.id, case_id),
    )
    for kind, value in keys:
        conn.execute(
            "INSERT INTO gateway.case_key (entity_id, key_kind, key_value, case_id, last_seen_at)"
            " VALUES (%s, %s, %s, %s, %s) ON CONFLICT (entity_id, key_kind, key_value, case_id)"
            " DO UPDATE SET last_seen_at = greatest(gateway.case_key.last_seen_at, EXCLUDED.last_seen_at)",
            (entity.id, kind, value, case_id, at),
        )
    path = alert.get("path") or {}
    src, dst = path.get("from") or {}, path.get("to") or {}
    conn.execute(
        "INSERT INTO gateway.case_step (entity_id, case_id, alert_id, at, rule_id, tactic, tactic_name, technique,"
        " title, outcome, src_kind, src_value, rel, dst_kind, dst_value, events)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (entity.id, case_id, alert["alert_id"], at, alert["rule_id"], attack.get("tactic"),
         attack.get("tactic_name"), attack.get("technique"), alert.get("step_title") or alert["rule_id"],
         alert.get("outcome") or "attempted", src.get("kind"), src.get("value"), path.get("rel"),
         dst.get("kind"), dst.get("value"), events),
    )
    relations = []
    if path:
        relations.append((src["kind"], src["value"], path["rel"], dst["kind"], dst["value"]))
    if ents.get("principal") and ents.get("access_key_token"):
        relations.append(("user", ents["principal"], "owns_key", "ak", ents["access_key_token"]))
    for r in dict.fromkeys(relations):
        conn.execute(
            "INSERT INTO gateway.entity_relation (entity_id, case_id, src_kind, src_value, rel, dst_kind, dst_value,"
            " first_seen, last_seen, last_alert_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            " ON CONFLICT (entity_id, case_id, src_kind, src_value, rel, dst_kind, dst_value) DO UPDATE SET"
            " last_seen = greatest(gateway.entity_relation.last_seen, EXCLUDED.last_seen),"
            " seen_count = gateway.entity_relation.seen_count + 1, last_alert_id = EXCLUDED.last_alert_id",
            (entity.id, case_id, *r, at, at, alert["alert_id"]),
        )
    sev = alert["severity_hint"]
    crit = entity.criticality(asset)
    origin = alert.get("origin") or {}
    conn.execute(
        "UPDATE gateway.alert_case SET alert_count = alert_count + 1, event_count = event_count + %s,"
        " max_severity = CASE WHEN %s > (array_position(%s::text[], max_severity)) THEN %s ELSE max_severity END,"
        " criticality = greatest(criticality, %s),"
        " tactics = CASE WHEN %s::text IS NULL OR %s = ANY(tactics) THEN tactics ELSE tactics || %s::text END,"
        " sources = CASE WHEN %s = ANY(sources) THEN sources ELSE sources || %s::text END,"
        " assets = CASE WHEN %s::text IS NULL OR %s = ANY(assets) THEN assets ELSE assets || %s::text END,"
        " origin_city = coalesce(origin_city, %s), origin_country = coalesce(origin_country, %s),"
        " origin_asn = coalesce(origin_asn, %s),"
        " last_seen_at = greatest(last_seen_at, %s), updated_at = now()"
        " WHERE entity_id = %s AND case_id = %s",
        (events, SEV_RANK[sev], list(SEV_RANK), sev, crit,
         attack.get("tactic"), attack.get("tactic"), attack.get("tactic"),
         alert["source"], alert["source"], asset, asset, asset,
         origin.get("city"), origin.get("country"), origin.get("asn"), at, entity.id, case_id),
    )
    conn.execute(
        "UPDATE gateway.alert_case SET priority = (array_position(%s::text[], max_severity)) * criticality,"
        " tactics = (SELECT coalesce(array_agg(t ORDER BY array_position(%s::text[], t)), '{}')"
        "            FROM unnest(tactics) t)"
        " WHERE entity_id = %s AND case_id = %s",
        (list(SEV_RANK), sorted(TACTIC_ORDER, key=TACTIC_ORDER.get), entity.id, case_id),
    )
    return case_id


def add_events(conn, entity_id: str, alert_id: str, events: int) -> None:
    """A merged duplicate still counts: its events go to the case of the original alert."""
    conn.execute(
        "UPDATE gateway.alert_case c SET event_count = event_count + %s, updated_at = now()"
        " FROM gateway.case_alert a WHERE a.alert_id = %s AND c.entity_id = a.entity_id AND c.case_id = a.case_id"
        " AND c.entity_id = %s",
        (events, alert_id, entity_id),
    )


def close_idle(conn, entity: Entity) -> list[str]:
    """Close open cases with no new alert for two correlation windows (wall clock)."""
    rows = conn.execute(
        "UPDATE gateway.alert_case SET status = 'closed', closed_at = now(), close_reason = 'idle'"
        " WHERE entity_id = %s AND status = 'open' AND updated_at < now() - make_interval(secs => %s)"
        " RETURNING case_id",
        (entity.id, 2 * entity.window_s),
    ).fetchall()
    for r in rows:
        ledger.append(conn, "case.closed", ACTOR, {"case_id": r["case_id"], "reason": "idle"}, entity.id)
    return [r["case_id"] for r in rows]
