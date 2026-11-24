"""What the console shows, read through the deca_soar_viewer login only."""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime

from hypersoar import ledger

FEED_LIMIT = 30
LEDGER_TAIL = 10
TEXT_MAX = 160
TOP_RULES = 6
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def _iso(v) -> str | None:
    return v.isoformat() if isinstance(v, datetime) else None


def _clip(v, n: int = TEXT_MAX) -> str | None:
    if v is None:
        return None
    s = str(v)
    return s if len(s) <= n else s[: n - 1] + "…"


class LedgerStatus:
    """Full chain verification, cached: it reads every entry, so it runs at most every `ttl_s`."""

    def __init__(self, ttl_s: float = 30) -> None:
        self.ttl_s = ttl_s
        self._at = -1e9
        self._value: dict | None = None
        self._lock = threading.Lock()

    def get(self, conn) -> dict:
        with self._lock:
            if self._value is not None and time.monotonic() - self._at < self.ttl_s:
                return self._value
            r = ledger.verify(conn)
            self._value = {
                "ok": r.ok,
                "entries": r.entries,
                "head_seq": r.head_seq,
                "head_hash": r.head_hash,
                "errors": [_clip(e) for e in r.errors[:5]],
                "checked_at": datetime.now(UTC).isoformat(),
            }
            self._at = time.monotonic()
            return self._value


def feed(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT e.alert_id, e.source, e.rule_id, e.severity_hint, e.detected_at, e.ingested_at, e.last_seen_at,"
        " e.event_count, e.status, e.forwarded_at, e.attempts,"
        " e.alert -> 'entities' ->> 'src_ip' AS src_token,"
        " e.alert -> 'untrusted_fields' ->> 'uri' AS uri,"
        " d.record -> 'ai' AS ai, d.created_at AS decided_at,"
        " r.action, r.status AS request_status, r.mode, r.level, r.reasons, r.would_execute"
        " FROM gateway.inbox_event e"
        " LEFT JOIN LATERAL (SELECT record, created_at, decision_id FROM broker.decision_record"
        "   WHERE alert_id = e.alert_id ORDER BY created_at DESC LIMIT 1) d ON true"
        " LEFT JOIN LATERAL (SELECT action, status, mode, level, reasons, would_execute FROM broker.action_request"
        "   WHERE decision_id = d.decision_id ORDER BY created_at DESC LIMIT 1) r ON true"
        " ORDER BY e.ingested_at DESC LIMIT %s",
        (FEED_LIMIT,),
    ).fetchall()
    out = []
    for r in rows:
        ai = r["ai"] or {}
        out.append({
            "alert_id": str(r["alert_id"]),
            "source": r["source"],
            "rule_id": _clip(r["rule_id"], 80),
            "severity": r["severity_hint"],
            "detected_at": _iso(r["detected_at"]),
            "ingested_at": _iso(r["ingested_at"]),
            "event_count": r["event_count"],
            "gateway_status": r["status"],
            "forwarded_at": _iso(r["forwarded_at"]),
            "src_token": _clip(r["src_token"], 64),
            "uri": _clip(r["uri"], 120),
            "triage": None if not ai else {
                "verdict": _clip(ai.get("verdict"), 32),
                "confidence": ai.get("confidence"),
                "model": _clip(ai.get("model"), 40),
                "source": _clip(ai.get("source"), 20),
            },
            "decided_at": _iso(r["decided_at"]),
            "broker": None if r["action"] is None else {
                "action": _clip(r["action"], 64),
                "status": r["request_status"],
                "mode": r["mode"],
                "level": r["level"],
                "reasons": [_clip(x, 120) for x in (r["reasons"] or [])][:5],
                "would_execute": _clip(r["would_execute"]),
            },
        })
    return out


def counts(conn) -> dict:
    inbox = {r["status"]: r["n"] for r in conn.execute(
        "SELECT status, count(*) AS n FROM gateway.inbox_event GROUP BY status").fetchall()}
    requests = {r["status"]: r["n"] for r in conn.execute(
        "SELECT status, count(*) AS n FROM broker.action_request GROUP BY status").fetchall()}
    modes = {r["mode"]: r["n"] for r in conn.execute(
        "SELECT mode, count(*) AS n FROM broker.action_request GROUP BY mode").fetchall()}
    last_hour = conn.execute(
        "SELECT count(*) AS alerts, max(ingested_at) AS last_ingest FROM gateway.inbox_event"
        " WHERE ingested_at > now() - interval '1 hour'").fetchone()
    latest = conn.execute("SELECT max(ingested_at) AS t FROM gateway.inbox_event").fetchone()
    decisions = conn.execute("SELECT count(*) AS n FROM broker.decision_record").fetchone()["n"]
    return {
        "inbox": inbox,
        "alerts_total": sum(inbox.values()),
        "alerts_last_hour": last_hour["alerts"],
        "last_ingest": _iso(latest["t"]),
        "decisions": decisions,
        "requests": requests,
        "request_modes": modes,
    }


def timeline(conn) -> list[dict]:
    """24 hourly buckets ending with the current hour, oldest first, empty hours included."""
    rows = conn.execute(
        "SELECT h.hour,"
        " count(e.alert_id) FILTER (WHERE e.severity_hint IN ('high', 'critical')) AS high,"
        " count(e.alert_id) FILTER (WHERE e.severity_hint = 'medium') AS medium,"
        " count(e.alert_id) FILTER (WHERE e.severity_hint IN ('low', 'info')) AS low"
        " FROM generate_series(date_trunc('hour', now()) - interval '23 hours', date_trunc('hour', now()),"
        "   interval '1 hour') AS h(hour)"
        " LEFT JOIN gateway.inbox_event e ON e.ingested_at >= h.hour AND e.ingested_at < h.hour + interval '1 hour'"
        " GROUP BY h.hour ORDER BY h.hour").fetchall()
    return [{"hour": _iso(r["hour"]), "high": r["high"], "medium": r["medium"], "low": r["low"]} for r in rows]


def top_rules(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT rule_id, source, count(*) AS n,"
        " (%(sev)s::text[])[max(array_position(%(sev)s::text[], severity_hint))] AS severity"
        " FROM gateway.inbox_event WHERE ingested_at > now() - interval '24 hours'"
        " GROUP BY rule_id, source ORDER BY n DESC, rule_id LIMIT %(limit)s",
        {"sev": list(SEVERITY_ORDER), "limit": TOP_RULES},
    ).fetchall()
    return [{"rule_id": _clip(r["rule_id"], 80), "source": r["source"], "n": r["n"],
             "severity": r["severity"]} for r in rows]


def kill_switch(conn) -> dict:
    rows = conn.execute(
        "SELECT scope, engaged, changed_at FROM broker.kill_switch ORDER BY scope").fetchall()
    scopes = [{"scope": _clip(r["scope"], 64), "engaged": r["engaged"], "changed_at": _iso(r["changed_at"])}
              for r in rows]
    return {"global_engaged": any(s["scope"] == "global" and s["engaged"] for s in scopes),
            "any_engaged": any(s["engaged"] for s in scopes), "scopes": scopes}


def ledger_tail(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT seq, recorded_at, event_type, actor, prev_hash, hash FROM ledger.entry ORDER BY seq DESC LIMIT %s",
        (LEDGER_TAIL,),
    ).fetchall()
    return [{"seq": r["seq"], "recorded_at": _iso(r["recorded_at"]), "event_type": _clip(r["event_type"], 40),
             "actor": _clip(r["actor"], 60), "prev_hash": r["prev_hash"], "hash": r["hash"]} for r in rows]


def state(conn, ledger_status: LedgerStatus) -> dict:
    return {
        "now": datetime.now(UTC).isoformat(),
        "counts": counts(conn),
        "kill_switch": kill_switch(conn),
        "ledger": {**ledger_status.get(conn), "tail": ledger_tail(conn)},
        "feed": feed(conn),
        "timeline": timeline(conn),
        "top_rules": top_rules(conn),
    }
