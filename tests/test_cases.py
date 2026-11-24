"""G1 case grouping, G2 entity relations and the attack path steps, on a real Postgres."""

from datetime import UTC, datetime, timedelta

from hypersoar import ledger
from hypersoar.common import entity as entity_mod

from helpers import ingest

T0 = datetime(2026, 11, 24, 7, 2, 11, tzinfo=UTC)


def at(minutes: float) -> str:
    return (T0 + timedelta(minutes=minutes)).isoformat()


def chain(ip="203.0.113.5", ak="LTAI5tSyntheticKey7Q2F", user="m-20931"):
    """The v3 mockup's lateral movement chain, credential stuffing to a blocked protected asset."""
    return [
        {"source": "waf", "rule_id": "waf.bot.credential_stuffing", "severity_hint": "high", "detected_at": at(0),
         "src_ip": ip, "dst_asset": "merchant-login.qash", "events": 1240},
        {"source": "internal", "rule_id": "internal.portal.login_after_failures", "severity_hint": "high",
         "detected_at": at(4.5), "src_ip": ip, "principal": user, "dst_asset": "merchant-login.qash"},
        {"source": "internal", "rule_id": "internal.portal.settlement_export", "severity_hint": "high",
         "detected_at": at(7), "principal": user, "dst_asset": "portal.dob"},
        {"source": "actiontrail", "rule_id": "actiontrail.ak_unusual_ip", "severity_hint": "critical",
         "detected_at": at(11), "src_ip": ip, "principal": "svc-settlement-report", "access_key_id": ak},
        {"source": "actiontrail", "rule_id": "actiontrail.oss.bulk_read", "severity_hint": "critical",
         "detected_at": at(11.5), "access_key_id": ak, "dst_asset": "oss-backup", "events": 41},
        {"source": "actiontrail", "rule_id": "actiontrail.ram.assume_role_denied", "severity_hint": "high",
         "detected_at": at(13.5), "access_key_id": ak, "dst_asset": "ram-console"},
        {"source": "actiontrail", "rule_id": "actiontrail.protected_asset_probe", "severity_hint": "high",
         "detected_at": at(14), "access_key_id": ak, "dst_asset": "ecs-pay-01"},
    ]


def test_chain_becomes_one_case_with_steps_and_relations(pool, settings, tmp_path, conn):
    r = ingest(pool, settings, tmp_path, chain())
    assert (r.new, r.rejected) == (7, 0)
    cases = conn.execute("SELECT * FROM gateway.alert_case").fetchall()
    assert len(cases) == 1
    c = cases[0]
    assert c["case_id"] == "CS-1001" and c["status"] == "open"
    assert c["alert_count"] == 7 and c["event_count"] == 1240 + 1 + 1 + 1 + 41 + 1 + 1
    assert c["max_severity"] == "critical" and c["criticality"] == 5 and c["priority"] == 25
    assert c["tactics"] == ["TA0001", "TA0006", "TA0007", "TA0008", "TA0009"]  # kill-chain order
    assert c["origin_city"] == "Amsterdam" and c["origin_asn"] == "AS208294"
    assert c["category"] == "Credential stuffing" and c["title"].endswith("on merchant-login.qash")
    assert set(c["sources"]) == {"waf", "internal", "actiontrail"}
    steps = conn.execute("SELECT * FROM gateway.case_step ORDER BY at").fetchall()
    assert [s["technique"] for s in steps] == ["T1110.004", "T1078", "T1552.001", "T1078.004", "T1530",
                                                "T1550.001", "T1526"]
    assert [s["outcome"] for s in steps][-2:] == ["blocked", "blocked"]
    rels = {(r["src_kind"], r["rel"], r["dst_kind"]) for r in
            conn.execute("SELECT * FROM gateway.entity_relation").fetchall()}
    assert {("ip", "targets", "asset"), ("ip", "authenticates_as", "user"), ("user", "targets", "asset"),
            ("ip", "uses_key", "ak"), ("user", "owns_key", "ak"), ("ak", "targets", "asset"),
            ("ak", "moves_to", "asset")} <= rels
    # Every alert carries its case to the workflow, and nothing raw reached the tables.
    alerts = conn.execute("SELECT alert FROM gateway.inbox_event").fetchall()
    assert {a["alert"]["case_id"] for a in alerts} == {"CS-1001"}
    dump = str(conn.execute("SELECT json_agg(s) AS a FROM gateway.case_step s").fetchone()["a"])
    dump += str(conn.execute("SELECT json_agg(r) AS a FROM gateway.entity_relation r").fetchone()["a"])
    assert "203.0.113.5" not in dump and "m-20931" not in dump and "LTAI5t" not in dump
    assert ledger.verify(conn).ok
    events = {e["event_type"] for e in conn.execute("SELECT event_type FROM ledger.entry").fetchall()}
    assert "case.opened" in events


def test_unrelated_alerts_and_window_split_cases(pool, settings, tmp_path, conn):
    rows = chain()[:1]
    rows.append({**chain(ip="203.0.113.20")[0], "rule_id": "waf.sqli.burst"})  # other IP: new case
    rows.append({**chain()[0], "detected_at": at(180)})  # same IP, 3h later (window 1h): new case
    ingest(pool, settings, tmp_path, rows)
    ids = [r["case_id"] for r in conn.execute("SELECT case_id FROM gateway.alert_case ORDER BY case_no")]
    assert ids == ["CS-1001", "CS-1002", "CS-1003"]


def test_merged_duplicate_adds_events_to_its_case(pool, settings, tmp_path, conn):
    a = chain()[0]
    ingest(pool, settings, tmp_path, [a, {**a, "detected_at": at(0.5), "events": 10}])
    c = conn.execute("SELECT alert_count, event_count FROM gateway.alert_case").fetchone()
    assert (c["alert_count"], c["event_count"]) == (1, 1250)


def test_idle_case_closes(pool, settings, tmp_path, conn):
    ingest(pool, settings, tmp_path, chain()[:1])
    with conn.transaction():
        conn.execute("UPDATE gateway.alert_case SET updated_at = now() - interval '3 hours'")
    r = ingest(pool, settings, tmp_path, [], name="replay")
    assert r.closed == 1
    c = conn.execute("SELECT status, close_reason FROM gateway.alert_case").fetchone()
    assert (c["status"], c["close_reason"]) == ("closed", "idle")
    # A later alert from the same IP opens a fresh case instead of reopening the closed one.
    ingest(pool, settings, tmp_path, [{**chain()[0], "rule_id": "waf.sqli.burst", "detected_at": at(1)}])
    rows = conn.execute("SELECT case_id, status FROM gateway.alert_case ORDER BY case_no").fetchall()
    assert [(r["case_id"], r["status"]) for r in rows] == [("CS-1001", "closed"), ("CS-1002", "open")]


def test_entity_file_drives_window_and_criticality():
    e = entity_mod.load(mode="sandbox")
    assert e.id == "dob" and e.window_s == 3600
    assert e.criticality("merchant-login.qash") == 5 and e.criticality("unknown") == 2
