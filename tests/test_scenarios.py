"""`hypersoar scenario run`: scenario files, the in-process pipeline and what qa.scenario_run records."""

from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest
from psycopg.rows import dict_row

from hypersoar import scenarios as scn
from hypersoar.broker import catalog as catalog_mod
from hypersoar.broker.integrations import hub as hub_mod
from hypersoar.common.config import ConfigError
from hypersoar.gateway import detections
from hypersoar.workflows.shadow import build_request

from helpers import ingest
from test_integrations import admin_hash, client, env, principals  # noqa: F401  (fixtures)

ROOT = Path(__file__).resolve().parents[1]
ALL = scn.load_dir(ROOT / "scenarios", detections.load_dir(ROOT / "detections"))
PIPELINE = sorted(s for s, v in ALL.items() if v.kind == "pipeline")


def test_scenario_files_cover_the_brief():
    assert set(ALL) == {"ak-lateral-movement", "account-takeover", "web-attack", "protected-source",
                        "ssh-bruteforce", "integrations-connection"}
    ak = ALL["ak-lateral-movement"]
    assert ak.quota == "ram.access_key.disable"
    assert ak.expect["case"]["tactics"] == ["TA0001", "TA0007", "TA0008", "TA0009"]
    assert ALL["integrations-connection"].expect["connection"] == {"lark": "pass", "jira": "pass", "ai": "pass"}


@pytest.mark.parametrize("doc, msg", [
    ({"version": 1, "id": "x", "title": "t", "alerts": [{"source": "waf", "rule_id": "nope"}],
      "expect": {"case": {}}}, "not in detections"),
    ({"version": 1, "id": "x", "title": "t", "alerts": [{"source": "waf", "rule_id": "waf.sqli.burst",
                                                         "raw_ref": "synthetic://x"}], "expect": {"case": {}}},
     "set by the runner"),
    ({"version": 1, "id": "x", "title": "t", "alerts": [{"source": "waf", "rule_id": "waf.sqli.burst",
                                                         "src_ip": "{secret}"}], "expect": {"case": {}}},
     "placeholders"),
    ({"version": 1, "id": "x", "title": "t", "kind": "connection_test", "expect": {"case": {}}}, "connection"),
])
def test_scenario_parse_rejects(doc, msg):
    with pytest.raises(ConfigError, match=msg):
        scn.parse(doc, None, detections.load_dir(ROOT / "detections"))


def test_render_uses_scenario_only_addresses_and_fresh_keys():
    a, b = scn.run_values(0), scn.run_values(1)
    assert a["ak"] != b["ak"] and a["svc"] != b["svc"]
    for v in (scn.run_values(n) for n in range(200)):
        assert 208 <= int(v["ip"].rsplit(".", 1)[1]) <= 254
        assert 129 <= int(v["pip"].rsplit(".", 1)[1]) <= 254
    rows = scn.render(ALL["ak-lateral-movement"], "run1", a)
    assert [r["raw_ref"] for r in rows] == [f"synthetic://scenario/run1/ak-lateral-movement/{i}" for i in range(4)]
    assert {r["access_key_id"] for r in rows} == {a["ak"]} and all("{" not in str(v) for r in rows for v in r.values())


# -- the whole pipeline in process: gateway pull, broker triage + policy, outbox sync ----------------
def _drive(client, principals, pool, settings, tmp_path, rows):
    ingest(pool, settings, tmp_path, rows, name=f"scn{len(list(tmp_path.iterdir()))}")
    refs = [r["raw_ref"] for r in rows]
    with pool.connection() as c:
        alerts = c.execute("SELECT alert_id, alert FROM gateway.inbox_event WHERE alert->>'raw_ref' = ANY(%s)"
                           " ORDER BY detected_at", (refs,)).fetchall()
    for a in alerts:
        alert = {**a["alert"], "alert_id": str(a["alert_id"])}
        d = client.post("/v1/triage", headers=principals["worker-svc"], json={"alert_id": alert["alert_id"]})
        assert d.status_code == 200, d.text
        req = build_request(alert, d.json())
        if req:
            r = client.post("/v1/actions/requests", headers=principals["worker-svc"], json=req)
            assert r.status_code in (200, 201), r.text
    for _ in range(10):
        if not hub_mod.tick(pool, client.broker.hub)["ops"]:
            break


@pytest.fixture
def broker_connect(roles):
    return lambda: psycopg.connect(roles["broker"], row_factory=dict_row)


@pytest.fixture
def rate_limits(settings):
    cat, _ = catalog_mod.load(settings.policy_dir)
    return {k: v.rate_per_hour for k, v in cat.items() if v.rate_per_hour}


def test_every_pipeline_scenario_passes_and_is_recorded(client, principals, pool, settings, tmp_path, conn,
                                                         broker_connect, rate_limits):
    run_id = scn.new_run_id()
    for i, sid in enumerate(PIPELINE):
        s = ALL[sid]
        started = datetime.now(UTC)
        r = scn.run_pipeline(broker_connect, "dob", run_id, s, i,
                             lambda rows: _drive(client, principals, pool, settings, tmp_path, rows),
                             rate_limits=rate_limits, quota_wait_s=0, sleep=lambda _: None)
        assert r.status == "pass", (sid, r.failures, r.got)
        with broker_connect() as c, c.transaction():  # the broker role writes the result
            scn.record(c, run_id, "dob", r, s, started, "abc1234")
    rows = conn.execute("SELECT scenario, status, checks, got FROM qa.scenario_run WHERE run_id = %s",
                        (run_id,)).fetchall()
    assert sorted(r["scenario"] for r in rows) == PIPELINE and {r["status"] for r in rows} == {"pass"}
    ak = next(r for r in rows if r["scenario"] == "ak-lateral-movement")
    assert ak["got"]["jira"] == {"issues": 1, "creates": 1}
    assert {"lark.case_notify", "lark.approval_card"} <= set(ak["got"]["lark"])
    pending = next(q for q in ak["got"]["requests"] if q["status"] == "pending_approval")
    assert pending["level"] == "L2" and 0 < pending["ttl_min"] <= 30
    assert [st["tactic"] for st in ak["got"]["steps"]] == ["TA0001", "TA0007", "TA0008", "TA0009"]
    # Nothing a scenario does is real: every case it opened is synthetic, every request shadow.
    assert conn.execute("SELECT bool_and(synthetic) ok FROM gateway.alert_case").fetchone()["ok"]
    assert conn.execute("SELECT count(*) n FROM broker.action_request WHERE mode <> 'shadow'").fetchone()["n"] == 0


def test_a_wrong_expectation_fails_with_the_check_named(client, principals, pool, settings, tmp_path,
                                                        broker_connect, rate_limits):
    s = ALL["ssh-bruteforce"]
    bad = scn.Scenario(s.id, s.title, s.kind, s.alerts, {**s.expect, "ai": {"verdicts": ["malicious"]}},
                       timeout_s=10)
    r = scn.run_pipeline(broker_connect, "dob", scn.new_run_id(), bad, 0,
                         lambda rows: _drive(client, principals, pool, settings, tmp_path, rows),
                         rate_limits=rate_limits, quota_wait_s=0, sleep=lambda _: None)
    assert r.status == "fail"
    assert [f["name"] for f in r.failures] == ["9router verdicts"]


def test_quota_taken_means_wait_then_error_not_a_bypass(client, principals, pool, settings, tmp_path,
                                                        broker_connect, rate_limits):
    s = ALL["ak-lateral-movement"]
    scn.run_pipeline(broker_connect, "dob", scn.new_run_id(), s, 0,
                     lambda rows: _drive(client, principals, pool, settings, tmp_path, rows),
                     rate_limits=rate_limits, quota_wait_s=0, sleep=lambda _: None)
    injected = []
    r = scn.run_pipeline(broker_connect, "dob", scn.new_run_id(), s, 1, injected.append,
                         rate_limits=rate_limits, quota_wait_s=0, sleep=lambda _: None, log=lambda _: None)
    assert r.status == "error" and "quota" in r.note and injected == []


def test_kill_switch_stops_the_run(client, principals, conn, broker_connect, rate_limits):
    with conn.transaction():
        pid = conn.execute("SELECT principal_id FROM broker.principal WHERE name = 'admin1'").fetchone()
        conn.execute("INSERT INTO broker.kill_switch (entity_id, scope, engaged, changed_by)"
                     " VALUES ('dob', 'global', true, %s)", (pid["principal_id"],))
    injected = []
    r = scn.run_pipeline(broker_connect, "dob", scn.new_run_id(), ALL["web-attack"], 0, injected.append,
                         rate_limits=rate_limits)
    assert r.status == "error" and "kill switch" in r.note and injected == []


def test_connection_scenario_runs_the_three_tests(client, broker_connect):
    hub = client.broker.hub
    r = scn.run_connection(lambda n: hub.test(broker_connect, n, "scenario:test"), ALL["integrations-connection"])
    assert r.status == "pass", r.got
    assert set(r.got) == {"lark", "jira", "ai"}
