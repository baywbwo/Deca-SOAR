"""The broker's integration runtime: which client to use for an entity and mode, the outbox that
sends Lark and Jira work after the transaction that caused it commits, and approval escalation.

Outbox rows are written in the same transaction as the event (a request, an approval, a verdict),
so a crash never loses a notification and never sends one for something that rolled back. The sync
loop claims a due row with a short lease, makes the call outside any transaction except the Jira
create (which holds the case's jira_issue row so two workers can never both create), then marks it
done or schedules a retry.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from psycopg.types.json import Jsonb

from hypersoar import ledger
from hypersoar.broker.integrations import ai as ai_mod
from hypersoar.broker.integrations import calls, config, jira as jira_mod, lark as lark_mod, secretbox
from hypersoar.broker.integrations.calls import IntegrationError, Timer
from hypersoar.common.entity import Entity

log = logging.getLogger("hypersoar.broker.integrations")
ACTOR = "service:broker"
MAX_ATTEMPTS = 6
LEASE = timedelta(seconds=90)
NOTIFY_VERDICTS = ("suspicious", "malicious", "unknown")


class NotConfigured(RuntimeError):
    pass


@dataclass
class Hub:
    entity: Entity
    mode: str
    box: secretbox.SecretBox | None
    console_url: str | None = None
    jira_inbound: bool = False
    # Tests inject an httpx transport per integration; production leaves this empty.
    transports: dict = field(default_factory=dict)

    @property
    def entity_id(self) -> str:
        return self.entity.id

    # -- clients -------------------------------------------------------------
    def _load(self, conn, name: str):
        row, model = config.settings_of(conn, self.entity_id, name, self.mode)
        if model is None:
            raise NotConfigured(f"{name} is not configured or disabled")
        secrets = secretbox.get_secrets(conn, self.box, self.entity_id, name, self.mode)
        return row, model, secrets

    def lark(self, conn):
        row, s, secrets = self._load(conn, "lark")
        return lark_mod.LarkClient(s, secrets, row["target"], transport=self.transports.get("lark")), s, row

    def lark_secrets(self, conn) -> dict:
        return secretbox.get_secrets(conn, self.box, self.entity_id, "lark", self.mode)

    def jira(self, conn):
        row, s, secrets = self._load(conn, "jira")
        if row["target"] == "mock":
            return jira_mod.MockJira(conn, self.entity_id, s.project), s, row
        return jira_mod.LiveJira(s, secrets, transport=self.transports.get("jira")), s, row

    def ai(self, conn):
        row, s, secrets = self._load(conn, "ai")
        return ai_mod.NineRouter(s, secrets, row["target"], transport=self.transports.get("ai")), s, row

    def ladder(self, conn):
        try:
            _, s = config.settings_of(conn, self.entity_id, "lark", self.mode)
        except config.ConfigInvalid:
            return None
        return s.ladder if s else None

    # -- connection test (screen 08 "Test connection") -------------------------
    def test(self, conn_factory, name: str, actor: str) -> dict:
        import uuid
        started = datetime.now(UTC)
        with conn_factory() as conn:
            row = config.get(conn, self.entity_id, name, self.mode)
            try:
                client = {"lark": self.lark, "jira": self.jira, "ai": self.ai}[name](conn)[0]
                load_error = None
            except (NotConfigured, config.ConfigInvalid) as e:
                client, load_error = None, str(e)
            except Exception as e:  # a secret that does not open with this key
                client, load_error = None, type(e).__name__
            if client is None:
                steps = [{"step": "settings valid", "ok": False, "detail": load_error}]
            else:
                if self.mode == "production" and row["target"] != "live":
                    steps = [{"step": "production uses a live target", "ok": False}]
                else:
                    steps = client.test()
        status = "pass" if steps and all(s["ok"] for s in steps) else "fail"
        run_id = str(uuid.uuid4())
        with conn_factory() as conn, conn.transaction():
            conn.execute(
                "INSERT INTO broker.integration_test_run (run_id, entity_id, integration, mode, target, config_version,"
                " status, steps, actor, started_at, finished_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())",
                (run_id, self.entity_id, name, self.mode, row["target"] if row else "mock",
                 row["version"] if row else 0, status, Jsonb(steps), actor[:120], started),
            )
            ledger.append(conn, "integration.tested", actor[:120], {
                "integration": name, "mode": self.mode, "status": status, "run_id": run_id,
                "config_version": row["version"] if row else 0,
                "failed_steps": [s["step"] for s in steps if not s["ok"]],
            }, self.entity_id)
        return {"run_id": run_id, "integration": name, "status": status, "steps": steps,
                "config_version": row["version"] if row else 0}


# -- outbox -------------------------------------------------------------------
def enqueue(conn, entity_id: str, integration: str, operation: str, *, case_id=None, request_id=None,
            payload=None, once: bool = False) -> bool:
    """Queue outbound work in the caller's transaction. once=True skips it if the same operation was
    already queued for this case (any status), e.g. the first Lark notification of a case."""
    if once:
        hit = conn.execute(
            "SELECT 1 FROM broker.integration_outbox WHERE entity_id = %s AND integration = %s AND operation = %s"
            " AND case_id IS NOT DISTINCT FROM %s LIMIT 1", (entity_id, integration, operation, case_id),
        ).fetchone()
        if hit:
            return False
    conn.execute(
        "INSERT INTO broker.integration_outbox (entity_id, integration, operation, case_id, request_id, payload)"
        " VALUES (%s, %s, %s, %s, %s, %s)",
        (entity_id, integration, operation, case_id, request_id, Jsonb(payload or {})),
    )
    return True


def _case(conn, entity_id: str, case_id: str | None) -> dict | None:
    if not case_id:
        return None
    return conn.execute(
        "SELECT case_id, title, category, max_severity, priority, status, assets, tactics, alert_count, origin_city,"
        " origin_country, opened_at, closed_at FROM gateway.alert_case WHERE entity_id = %s AND case_id = %s",
        (entity_id, case_id),
    ).fetchone()


def _request(conn, request_id) -> dict | None:
    r = conn.execute("SELECT * FROM broker.action_request WHERE request_id = %s", (request_id,)).fetchone()
    if r is None:
        return None
    return {"request_id": str(r["request_id"]), "action": r["action"], "level": r["level"], "status": r["status"],
            "impact": r["impact"], "rollback_plan": r["rollback_plan"], "case_id": r["case_id"],
            "expires_at": r["expires_at"].astimezone(UTC).strftime("%H:%M UTC") if r["expires_at"] else None}


def _console_link(hub: Hub, case_id: str | None) -> str | None:
    if not hub.console_url or not case_id:
        return None
    return f"{hub.console_url.rstrip('/')}/cases?case={case_id}"


def _do_lark(conn, hub: Hub, row: dict) -> tuple[str, str | None, dict]:
    """Returns (status, external_ref, detail)."""
    client, s, _ = hub.lark(conn)
    op, p = row["operation"], row["payload"]
    case = _case(conn, hub.entity_id, row["case_id"])
    sent = []
    if op == "lark.approval_card":
        req = _request(conn, row["request_id"])
        if req is None or req["status"] != "pending_approval":
            return "skipped", None, {"reason": "request no longer pending"}
        step_no = min(int(p.get("step", 0)), len(s.ladder) - 1)
        step = s.ladder[step_no]
        card = lark_mod.approval_card(req, case, step.model_dump(), _console_link(hub, row["case_id"]))
        for a in step.approvers:
            sent.append(client.send("open_id", a.lark_user_id, card))
        return "ok", sent[0] if sent else None, {"step": step_no, "role": step.role, "recipients": len(sent)}
    sev = (case or {}).get("max_severity") or p.get("severity") or "high"
    route = s.routing.get(sev if sev in s.routing else "low")
    if route.delivery == "off" or not route.chat_id:
        return "skipped", None, {"reason": f"routing for {sev} is off"}
    if route.delivery != "now" and op == "lark.case_notify":
        # Digest delivery is not built yet: the case is still visible in the console and Jira.
        return "skipped", None, {"reason": f"{route.delivery} digest not implemented"}
    if op == "lark.case_notify":
        if case is None:
            return "skipped", None, {"reason": "case not found"}
        text = (f"**{case['case_id']}** · {case['title']}\nSeverity {case['max_severity']} · priority "
                f"{case['priority']} · {case['alert_count']} alerts\nAI verdict: {p.get('verdict', '-')}")
        card = lark_mod.notice_card(f"New case {case['case_id']}", text, sev)
    elif op == "lark.notice":
        card = lark_mod.notice_card(str(p.get("title", "HyperSoar"))[:120], str(p.get("text", ""))[:1500], sev)
    else:
        raise IntegrationError(f"unknown lark operation {op}")
    sent.append(client.send("chat_id", route.chat_id, card))
    if route.oncall_dm or p.get("oncall"):
        for a in s.ladder[0].approvers:
            sent.append(client.send("open_id", a.lark_user_id, card))
    return "ok", sent[0], {"recipients": len(sent), "severity": sev}


def ensure_jira_issue(conn, hub: Hub, case_id: str) -> tuple[str, str]:
    """(status, issue key). Runs inside the caller's transaction and holds the case's jira_issue row."""
    client, s, row = hub.jira(conn)
    label = jira_mod.label_for(case_id)
    conn.execute(
        "INSERT INTO broker.jira_issue (entity_id, case_id, label, status) VALUES (%s, %s, %s, 'pending')"
        " ON CONFLICT (entity_id, case_id) DO NOTHING", (hub.entity_id, case_id, label),
    )
    ji = conn.execute("SELECT * FROM broker.jira_issue WHERE entity_id = %s AND case_id = %s FOR UPDATE",
                      (hub.entity_id, case_id)).fetchone()
    if ji["issue_key"]:
        return "duplicate", ji["issue_key"]
    found = client.search(label)
    if found:
        status, key = "duplicate", found
        calls.record(conn, hub.entity_id, "jira", "jira.search", row["target"], "duplicate", case_id=case_id,
                     external_ref=key, detail={"label": label, "found": True})
    else:
        case = _case(conn, hub.entity_id, case_id)
        if case is None:
            raise IntegrationError("case not found")
        summary = jira_mod.title(s, case)
        lines = [
            f"HyperSoar case {case['case_id']}: {case['title']}",
            f"Category: {case['category']} · severity {case['max_severity']} · priority {case['priority']}",
            f"MITRE tactics: {', '.join(case['tactics'] or []) or '-'}",
            f"Origin: {case['origin_city'] or 'unknown'} {case['origin_country'] or ''}".strip(),
            f"Assets: {', '.join(case['assets'] or []) or '-'}",
            "Mode: shadow. HyperSoar records what it would do; nothing is executed.",
            _console_link(hub, case_id) or "",
        ]
        jira_mod.assert_tokenized(summary, *lines)
        fields = {"project": {"key": s.project}, "issuetype": {"name": s.issue_type}, "summary": summary,
                  "labels": [label, "hypersoar"], "priority": {"name": s.priority_map[case["max_severity"]]
                                                               if case["max_severity"] in s.priority_map
                                                               else s.priority_map["low"]},
                  "description": jira_mod.adf(lines)}
        with Timer() as t:
            key = client.create(fields)
        status = "ok"
        calls.record(conn, hub.entity_id, "jira", "jira.create", row["target"], "ok", case_id=case_id,
                     external_ref=key, detail={"label": label, "priority": fields["priority"]["name"]},
                     duration_ms=t.ms)
    conn.execute(
        "UPDATE broker.jira_issue SET issue_key = %s, status = 'created', attempts = attempts + 1, updated_at = now()"
        " WHERE entity_id = %s AND case_id = %s", (key, hub.entity_id, case_id),
    )
    ledger.append(conn, "jira.issue_linked", ACTOR, {"case_id": case_id, "issue_key": key, "found_existing":
                                                     status == "duplicate"}, hub.entity_id)
    return status, key


def _do_jira(conn, hub: Hub, row: dict) -> tuple[str, str | None, dict]:
    op, case_id = row["operation"], row["case_id"]
    if op == "jira.ensure_issue":
        status, key = ensure_jira_issue(conn, hub, case_id)
        return ("ok" if status == "ok" else "duplicate"), key, {"op": "ensure"}
    client, s, cfg = hub.jira(conn)
    ji = conn.execute("SELECT issue_key, status FROM broker.jira_issue WHERE entity_id = %s AND case_id = %s",
                      (hub.entity_id, case_id)).fetchone()
    if op == "jira.close" and (ji is None or not ji["issue_key"]):
        return "skipped", None, {"reason": "case has no Jira issue"}
    if ji is None or not ji["issue_key"]:
        # A comment can be the first thing a case sends (an L2 request before triage ran): the issue
        # is created here, through the same label check, so there is still one issue per case.
        if not case_id:
            return "skipped", None, {"reason": "request has no case"}
        ensure_jira_issue(conn, hub, case_id)
        ji = conn.execute("SELECT issue_key, status FROM broker.jira_issue WHERE entity_id = %s AND case_id = %s",
                          (hub.entity_id, case_id)).fetchone()
    if op == "jira.comment":
        if not s.sync.comment_on_update:
            return "skipped", ji["issue_key"], {"reason": "comment sync off"}
        text = str(row["payload"].get("text", ""))[:1500]
        jira_mod.assert_tokenized(text)
        client.comment(ji["issue_key"], jira_mod.adf(text.split("\n")))
        return "ok", ji["issue_key"], {"op": "comment"}
    if op == "jira.close":
        if not s.sync.done_on_close:
            return "skipped", ji["issue_key"], {"reason": "done on close off"}
        if ji["status"] == "closed":
            return "duplicate", ji["issue_key"], {"op": "close"}
        name = client.close(ji["issue_key"])
        conn.execute("UPDATE broker.jira_issue SET status = 'closed', updated_at = now() WHERE entity_id = %s"
                     " AND case_id = %s", (hub.entity_id, case_id))
        return "ok", ji["issue_key"], {"op": "close", "status": name}
    raise IntegrationError(f"unknown jira operation {op}")


def process_one(pool, hub: Hub, now: datetime | None = None) -> dict | None:
    """Claim and run one due outbox row. Returns what happened, or None when nothing is due."""
    now = now or datetime.now(UTC)
    with pool.connection() as conn, conn.transaction():
        row = conn.execute(
            "SELECT * FROM broker.integration_outbox WHERE entity_id = %s AND status = 'pending' AND next_at <= %s"
            " ORDER BY outbox_id LIMIT 1 FOR UPDATE SKIP LOCKED", (hub.entity_id, now),
        ).fetchone()
        if row is None:
            return None
        conn.execute("UPDATE broker.integration_outbox SET next_at = %s, attempts = attempts + 1"
                     " WHERE outbox_id = %s", (now + LEASE, row["outbox_id"]))
    attempt = row["attempts"] + 1
    target = "mock"
    error = None
    with pool.connection() as conn, conn.transaction():
        with Timer() as t:
            try:
                cfg = config.get(conn, hub.entity_id, row["integration"], hub.mode)
                target = cfg["target"] if cfg else "mock"
                with conn.transaction():  # savepoint: a failed call leaves no half-written row
                    fn = _do_lark if row["integration"] == "lark" else _do_jira
                    status, ref, detail = fn(conn, hub, row)
            except NotConfigured as e:
                status, ref, detail = "skipped", None, {"reason": str(e)[:200]}
            except (IntegrationError, config.ConfigInvalid) as e:
                status, ref, detail, error = "error", None, {"error": str(e)[:300]}, str(e)[:300]
        if row["operation"] != "jira.ensure_issue" or status == "error":
            calls.record(conn, hub.entity_id, row["integration"], row["operation"], target, status,
                         case_id=row["case_id"], request_id=row["request_id"], external_ref=ref,
                         detail={**detail, "attempt": attempt}, duration_ms=t.ms)
        if error and attempt < MAX_ATTEMPTS:
            conn.execute("UPDATE broker.integration_outbox SET next_at = %s WHERE outbox_id = %s",
                         (now + timedelta(seconds=10 * 2 ** attempt), row["outbox_id"]))
            final = "retry"
        else:
            final = "error" if error else "done"
            conn.execute("UPDATE broker.integration_outbox SET status = %s, done_at = now() WHERE outbox_id = %s",
                         (final, row["outbox_id"]))
            if final == "error":
                ledger.append(conn, "integration.failed", ACTOR, {
                    "integration": row["integration"], "operation": row["operation"], "case_id": row["case_id"],
                    "attempts": attempt, "error": error}, hub.entity_id)
    if error:
        log.warning("%s %s attempt %d failed: %s", row["integration"], row["operation"], attempt, error)
    return {"outbox_id": row["outbox_id"], "operation": row["operation"], "status": status, "outcome": final}


# -- escalation ---------------------------------------------------------------
def step_at(ladder, elapsed: timedelta) -> int:
    """Ladder step that should hold the request after `elapsed`: step k starts once the timeouts of
    steps 0..k-1 have passed."""
    start, level = timedelta(0), 0
    for i, s in enumerate(ladder):
        if elapsed >= start:
            level = i
        start += timedelta(minutes=s.timeout_min)
    return level


def escalate_due(pool, hub: Hub, now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(UTC)
    out = []
    with pool.connection() as conn, conn.transaction():
        ladder = hub.ladder(conn)
        rows = conn.execute(
            "SELECT * FROM broker.action_request WHERE entity_id = %s AND status = 'pending_approval'"
            " ORDER BY created_at FOR UPDATE SKIP LOCKED", (hub.entity_id,),
        ).fetchall()
        for r in rows:
            rid = str(r["request_id"])
            if r["expires_at"] and now >= r["expires_at"]:
                conn.execute("UPDATE broker.action_request SET status = 'expired' WHERE request_id = %s", (rid,))
                ledger.append(conn, "action.expired", ACTOR, {
                    "request_id": rid, "case_id": r["case_id"], "reason": "no approver answered in time",
                    "escalation_level": r["escalation_level"]}, hub.entity_id)
                text = (f"Approval for {r['action']} expired: nobody on the ladder answered. Nothing ran; the case "
                        "stays open.")
                if r["case_id"]:
                    enqueue(conn, hub.entity_id, "jira", "jira.comment", case_id=r["case_id"], request_id=rid,
                            payload={"text": text})
                enqueue(conn, hub.entity_id, "lark", "lark.notice", case_id=r["case_id"], request_id=rid,
                        payload={"title": "Approval expired", "text": text, "severity": "high"})
                out.append({"request_id": rid, "event": "expired"})
                continue
            if not ladder:
                continue
            level = step_at(ladder, now - r["created_at"])
            if level > r["escalation_level"]:
                conn.execute("UPDATE broker.action_request SET escalation_level = %s, escalated_at = %s"
                             " WHERE request_id = %s", (level, now, rid))
                ledger.append(conn, "action.escalated", ACTOR, {
                    "request_id": rid, "case_id": r["case_id"], "level": level, "role": ladder[level].role},
                    hub.entity_id)
                enqueue(conn, hub.entity_id, "lark", "lark.approval_card", case_id=r["case_id"], request_id=rid,
                        payload={"step": level})
                out.append({"request_id": rid, "event": "escalated", "level": level})
    return out


def close_issues_for_closed_cases(pool, hub: Hub) -> int:
    with pool.connection() as conn, conn.transaction():
        rows = conn.execute(
            "SELECT j.case_id FROM broker.jira_issue j JOIN gateway.alert_case c USING (entity_id, case_id)"
            " WHERE j.entity_id = %s AND j.status = 'created' AND c.status = 'closed'", (hub.entity_id,),
        ).fetchall()
        return sum(enqueue(conn, hub.entity_id, "jira", "jira.close", case_id=r["case_id"], once=True) for r in rows)


def tick(pool, hub: Hub, now: datetime | None = None, max_ops: int = 50) -> dict:
    """One pass of the sync loop: escalate/expire approvals, queue Jira closes, send due outbox rows."""
    esc = escalate_due(pool, hub, now)
    closes = close_issues_for_closed_cases(pool, hub)
    ops = []
    for _ in range(max_ops):
        r = process_one(pool, hub, now)
        if r is None:
            break
        ops.append(r)
    return {"escalations": esc, "jira_closes_queued": closes, "ops": ops}
