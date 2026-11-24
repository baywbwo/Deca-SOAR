"""Jira Cloud: one issue per case, kept up to date.

Never more than one issue per case: the broker takes the jira_issue row (FOR UPDATE) before any
call, and before creating it searches for the label hypersoar-<case_id>, so a crash after Jira
created the issue but before the row was updated finds the issue instead of making a second one.
"""

from __future__ import annotations

import re

import httpx

from hypersoar.broker.integrations.calls import IntegrationError

LABEL_RE = re.compile(r"^hypersoar-[A-Za-z0-9-]{1,40}$")
_RAW = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
                  r"|\bLTAI[0-9A-Za-z]{12,30}\b")


def label_for(case_id: str) -> str:
    label = f"hypersoar-{case_id}"
    if not LABEL_RE.match(label):
        raise IntegrationError("case id cannot be used as a Jira label")
    return label


def adf(lines: list[str]) -> dict:
    """Atlassian document format: one paragraph per line."""
    return {"type": "doc", "version": 1, "content": [
        {"type": "paragraph", "content": [{"type": "text", "text": ln[:1000]}]} for ln in lines if ln
    ]}


def assert_tokenized(*texts: str) -> None:
    """Issue text is built from case fields that are already tokenised; this is the last check."""
    for t in texts:
        if _RAW.search(t or ""):
            raise IntegrationError("refusing to send a raw IP, email or AccessKey to Jira")


def title(settings, case: dict) -> str:
    asset = (case.get("assets") or [None])[0] or "-"
    return settings.title_template.format(
        severity=case["max_severity"].capitalize(), case_id=case["case_id"], case_title=case["title"], asset=asset,
    )[:250]


class MockJira:
    """Sandbox stand-in. Its 'Jira' is the broker's own call log, so search-before-create is real:
    an issue created earlier (by any process) is found by its label."""

    def __init__(self, conn, entity_id: str, project: str):
        self.conn, self.entity_id, self.project = conn, entity_id, project

    def search(self, label: str) -> str | None:
        r = self.conn.execute(
            "SELECT external_ref FROM broker.integration_call WHERE entity_id = %s AND integration = 'jira'"
            " AND operation = 'jira.create' AND status = 'ok' AND target = 'mock' AND detail->>'label' = %s"
            " ORDER BY created_at LIMIT 1", (self.entity_id, label),
        ).fetchone()
        return r["external_ref"] if r else None

    def create(self, fields: dict) -> str:
        n = self.conn.execute(
            "SELECT count(*) AS n FROM broker.integration_call WHERE entity_id = %s AND integration = 'jira'"
            " AND operation = 'jira.create' AND status = 'ok' AND target = 'mock'", (self.entity_id,),
        ).fetchone()["n"]
        return f"{self.project}-{101 + n}"

    def comment(self, key: str, body: dict) -> None:
        return None

    def close(self, key: str) -> str:
        return "Done"

    def test(self) -> list[dict]:
        return [{"step": "settings valid", "ok": True}, {"step": "mock target (sandbox): no call made", "ok": True}]


class LiveJira:
    def __init__(self, settings, secrets: dict, *, transport=None):
        self.s = settings
        self._token = secrets.get("api_token")
        self._transport = transport

    def _http(self) -> httpx.Client:
        if not self._token:
            raise IntegrationError("jira api token not set")
        return httpx.Client(base_url=self.s.site, timeout=httpx.Timeout(15.0), follow_redirects=False,
                            auth=(self.s.email, self._token), transport=self._transport,
                            headers={"Accept": "application/json"})

    def _call(self, method: str, path: str, what: str, **kw) -> httpx.Response:
        try:
            with self._http() as http:
                r = http.request(method, path, **kw)
        except httpx.TimeoutException:
            raise IntegrationError(f"jira {what} timed out") from None
        except httpx.TransportError as e:
            raise IntegrationError(f"jira {what} unreachable ({type(e).__name__})") from None
        if r.status_code >= 400:
            raise IntegrationError(f"jira {what} http {r.status_code}")
        return r

    def _json(self, r: httpx.Response, what: str):
        try:
            return r.json()
        except ValueError:
            raise IntegrationError(f"jira {what}: response is not JSON") from None

    def search(self, label: str) -> str | None:
        r = self._call("GET", "/rest/api/3/search/jql", "search",
                       params={"jql": f'project = "{self.s.project}" AND labels = "{label}"',
                               "fields": "key", "maxResults": 2})
        issues = (self._json(r, "search") or {}).get("issues") or []
        return str(issues[0]["key"])[:40] if issues and isinstance(issues[0], dict) and issues[0].get("key") else None

    def create(self, fields: dict) -> str:
        r = self._call("POST", "/rest/api/3/issue", "create", json={"fields": fields})
        key = (self._json(r, "create") or {}).get("key")
        if not isinstance(key, str) or not key:
            raise IntegrationError("jira create: no issue key in response")
        return key[:40]

    def comment(self, key: str, body: dict) -> None:
        self._call("POST", f"/rest/api/3/issue/{key}/comment", "comment", json={"body": body})

    def close(self, key: str) -> str:
        r = self._call("GET", f"/rest/api/3/issue/{key}/transitions", "transitions")
        ts = (self._json(r, "transitions") or {}).get("transitions") or []
        done = next((t for t in ts if ((t.get("to") or {}).get("statusCategory") or {}).get("key") == "done"), None)
        if done is None:
            raise IntegrationError("jira: no transition to a Done status")
        self._call("POST", f"/rest/api/3/issue/{key}/transitions", "transition",
                   json={"transition": {"id": str(done["id"])}})
        return str((done.get("to") or {}).get("name") or "Done")[:40]

    def test(self) -> list[dict]:
        steps = [{"step": "settings valid", "ok": True},
                 {"step": "secrets set", "ok": bool(self._token), "detail": None if self._token else "api_token"}]
        if not self._token:
            return steps
        checks = [
            ("credentials accepted", lambda: self._call("GET", "/rest/api/3/myself", "auth")),
            (f"project {self.s.project} found", lambda: self._call("GET", f"/rest/api/3/project/{self.s.project}",
                                                                   "project")),
            (f"issue type {self.s.issue_type} exists", self._has_issue_type),
            ("priorities exist", self._has_priorities),
        ]
        for name, fn in checks:
            try:
                fn()
                steps.append({"step": name, "ok": True})
            except IntegrationError as e:
                steps.append({"step": name, "ok": False, "detail": str(e)})
                break
        return steps

    def _has_issue_type(self):
        r = self._call("GET", f"/rest/api/3/issue/createmeta/{self.s.project}/issuetypes", "issue types")
        names = {t.get("name") for t in (self._json(r, "issue types") or {}).get("issueTypes", [])
                 if isinstance(t, dict)}
        if self.s.issue_type not in names:
            raise IntegrationError("issue type not in project")

    def _has_priorities(self):
        r = self._call("GET", "/rest/api/3/priority", "priorities")
        names = {p.get("name") for p in (self._json(r, "priorities") or []) if isinstance(p, dict)}
        missing = sorted(set(self.s.priority_map.values()) - names)
        if missing:
            raise IntegrationError(f"priority not found: {', '.join(missing)[:80]}")
