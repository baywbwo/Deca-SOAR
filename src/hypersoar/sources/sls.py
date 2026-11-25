"""Alibaba Cloud Log Service (SLS) pull: GetLogs over a moving, complete time window.

Each pull reads [from, from + window_s) once that window ends at least lag_s seconds ago, page by
page; the cursor ("<from>:<offset>") only moves past a window when SLS reports it complete. The
AccessKey needs log:GetLogStoreLogs on that one logstore only (read-only RAM policy).
Requests are signed with the SLS v1 scheme (HMAC-SHA1 over verb, date, x-log-* headers and resource).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from email.utils import formatdate
from urllib.parse import urlencode

import httpx

from hypersoar.common import egress
from hypersoar.sources import mapping
from hypersoar.sources.models import SlsSettings
from hypersoar.sources.spool import map_record

API_VERSION = "0.6.0"
TIMEOUT_S = 20


class SlsError(RuntimeError):
    pass


def signature(secret: str, verb: str, date: str, headers: dict[str, str], resource: str,
              params: dict[str, str]) -> str:
    log_headers = "\n".join(f"{k}:{v}" for k, v in sorted((k.lower(), v) for k, v in headers.items()
                                                          if k.lower().startswith(("x-log-", "x-acs-"))))
    canon = resource + ("?" + "&".join(f"{k}={params[k]}" for k in sorted(params)) if params else "")
    to_sign = f"{verb}\n\n\n{date}\n{log_headers}\n{canon}"
    return base64.b64encode(hmac.new(secret.encode(), to_sign.encode(), hashlib.sha1).digest()).decode()


class SlsClient:
    def __init__(self, s: SlsSettings, secrets: dict[str, str], transport: httpx.BaseTransport | None = None):
        self.s = s
        self.key_id = secrets.get("access_key_id")
        self.key_secret = secrets.get("access_key_secret")
        host = s.endpoint.removeprefix("https://")
        self.base = f"https://{s.project}.{host}"
        self.http = httpx.Client(timeout=TIMEOUT_S, transport=transport or egress.transport("sls"),
                                 follow_redirects=False)

    def get_logs(self, frm: int, to: int, offset: int, line: int) -> tuple[list[dict], bool]:
        """(logs, complete). Raises SlsError with the HTTP status/SLS error code only."""
        if not (self.key_id and self.key_secret):
            raise SlsError("access key not set")
        resource = f"/logstores/{self.s.logstore}"
        params = {"type": "log", "from": str(frm), "to": str(to), "query": self.s.query, "line": str(line),
                  "offset": str(offset), "reverse": "false"}
        date = formatdate(usegmt=True)
        headers = {"x-log-apiversion": API_VERSION, "x-log-signaturemethod": "hmac-sha1", "x-log-bodyrawsize": "0"}
        sig = signature(self.key_secret, "GET", date, headers, resource, params)
        try:
            r = self.http.get(f"{self.base}{resource}?{urlencode(params)}",
                              headers={**headers, "Date": date, "Authorization": f"LOG {self.key_id}:{sig}"})
        except httpx.HTTPError as e:
            raise SlsError(type(e).__name__) from None
        if r.status_code != 200:
            code = ""
            try:
                code = str(r.json().get("errorCode", ""))[:60]
            except ValueError:
                pass
            raise SlsError(f"HTTP {r.status_code} {code}".strip())
        try:
            logs = r.json()
        except ValueError:
            raise SlsError("response is not JSON") from None
        if not isinstance(logs, list):
            raise SlsError("unexpected response")
        return [x for x in logs if isinstance(x, dict)], r.headers.get("x-log-progress", "Complete") == "Complete"

    def test(self) -> list[dict]:
        steps = [{"step": "settings valid", "ok": True}]
        missing = [n for n, v in (("access_key_id", self.key_id), ("access_key_secret", self.key_secret)) if not v]
        steps.append({"step": "secrets set", "ok": not missing, "detail": ", ".join(missing) or None})
        if missing:
            return steps
        now = int(time.time())
        t0 = time.monotonic()
        try:
            logs, _ = self.get_logs(now - 900, now, 0, 1)
            steps.append({"step": f"read {self.s.project}/{self.s.logstore}", "ok": True,
                          "latency_ms": int((time.monotonic() - t0) * 1000)})
        except SlsError as e:
            steps.append({"step": f"read {self.s.project}/{self.s.logstore}", "ok": False, "detail": str(e)})
            return steps
        if logs:
            try:
                mapping.to_raw(logs[0], self.s, "sls://test")
                steps.append({"step": "latest log maps to an alert", "ok": True})
            except mapping.MappingError as e:
                steps.append({"step": "latest log maps to an alert", "ok": False, "detail": str(e)})
        return steps


class SlsSource:
    def __init__(self, client: SlsClient, name: str = "sls", clock=time.time) -> None:
        self.client = client
        self.name = name
        self.clock = clock

    def pull(self, cursor: str | None, limit: int) -> tuple[list[dict], str]:
        s = self.client.s
        newest = int(self.clock()) - s.lag_s
        if cursor:
            frm, offset = (int(x) for x in cursor.split(":"))
        else:
            frm, offset = newest - s.window_s, 0  # a new source starts now; no backfill
        out: list[dict] = []
        while frm + s.window_s <= newest and len(out) < limit:
            to = frm + s.window_s
            want = min(s.page, limit - len(out))
            logs, complete = self.client.get_logs(frm, to, offset, want)
            if not complete:
                break  # SLS is still indexing this window; read it again next cycle
            for n, rec in enumerate(logs):
                out.append(map_record(rec, s, f"sls://{s.project}/{s.logstore}/{frm}/{offset + n}"))
            if len(logs) == want:
                offset += len(logs)  # a full page: there may be more in this window
                continue
            frm, offset = to, 0
        return out, f"{frm}:{offset}"
