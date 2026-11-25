"""Generic webhook: any SIEM alert action (Splunk, Elastic, Wazuh, Sentinel playbooks, ...) posts JSON.

  POST /v1/ingest/webhook
  X-HyperSoar-Timestamp: <unix seconds>
  X-HyperSoar-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<raw body>" with the shared secret>

The body is one alert object, a list of them, or {"alerts": [...]}. The timestamp must be within
max_skew_s of the gateway clock and a signature is accepted once, so a captured request cannot be
replayed later or twice.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time

MAX_RECORDS = 500
MIN_SECRET = 32


class Rejected(ValueError):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status


def sign(secret: str, ts: int | str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()


class SeenSignatures:
    """Signatures accepted inside the skew window; older ones are refused by the timestamp anyway."""

    def __init__(self, max_items: int = 100_000) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()
        self.max_items = max_items

    def first_time(self, sig: str, ttl_s: float) -> bool:
        now = time.monotonic()
        with self._lock:
            if len(self._seen) >= self.max_items:
                self._seen = {k: t for k, t in self._seen.items() if t > now}
                if len(self._seen) >= self.max_items:
                    return False
            if self._seen.get(sig, 0) > now:
                return False
            self._seen[sig] = now + ttl_s
            return True


class DbSeen:
    """Accepted signatures in gateway.webhook_seen: shared by every gateway process and kept across
    restarts, so a captured request cannot be replayed after a restart or against another replica."""

    def __init__(self, pool, entity_id: str) -> None:
        self.pool, self.entity_id = pool, entity_id
        self._n = 0

    def first_time(self, sig: str, ttl_s: float) -> bool:
        digest = hashlib.sha256(sig.encode()).hexdigest()
        with self.pool.connection() as conn, conn.transaction():
            self._n += 1
            if self._n % 500 == 1:
                conn.execute("DELETE FROM gateway.webhook_seen WHERE expires_at < now()")
            row = conn.execute(
                "INSERT INTO gateway.webhook_seen (entity_id, sig_sha256, expires_at)"
                " VALUES (%s, %s, now() + make_interval(secs => %s))"
                " ON CONFLICT (entity_id, sig_sha256) DO UPDATE SET expires_at = EXCLUDED.expires_at"
                " WHERE gateway.webhook_seen.expires_at < now() RETURNING 1",
                (self.entity_id, digest, float(ttl_s))).fetchone()
        return row is not None


def verify(secret: str | None, ts_header: str | None, sig_header: str | None, body: bytes, max_skew_s: int,
           seen: SeenSignatures | DbSeen, now: float | None = None) -> None:
    if not secret or len(secret) < MIN_SECRET:
        raise Rejected(503, "webhook secret is not set")
    if not ts_header or not sig_header or not ts_header.isdigit():
        raise Rejected(401, "missing signature")
    now = time.time() if now is None else now
    if abs(now - int(ts_header)) > max_skew_s:
        raise Rejected(401, "timestamp outside the allowed window")
    if not hmac.compare_digest(sign(secret, ts_header, body), sig_header.strip()):
        raise Rejected(401, "bad signature")
    if not seen.first_time(sig_header.strip(), 2 * max_skew_s):
        raise Rejected(409, "signature already used")


def records(body: bytes) -> list[dict]:
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise Rejected(400, "body is not JSON") from None
    if isinstance(doc, dict) and isinstance(doc.get("alerts"), list):
        doc = doc["alerts"]
    items = doc if isinstance(doc, list) else [doc]
    if not items or len(items) > MAX_RECORDS or not all(isinstance(x, dict) for x in items):
        raise Rejected(400, f"send 1 to {MAX_RECORDS} alert objects")
    return items
