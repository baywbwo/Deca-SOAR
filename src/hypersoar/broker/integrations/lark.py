"""Lark (Larksuite) custom app: case notifications and approval cards with Approve/Reject buttons.

A plain group webhook cannot receive button clicks, so this is a custom app (app_id + app secret).
Card clicks come back to /hooks/lark/card, signed and encrypted with the app's encrypt key; see
verify_callback. Who clicked must be on the entity's approver ladder, and the broker re-checks the
request (status, TTL, kill switch, level) before anything is recorded.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import httpx
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from hypersoar.broker.integrations.calls import IntegrationError
from hypersoar.common import egress

MAX_SKEW_S = 300
SEV_TEMPLATE = {"critical": "red", "high": "orange", "medium": "yellow", "low": "grey"}


class CallbackRejected(ValueError):
    """Not a genuine Lark callback. The message says which check failed, nothing more."""


def sign(timestamp: str, nonce: str, encrypt_key: str, body: bytes) -> str:
    return hashlib.sha256(timestamp.encode() + nonce.encode() + encrypt_key.encode() + body).hexdigest()


def encrypt(encrypt_key: str, plaintext: bytes, iv: bytes) -> str:
    """Lark's scheme (used by tests and the sandbox simulator): AES-256-CBC, key sha256(encrypt key)."""
    p = padding.PKCS7(128).padder()
    data = p.update(plaintext) + p.finalize()
    enc = Cipher(algorithms.AES(hashlib.sha256(encrypt_key.encode()).digest()), modes.CBC(iv)).encryptor()
    return base64.b64encode(iv + enc.update(data) + enc.finalize()).decode()


def decrypt(encrypt_key: str, blob: str) -> bytes:
    try:
        raw = base64.b64decode(blob, validate=True)
        if len(raw) < 32 or len(raw) % 16:
            raise ValueError
        dec = Cipher(algorithms.AES(hashlib.sha256(encrypt_key.encode()).digest()), modes.CBC(raw[:16])).decryptor()
        data = dec.update(raw[16:]) + dec.finalize()
        u = padding.PKCS7(128).unpadder()
        return u.update(data) + u.finalize()
    except ValueError:
        raise CallbackRejected("payload cannot be decrypted") from None


def verify_callback(headers, body: bytes, *, encrypt_key: str, verification_token: str,
                    now: float | None = None) -> dict:
    """Return the decrypted event, or raise CallbackRejected.

    Order matters: signature and timestamp first (cheap, before touching the ciphertext), then
    decryption, then the verification token inside the payload.
    """
    if not encrypt_key or not verification_token:
        raise CallbackRejected("callback secrets not set")
    ts = headers.get("x-lark-request-timestamp", "")
    nonce = headers.get("x-lark-request-nonce", "")
    sig = headers.get("x-lark-signature", "")
    if not (ts.isdigit() and nonce and len(nonce) <= 128 and sig):
        raise CallbackRejected("missing signature headers")
    if abs((now if now is not None else time.time()) - int(ts)) > MAX_SKEW_S:
        raise CallbackRejected("stale timestamp")
    if not hmac.compare_digest(sign(ts, nonce, encrypt_key, body), sig.lower()):
        raise CallbackRejected("bad signature")
    try:
        outer = json.loads(body)
    except ValueError:
        raise CallbackRejected("body is not JSON") from None
    if not isinstance(outer, dict) or not isinstance(outer.get("encrypt"), str):
        raise CallbackRejected("body is not encrypted")
    try:
        event = json.loads(decrypt(encrypt_key, outer["encrypt"]))
    except ValueError:
        raise CallbackRejected("payload is not JSON") from None
    if not isinstance(event, dict):
        raise CallbackRejected("payload is not an object")
    token = event.get("token") or (event.get("header") or {}).get("token") or ""
    if not hmac.compare_digest(str(token).encode(), verification_token.encode()):
        raise CallbackRejected("bad verification token")
    return event


def card_click(event: dict) -> tuple[str, str, bool] | None:
    """(operator open_id, request_id, approve) from a card.action.trigger event, else None."""
    if (event.get("header") or {}).get("event_type") != "card.action.trigger":
        return None
    ev = event.get("event") or {}
    op = (ev.get("operator") or {}).get("open_id")
    value = (ev.get("action") or {}).get("value") or {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return None
    if not (isinstance(op, str) and isinstance(value, dict) and isinstance(value.get("request_id"), str)
            and isinstance(value.get("approve"), bool)):
        return None
    return op, value["request_id"], value["approve"]


def approval_card(req: dict, case: dict | None, step: dict, console_url: str | None) -> dict:
    """Interactive card for an L2 request. Values carry only the request id and the choice."""
    case_line = f"**{case['case_id']}** · {case['title']}" if case else "No case"
    lines = [
        case_line,
        f"Action: `{req['action']}` (level {req['level']}, runs in shadow: nothing executes)",
        f"Impact: {req.get('impact') or '-'}",
        f"Rollback: {req.get('rollback_plan') or '-'}",
        f"Escalation: {step['role']} · expires {req.get('expires_at') or '-'}",
    ]
    actions = [
        {"tag": "button", "text": {"tag": "plain_text", "content": "Approve"}, "type": "primary",
         "value": {"request_id": req["request_id"], "approve": True}},
        {"tag": "button", "text": {"tag": "plain_text", "content": "Reject"}, "type": "danger",
         "value": {"request_id": req["request_id"], "approve": False}},
    ]
    if console_url:
        actions.append({"tag": "button", "text": {"tag": "plain_text", "content": "Open in HyperSoar"},
                        "type": "default", "url": console_url})
    return {
        "config": {"wide_screen_mode": True},
        "header": {"title": {"tag": "plain_text", "content": f"Approval needed · {req['action']}"},
                   "template": SEV_TEMPLATE.get((case or {}).get("max_severity", "high"), "orange")},
        "elements": [{"tag": "markdown", "content": "\n".join(lines)}, {"tag": "action", "actions": actions}],
    }


def notice_card(title: str, text: str, severity: str) -> dict:
    return {
        "config": {"wide_screen_mode": True},
        "header": {"title": {"tag": "plain_text", "content": title[:120]},
                   "template": SEV_TEMPLATE.get(severity, "grey")},
        "elements": [{"tag": "markdown", "content": text[:2000]}],
    }


class LarkClient:
    def __init__(self, settings, secrets: dict, target: str, *, transport=None):
        self.s = settings
        self.target = target
        self._secrets = secrets
        self._transport = transport
        self._token: tuple[str, float] | None = None

    def _http(self) -> httpx.Client:
        return httpx.Client(base_url=self.s.base_url, timeout=httpx.Timeout(10.0), follow_redirects=False,
                            transport=self._transport or egress.transport("lark"))

    def _tenant_token(self, http: httpx.Client) -> str:
        if self._token and self._token[1] > time.monotonic():
            return self._token[0]
        secret = self._secrets.get("app_secret")
        if not secret:
            raise IntegrationError("lark app secret not set")
        r = _post(http, "/open-apis/auth/v3/tenant_access_token/internal",
                  json={"app_id": self.s.app_id, "app_secret": secret})
        data = _json(r, "lark auth")
        if data.get("code") != 0 or not data.get("tenant_access_token"):
            raise IntegrationError(f"lark auth refused (code {data.get('code')})")
        self._token = (data["tenant_access_token"], time.monotonic() + max(60, int(data.get("expire", 0)) - 300))
        return self._token[0]

    def send(self, receive_id_type: str, receive_id: str, card: dict) -> str:
        """Send an interactive card; returns the Lark message id (mock: a deterministic fake)."""
        if self.target == "mock":
            return "om_mock_" + hashlib.sha256(json.dumps([receive_id, card], sort_keys=True).encode()).hexdigest()[:20]
        with self._http() as http:
            token = self._tenant_token(http)
            r = _post(http, f"/open-apis/im/v1/messages?receive_id_type={receive_id_type}",
                      headers={"Authorization": f"Bearer {token}"},
                      json={"receive_id": receive_id, "msg_type": "interactive", "content": json.dumps(card)})
            data = _json(r, "lark send")
            if data.get("code") != 0:
                raise IntegrationError(f"lark send refused (code {data.get('code')})")
            return str((data.get("data") or {}).get("message_id", ""))[:80]

    def test(self) -> list[dict]:
        steps = [{"step": "settings valid", "ok": True}]
        if self.target == "mock":
            steps.append({"step": "mock target (sandbox): no call made", "ok": True})
            return steps
        missing = [n for n in ("app_secret", "verification_token", "encrypt_key") if not self._secrets.get(n)]
        steps.append({"step": "secrets set", "ok": not missing, "detail": ", ".join(missing) or None})
        if missing:
            return steps
        try:
            with self._http() as http:
                self._tenant_token(http)
            steps.append({"step": "app credentials accepted", "ok": True})
        except IntegrationError as e:
            steps.append({"step": "app credentials accepted", "ok": False, "detail": str(e)})
        return steps


def _post(http: httpx.Client, path: str, **kw) -> httpx.Response:
    try:
        return http.post(path, **kw)
    except httpx.TimeoutException:
        raise IntegrationError("lark timed out") from None
    except httpx.TransportError as e:
        raise IntegrationError(f"lark unreachable ({type(e).__name__})") from None


def _json(r: httpx.Response, what: str) -> dict:
    if r.status_code >= 400:
        raise IntegrationError(f"{what} http {r.status_code}")
    try:
        d = r.json()
    except ValueError:
        raise IntegrationError(f"{what}: response is not JSON") from None
    if not isinstance(d, dict):
        raise IntegrationError(f"{what}: unexpected response")
    return d
