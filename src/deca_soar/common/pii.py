"""PII tokenisation (design 6.1) and the encrypted token vault (design 6.3 item 8).

Tokens are deterministic, `tok_<kind>_<16 hex>` = HMAC-SHA256(tokenization_key, kind|value),
so the same IP gets the same token across alerts (dedup and correlation keep working)
without the value being recoverable from the token. The real value is stored in the vault
encrypted with AES-256-GCM, with the token as associated data.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

import psycopg
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TOKEN_RE = re.compile(r"\btok_[a-z]+_[0-9a-f]{16}\b")

_IPV4 = r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d.])"
_IPV6_CANDIDATE = r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"
_EMAIL = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
_PHONE_ID = r"(?<![\d+])(?:\+?62|0)8\d{1,3}[\s-]?\d{3,4}[\s-]?\d{3,5}(?!\d)"
_SECRET_PARAM = (
    r"(?i)(?P<k>[?&;](?:access_token|refresh_token|id_token|token|api_?key|key|secret|password|passwd|pwd"
    r"|signature|sig|auth|session(?:id)?|code|otp|pin)=)(?P<v>[^&#\s]+)"
)
_BEARER = r"(?i)(?P<k>\b(?:bearer|basic)\s+)(?P<v>[A-Za-z0-9._~+/=-]{8,})"
_ALIBABA_AK = r"\bLTAI[0-9A-Za-z]{12,30}\b"
_DIGITS = r"(?<![\d])\d{10,19}(?![\d])"


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass
class Tokenizer:
    key: bytes
    internal_cidrs: list = field(default_factory=list)
    # token -> (kind, original value); collected for the vault, never logged.
    found: dict[str, tuple[str, str]] = field(default_factory=dict)

    def token(self, kind: str, value: str) -> str:
        digest = hmac.new(self.key, f"{kind}|{value}".encode(), hashlib.sha256).hexdigest()[:16]
        tok = f"tok_{kind}_{digest}"
        self.found[tok] = (kind, value)
        return tok

    def is_internal_ip(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return any(ip in net for net in self.internal_cidrs)

    def token_ip(self, value: str) -> str:
        """Tokenise an IP unless it belongs to DECA's internal ranges (those are not customer data)."""
        ip = ipaddress.ip_address(value)
        if self.is_internal_ip(ip):
            return str(ip)
        return self.token("ip", str(ip))

    def scrub(self, text: str) -> str:
        """Replace every PII/secret pattern in free text with a token."""
        if not text:
            return text
        passes = (
            (_SECRET_PARAM, lambda m: m.group("k") + self.token("secret", m.group("v"))),
            (_BEARER, lambda m: m.group("k") + self.token("secret", m.group("v"))),
            (_ALIBABA_AK, lambda m: self.token("ak", m.group(0))),
            (_EMAIL, lambda m: self.token("email", m.group(0).lower())),
            (_IPV4, lambda m: self.token_ip(m.group(0))),
            (_IPV6_CANDIDATE, self._ipv6_sub),
            (_PHONE_ID, lambda m: self.token("phone", re.sub(r"[\s-]", "", m.group(0)))),
            (_DIGITS, self._digits_sub),
        )
        for pattern, repl in passes:
            text = _sub_outside_tokens(pattern, repl, text)
        return text

    def _ipv6_sub(self, m: re.Match) -> str:
        s = m.group(0)
        try:
            ip = ipaddress.IPv6Address(s)
        except ValueError:
            return s
        return self.token_ip(str(ip))

    def _digits_sub(self, m: re.Match) -> str:
        d = m.group(0)
        if 13 <= len(d) <= 19 and _luhn_ok(d):
            return self.token("card", d)
        if len(d) == 16:
            return self.token("nik", d)
        # Unknown long numbers (account numbers, ids) are tokenised too: fail-safe over useful.
        return self.token("num", d)


def _sub_outside_tokens(pattern: str, repl, text: str) -> str:
    """Apply a substitution only to text between existing tokens, so hex digests are never re-tokenised."""
    parts = TOKEN_RE.split(text)
    toks = TOKEN_RE.findall(text)
    out = [re.sub(pattern, repl, parts[0])]
    for tok, rest in zip(toks, parts[1:], strict=True):
        out.append(tok)
        out.append(re.sub(pattern, repl, rest))
    return "".join(out)


def mask_access_key(ak: str | None) -> str | None:
    if not ak:
        return None
    return "****" + ak[-4:]


def tokens_in(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    for v in values:
        if v:
            out.extend(TOKEN_RE.findall(v))
    return sorted(set(out))


class Vault:
    """Encrypted token -> value map. Only the gateway (writes) and broker (reads) hold the key."""

    def __init__(self, key: bytes, key_id: str = "v1") -> None:
        self._aead = AESGCM(key)
        self.key_id = key_id

    def store(self, conn: psycopg.Connection, found: dict[str, tuple[str, str]]) -> None:
        for tok, (kind, value) in found.items():
            nonce = os.urandom(12)
            ct = self._aead.encrypt(nonce, value.encode(), tok.encode())
            conn.execute(
                "INSERT INTO vault.token_map (token, kind, key_id, nonce, ciphertext)"
                " VALUES (%s, %s, %s, %s, %s) ON CONFLICT (token) DO NOTHING",
                (tok, kind, self.key_id, nonce, ct),
            )

    def reveal(self, conn: psycopg.Connection, token: str) -> str | None:
        row = conn.execute("SELECT nonce, ciphertext FROM vault.token_map WHERE token = %s", (token,)).fetchone()
        if row is None:
            return None
        nonce, ct = (row["nonce"], row["ciphertext"]) if isinstance(row, dict) else row
        return self._aead.decrypt(bytes(nonce), bytes(ct), token.encode()).decode()
