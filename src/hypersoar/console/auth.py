"""Console login: one account, scrypt password hash, server-side sessions, login rate limits.

The password itself never reaches this process's configuration; only `scrypt$N$r$p$salt$hash`
(from `hypersoar console-hash`, read on stdin) is stored, in a secret file.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from hypersoar.common.config import ConfigError

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1
MAXMEM = 64 * 1024 * 1024
MIN_PASSWORD_LEN = 16


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=MAXMEM, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(dk)}"


@dataclass(frozen=True)
class PasswordHash:
    n: int
    r: int
    p: int
    salt: bytes
    digest: bytes

    @classmethod
    def parse(cls, value: str) -> "PasswordHash":
        parts = value.strip().split("$")
        if len(parts) != 6 or parts[0] != "scrypt":
            raise ConfigError("console password hash is not in scrypt$N$r$p$salt$hash form")
        try:
            n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
            salt, digest = _unb64(parts[4]), _unb64(parts[5])
        except ValueError as e:
            raise ConfigError("console password hash is malformed") from e
        if n < 2**14 or r < 8 or p < 1 or len(salt) < 16 or len(digest) != 32:
            raise ConfigError("console password hash parameters are too weak")
        return cls(n, r, p, salt, digest)

    def verify(self, password: str) -> bool:
        dk = hashlib.scrypt(password.encode()[:1024], salt=self.salt, n=self.n, r=self.r, p=self.p,
                            maxmem=MAXMEM, dklen=32)
        return hmac.compare_digest(dk, self.digest)


@dataclass
class Session:
    user: str
    created: float
    seen: float
    # Sent back by console.js in X-HyperSoar-CSRF on every write; another site cannot read it.
    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(32))


class SessionStore:
    """In-memory sessions: a restart logs everyone out, which is fine for one owner account."""

    def __init__(self, idle_s: float = 30 * 60, absolute_s: float = 8 * 3600, max_sessions: int = 32) -> None:
        self.idle_s, self.absolute_s, self.max_sessions = idle_s, absolute_s, max_sessions
        self._s: dict[str, Session] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def create(self, user: str) -> str:
        token = secrets.token_urlsafe(32)
        now = time.monotonic()
        with self._lock:
            self._purge(now)
            while len(self._s) >= self.max_sessions:
                oldest = min(self._s, key=lambda k: self._s[k].seen)
                del self._s[oldest]
            self._s[self._key(token)] = Session(user, now, now)
        return token

    def get(self, token: str | None) -> Session | None:
        if not token or len(token) > 128:
            return None
        now = time.monotonic()
        with self._lock:
            s = self._s.get(self._key(token))
            if s is None:
                return None
            if now - s.seen > self.idle_s or now - s.created > self.absolute_s:
                del self._s[self._key(token)]
                return None
            s.seen = now
            return s

    def drop(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._s.pop(self._key(token), None)

    def _purge(self, now: float) -> None:
        for k in [k for k, s in self._s.items() if now - s.seen > self.idle_s or now - s.created > self.absolute_s]:
            del self._s[k]


class LoginLimiter:
    """Failed logins per client (default 5 per 15 minutes) and all attempts together (30 per minute).

    The global cap also bounds the CPU spent on scrypt when many addresses are used at once.
    """

    def __init__(self, per_client: int = 5, window_s: float = 900, global_per_min: int = 30,
                 max_clients: int = 10_000) -> None:
        self.per_client, self.window_s, self.global_per_min, self.max_clients = (
            per_client, window_s, global_per_min, max_clients)
        self._fail: dict[str, deque[float]] = {}
        self._all: deque[float] = deque()
        self._lock = threading.Lock()

    def allow(self, client: str) -> bool:
        now = time.monotonic()
        with self._lock:
            while self._all and now - self._all[0] > 60:
                self._all.popleft()
            if len(self._all) >= self.global_per_min:
                return False
            q = self._fail.get(client)
            if q is not None:
                while q and now - q[0] > self.window_s:
                    q.popleft()
                if len(q) >= self.per_client:
                    return False
            self._all.append(now)
            return True

    def failed(self, client: str) -> None:
        now = time.monotonic()
        with self._lock:
            if client not in self._fail and len(self._fail) >= self.max_clients:
                stale = [k for k, q in self._fail.items() if not q or now - q[-1] > self.window_s]
                for k in stale or list(self._fail)[: self.max_clients // 10]:
                    del self._fail[k]
            self._fail.setdefault(client, deque()).append(now)

    def succeeded(self, client: str) -> None:
        with self._lock:
            self._fail.pop(client, None)


def client_address(peer: str | None, headers: dict[str, str], trusted_proxies: list) -> str:
    """The peer address, or CF-Connecting-IP when the peer is a trusted proxy (the tunnel connector)."""
    peer = peer or "unknown"
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if any(ip in net for net in trusted_proxies):
        forwarded = headers.get("cf-connecting-ip", "").strip()
        try:
            return str(ipaddress.ip_address(forwarded))
        except ValueError:
            return peer
    return peer
