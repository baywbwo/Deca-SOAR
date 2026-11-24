"""Integration secrets: write-only, AES-256-GCM sealed with a master key from a file mount.

The associated data binds a ciphertext to its entity, integration, mode, name and key id, so a sealed
value copied to another row does not open. Values are never logged, returned or written to the
ledger; the API only reports whether a secret is set and when and by whom it was rotated.

  HYPERSOAR_INTEGRATION_KEY_FILE   32-byte master key (hex or urlsafe base64), broker only
  HYPERSOAR_INTEGRATION_KEY_ID     default i1
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from hypersoar import ledger
from hypersoar.common.config import ConfigError, read_key32

REQUIRED = {
    "lark": ("app_secret", "verification_token", "encrypt_key"),
    "jira": ("api_token",),
    "ai": ("api_key",),
}
# Only needed when the matching feature is on (Jira inbound "close the case when Done").
OPTIONAL = {"jira": ("webhook_secret",)}
MAX_LEN = 4096


@dataclass(frozen=True)
class SecretBox:
    key: bytes
    key_id: str = "i1"

    @classmethod
    def from_env(cls) -> "SecretBox | None":
        if not (os.environ.get("HYPERSOAR_INTEGRATION_KEY_FILE") or os.environ.get("HYPERSOAR_INTEGRATION_KEY")):
            return None
        return cls(read_key32("HYPERSOAR_INTEGRATION_KEY"), os.environ.get("HYPERSOAR_INTEGRATION_KEY_ID", "i1"))

    @staticmethod
    def _aad(entity_id: str, integration: str, mode: str, name: str, key_id: str) -> bytes:
        return f"hypersoar-secret|{entity_id}|{integration}|{mode}|{name}|{key_id}".encode()

    def seal(self, entity_id: str, integration: str, mode: str, name: str, value: str) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        ct = AESGCM(self.key).encrypt(nonce, value.encode(), self._aad(entity_id, integration, mode, name, self.key_id))
        return nonce, ct

    def open(self, entity_id: str, integration: str, mode: str, name: str, key_id: str,
             nonce: bytes, ct: bytes) -> str:
        if key_id != self.key_id:
            raise ConfigError(f"integration secret {integration}.{name} is sealed with another key id")
        try:
            return AESGCM(self.key).decrypt(nonce, ct, self._aad(entity_id, integration, mode, name, key_id)).decode()
        except InvalidTag:
            raise ConfigError(f"integration secret {integration}.{name} does not open with this key") from None


def validate_name(integration: str, name: str) -> None:
    if name not in REQUIRED.get(integration, ()) + OPTIONAL.get(integration, ()):
        raise ValueError(f"{integration} has no secret named {name[:40]!r}")


def set_secret(conn, box: SecretBox, entity_id: str, integration: str, mode: str, name: str, value: str,
               actor: str, expires_at: datetime | None = None) -> None:
    validate_name(integration, name)
    value = value.strip()
    if not value or len(value) > MAX_LEN:
        raise ValueError("secret value is empty or too long")
    nonce, ct = box.seal(entity_id, integration, mode, name, value)
    conn.execute(
        "INSERT INTO broker.integration_secret (entity_id, integration, mode, name, key_id, nonce, ciphertext,"
        " rotated_at, rotated_by, expires_at) VALUES (%s, %s, %s, %s, %s, %s, %s, now(), %s, %s)"
        " ON CONFLICT (entity_id, integration, mode, name) DO UPDATE SET key_id = EXCLUDED.key_id,"
        " nonce = EXCLUDED.nonce, ciphertext = EXCLUDED.ciphertext, rotated_at = now(),"
        " rotated_by = EXCLUDED.rotated_by, expires_at = EXCLUDED.expires_at",
        (entity_id, integration, mode, name, box.key_id, nonce, ct, actor[:120], expires_at),
    )
    # Name, who and when only: never the value, its length or a hash of it.
    ledger.append(conn, "integration.secret_rotated", actor[:120],
                  {"integration": integration, "mode": mode, "name": name}, entity_id)


def get_secrets(conn, box: SecretBox | None, entity_id: str, integration: str, mode: str) -> dict[str, str]:
    if box is None:
        return {}
    rows = conn.execute(
        "SELECT name, key_id, nonce, ciphertext FROM broker.integration_secret"
        " WHERE entity_id = %s AND integration = %s AND mode = %s",
        (entity_id, integration, mode),
    ).fetchall()
    return {r["name"]: box.open(entity_id, integration, mode, r["name"], r["key_id"], bytes(r["nonce"]),
                                bytes(r["ciphertext"])) for r in rows}


def status(conn, entity_id: str, integration: str, mode: str) -> dict[str, dict]:
    """What the API shows: set or not, rotated when and by whom, expiry. Never a value."""
    rows = {r["name"]: r for r in conn.execute(
        "SELECT name, rotated_at, rotated_by, expires_at FROM broker.integration_secret"
        " WHERE entity_id = %s AND integration = %s AND mode = %s",
        (entity_id, integration, mode),
    ).fetchall()}
    out = {}
    for name in REQUIRED[integration] + OPTIONAL.get(integration, ()):
        r = rows.get(name)
        out[name] = {"set": r is not None, "required": name in REQUIRED[integration],
                     "rotated_at": r["rotated_at"].isoformat() if r else None,
                     "rotated_by": r["rotated_by"] if r else None,
                     "expires_at": r["expires_at"].isoformat() if r and r["expires_at"] else None}
    return out
