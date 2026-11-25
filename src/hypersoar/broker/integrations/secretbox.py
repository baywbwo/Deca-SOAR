"""Integration secrets: write-only, AES-256-GCM sealed with keys derived from a master key file.

Two subkeys are derived from the master with HKDF-SHA256: one for outbound integrations (Lark, Jira,
9router) and one for data sources. The broker holds the master; the gateway holds only the derived
source key, so it cannot open an outbound secret even if it could read the row.

The associated data binds a ciphertext to its entity, integration, mode, name, key id and the host
the secret was entered for, so a sealed value copied to another row, or kept after the host changed,
does not open. Changing the host deletes the secrets (config.save); they must be entered again.
Values are never logged, returned or written to the ledger; the API only reports whether a secret is
set and when and by whom it was rotated.

  HYPERSOAR_INTEGRATION_KEY_FILE   32-byte master key (hex or urlsafe base64), broker only
  HYPERSOAR_SOURCE_KEY_FILE        derived data-source key (`hypersoar integration derive-source-key`), gateway
  HYPERSOAR_INTEGRATION_KEY_ID     default i1
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from hypersoar import ledger, sources
from hypersoar.broker.integrations import CATEGORY
from hypersoar.common.config import ConfigError, read_key32

REQUIRED = {
    "lark": ("app_secret", "verification_token", "encrypt_key"),
    "jira": ("api_token",),
    "ai": ("api_key",),
    **{n: s.required_secrets for n, s in sources.SPECS.items()},
}
# Only needed when the matching feature is on (Jira inbound "close the case when Done").
OPTIONAL = {"jira": ("webhook_secret",)}
MAX_LEN = 4096
SCOPES = ("outbound", "source")


def scope_of(integration: str) -> str:
    return "source" if CATEGORY.get(integration) == "source" else "outbound"


def derive(master: bytes, scope: str) -> bytes:
    assert scope in SCOPES
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=f"hypersoar-integration-secret|{scope}".encode()).derive(master)


def bound_host(integration: str, settings: dict | None) -> str:
    """The host a secret of this integration is sent to; "" for push sources that call nobody."""
    s = settings or {}
    url = {"lark": s.get("base_url", "https://open.larksuite.com"), "jira": s.get("site"),
           "ai": s.get("base_url")}.get(integration)
    if integration == "sls" and s.get("endpoint") and s.get("project"):
        url = f"https://{s['project']}.{urlsplit(s['endpoint']).hostname}"
    try:
        return (urlsplit(url).hostname or "").lower() if url else ""
    except ValueError:
        return ""


@dataclass(frozen=True)
class SecretBox:
    keys: Mapping[str, bytes]  # scope -> AES key
    key_id: str = "i1"

    @classmethod
    def from_master(cls, master: bytes, key_id: str = "i1") -> "SecretBox":
        return cls({s: derive(master, s) for s in SCOPES}, key_id)

    @classmethod
    def from_env(cls) -> "SecretBox | None":
        """The broker: both scopes, from the master key."""
        if not (os.environ.get("HYPERSOAR_INTEGRATION_KEY_FILE") or os.environ.get("HYPERSOAR_INTEGRATION_KEY")):
            return None
        return cls.from_master(read_key32("HYPERSOAR_INTEGRATION_KEY"),
                               os.environ.get("HYPERSOAR_INTEGRATION_KEY_ID", "i1"))

    @classmethod
    def source_from_env(cls) -> "SecretBox | None":
        """The gateway: the derived data-source key only."""
        if not (os.environ.get("HYPERSOAR_SOURCE_KEY_FILE") or os.environ.get("HYPERSOAR_SOURCE_KEY")):
            return None
        return cls({"source": read_key32("HYPERSOAR_SOURCE_KEY")},
                   os.environ.get("HYPERSOAR_INTEGRATION_KEY_ID", "i1"))

    def _key(self, integration: str) -> bytes:
        key = self.keys.get(scope_of(integration))
        if key is None:
            raise ConfigError(f"this service holds no key for {integration} secrets")
        return key

    @staticmethod
    def _aad(entity_id: str, integration: str, mode: str, name: str, key_id: str, host: str) -> bytes:
        return f"hypersoar-secret|v2|{entity_id}|{integration}|{mode}|{name}|{key_id}|{host}".encode()

    def seal(self, entity_id: str, integration: str, mode: str, name: str, value: str,
             host: str) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        ct = AESGCM(self._key(integration)).encrypt(
            nonce, value.encode(), self._aad(entity_id, integration, mode, name, self.key_id, host))
        return nonce, ct

    def open(self, entity_id: str, integration: str, mode: str, name: str, key_id: str,
             nonce: bytes, ct: bytes, host: str) -> str:
        if key_id != self.key_id:
            raise ConfigError(f"integration secret {integration}.{name} is sealed with another key id")
        key = self._key(integration)
        try:
            return AESGCM(key).decrypt(nonce, ct, self._aad(entity_id, integration, mode, name, key_id,
                                                            host)).decode()
        except InvalidTag:
            raise ConfigError(f"integration secret {integration}.{name} does not open with this key") from None


def validate_name(integration: str, name: str) -> None:
    if name not in REQUIRED.get(integration, ()) + OPTIONAL.get(integration, ()):
        raise ValueError(f"{integration} has no secret named {name[:40]!r}")


def set_secret(conn, box: SecretBox, entity_id: str, integration: str, mode: str, name: str, value: str,
               actor: str, expires_at: datetime | None = None) -> None:
    """Sealed for the host of the latest saved settings, so configure the integration first."""
    validate_name(integration, name)
    value = value.strip()
    if not value or len(value) > MAX_LEN:
        raise ValueError("secret value is empty or too long")
    cfg = conn.execute(
        "SELECT settings FROM broker.integration_config WHERE entity_id = %s AND integration = %s AND mode = %s"
        " FOR SHARE", (entity_id, integration, mode)).fetchone()
    if cfg is None:
        raise ValueError(f"save the {integration} settings before its secrets")
    host = bound_host(integration, cfg["settings"])
    nonce, ct = box.seal(entity_id, integration, mode, name, value, host)
    conn.execute(
        "INSERT INTO broker.integration_secret (entity_id, integration, mode, name, key_id, nonce, ciphertext,"
        " rotated_at, rotated_by, expires_at, host) VALUES (%s, %s, %s, %s, %s, %s, %s, now(), %s, %s, %s)"
        " ON CONFLICT (entity_id, integration, mode, name) DO UPDATE SET key_id = EXCLUDED.key_id,"
        " nonce = EXCLUDED.nonce, ciphertext = EXCLUDED.ciphertext, rotated_at = now(),"
        " rotated_by = EXCLUDED.rotated_by, expires_at = EXCLUDED.expires_at, host = EXCLUDED.host",
        (entity_id, integration, mode, name, box.key_id, nonce, ct, actor[:120], expires_at, host),
    )
    # Name, who and when only: never the value, its length or a hash of it.
    ledger.append(conn, "integration.secret_rotated", actor[:120],
                  {"integration": integration, "mode": mode, "name": name}, entity_id)


def get_secrets(conn, box: SecretBox | None, entity_id: str, integration: str, mode: str, host: str,
                table: str = "broker.integration_secret") -> dict[str, str]:
    """Only secrets entered for `host` (the host of the settings in use). table="broker.source_secret"
    for the gateway, which may read data-source secrets only."""
    if box is None:
        return {}
    assert table in ("broker.integration_secret", "broker.source_secret")
    rows = conn.execute(
        f"SELECT name, key_id, nonce, ciphertext FROM {table}"
        " WHERE entity_id = %s AND integration = %s AND mode = %s AND host = %s",
        (entity_id, integration, mode, host),
    ).fetchall()
    return {r["name"]: box.open(entity_id, integration, mode, r["name"], r["key_id"], bytes(r["nonce"]),
                                bytes(r["ciphertext"]), host) for r in rows}


def clear_other_hosts(conn, entity_id: str, integration: str, mode: str, host: str, actor: str,
                      reason: str) -> list[str]:
    """Delete the secrets entered for any other host; they must be entered again for the new one."""
    gone = [r["name"] for r in conn.execute(
        "DELETE FROM broker.integration_secret WHERE entity_id = %s AND integration = %s AND mode = %s"
        " AND host <> %s RETURNING name", (entity_id, integration, mode, host)).fetchall()]
    if gone:
        ledger.append(conn, "integration.secrets_cleared", actor[:120],
                      {"integration": integration, "mode": mode, "names": sorted(gone), "reason": reason},
                      entity_id)
    return gone


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
