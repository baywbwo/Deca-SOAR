"""Settings from the environment.

Secrets are read from `<NAME>_FILE` (a path, preferred in production) or `<NAME>`.
Their values are never logged or included in error messages.
"""

from __future__ import annotations

import base64
import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(RuntimeError):
    pass


def read_secret(name: str, *, required: bool = True) -> str | None:
    path = os.environ.get(f"{name}_FILE")
    if path:
        try:
            value = Path(path).read_text().strip()
        except OSError as e:
            raise ConfigError(f"{name}_FILE could not be read") from e
    else:
        value = os.environ.get(name, "").strip()
    if not value:
        if required:
            raise ConfigError(f"{name} (or {name}_FILE) is required")
        return None
    return value


def read_key32(name: str) -> bytes:
    """A 32-byte key, encoded as urlsafe base64 or 64 hex characters."""
    raw = read_secret(name)
    assert raw is not None
    key: bytes | None = None
    if len(raw) == 64:
        try:
            key = bytes.fromhex(raw)
        except ValueError:
            key = None
    if key is None:
        try:
            key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except ValueError as e:
            raise ConfigError(f"{name} is not valid base64/hex") from e
    if len(key) != 32:
        raise ConfigError(f"{name} must decode to 32 bytes")
    return key


def _cidrs(value: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    return [ipaddress.ip_network(v.strip(), strict=False) for v in value.split(",") if v.strip()]


DEFAULT_INTERNAL_CIDRS = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,127.0.0.0/8,::1/128,fc00::/7,fe80::/10"

# Credentials that would let this build write to Alibaba. Phase 0 is shadow-only, so the
# broker refuses to start if any of them is present.
FORBIDDEN_WRITE_CREDENTIAL_ENV = (
    "ALIBABA_CLOUD_ACCESS_KEY_ID",
    "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
    "ALIBABA_CLOUD_SECURITY_TOKEN",
    "ALICLOUD_ACCESS_KEY",
    "ALICLOUD_SECRET_KEY",
    "DECA_SOAR_ACTOR_ROLE_ARN",
)


# Old symmetric vault key (gateway could decrypt everything) and the broker's private key:
# neither may ever be present in the gateway's environment (review F5).
GATEWAY_FORBIDDEN_ENV = ("DECA_VAULT_KEY", "DECA_VAULT_PRIVATE_KEY")


def _present(name: str) -> bool:
    return bool(os.environ.get(name) or os.environ.get(f"{name}_FILE"))


@dataclass(frozen=True)
class Settings:
    db_url: str
    tokenization_key: bytes | None = None
    vault_public_key: bytes | None = None
    vault_private_key: bytes | None = None
    vault_key_id: str = "v2"
    internal_cidrs: list = field(default_factory=lambda: _cidrs(DEFAULT_INTERNAL_CIDRS))
    policy_dir: Path = Path("policy")

    @classmethod
    def _common(cls) -> dict:
        db_url = read_secret("DECA_DB_URL")
        assert db_url is not None
        return {
            "db_url": db_url,
            "vault_key_id": os.environ.get("DECA_VAULT_KEY_ID", "v2"),
            "internal_cidrs": _cidrs(os.environ.get("DECA_INTERNAL_CIDRS", DEFAULT_INTERNAL_CIDRS)),
            "policy_dir": Path(os.environ.get("DECA_POLICY_DIR", "policy")),
        }

    @classmethod
    def for_gateway(cls) -> "Settings":
        """Tokenisation key + vault public key only: the gateway can seal PII but never open it."""
        bad = [n for n in GATEWAY_FORBIDDEN_ENV if _present(n)]
        if bad:
            raise ConfigError("gateway must not hold a vault decryption key (found: " + ", ".join(bad) + ")")
        return cls(
            **cls._common(),
            tokenization_key=read_key32("DECA_TOKENIZATION_KEY"),
            vault_public_key=read_key32("DECA_VAULT_PUBLIC_KEY"),
        )

    @classmethod
    def for_broker(cls) -> "Settings":
        return cls(**cls._common(), vault_private_key=read_key32("DECA_VAULT_PRIVATE_KEY"))


def assert_no_write_credentials() -> None:
    present = [n for n in FORBIDDEN_WRITE_CREDENTIAL_ENV if os.environ.get(n) or os.environ.get(f"{n}_FILE")]
    if present:
        raise ConfigError(
            "shadow-only build: write credentials must not be configured (found: " + ", ".join(present) + ")"
        )
