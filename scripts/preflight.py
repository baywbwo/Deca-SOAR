#!/usr/bin/env python3
"""Pre-deploy hardening check (design 11). Never prints secret values.

  python scripts/preflight.py                                  # static checks on the rendered compose
  python scripts/preflight.py --env /etc/deca-soar/tracecat.env  # plus the production env file
Exit code 0 = pass, 1 = at least one FAIL.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import stat
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/tracecat/docker-compose.prod.yml"
DEFAULTS = {"postgres", "password", "minio", "temporal", "admin", "changeme", "secret", "tracecat"}
PLATFORM_SECRETS = ("TRACECAT__SERVICE_KEY", "TRACECAT__SIGNING_SECRET", "USER_AUTH_SECRET")
REQUIRED_ENV = (
    "TRACECAT__DB_ENCRYPTION_KEY", *PLATFORM_SECRETS, "TRACECAT__DB_URI", "REDIS_URL",
    "TRACECAT__BLOB_STORAGE_ENDPOINT", "TRACECAT__BLOB_STORAGE_PRESIGNED_URL_ENDPOINT", "DECA_OSS_ACCESS_KEY_ID",
    "DECA_OSS_ACCESS_KEY_SECRET", "TEMPORAL__CLUSTER_URL", "TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING",
    "TEMPORAL__POSTGRES_SEEDS", "TEMPORAL__POSTGRES_USER", "TEMPORAL__POSTGRES_PASSWORD", "DECA_BIND_IP",
    "BASE_DOMAIN", "TRACECAT__TRUSTED_PROXY_CIDRS", "TRACECAT__PUBLIC_APP_URL",
)

results: list[tuple[str, str]] = []


def check(ok: bool, msg: str, *, warn: bool = False) -> None:
    results.append(("PASS" if ok else ("WARN" if warn else "FAIL"), msg))


def static_compose() -> None:
    doc = yaml.safe_load(COMPOSE.read_text())
    svcs = doc["services"]
    for bad in ("postgres_db", "redis", "minio", "minio-init", "temporal_postgres_db", "temporal_ui", "mcp"):
        check(bad not in svcs, f"compose: bundled service '{bad}' removed")
    for bad in ("agent-worker", "agent-executor", "litellm"):
        check(bad not in svcs, f"compose: Enterprise-licensed agent runtime '{bad}' not deployed")
    for name, s in svcs.items():
        img = s.get("image", "")
        check(":" in img and not img.endswith(":latest") and "${" not in img, f"compose: {name} image pinned ({img})")
        ports = s.get("ports") or []
        if name == "caddy":
            check(len(ports) == 1 and str(ports[0]).startswith("${DECA_BIND_IP:?"),
                  "compose: caddy publishes only on ${DECA_BIND_IP}")
        else:
            check(not ports, f"compose: {name} publishes no host port")
        env = s.get("environment") or {}
        if isinstance(env, dict) and any(k.startswith("TRACECAT__") for k in env) and name not in ("ui", "caddy"):
            check(str(env.get("ENTERPRISE_EDITION")) == "false", f"compose: {name} ENTERPRISE_EDITION=false")
            check(env.get("TRACECAT__FEATURE_FLAGS", "") == "", f"compose: {name} TRACECAT__FEATURE_FLAGS empty")
        if isinstance(env, dict):
            check(not any(k.startswith("MINIO_") for k in env), f"compose: {name} has no MinIO root credentials")
            for k in ("TRACECAT__DB_ENCRYPTION_KEY", *PLATFORM_SECRETS):
                if k in env:
                    check(str(env[k]).startswith(f"${{{k}:?"), f"compose: {name} {k} is required (no default)")
        vols = s.get("volumes") or []
        check(not any("ee" in Path(str(v).split(":")[0]).parts for v in vols), f"compose: {name} mounts no ee folder")


def parse_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        env[k.strip()] = v
    return env


def env_file(path: Path) -> None:
    st = path.stat()
    check(not (st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)), "env file: mode is 0600 (owner only)")
    try:
        path.resolve().relative_to(ROOT.resolve())
        check(False, "env file: lives outside the repository")
    except ValueError:
        check(True, "env file: lives outside the repository")
    env = parse_env(path)
    for k in REQUIRED_ENV:
        check(bool(env.get(k)), f"env: {k} set")
    for k, v in env.items():
        if any(x in k for x in ("PASSWORD", "SECRET", "_KEY")) and v:
            check(v.lower() not in DEFAULTS and not v.lower().startswith("your-"), f"env: {k} is not a default value")
    try:
        ok = len(base64.urlsafe_b64decode(env.get("TRACECAT__DB_ENCRYPTION_KEY", ""))) == 32
    except ValueError:
        ok = False
    check(ok, "env: TRACECAT__DB_ENCRYPTION_KEY is a valid Fernet key")
    for k in PLATFORM_SECRETS:
        check(len(env.get(k, "")) >= 32, f"env: {k} has >= 32 characters")
    check(len({env.get(k) for k in ("TRACECAT__DB_ENCRYPTION_KEY", *PLATFORM_SECRETS)}) == 4,
          "env: the 4 platform secrets are distinct")
    check(env.get("ENTERPRISE_EDITION", "false").lower() in ("", "false", "0"), "env: ENTERPRISE_EDITION not enabled")
    check(env.get("TRACECAT__FEATURE_FLAGS", "") == "", "env: TRACECAT__FEATURE_FLAGS empty")
    try:
        ip = ipaddress.ip_address(env.get("DECA_BIND_IP", ""))
        check(ip.is_private and not ip.is_unspecified and not ip.is_loopback,
              "env: DECA_BIND_IP is a private, non-wildcard address")
    except ValueError:
        check(False, "env: DECA_BIND_IP is a valid IP")
    for c in env.get("TRACECAT__TRUSTED_PROXY_CIDRS", "").split(","):
        try:
            net = ipaddress.ip_network(c.strip(), strict=False)
            check(net.prefixlen >= 16 and net.is_private, f"env: trusted proxy CIDR {net} is private and narrow")
        except ValueError:
            check(False, "env: TRACECAT__TRUSTED_PROXY_CIDRS valid")
    check(env.get("TRACECAT__DB_SSLMODE", "require") in ("require", "verify-ca", "verify-full"),
          "env: TRACECAT__DB_SSLMODE requires TLS")
    check(bool(re.match(r"^rediss?://[^/@]*:[^/@]+@", env.get("REDIS_URL", ""))), "env: REDIS_URL carries a password")
    check(env.get("REDIS_URL", "").startswith("rediss://"), "env: REDIS_URL uses TLS (rediss://)", warn=True)
    check(env.get("TRACECAT__BLOB_STORAGE_ENDPOINT", "").startswith("https://"), "env: OSS endpoint uses https")
    try:
        ring = json.loads(env.get("TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING", ""))
        cur = ring["keys"][ring["current_key_id"]]
        check(len(bytes.fromhex(cur)) == 32, "env: Temporal payload keyring has a 32-byte current key")
    except (ValueError, KeyError, TypeError):
        check(False, "env: TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING is valid JSON with current key")
    auth = env.get("TRACECAT__AUTH_TYPES", "basic")
    check("basic" not in auth.split(","), "env: Tracecat UI login via OIDC/SAML, not basic", warn=True)
    check(env.get("TRACECAT__AUTH_MIN_PASSWORD_LENGTH", "12").isdigit()
          and int(env.get("TRACECAT__AUTH_MIN_PASSWORD_LENGTH", "12")) >= 14, "env: min password length >= 14",
          warn=True)
    check(env.get("TRACECAT__EXECUTOR_BACKEND", "direct") == "nsjail", "env: executor sandbox is nsjail", warn=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", type=Path)
    a = ap.parse_args()
    static_compose()
    if a.env:
        env_file(a.env)
    for status, msg in results:
        if status != "PASS" or os.environ.get("PREFLIGHT_VERBOSE"):
            print(f"{status}  {msg}")
    n = {s: sum(1 for x, _ in results if x == s) for s in ("PASS", "WARN", "FAIL")}
    print(f"preflight: {n['PASS']} pass, {n['WARN']} warn, {n['FAIL']} fail")
    return 1 if n["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
