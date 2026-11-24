#!/usr/bin/env python3
"""Render the production compose for Tracecat 1.5.2 OSS from the unmodified upstream file.

  python scripts/render_tracecat_compose.py            # writes deploy/tracecat/docker-compose.prod.yml
  python scripts/render_tracecat_compose.py --check    # fails if the committed file is stale

What changes versus upstream (design 11, 12.2 stage 1):
- Postgres, Redis, MinIO and Temporal's Postgres are removed: RDS PostgreSQL, Tair and OSS come in via env.
- Image tags are pinned; no `latest`.
- ENTERPRISE_EDITION is forced false and TRACECAT__FEATURE_FLAGS forced empty (no EE gates opened).
- Every secret and endpoint uses ${VAR:?}: compose refuses to start without it, so no default credential exists.
- MinIO root credentials are replaced by AWS_ACCESS_KEY_ID/SECRET for a bucket-scoped OSS RAM user.
- Only Caddy publishes a port, bound to ${DECA_BIND_IP} (a private VPC address); Temporal UI and MCP are dropped.
- agent-worker, agent-executor and litellm are dropped: Tracecat's agent runtime is Enterprise-licensed code.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
UP = ROOT / "deploy/tracecat/upstream"
OUT = ROOT / "deploy/tracecat/docker-compose.prod.yml"

TRACECAT_VERSION = "1.5.2"
TEMPORAL_IMAGE = "temporalio/auto-setup:1.27.1"
# The agent runtime (agent-worker's DurableAgentWorkflow, ApprovalManager) lives in tracecat_ee under the
# Tracecat Enterprise License, which forbids production use without a subscription. Phase 0 has no LLM, so the
# agent services and their LiteLLM gateway are not deployed at all.
AGENT_SERVICES = {"agent-worker", "agent-executor", "litellm"}
DROP_SERVICES = {"postgres_db", "temporal_postgres_db", "minio", "minio-init", "redis", "temporal_ui", "mcp",
                 *AGENT_SERVICES}
DROP_NETWORKS = {"core-db", "temporal-db"}
DROP_VOLUMES = {"core-db", "temporal-db", "minio-data", "redis-data"}

REQUIRED = {
    # name -> message shown by compose when missing
    "TRACECAT__DB_ENCRYPTION_KEY": "set in the secret env file",
    "TRACECAT__SERVICE_KEY": "set in the secret env file",
    "TRACECAT__SIGNING_SECRET": "set in the secret env file",
    "USER_AUTH_SECRET": "set in the secret env file",
    "TRACECAT__DB_URI": "RDS URI (postgresql+psycopg://...)",
    "REDIS_URL": "Tair URI with password (rediss://...)",
    "TRACECAT__BLOB_STORAGE_ENDPOINT": "OSS S3-compatible internal endpoint",
    "TEMPORAL__CLUSTER_URL": "temporal:7233",
    "TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING": "JSON keyring, see RUNBOOK",
    "TRACECAT__PUBLIC_APP_URL": "internal URL behind the DECA proxy",
}
FORCED = {
    "ENTERPRISE_EDITION": "false",
    "TRACECAT__FEATURE_FLAGS": "",
    "TRACECAT__EE_MULTI_TENANT": "false",
    "TRACECAT__APP_ENV": "production",
    "TRACECAT__PLATFORM_ADMIN_MFA_BYPASS": "false",
    "TRACECAT__PLATFORM_ADMIN_IP_ALLOWLIST_BYPASS": "false",
    "TRACECAT__UNSAFE_DISABLE_SECRET_ERROR_WITHHOLDING": "false",
    "TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED": "true",
}
# Variables that only exist for the bundled MinIO/Postgres and must not survive.
DROP_ENV = {"MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD", "TRACECAT__POSTGRES_USER", "TRACECAT__POSTGRES_PASSWORD"}

CADDYFILE = """\
# DECA production Caddyfile for Tracecat 1.5.2 OSS (rendered alongside docker-compose.prod.yml).
# Differences from upstream: no /s3 MinIO proxy (OSS is used directly), no MCP routes (MCP service dropped).
# TLS terminates at the DECA reverse proxy in front of this; Caddy listens on the private bind only.
{
\tservers {
\t\ttrusted_proxies static {$TRACECAT__TRUSTED_PROXY_CIDRS}
\t\ttrusted_proxies_strict
\t}
\tadmin off
}

{$BASE_DOMAIN} {
\tbind {$ADDRESS}

\theader {
\t\t-Server
\t\tX-Content-Type-Options nosniff
\t\tReferrer-Policy no-referrer
\t\tX-Frame-Options DENY
\t}

\thandle_path /api* {
\t\treverse_proxy http://api:8000 {
\t\t\theader_up X-Forwarded-For {client_ip}
\t\t\theader_up X-Real-IP {client_ip}
\t\t\theader_up X-Forwarded-Host {host}
\t\t\theader_up X-Forwarded-Proto {scheme}
\t\t}
\t}

\treverse_proxy http://ui:3000 {
\t\theader_up X-Forwarded-For {client_ip}
\t\theader_up X-Real-IP {client_ip}
\t}
}
"""


def _env_dict(env) -> dict:
    if isinstance(env, dict):
        return dict(env)
    out = {}
    for item in env or []:
        k, _, v = str(item).partition("=")
        out[k] = v
    return out


def _harden_env(name: str, env: dict) -> dict:
    env = {k: v for k, v in env.items() if k not in DROP_ENV}
    for k in list(env):
        if k in REQUIRED:
            env[k] = f"${{{k}:?{REQUIRED[k]}}}"
    is_tracecat = any(k.startswith("TRACECAT__") for k in env)
    if is_tracecat and name not in ("ui",):
        for k, v in FORCED.items():
            if k.startswith("TEMPORAL__") and not any(x.startswith("TEMPORAL__") for x in env):
                continue
            env[k] = v
        if any(k.startswith("TRACECAT__BLOB_STORAGE") for k in env):
            env["AWS_ACCESS_KEY_ID"] = "${DECA_OSS_ACCESS_KEY_ID:?bucket-scoped OSS RAM user}"
            env["AWS_SECRET_ACCESS_KEY"] = "${DECA_OSS_ACCESS_KEY_SECRET:?bucket-scoped OSS RAM user}"
            env["AWS_DEFAULT_REGION"] = "${DECA_OSS_REGION:-ap-southeast-5}"
            env["TRACECAT__BLOB_STORAGE_PRESIGNED_URL_ENDPOINT"] = (
                "${TRACECAT__BLOB_STORAGE_PRESIGNED_URL_ENDPOINT:?OSS endpoint reachable by SOAR engineers}"
            )
        if "TRACECAT__DB_SSLMODE" in env:
            env["TRACECAT__DB_SSLMODE"] = "${TRACECAT__DB_SSLMODE:-require}"
    if name == "ui":
        env["TRACECAT__SERVICE_KEY"] = "${TRACECAT__SERVICE_KEY:?set in the secret env file}"
        env["TRACECAT__CSP_CONNECT_SRC_ORIGINS"] = "${TRACECAT__BLOB_STORAGE_PRESIGNED_URL_ENDPOINT:?OSS endpoint}"
    return env


def render() -> tuple[str, str]:
    src = (UP / "docker-compose.yml").read_text()
    doc = yaml.safe_load(src)
    out = copy.deepcopy(doc)
    services = out["services"]
    for n in DROP_SERVICES:
        services.pop(n, None)
    for name, s in services.items():
        img = s.get("image", "")
        if img.startswith("ghcr.io/tracecathq/"):
            s["image"] = img.split(":", 1)[0] + f":{TRACECAT_VERSION}"
        if isinstance(s.get("depends_on"), dict):
            s["depends_on"] = {k: v for k, v in s["depends_on"].items() if k not in DROP_SERVICES}
        elif isinstance(s.get("depends_on"), list):
            s["depends_on"] = [k for k in s["depends_on"] if k not in DROP_SERVICES]
        if not s.get("depends_on"):
            s.pop("depends_on", None)
        if "networks" in s:
            s["networks"] = [n for n in s["networks"] if n not in DROP_NETWORKS] or ["core"]
        if "environment" in s:
            s["environment"] = _harden_env(name, _env_dict(s["environment"]))
        s.pop("ports", None)
        s.pop("container_name", None)
        s["logging"] = {"driver": "json-file", "options": {"max-size": "50m", "max-file": "5"}}
    # Temporal server: its persistence is an RDS database (separate DB + user), TLS on.
    t = services["temporal"]
    t["image"] = TEMPORAL_IMAGE
    t["environment"] = {
        "DB": "postgres12",
        "DB_PORT": "${TEMPORAL__POSTGRES_PORT:-5432}",
        "POSTGRES_SEEDS": "${TEMPORAL__POSTGRES_SEEDS:?RDS host for Temporal}",
        "POSTGRES_USER": "${TEMPORAL__POSTGRES_USER:?RDS user for Temporal}",
        "POSTGRES_PWD": "${TEMPORAL__POSTGRES_PASSWORD:?set in the secret env file}",
        "DBNAME": "${TEMPORAL__POSTGRES_DB:-temporal}",
        "VISIBILITY_DBNAME": "${TEMPORAL__POSTGRES_VISIBILITY_DB:-temporal_visibility}",
        "SQL_TLS_ENABLED": "${TEMPORAL__POSTGRES_TLS:-true}",
        "DEFAULT_NAMESPACE_RETENTION": "${TEMPORAL__DEFAULT_NAMESPACE_RETENTION:-72h}",
        "LOG_LEVEL": "warn",
        "BIND_ON_IP": "0.0.0.0",
        "TEMPORAL_BROADCAST_ADDRESS": "127.0.0.1",
    }
    t["networks"] = ["core", "temporal"]
    # Only Caddy listens, and only on a private address of the ECS (fronted by the DECA proxy).
    c = services["caddy"]
    c["ports"] = ["${DECA_BIND_IP:?private VPC IP of this ECS}:${PUBLIC_APP_PORT:-8080}:${PUBLIC_APP_PORT:-8080}"]
    c["environment"] = {
        "BASE_DOMAIN": "${BASE_DOMAIN:?e.g. :8080}",
        "ADDRESS": "0.0.0.0",
        "TRACECAT__TRUSTED_PROXY_CIDRS": "${TRACECAT__TRUSTED_PROXY_CIDRS:?DECA proxy CIDR}",
    }
    c["volumes"] = ["./Caddyfile.prod:/etc/caddy/Caddyfile:ro"]
    for name in ("api", "ui", "caddy", "worker", "background-worker"):
        services[name].setdefault("security_opt", ["no-new-privileges:true"])
    out["networks"] = {k: v for k, v in out["networks"].items() if k not in DROP_NETWORKS}
    out["volumes"] = {k: v for k, v in out["volumes"].items() if k not in DROP_VOLUMES}
    up_sha = hashlib.sha256(src.encode()).hexdigest()
    header = (
        "# GENERATED by scripts/render_tracecat_compose.py from deploy/tracecat/upstream/docker-compose.yml\n"
        f"# (Tracecat {TRACECAT_VERSION}, sha256 {up_sha}). Do not edit by hand; change the renderer.\n"
        "# Run: docker compose --env-file /etc/deca-soar/tracecat.env -f docker-compose.prod.yml up -d\n"
        "# Production executor: add upstream/docker-compose.sandbox.yml (nsjail), see deploy/RUNBOOK.md.\n"
    )
    return header + yaml.safe_dump(out, sort_keys=False, width=120), CADDYFILE


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    compose, caddy = render()
    caddy_path = OUT.parent / "Caddyfile.prod"
    if a.check:
        stale = [p.name for p, want in ((OUT, compose), (caddy_path, caddy)) if not p.exists() or p.read_text() != want]
        if stale:
            print("stale: " + ", ".join(stale), file=sys.stderr)
            return 1
        print("up to date")
        return 0
    OUT.write_text(compose)
    caddy_path.write_text(caddy)
    print(f"wrote {OUT.relative_to(ROOT)} and {caddy_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
