#!/usr/bin/env python3
"""Pre-deploy hardening check (design 11). Never prints secret values.

  python scripts/preflight.py                                   # static checks on the repo's deploy files
  python scripts/preflight.py --temporal-bin /opt/temporal/1.32.2  # plus render the Temporal config, verify binaries
  python scripts/preflight.py --env /etc/deca-soar/deca.env --temporal-env /etc/deca-soar/temporal/temporal.env \
      --secrets-dir /etc/deca-soar/secrets                      # plus the production files on the host
Exit code 0 = pass, 1 = at least one FAIL.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DECA_COMPOSE = ROOT / "deploy/deca/docker-compose.yml"
TEMPORAL_DIR = ROOT / "deploy/temporal"
RETIRED_ENGINE = "trace" + "cat"  # the phase-0 engine this build replaced; must not come back
WRITE_CREDENTIALS = ("ALIBABA_CLOUD_ACCESS_KEY", "ALICLOUD_ACCESS_KEY", "ALICLOUD_SECRET_KEY", "DECA_SOAR_ACTOR_ROLE_ARN")
# Which secrets each service may hold (least privilege, review F3/F5).
SECRET_ALLOWLIST = {
    "deca-migrate": {"deca_db_url_owner"},
    "broker": {"deca_db_url_broker", "deca_vault_private_key", "broker_tls_cert", "broker_tls_key"},
    "gateway": {"deca_db_url_gateway", "deca_tokenization_key", "deca_vault_public_key", "deca_temporal_payload_key",
                "temporal_server_ca", "temporal_gateway_cert", "temporal_gateway_key"},
    "worker": {"deca_temporal_payload_key", "temporal_server_ca", "temporal_worker_cert", "temporal_worker_key",
               "deca_broker_worker_token", "broker_tls_ca"},
    "ledger-anchor": {"deca_db_url_auditor"},
}
KEY_FILES = ("deca_tokenization_key", "deca_vault_public_key", "deca_vault_private_key", "deca_temporal_payload_key")
RENDER_ENV = {
    "POSTGRES_SEEDS": "rds.internal", "POSTGRES_USER": "temporal", "POSTGRES_PWD": "preflight-dummy",
    "BIND_ON_IP": "10.0.0.5", "SQL_CA": "/ca.pem", "SQL_HOST_NAME": "rds.internal",
    "TEMPORAL_TLS_SERVER_CERT": "/s.pem", "TEMPORAL_TLS_SERVER_KEY": "/s.key", "TEMPORAL_TLS_CA_CERT": "/ca.pem",
    "TEMPORAL_TLS_SERVER_NAME": "temporal.deca.internal", "TEMPORAL_TLS_CLIENT_CA_CERT": "/cca.pem",
    "TEMPORAL_TLS_SYSTEM_WORKER_CERT": "/sw.pem", "TEMPORAL_TLS_SYSTEM_WORKER_KEY": "/sw.key",
}

results: list[tuple[str, str]] = []


def check(ok: bool, msg: str, *, warn: bool = False) -> None:
    results.append(("PASS" if ok else ("WARN" if warn else "FAIL"), msg))


def tracked_files() -> list[Path]:
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
        return [ROOT / p for p in out.decode().split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        return [p for p in ROOT.rglob("*") if p.is_file() and ".venv" not in p.parts and ".git" not in p.parts]


def static_repo() -> None:
    hits = []
    for p in tracked_files():
        if p == Path(__file__).resolve() or not p.is_file():
            continue
        if RETIRED_ENGINE in str(p.relative_to(ROOT)).lower():
            hits.append(str(p.relative_to(ROOT)))
            continue
        try:
            if RETIRED_ENGINE in p.read_text(errors="ignore").lower():
                hits.append(str(p.relative_to(ROOT)))
        except OSError:
            pass
    check(not hits, "repo: no reference to the retired workflow engine" + (f" (found in {', '.join(hits[:5])})" if hits else ""))
    ee = [p for p in tracked_files() if "ee" in p.relative_to(ROOT).parts or "ENTERPRISE_EDITION" in p.name]
    check(not ee, "repo: no Enterprise-edition code or folders")
    py = (ROOT / "pyproject.toml").read_text()
    check(bool(re.search(r'"temporalio>=[\d.]+,<2"', py)), "pyproject: temporalio pinned to major 1")


def static_deca_compose() -> None:
    doc = yaml.safe_load(DECA_COMPOSE.read_text())
    svcs = doc["services"]
    check(set(svcs) == set(SECRET_ALLOWLIST), f"deca compose: services are exactly {sorted(SECRET_ALLOWLIST)}")
    for name, s in svcs.items():
        img = str(s.get("image", ""))
        check(img.startswith("${DECA_SOAR_IMAGE:?"), f"deca compose: {name} image is the required pinned variable")
        check(s.get("read_only") is True, f"deca compose: {name} read-only root fs")
        check(s.get("cap_drop") == ["ALL"], f"deca compose: {name} drops all capabilities")
        check("no-new-privileges:true" in (s.get("security_opt") or []), f"deca compose: {name} no-new-privileges")
        env = s.get("environment") or {}
        check(env.get("DECA_ENV") == "production", f"deca compose: {name} DECA_ENV=production")
        check(not any(k.startswith(WRITE_CREDENTIALS) for k in env), f"deca compose: {name} has no Alibaba write credential")
        check(not any(v for k, v in env.items() if not k.endswith("_FILE") and re.search(r"(KEY|TOKEN|PASSWORD|DB_URL)$", k)),
              f"deca compose: {name} passes secrets as files only")
        secrets = set(s.get("secrets") or [])
        extra = secrets - SECRET_ALLOWLIST.get(name, set())
        check(not extra, f"deca compose: {name} holds only its own secrets" + (f" (extra: {sorted(extra)})" if extra else ""))
        ports = s.get("ports") or []
        if name == "broker":
            check(len(ports) == 1 and str(ports[0]).startswith("${DECA_BIND_IP:?"),
                  "deca compose: broker publishes only on ${DECA_BIND_IP}")
            cmd = s.get("command") or []
            check("--ssl-certfile" in cmd and "--ssl-keyfile" in cmd, "deca compose: broker serves TLS")
        else:
            check(not ports, f"deca compose: {name} publishes no host port")
    w = svcs["worker"]["environment"]
    check(str(w.get("DECA_BROKER_URL", "")).startswith("${DECA_BROKER_URL:?https://"), "deca compose: worker -> broker over https")
    for name in ("gateway", "worker"):
        env = svcs[name]["environment"]
        check(all(env.get(k) for k in ("DECA_TEMPORAL_TLS_CA_FILE", "DECA_TEMPORAL_TLS_CERT_FILE", "DECA_TEMPORAL_TLS_KEY_FILE")),
              f"deca compose: {name} uses mTLS to Temporal")
        check(bool(env.get("DECA_TEMPORAL_PAYLOAD_KEY_FILE")), f"deca compose: {name} encrypts Temporal payloads")
    dockerfile = (ROOT / "deploy/deca/Dockerfile").read_text()
    check("REPLACE_WITH_PINNED_DIGEST" not in dockerfile, "Dockerfile: base image pinned by digest (pin before build)",
          warn=True)


def static_temporal() -> None:
    tpl = (TEMPORAL_DIR / "config/deca-production.yaml").read_text()
    check("pluginName: postgres12_pgx" in tpl and "cassandra" not in tpl, "temporal config: PostgreSQL (RDS) only")
    check(tpl.count("requireClientAuth: true") == 2, "temporal config: mTLS required on frontend and internode")
    check('enabled: {{ default "true" (env "SQL_TLS_ENABLED") }}' in tpl, "temporal config: SQL TLS on by default")
    check("state: enabled" not in tpl, "temporal config: archival disabled")
    check("port: 0" in tpl, "temporal config: pprof disabled")
    check(re.search(r"^\s*httpPort: 0\s*$", tpl, re.M) is not None and "FRONTEND_HTTP_PORT" not in tpl
          and "httpAddress" not in tpl, "temporal config: frontend HTTP API off (httpPort 0, not overridable; N5)")
    check("temporal_cloud" not in tpl.lower() and "tmprl.cloud" not in tpl, "temporal config: no Temporal Cloud")
    example = (TEMPORAL_DIR / "temporal.env.example").read_text()
    check("POSTGRES_PWD" not in example, "temporal env: DB password is not an env-file entry")
    for unit in ("temporal-server.service", "temporal-schema.service"):
        u = (TEMPORAL_DIR / "systemd" / unit).read_text()
        check("LoadCredential=temporal_db_password:" in u, f"systemd {unit}: DB password via LoadCredential")
        check("NoNewPrivileges=yes" in u and "ProtectSystem=strict" in u, f"systemd {unit}: sandboxed")
        check("User=temporal" in u, f"systemd {unit}: not root")
    ui = [p for p in TEMPORAL_DIR.rglob("*") if p.is_file() and "temporal-ui" in p.read_text(errors="ignore")]
    check(not ui, "temporal: Web UI not deployed (operators use the CLI over mTLS)")


def temporal_binaries(bin_dir: Path) -> None:
    source = (TEMPORAL_DIR / "SOURCE.txt").read_text()
    for name in ("temporal-server", "temporal-sql-tool"):
        m = re.search(rf"^([0-9a-f]{{64}})  {name}$", source, re.M)
        p = bin_dir / name
        if not p.exists():
            check(False, f"temporal: {name} present in {bin_dir}")
            continue
        check(bool(m) and hashlib.sha256(p.read_bytes()).hexdigest() == m.group(1), f"temporal: {name} sha256 matches SOURCE.txt")
    server = bin_dir / "temporal-server"
    run = lambda env: subprocess.run(  # noqa: E731
        [str(server), "-c", str(TEMPORAL_DIR / "config"), "-e", "deca-production", "render-config"],
        env={"PATH": "/usr/bin:/bin", **env}, capture_output=True, text=True, timeout=60,
    )
    r = run(RENDER_ENV)
    out = r.stdout
    check(r.returncode == 0 and "bindOnIP: 10.0.0.5" in out, "temporal config: renders with the production env")
    check("preflight-dummy" not in out, "temporal config: rendering masks the DB password")
    check(out.count("requireClientAuth: true") == 2 and "enableHostVerification: true" in out,
          "temporal config (rendered): mTLS required, RDS host verified")
    check(run({**RENDER_ENV, "BIND_ON_IP": "0.0.0.0"}).returncode != 0, "temporal config: refuses a wildcard bind")
    check(run({k: v for k, v in RENDER_ENV.items() if k != "TEMPORAL_TLS_CLIENT_CA_CERT"}).returncode != 0,
          "temporal config: refuses to start without the client CA")
    http_on = run({**RENDER_ENV, "FRONTEND_HTTP_PORT": "7243"}).stdout
    check(set(re.findall(r"httpPort: (\d+)", out)) == {"0"} == set(re.findall(r"httpPort: (\d+)", http_on)),
          "temporal config (rendered): frontend httpPort 0 even with FRONTEND_HTTP_PORT set (N5)")
    check("systemWorker:" in out and "certFile: /sw.pem" in out, "temporal config (rendered): system worker uses mTLS")
    dc = subprocess.run([str(server), "validate-dynamic-config", str(TEMPORAL_DIR / "dynamicconfig/production.yaml")],
                        capture_output=True, text=True, timeout=60)
    check(dc.returncode == 0 and "warning" not in (dc.stdout + dc.stderr).lower(), "temporal dynamic config: valid keys only")


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


def _outside_repo(path: Path) -> bool:
    return ROOT.resolve() not in path.resolve().parents


def _private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_private and not ip.is_unspecified and not ip.is_loopback


def env_files(deca: Path | None, temporal: Path | None) -> None:
    for label, path in (("deca env", deca), ("temporal env", temporal)):
        if path is None:
            continue
        st = path.stat()
        check(not (st.st_mode & (stat.S_IWGRP | stat.S_IRWXO)), f"{label}: not writable by group, nothing for others")
        check(_outside_repo(path), f"{label}: lives outside the repository")
        env = parse_env(path)
        check(not any("REPLACE" in v for v in env.values()), f"{label}: no REPLACE placeholders left")
        check(not any(re.search(r"(PASSWORD|PWD|SECRET|TOKEN|_KEY)$", k) and v for k, v in env.items()),
              f"{label}: holds no secret values (secrets are files)")
        check(not any(k.startswith(WRITE_CREDENTIALS) for k in env), f"{label}: no Alibaba write credential")
    if deca:
        env = parse_env(deca)
        check(_private_ip(env.get("DECA_BIND_IP", "")), "deca env: DECA_BIND_IP is a private, non-wildcard address")
        check(env.get("DECA_BROKER_URL", "").startswith("https://"), "deca env: DECA_BROKER_URL is https")
        host = env.get("DECA_TEMPORAL_ADDRESS", "").rsplit(":", 1)[0].strip("[]")
        try:
            check(not ipaddress.ip_address(host).is_global, "deca env: Temporal address is not a public IP")
        except ValueError:
            check(bool(host), "deca env: Temporal address set (hostname)")
    if temporal:
        env = parse_env(temporal)
        check(_private_ip(env.get("BIND_ON_IP", "")), "temporal env: BIND_ON_IP is a private, non-wildcard address")
        check(env.get("SQL_TLS_ENABLED", "true") == "true" and env.get("SQL_HOST_VERIFICATION", "true") == "true",
              "temporal env: RDS over verified TLS")
        check(not env.get("PROMETHEUS_ENDPOINT") or env["PROMETHEUS_ENDPOINT"].startswith("127.0.0.1:"),
              "temporal env: metrics on loopback only")


def secrets_dir(path: Path) -> None:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    check(_outside_repo(path), "secrets: directory outside the repository")
    keys: dict[str, bytes] = {}
    for name in KEY_FILES:
        p = path / name
        if not p.exists():
            check(False, f"secrets: {name} present")
            continue
        check(not (p.stat().st_mode & (stat.S_IWGRP | stat.S_IRWXO)), f"secrets: {name} mode 0600/0440")
        try:
            keys[name] = bytes.fromhex(p.read_text().strip())
            check(len(keys[name]) == 32, f"secrets: {name} is 32 bytes")
        except ValueError:
            check(False, f"secrets: {name} is hex")
    if "deca_vault_private_key" in keys and "deca_vault_public_key" in keys:
        pub = X25519PrivateKey.from_private_bytes(keys["deca_vault_private_key"]).public_key()
        check(pub.public_bytes(Encoding.Raw, PublicFormat.Raw) == keys["deca_vault_public_key"],
              "secrets: vault public key matches the private key")
    check(len(set(keys.values())) == len(keys), "secrets: keys are distinct")
    for name in ("deca_db_url_owner", "deca_db_url_gateway", "deca_db_url_broker", "deca_db_url_auditor"):
        p = path / name
        if not p.exists():
            check(False, f"secrets: {name} present")
            continue
        url = p.read_text().strip()
        check("sslmode=verify-full" in url, f"secrets: {name} uses sslmode=verify-full")
    users = []
    for name in ("deca_db_url_owner", "deca_db_url_gateway", "deca_db_url_broker", "deca_db_url_auditor"):
        m = re.match(r"^postgres(?:ql)?://([^:@/]+)", (path / name).read_text().strip()) if (path / name).exists() else None
        users.append(m.group(1) if m else None)
    check(None not in users and len(set(users)) == 4, "secrets: four distinct DB logins (owner, gateway, broker, auditor)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--temporal-bin", type=Path, help="directory with temporal-server and temporal-sql-tool")
    ap.add_argument("--env", type=Path, help="production deca.env")
    ap.add_argument("--temporal-env", type=Path, help="production temporal.env")
    ap.add_argument("--secrets-dir", type=Path)
    a = ap.parse_args()
    static_repo()
    static_deca_compose()
    static_temporal()
    if a.temporal_bin:
        temporal_binaries(a.temporal_bin)
    else:
        check(False, "temporal: config render and binary checksums skipped (pass --temporal-bin)", warn=True)
    if a.env or a.temporal_env:
        env_files(a.env, a.temporal_env)
    if a.secrets_dir:
        secrets_dir(a.secrets_dir)
    for status, msg in results:
        if status != "PASS" or os.environ.get("PREFLIGHT_VERBOSE"):
            print(f"{status}  {msg}")
    n = {s: sum(1 for x, _ in results if x == s) for s in ("PASS", "WARN", "FAIL")}
    print(f"preflight: {n['PASS']} pass, {n['WARN']} warn, {n['FAIL']} fail")
    return 1 if n["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
