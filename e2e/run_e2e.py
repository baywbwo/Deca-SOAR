#!/usr/bin/env python3
"""Disposable end-to-end stack: synthetic alert -> gateway -> Tracecat 1.5.2 OSS workflow -> broker (shadow) -> ledger.

Everything runs as local processes on 127.0.0.1 in a fresh 0700 temp dir and is torn down at the end
(the CI variant runs the same steps in throwaway containers). Secrets are generated per run, passed via
env/0600 files, never printed, and every log is scanned for them before the run dir is deleted.
Only a redacted JSON summary is written to --evidence.

Stand-ins for managed services: Postgres 18 + pgvector (RDS), Redis with requirepass (Tair),
moto S3 (OSS), `temporal server start-dev` (Temporal on RDS). No Alibaba or LLM credentials are used.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path
from urllib.parse import quote

import httpx
import psycopg
import psycopg.sql

REPO = Path(__file__).resolve().parents[1]
TOOLS = Path(os.environ.get("DECA_E2E_TOOLS", "/data/work/tools/soar-deps"))
PG_BIN = TOOLS / "pg18v/bin"
REDIS = TOOLS / "root/usr/bin/redis-server"
REDIS_LIB = TOOLS / "root/usr/lib/x86_64-linux-gnu"
TEMPORAL = TOOLS / "temporal"
MOTO = TOOLS / "moto-venv/bin/moto_server"
TC_SRC = Path(os.environ.get("DECA_E2E_TRACECAT_SRC", "/tmp/soar-src/tracecat"))
TC_PY = TC_SRC / ".venv/bin/python"
DECA_PY = REPO / ".venv/bin/python"

RAW_IP = "203.0.113.7"          # RFC5737 TEST-NET-3: synthetic attacker
PROTECTED_IP = "198.51.100.20"  # inside the protected placeholder range
RAW_EMAIL = "victim.e2e@example.com"
BUCKETS = ("attachments", "registry", "workflow", "skills", "agent")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(fn, what: str, timeout: float = 120.0, interval: float = 1.0):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            r = fn()
            if r:
                return r
        except RuntimeError:
            raise  # a stack process died; no point polling further
        except Exception as e:  # noqa: BLE001 - polling
            last = type(e).__name__
        time.sleep(interval)
    raise TimeoutError(f"timed out waiting for {what} (last error: {last})")


class Stack:
    def __init__(self, run: Path) -> None:
        self.run = run
        self.logs = run / "logs"
        self.logs.mkdir()
        self.procs: list[tuple[str, subprocess.Popen]] = []
        self.secret_values: list[str] = []
        self.ports = {k: free_port() for k in ("pg", "redis", "temporal", "s3", "api", "broker", "gateway")}
        self.pg_data = run / "pg"

    def secret(self, value: str) -> str:
        self.secret_values.append(value)
        return value

    def start(self, name: str, argv: list[str], env: dict | None = None, cwd: Path | None = None) -> None:
        log = (self.logs / f"{name}.log").open("ab")
        p = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env, cwd=cwd, start_new_session=True)
        self.procs.append((name, p))

    def check_alive(self) -> None:
        for name, p in self.procs:
            if p.poll() is not None:
                tail = (self.logs / f"{name}.log").read_text(errors="replace")[-3000:]
                raise RuntimeError(f"{name} exited with {p.returncode}\n{tail}")

    def stop(self) -> list[str]:
        stopped = []
        for name, p in reversed(self.procs):
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for name, p in reversed(self.procs):
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=5)
            stopped.append(name)
        if (self.pg_data / "PG_VERSION").exists():
            subprocess.run([str(PG_BIN / "pg_ctl"), "-D", str(self.pg_data), "-m", "fast", "-w", "stop"],
                           capture_output=True, check=False)
            stopped.append("postgres")
        return stopped


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", type=Path, required=True, help="directory for the redacted summary")
    ap.add_argument("--keep-run-dir", action="store_true", help="debug only: keep logs (may contain tokens)")
    a = ap.parse_args()

    run = Path(tempfile.mkdtemp(prefix="deca-e2e-"))
    os.chmod(run, 0o700)
    st = Stack(run)
    summary: dict = {"started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "checks": {}, "oss": {}}
    rc = 1
    try:
        rc = scenario(st, summary)
    except Exception as e:  # noqa: BLE001
        summary["error"] = f"{type(e).__name__}: {e}"[:4000]
        summary["traceback"] = traceback.format_exc()[-4000:]
    finally:
        summary["stopped"] = st.stop()
        leaks = []
        for f in st.logs.glob("*.log"):
            text = f.read_text(errors="replace")
            for v in st.secret_values:
                if len(v) >= 8 and v in text:
                    leaks.append(f.name)
        summary["checks"]["no_secret_in_logs"] = not leaks
        if leaks:
            summary["secret_leak_files"] = sorted(set(leaks))
            rc = 1
        left = subprocess.run(["pgrep", "-f", str(run)], capture_output=True, text=True).stdout.split()
        summary["checks"]["no_process_left"] = not left
        a.evidence.mkdir(parents=True, exist_ok=True)
        out = a.evidence / "e2e-summary.json"
        redacted = json.dumps(summary, indent=2, default=str)
        for v in st.secret_values:
            if len(v) >= 8:
                redacted = redacted.replace(v, "<redacted>")
        out.write_text(redacted + "\n")
        if a.keep_run_dir:
            print(f"run dir kept: {run}")
        else:
            shutil.rmtree(run, ignore_errors=True)
        print(f"summary: {out}")
        print(json.dumps(summary["checks"], indent=2))
        if "error" in summary:
            print(summary["error"][:2000], file=sys.stderr)
    return 0 if rc == 0 and all(summary["checks"].values()) else 1


# --------------------------------------------------------------------------------------------- infra

def start_infra(st: Stack) -> dict:
    P = st.ports
    pw = {k: st.secret(secrets.token_urlsafe(24)) for k in ("pg_admin", "tracecat", "deca", "redis")}
    pwfile = st.run / "pgpw"
    pwfile.write_text(pw["pg_admin"] + "\n")
    os.chmod(pwfile, 0o600)
    subprocess.run([str(PG_BIN / "initdb"), "-D", str(st.pg_data), "-U", "postgres", "--pwfile", str(pwfile),
                    "--auth-local=trust", "--auth-host=scram-sha-256", "-E", "UTF8"],
                   check=True, capture_output=True)
    pwfile.unlink()
    (st.run / "sock").mkdir()
    subprocess.run([str(PG_BIN / "pg_ctl"), "-D", str(st.pg_data), "-w", "-l", str(st.logs / "postgres.log"), "-o",
                    f"-c listen_addresses=127.0.0.1 -p {P['pg']} -k {st.run / 'sock'} -c max_connections=300"
                    " -c log_statement=none -c log_min_messages=warning", "start"], check=True, capture_output=True)
    admin = f"host={st.run / 'sock'} port={P['pg']} user=postgres dbname=postgres"
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute(f"CREATE ROLE tracecat_app LOGIN PASSWORD '{pw['tracecat']}'")
        c.execute(f"CREATE ROLE deca_app LOGIN PASSWORD '{pw['deca']}'")
        c.execute("CREATE DATABASE tracecat OWNER tracecat_app")
        c.execute("CREATE DATABASE deca_soar OWNER deca_app")
    with psycopg.connect(admin.replace("dbname=postgres", "dbname=tracecat"), autocommit=True) as c:
        c.execute("CREATE EXTENSION IF NOT EXISTS vector")  # RDS: enabled by the DBA [A]

    conf = st.run / "redis.conf"
    conf.write_text(f"bind 127.0.0.1\nport {P['redis']}\nrequirepass {pw['redis']}\nsave \"\"\nappendonly no\n"
                    f"dir {st.run}\n")
    os.chmod(conf, 0o600)
    st.start("redis", [str(REDIS), str(conf)], env={**os.environ, "LD_LIBRARY_PATH": str(REDIS_LIB)})
    st.start("temporal", [str(TEMPORAL), "server", "start-dev", "--ip", "127.0.0.1", "--port", str(P["temporal"]),
                          "--headless", "--log-level", "warn"])
    st.start("s3", [str(MOTO), "-H", "127.0.0.1", "-p", str(P["s3"])])
    wait_for(lambda: socket.create_connection(("127.0.0.1", P["temporal"]), 1).close() or True, "temporal")
    wait_for(lambda: httpx.get(f"http://127.0.0.1:{P['s3']}/", timeout=2).status_code < 500, "s3")
    return {"admin_dsn": admin, **pw}


def squashfs_bin(st: Stack) -> Path:
    """Wrappers for squashfs-tools (present in the Tracecat image; extracted from the Debian package here)."""
    bindir = st.run / "bin"
    bindir.mkdir()
    libs = f"{TOOLS}/root/usr/lib/x86_64-linux-gnu:{TOOLS}/root/lib/x86_64-linux-gnu"
    for tool in ("mksquashfs", "unsquashfs"):
        w = bindir / tool
        w.write_text(f'#!/bin/sh\nLD_LIBRARY_PATH={libs} exec {TOOLS}/root/usr/bin/{tool} "$@"\n')
        w.chmod(0o755)
    return bindir


def tracecat_env(st: Stack, infra: dict) -> dict:
    P = st.ports
    keyring = json.dumps({"current_key_id": "v1", "keys": {"v1": secrets.token_hex(32)}}, separators=(",", ":"))
    env = {
        "PATH": f"{squashfs_bin(st)}:{os.environ['PATH']}", "HOME": str(st.run), "TMPDIR": str(st.run),
        "LOG_LEVEL": "INFO", "TRACECAT__LOG_FORMAT": "json",
        # Same forced values as the production render (scripts/render_tracecat_compose.py).
        "ENTERPRISE_EDITION": "false", "TRACECAT__FEATURE_FLAGS": "", "TRACECAT__EE_MULTI_TENANT": "false",
        "TRACECAT__APP_ENV": "production", "TRACECAT__PLATFORM_ADMIN_MFA_BYPASS": "false",
        "TRACECAT__PLATFORM_ADMIN_IP_ALLOWLIST_BYPASS": "false",
        "TRACECAT__UNSAFE_DISABLE_SECRET_ERROR_WITHHOLDING": "false",
        "TRACECAT__DB_ENCRYPTION_KEY": st.secret(base64.urlsafe_b64encode(os.urandom(32)).decode()),
        "TRACECAT__SERVICE_KEY": st.secret(secrets.token_urlsafe(48)),
        "TRACECAT__SIGNING_SECRET": st.secret(secrets.token_urlsafe(48)),
        "USER_AUTH_SECRET": st.secret(secrets.token_urlsafe(48)),
        "TRACECAT__DB_URI": f"postgresql+psycopg://tracecat_app:{infra['tracecat']}@127.0.0.1:{P['pg']}/tracecat",
        "TRACECAT__DB_SSLMODE": "disable",  # local only; production render defaults to require
        "REDIS_URL": f"redis://default:{infra['redis']}@127.0.0.1:{P['redis']}/0",
        "TEMPORAL__CLUSTER_URL": f"127.0.0.1:{P['temporal']}", "TEMPORAL__CLUSTER_NAMESPACE": "default",
        "TEMPORAL__CLUSTER_QUEUE": "tracecat-task-queue",
        "TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED": "true",
        "TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING": st.secret(keyring),
        "TRACECAT__BLOB_STORAGE_ENDPOINT": f"http://127.0.0.1:{P['s3']}",
        "TRACECAT__BLOB_STORAGE_PRESIGNED_URL_ENDPOINT": f"http://127.0.0.1:{P['s3']}",
        "AWS_ACCESS_KEY_ID": "e2e-synthetic", "AWS_SECRET_ACCESS_KEY": st.secret(secrets.token_urlsafe(24)),
        "AWS_DEFAULT_REGION": "ap-southeast-5",
        **{f"TRACECAT__BLOB_STORAGE_BUCKET_{b.upper()}": f"deca-e2e-{b}" for b in BUCKETS},
        "TRACECAT__API_URL": f"http://127.0.0.1:{P['api']}",
        "TRACECAT__PUBLIC_API_URL": f"http://127.0.0.1:{P['api']}",
        "TRACECAT__PUBLIC_APP_URL": f"http://127.0.0.1:{P['api']}",
        "TRACECAT__ALLOW_ORIGINS": f"http://127.0.0.1:{P['api']}",
        "TRACECAT__AUTH_TYPES": "basic", "TRACECAT__AUTH_MIN_PASSWORD_LENGTH": "16",
        "TRACECAT__AUTH_SUPERADMIN_EMAIL": "soar-admin@deca-e2e.example.com",
        "TRACECAT__AUTH_ALLOWED_DOMAINS": "deca-e2e.example.com",
        "TRACECAT__EXECUTOR_BACKEND": "direct",  # nsjail needs privileged containers; not available here
        "TRACECAT__EXECUTOR_QUEUE": "shared-action-queue",
        "TRACECAT__AGENT_QUEUE": "shared-agent-queue",
        "TRACECAT__BACKGROUND_QUEUE": "shared-background-queue",
        "TRACECAT__LOCAL_REPOSITORY_ENABLED": "false",
        "PYTHONPATH": str(TC_SRC),
        "DECA_E2E_RUN_DIR": str(st.run),
        "TRACECAT__ACTION_GATEWAY_SOCKET": str(st.run / "action-gateway.sock"),
    }
    return env


def create_buckets(st: Stack, env: dict) -> None:
    code = ("import boto3,os,sys\n"
            "s3=boto3.client('s3',endpoint_url=os.environ['TRACECAT__BLOB_STORAGE_ENDPOINT'],"
            "region_name=os.environ['AWS_DEFAULT_REGION'])\n"
            "for b in sys.argv[1:]:\n"
            "  s3.create_bucket(Bucket=b,CreateBucketConfiguration={'LocationConstraint':os.environ['AWS_DEFAULT_REGION']})\n")
    subprocess.run([str(TC_PY), "-c", code, *[f"deca-e2e-{b}" for b in BUCKETS]], env=env, check=True,
                   capture_output=True)


def start_tracecat(st: Stack, env: dict) -> None:
    mig = subprocess.run([str(TC_PY), "-m", "tracecat.db.roles", "migrate"], env=env, cwd=TC_SRC,
                         capture_output=True, text=True)
    (st.logs / "tracecat-migrations.log").write_text(mig.stdout + mig.stderr)
    if mig.returncode != 0:
        raise RuntimeError("tracecat migrations failed:\n" + (mig.stdout + mig.stderr)[-3000:])
    P = st.ports
    st.start("tc-api", [str(TC_PY), "-m", "uvicorn", "tracecat.api.app:app", "--host", "127.0.0.1",
                        "--port", str(P["api"]), "--no-access-log"], env=env, cwd=TC_SRC)
    for name, mod in (("tc-worker", "tracecat.dsl.worker"), ("tc-executor", "tracecat.executor.worker"),
                      ("tc-background", "tracecat.background.worker")):
        st.start(name, [str(TC_PY), str(REPO / "e2e/tc_launch.py"), mod], env=env, cwd=TC_SRC)

    def ready():
        st.check_alive()
        return httpx.get(f"http://127.0.0.1:{P['api']}/health", timeout=5).status_code == 200
    wait_for(ready, "tracecat api /health", timeout=300, interval=2)


# --------------------------------------------------------------------------------------------- DECA

def deca_env(st: Stack, infra: dict) -> dict:
    url = f"postgresql://deca_app:{infra['deca']}@127.0.0.1:{st.ports['pg']}/deca_soar"
    files = {"db_url": url, "tok": st.secret(secrets.token_hex(32)), "vault": st.secret(secrets.token_hex(32))}
    sec = st.run / "deca-secrets"
    sec.mkdir(mode=0o700)
    for k, v in files.items():
        p = sec / k
        p.write_text(v + "\n")
        os.chmod(p, 0o600)
    return {
        "PATH": os.environ["PATH"], "HOME": str(st.run),
        "DECA_DB_URL_FILE": str(sec / "db_url"), "DECA_TOKENIZATION_KEY_FILE": str(sec / "tok"),
        "DECA_VAULT_KEY_FILE": str(sec / "vault"), "DECA_POLICY_DIR": str(REPO / "policy"),
        "DECA_MIGRATIONS_DIR": str(REPO / "migrations"), "DECA_ENV": "e2e",
    }


def deca_cli(st: Stack, env: dict, *args: str) -> dict:
    r = subprocess.run([str(DECA_PY), "-m", "deca_soar.cli", *args], env=env, capture_output=True, text=True)
    (st.logs / "deca-cli.log").open("a").write(r.stdout + r.stderr)
    if r.returncode not in (0, 1):
        raise RuntimeError(f"deca-soar {args[0]} failed: {r.stderr[-1500:]}")
    return {"rc": r.returncode, **json.loads(r.stdout.strip().splitlines()[-1])}


def principal(st: Stack, env: dict, name: str, kind: str, role: str) -> str:
    f = st.run / "deca-secrets" / f"{name}.token"
    deca_cli(st, env, "create-principal", "--name", name, "--kind", kind, "--role", role, "--token-file", str(f))
    return st.secret(f.read_text().strip())


# --------------------------------------------------------------------------------------------- Tracecat API

class TC:
    def __init__(self, base: str) -> None:
        self.base = base
        self.c = httpx.Client(base_url=base, timeout=30)

    def login(self, email: str, password: str) -> None:
        r = self.c.post("/auth/login", data={"username": email, "password": password})
        r.raise_for_status()

    def j(self, method: str, path: str, **kw) -> httpx.Response:
        return self.c.request(method, path, **kw)


def bootstrap_tracecat(st: Stack, summary: dict) -> tuple[TC, str, str]:
    base = f"http://127.0.0.1:{st.ports['api']}"
    tc = TC(base)
    email, pw = "soar-admin@deca-e2e.example.com", st.secret(secrets.token_urlsafe(24))
    r = tc.c.post("/auth/register", json={"email": email, "password": pw})
    if r.status_code not in (200, 201):
        raise RuntimeError(f"register superadmin: {r.status_code} {r.text[:500]}")
    tc.login(email, pw)
    r = tc.j("GET", "/workspaces")
    r.raise_for_status()
    wss = r.json()
    if not wss:
        r = tc.j("POST", "/workspaces", json={"name": "deca-soc"})
        if r.status_code >= 400:
            raise RuntimeError(f"create workspace: {r.status_code} {r.text[:500]}")
        ws = r.json()["id"]
    else:
        ws = wss[0]["id"]
    summary["tracecat"] = {"workspace_created": True}
    return tc, ws, pw


def run_main_flow(st: Stack, summary: dict, tc: TC, ws: str, denv: dict, svc_token: str) -> None:
    P = st.ports
    W = f"/workspaces/{ws}"
    r = tc.j("POST", f"{W}/secrets", json={
        "name": "deca_broker", "type": "custom",
        "keys": [{"key": "URL", "value": f"http://127.0.0.1:{P['broker']}"}, {"key": "TOKEN", "value": svc_token}],
    })
    if r.status_code >= 400:
        raise RuntimeError(f"create secret: {r.status_code} {r.text[:500]}")
    wf_file = REPO / "tracecat/workflows/deca-alert-shadow.yml"
    def do_import():
        resp = tc.j("POST", f"{W}/workflows", files={"file": (wf_file.name, wf_file.read_bytes(), "application/yaml")})
        return None if "builtin_sync_pending" in resp.text else resp
    r = wait_for(do_import, "builtin registry sync", timeout=300, interval=5)
    if r.status_code >= 400:
        raise RuntimeError(f"import workflow: {r.status_code} {r.text[:800]}")
    wf_id = r.json()["id"]
    r = tc.j("POST", f"{W}/workflows/{wf_id}/commit")
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    if r.status_code >= 400 or body.get("status") == "failure":
        raise RuntimeError(f"commit workflow: {r.status_code} {r.text[:1500]}")
    r = tc.j("PATCH", f"{W}/workflows/{wf_id}/webhook",
             json={"status": "online", "methods": ["POST"], "allowlisted_cidrs": ["127.0.0.1/32"]})
    if r.status_code >= 400:
        raise RuntimeError(f"enable webhook: {r.status_code} {r.text[:500]}")
    r = tc.j("POST", f"{W}/workflows/{wf_id}/webhook/api-key")
    if r.status_code >= 400:
        raise RuntimeError(f"webhook api key: {r.status_code} {r.text[:500]}")
    wh_key = st.secret(r.json()["api_key"])
    wh = tc.j("GET", f"{W}/workflows/{wf_id}/webhook").json()
    wh_url = st.secret(wh["url"])
    summary["tracecat"].update({"workflow_committed": True, "webhook_online": wh.get("status") == "online",
                                "webhook_api_key_required": True, "webhook_allowlisted_cidrs": ["127.0.0.1/32"]})

    # Webhook without the API key must be refused.
    r = httpx.post(wh_url, json={"probe": True}, timeout=10)
    summary["checks"]["webhook_rejects_missing_api_key"] = r.status_code in (401, 403)

    sec = st.run / "deca-secrets"
    (sec / "wh_url").write_text(wh_url + "\n")
    (sec / "wh_key").write_text(wh_key + "\n")
    os.chmod(sec / "wh_url", 0o600)
    os.chmod(sec / "wh_key", 0o600)
    replay = st.run / "replay.ndjson"
    alerts = [
        {"source": "waf", "rule_id": "waf.sqli.burst", "severity_hint": "high", "detected_at": "2026-11-24T03:00:10Z",
         "src_ip": RAW_IP, "uri": f"/api/v1/login?email={RAW_EMAIL}", "ua": "sqlmap/1.7", "events": 40},
        {"source": "waf", "rule_id": "waf.scanner", "severity_hint": "medium", "detected_at": "2026-11-24T03:01:00Z",
         "src_ip": PROTECTED_IP, "uri": "/.env", "ua": "curl/8", "events": 25},
    ]
    replay.write_text("".join(json.dumps(x) + "\n" for x in alerts))
    genv = {**denv, "DECA_GATEWAY_SOURCE": "replay", "DECA_REPLAY_FILE": str(replay), "DECA_SOURCE_NAME": "e2e",
            "DECA_PULL_INTERVAL_S": "2", "DECA_TRACECAT_WEBHOOK_URL_FILE": str(sec / "wh_url"),
            "DECA_TRACECAT_WEBHOOK_API_KEY_FILE": str(sec / "wh_key")}
    # Tracecat builds the builtin registry artifact in the background after startup (~2 min here);
    # actions fail with "Registry artifact not found" until it is uploaded.
    wait_for(lambda: st.check_alive() or "Platform registry artifact build completed"
             in (st.logs / "tc-api.log").read_text(errors="replace"), "registry artifact build", timeout=600, interval=5)
    st.start("deca-gateway", [str(DECA_PY), "-m", "uvicorn", "deca_soar.gateway.app:app", "--host", "127.0.0.1",
                              "--port", str(P["gateway"]), "--no-access-log"], env=genv, cwd=REPO)

    db = denv_db(st)

    def requests_done():
        st.check_alive()
        with psycopg.connect(db) as c:
            n = c.execute("SELECT count(*) FROM broker.action_request").fetchone()[0]
        return n >= 2
    wait_for(requests_done, "two broker action requests via Tracecat", timeout=240, interval=2)

    with psycopg.connect(db) as c:
        inbox = c.execute("SELECT status, count(*) FROM gateway.inbox_event GROUP BY 1").fetchall()
        reqs = c.execute(
            "SELECT r.action, r.status, r.mode, r.reasons::text, p.name"
            " FROM broker.action_request r JOIN broker.principal p ON p.principal_id = r.requested_by"
            " ORDER BY r.created_at").fetchall()
        kinds = c.execute("SELECT event_type, count(*) FROM ledger.entry GROUP BY 1 ORDER BY 1").fetchall()
    summary["flow"] = {
        "inbox": dict(inbox),
        "action_requests": [dict(zip(("action", "status", "mode", "reasons", "requested_by"), x)) for x in reqs],
        "ledger_events": dict(kinds),
    }
    statuses = sorted(x[1] for x in reqs)
    summary["checks"]["alert_flowed_to_broker_validated_shadow"] = any(x[1] == "validated" and x[2] == "shadow"
                                                                       for x in reqs)
    summary["checks"]["protected_target_rejected"] = any(x[1] == "rejected" and "protected" in (x[3] or "")
                                                         for x in reqs)
    summary["checks"]["two_requests"] = statuses == ["rejected", "validated"]

    # Tracecat runs succeeded?
    r = tc.j("GET", f"{W}/workflow-executions", params={"workflow_id": wf_id, "limit": 10})
    if r.status_code == 200:
        items = r.json()
        items = items.get("items", items) if isinstance(items, dict) else items
        summary["tracecat"]["executions"] = [x.get("status") for x in items]
        summary["checks"]["tracecat_runs_completed"] = bool(items) and all(x.get("status") == "COMPLETED"
                                                                           for x in items)

    v = deca_cli(st, denv, "verify-ledger")
    summary["ledger_verify"] = {k: v[k] for k in ("ok", "entries", "head_seq", "errors")}
    summary["checks"]["ledger_chain_ok"] = v["ok"] is True and v["entries"] > 0

    # No raw PII in Tracecat's database or object storage (only tok_* tokens should reach it).
    dump = tracecat_db_text(st)
    raw_hits = {s: dump.count(s) for s in (RAW_IP, PROTECTED_IP, RAW_EMAIL)}
    tok_hits = dump.count("tok_ip_")
    summary["pii"] = {"tracecat_db_raw_hits": raw_hits, "tracecat_db_tok_ip_mentions": tok_hits,
                      "scanned_bytes": len(dump)}
    blob = scan_blob_storage(st)
    summary["pii"]["object_storage"] = blob
    # Positive control: what Tracecat itself reports as the run input carries tokens, not raw values.
    ev_text = ""
    for ex in (tc.j("GET", f"{W}/workflow-executions", params={"workflow_id": wf_id, "limit": 10}).json() or []):
        ex_id = ex.get("id") if isinstance(ex, dict) else None
        if ex_id:
            ev_text += tc.j("GET", f"{W}/workflow-executions/{quote(ex_id, safe='')}/compact").text
    summary["pii"]["execution_api"] = {"raw_hits": {s_: ev_text.count(s_) for s_ in (RAW_IP, PROTECTED_IP, RAW_EMAIL)},
                                       "tok_ip_mentions": ev_text.count("tok_ip_"), "bytes": len(ev_text)}
    raw_anywhere = any(raw_hits.values()) or any(blob["raw_hits"].values()) \
        or any(summary["pii"]["execution_api"]["raw_hits"].values())
    tok_seen = tok_hits + blob["tok_ip_mentions"] + summary["pii"]["execution_api"]["tok_ip_mentions"]
    summary["checks"]["no_raw_pii_in_tracecat"] = not raw_anywhere and tok_seen > 0


def tracecat_db_text(st: Stack) -> str:
    """Every row of every table in the Tracecat database as text (stand-in for pg_dump --data-only)."""
    dsn = f"host={st.run / 'sock'} port={st.ports['pg']} user=postgres dbname=tracecat"
    out = []
    with psycopg.connect(dsn) as c:
        tables = c.execute(
            "SELECT table_schema, table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE'"
            " AND table_schema NOT IN ('pg_catalog', 'information_schema')").fetchall()
        for schema, name in tables:
            row = c.execute(psycopg.sql.SQL("SELECT coalesce(string_agg(t::text, chr(10)), '') FROM {}.{} t")
                            .format(psycopg.sql.Identifier(schema), psycopg.sql.Identifier(name))).fetchone()
            out.append(row[0])
    return "\n".join(out)


def scan_blob_storage(st: Stack) -> dict:
    """Count raw PII vs tokens across every object in the S3 stand-in (gzip/zstd bodies are expanded)."""
    code = (
        "import boto3,gzip,json,os,sys\n"
        "s3=boto3.client('s3',endpoint_url=os.environ['TRACECAT__BLOB_STORAGE_ENDPOINT'],"
        "region_name=os.environ['AWS_DEFAULT_REGION'])\n"
        "needles=sys.argv[1:]; raw={n:0 for n in needles}; tok=0; n_obj=0\n"
        "for b in [x['Name'] for x in s3.list_buckets()['Buckets']]:\n"
        "  for page in s3.get_paginator('list_objects_v2').paginate(Bucket=b):\n"
        "    for o in page.get('Contents',[]):\n"
        "      if o['Size']>50_000_000: continue\n"
        "      n_obj+=1; body=s3.get_object(Bucket=b,Key=o['Key'])['Body'].read()\n"
        "      try: body=gzip.decompress(body)\n"
        "      except Exception: pass\n"
        "      try:\n"
        "        import zstandard; body=zstandard.ZstdDecompressor().decompress(body, max_output_size=200_000_000)\n"
        "      except Exception: pass\n"
        "      for n in needles: raw[n]+=body.count(n.encode())\n"
        "      tok+=body.count(b'tok_ip_')\n"
        "print(json.dumps({'objects':n_obj,'raw_hits':raw,'tok_ip_mentions':tok}))\n")
    env = st.tc_env
    r = subprocess.run([str(TC_PY), "-c", code, RAW_IP, PROTECTED_IP, RAW_EMAIL], env=env, capture_output=True,
                       text=True, timeout=300)
    if r.returncode != 0:
        raise RuntimeError("blob scan failed: " + r.stderr[-1000:])
    return json.loads(r.stdout.strip().splitlines()[-1])


def denv_db(st: Stack) -> str:
    return (st.run / "deca-secrets" / "db_url").read_text().strip()


# --------------------------------------------------------------------------------------------- OSS probes

def oss_probes(st: Stack, summary: dict, tc: TC, ws: str) -> None:
    o = summary["oss"]
    W = f"/workspaces/{ws}"

    def probe(method, path, **kw):
        r = tc.j(method, path, **kw)
        try:
            body = r.json()
        except ValueError:
            body = r.text[:200]
        return r.status_code, body

    code, ent = probe("GET", "/organization/entitlements")
    if code != 200:
        code, ent = probe("GET", "/organization/settings/entitlements")
    o["entitlements"] = {"status": code, "body": ent}
    code, roles = probe("GET", "/rbac/roles")
    o["rbac_roles"] = {"status": code,
                       "roles": [{"name": x.get("name"), "slug": x.get("slug"), "is_system": x.get("is_system")}
                                 for x in (roles.get("items", roles) if isinstance(roles, (dict, list)) else [])
                                 if isinstance(x, dict)] if code == 200 else roles}
    o["rbac_create_custom_role"] = probe("POST", "/rbac/roles", json={"name": "deca-approver", "scopes": []})[0]
    o["service_accounts_org"] = probe("GET", "/organization/service-accounts")[0]
    o["service_accounts_ws"] = probe("GET", f"{W}/service-accounts")[0]
    o["mcp_pat_list"] = probe("GET", f"{W}/mcp-personal-access-tokens")[0]
    o["inbox_items"] = probe("GET", f"{W}/inbox/items")[0]
    o["inbox_pending_count"] = probe("GET", f"{W}/inbox/items/pending-count")
    o["agent_sessions_list"] = probe("GET", f"{W}/agent/sessions")[0]
    code, members = probe("GET", f"{W}/memberships")
    o["workspace_memberships"] = code
    # Agent tool approvals: where the code lives (read-only inspection of the installed source; ee is not run).
    approvals_init = (TC_SRC / "tracecat/agent/approvals/__init__.py").read_text()
    agent_worker = (TC_SRC / "tracecat/agent/worker.py").read_text()
    dsl_workflow = (TC_SRC / "tracecat/dsl/workflow.py").read_text()
    o["agent_tool_approvals"] = {
        "core_says_moved_to_ee": "moved to Enterprise Edition (tracecat_ee)" in approvals_init,
        "agent_worker_runs_tracecat_ee_DurableAgentWorkflow": "from tracecat_ee.agent.workflows.durable import" in agent_worker,
        "dsl_worker_imports_tracecat_ee": "from tracecat_ee." in dsl_workflow,
        "tested_end_to_end": False,
        "note": "agent-worker/litellm not started (Enterprise-licensed runtime, no LLM in phase 0)",
    }


# --------------------------------------------------------------------------------------------- scenario

def scenario(st: Stack, summary: dict) -> int:
    infra = start_infra(st)
    env = tracecat_env(st, infra)
    st.tc_env = env
    create_buckets(st, env)
    start_tracecat(st, env)
    summary["checks"]["tracecat_started"] = True

    denv = deca_env(st, infra)
    deca_cli(st, denv, "migrate")
    svc_token = principal(st, denv, "tracecat-svc", "service", "analyst")
    P = st.ports
    st.start("deca-broker", [str(DECA_PY), "-m", "uvicorn", "deca_soar.broker.app:app", "--host", "127.0.0.1",
                             "--port", str(P["broker"]), "--no-access-log"], env=denv, cwd=REPO)
    wait_for(lambda: httpx.get(f"http://127.0.0.1:{P['broker']}/healthz", timeout=2).status_code == 200, "broker")

    tc, ws, _ = bootstrap_tracecat(st, summary)
    run_main_flow(st, summary, tc, ws, denv, svc_token)
    oss_probes(st, summary, tc, ws)
    return 0


if __name__ == "__main__":
    sys.exit(main())
