#!/usr/bin/env python3
"""Disposable end-to-end stack: synthetic alerts -> gateway -> Temporal workflow -> broker (shadow) -> ledger.

Production artefacts under test, unchanged: Temporal server 1.32.2 with deploy/temporal/config (mTLS on frontend
and internode, PostgreSQL over verified TLS), deploy/temporal/bin/temporal-schema.sh, temporal-namespace.sh and
temporal-start.sh, the DECA migrations and the least-privilege DB roles. Stand-ins: a local Postgres 18 for RDS,
a throwaway PKI for the internal CAs, a replay file for SLS. No Alibaba, cloud or LLM credentials are used.

Everything listens on a private loopback address (127.0.73.1) inside a fresh 0700 temp dir and is torn down at
the end. Secrets are generated per run, passed as 0600 files, never printed, and every log is scanned for them
(and for the raw synthetic PII) before the run dir is deleted. Only a redacted JSON summary goes to --evidence.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import ipaddress
import json
import os
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

import httpx
import psycopg
import psycopg.sql
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REPO = Path(__file__).resolve().parents[1]
TOOLS = Path(os.environ.get("DECA_E2E_TOOLS", "/data/work/tools/soar-deps"))
PG_BIN = Path(os.environ.get("DECA_E2E_PG_BIN", TOOLS / "pg18v/bin"))
TEMPORAL_BIN_DIR = Path(os.environ.get("DECA_E2E_TEMPORAL_BIN_DIR", "/data/work/tools/temporal-server-1.32.2"))
TEMPORAL_CLI = Path(os.environ.get("DECA_E2E_TEMPORAL_CLI", TOOLS / "temporal"))
DECA_PY = REPO / ".venv/bin/python"
TBIN = REPO / "deploy/temporal/bin"

HOST = "127.0.73.1"                 # private loopback address: nothing binds a wildcard
TEMPORAL_NAME = "temporal.deca.internal"
PG_NAME = "rds.deca.internal"
NAMESPACE = "deca-soar"
RAW_IP = "203.0.113.7"              # RFC5737 TEST-NET-3: synthetic attacker
URI_IP = "203.0.113.99"             # only inside the attacker-controlled URI (review F1)
PROTECTED_IP = "198.51.100.20"      # inside the protected placeholder range
MAPPED_PROTECTED = "::ffff:198.51.100.21"  # IPv4-mapped form of a protected address (review F2)
RAW_EMAIL = "victim.e2e@example.com"
RULES = ("waf.sqli.burst", "waf.scanner", "waf.mapped", "sas.bruteforce")
TAMPER = ("DELETE FROM ledger.entry", "UPDATE ledger.entry SET actor = 'x'", "TRUNCATE ledger.entry",
          "ALTER TABLE ledger.entry DISABLE TRIGGER ALL", "SET session_replication_role = replica")


def free_port() -> int:
    with socket.socket() as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def port_free(port: int) -> bool:
    """No socket listening on HOST:port (connections in TIME_WAIT after teardown do not count)."""
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((HOST, port))
            return True
        except OSError:
            return False


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


# --------------------------------------------------------------------------------------------- PKI

class PKI:
    """Throwaway internal CAs: server CA (Temporal, Postgres, broker) and the DECA client CA."""

    def __init__(self, d: Path) -> None:
        self.d = d
        d.mkdir(mode=0o700)
        self.server_ca = self._ca("deca-e2e-server-ca")
        self.client_ca = self._ca("deca-e2e-client-ca")
        self.rogue_ca = self._ca("not-deca-ca")

    def _key(self):
        return ec.generate_private_key(ec.SECP256R1())

    def _ca(self, name: str):
        key = self._key()
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(now + dt.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
                .sign(key, hashes.SHA256()))
        self._write(name, cert, key)
        return cert, key

    def _write(self, name: str, cert, key) -> tuple[Path, Path]:
        c, k = self.d / f"{name}.pem", self.d / f"{name}.key"
        c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
        os.chmod(k, 0o600)
        return c, k

    def ca_file(self, which: str) -> Path:
        return self.d / f"deca-e2e-{which}-ca.pem"

    def leaf(self, name: str, *, ca, dns: list[str] = (), ips: list[str] = (), server: bool) -> tuple[Path, Path]:
        ca_cert, ca_key = ca
        key = self._key()
        now = dt.datetime.now(dt.timezone.utc)
        san = [x509.DNSName(n) for n in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
        usages = [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH] if server \
            else [ExtendedKeyUsageOID.CLIENT_AUTH]
        b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
             .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.ExtendedKeyUsage(usages), critical=False))
        if san:
            b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
        return self._write(name, b.sign(ca_key, hashes.SHA256()), key)


# --------------------------------------------------------------------------------------------- stack

class Stack:
    def __init__(self, run: Path) -> None:
        self.run = run
        self.logs = run / "logs"
        self.logs.mkdir()
        self.sec = run / "secrets"
        self.sec.mkdir(mode=0o700)
        self.procs: list[tuple[str, subprocess.Popen]] = []
        self.secret_values: list[str] = []
        self.ports = {k: free_port() for k in ("pg", "temporal", "temporal_http", "broker", "gateway")}
        self.pg_data = run / "pg"

    def secret(self, value: str) -> str:
        self.secret_values.append(value)
        return value

    def secret_file(self, name: str, value: str) -> Path:
        p = self.sec / name
        p.write_text(value + "\n")
        os.chmod(p, 0o600)
        return p

    def start(self, name: str, argv: list[str], env: dict, cwd: Path | None = None) -> subprocess.Popen:
        log = (self.logs / f"{name}.log").open("ab")
        p = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env, cwd=cwd, start_new_session=True)
        self.procs.append((name, p))
        return p

    def check_alive(self) -> None:
        for name, p in self.procs:
            if p.poll() is not None:
                tail = (self.logs / f"{name}.log").read_text(errors="replace")[-3000:]
                raise RuntimeError(f"{name} exited with {p.returncode}\n{tail}")

    def stop_one(self, name: str) -> None:
        for n, p in self.procs:
            if n == name and p.poll() is None:
                os.killpg(p.pid, signal.SIGTERM)
                p.wait(timeout=30)

    def stop(self) -> list[str]:
        stopped = []
        for _, p in reversed(self.procs):
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for name, p in reversed(self.procs):
            try:
                p.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=5)
            stopped.append(name)
        if (self.pg_data / "postmaster.pid").exists():
            subprocess.run([str(PG_BIN / "pg_ctl"), "-D", str(self.pg_data), "-m", "fast", "-w", "stop"],
                           capture_output=True, check=False)
            stopped.append("postgres")
        return stopped


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", type=Path, required=True, help="directory for the redacted summary")
    ap.add_argument("--keep-run-dir", action="store_true", help="debug only: keep logs and keys")
    a = ap.parse_args()

    run = Path(tempfile.mkdtemp(prefix="deca-e2e-"))
    os.chmod(run, 0o700)
    st = Stack(run)
    summary: dict = {"started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "git_sha": git_sha(), "checks": {}}
    rc = 1
    try:
        rc = scenario(st, summary)
    except Exception as e:  # noqa: BLE001
        summary["error"] = f"{type(e).__name__}: {e}"[:4000]
        summary["traceback"] = traceback.format_exc()[-4000:]
    finally:
        summary["stopped"] = st.stop()
        secret_leaks, pii_leaks = [], {}
        for f in sorted(st.logs.glob("*.log")):
            text = f.read_text(errors="replace")
            if any(len(v) >= 8 and v in text for v in st.secret_values):
                secret_leaks.append(f.name)
            hits = [s for s in (RAW_IP, URI_IP, PROTECTED_IP, RAW_EMAIL) if s in text]
            if hits:
                pii_leaks[f.name] = len(hits)
        summary["checks"]["no_secret_in_logs"] = not secret_leaks
        summary["checks"]["no_raw_pii_in_logs"] = not pii_leaks
        summary["log_files_scanned"] = sorted(f.name for f in st.logs.glob("*.log"))
        if secret_leaks:
            summary["secret_leak_files"] = secret_leaks
        if pii_leaks:
            summary["pii_leak_files"] = pii_leaks
        time.sleep(1)
        left = subprocess.run(["pgrep", "-f", str(run)], capture_output=True, text=True).stdout.split()
        summary["checks"]["no_process_left"] = not left
        summary["checks"]["no_listener_left"] = all(port_free(p) for p in st.ports.values())
        summary["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
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
    return 0 if rc == 0 and summary["checks"] and all(summary["checks"].values()) else 1


def git_sha() -> str:
    r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True)
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=REPO,
                           capture_output=True, text=True).stdout.strip()
    return r.stdout.strip() + ("-dirty" if dirty else "")


# --------------------------------------------------------------------------------------------- Postgres (RDS stand-in)

def start_postgres(st: Stack, pki: PKI) -> dict:
    P = st.ports
    pw = {k: st.secret(secrets.token_urlsafe(24)) for k in ("admin", "temporal", "owner", "gw", "brk", "aud")}
    pwfile = st.run / "pgpw"
    pwfile.write_text(pw["admin"] + "\n")
    os.chmod(pwfile, 0o600)
    subprocess.run([str(PG_BIN / "initdb"), "-D", str(st.pg_data), "-U", "postgres", "--pwfile", str(pwfile),
                    "--auth-local=trust", "--auth-host=scram-sha-256", "-E", "UTF8"], check=True, capture_output=True)
    pwfile.unlink()
    cert, key = pki.leaf("rds", ca=pki.server_ca, dns=[PG_NAME], ips=[HOST], server=True)
    # TLS only over TCP, like RDS with rds.force_ssl=1.
    (st.pg_data / "pg_hba.conf").write_text("local all postgres trust\nhostssl all all 127.0.0.0/8 scram-sha-256\n")
    (st.run / "sock").mkdir()
    subprocess.run([str(PG_BIN / "pg_ctl"), "-D", str(st.pg_data), "-w", "-l", str(st.logs / "postgres.log"), "-o",
                    f"-c listen_addresses={HOST} -p {P['pg']} -k {st.run / 'sock'} -c max_connections=300"
                    f" -c ssl=on -c ssl_cert_file={cert} -c ssl_key_file={key}"
                    " -c log_statement=none -c log_min_messages=warning", "start"], check=True, capture_output=True)
    admin = f"host={st.run / 'sock'} port={P['pg']} user=postgres dbname=postgres"
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute(f"CREATE ROLE temporal LOGIN PASSWORD '{pw['temporal']}'")
        c.execute("CREATE DATABASE temporal OWNER temporal")
        c.execute("CREATE DATABASE temporal_visibility OWNER temporal")
        c.execute(f"CREATE ROLE deca_owner LOGIN CREATEROLE PASSWORD '{pw['owner']}'")
        c.execute("CREATE DATABASE deca_soar OWNER deca_owner")
    return {"admin_dsn": admin, **pw}


def db_url(st: Stack, pki: PKI, user: str, pw: str) -> str:
    return (f"postgresql://{user}:{pw}@{HOST}:{st.ports['pg']}/deca_soar"
            f"?sslmode=verify-full&sslrootcert={pki.ca_file('server')}")


# --------------------------------------------------------------------------------------------- Temporal

def temporal_env(st: Stack, pki: PKI, pg: dict) -> dict:
    srv_cert, srv_key = pki.leaf("temporal-server", ca=pki.server_ca, dns=[TEMPORAL_NAME], server=True)
    sw_cert, sw_key = pki.leaf("temporal-system-worker", ca=pki.client_ca, server=False)
    pwf = st.secret_file("temporal_db_password", pg["temporal"])
    return {
        "PATH": "/usr/bin:/bin", "HOME": str(st.run),
        "TEMPORAL_BIN_DIR": str(TEMPORAL_BIN_DIR), "TEMPORAL_CONFIG_DIR": str(REPO / "deploy/temporal/config"),
        "DYNAMIC_CONFIG_FILE_PATH": str(REPO / "deploy/temporal/dynamicconfig/production.yaml"),
        "TEMPORAL_DB_PASSWORD_FILE": str(pwf), "LOG_LEVEL": "warn", "NUM_HISTORY_SHARDS": "4",
        "POSTGRES_SEEDS": HOST, "DB_PORT": str(st.ports["pg"]), "POSTGRES_USER": "temporal",
        "SQL_TLS_ENABLED": "true", "SQL_HOST_VERIFICATION": "true",
        "SQL_CA": str(pki.ca_file("server")), "SQL_HOST_NAME": PG_NAME,
        "BIND_ON_IP": HOST, "FRONTEND_GRPC_PORT": str(st.ports["temporal"]),
        "FRONTEND_HTTP_PORT": str(st.ports["temporal_http"]),
        "TEMPORAL_TLS_SERVER_CERT": str(srv_cert), "TEMPORAL_TLS_SERVER_KEY": str(srv_key),
        "TEMPORAL_TLS_CA_CERT": str(pki.ca_file("server")), "TEMPORAL_TLS_SERVER_NAME": TEMPORAL_NAME,
        "TEMPORAL_TLS_CLIENT_CA_CERT": str(pki.ca_file("client")),
        "TEMPORAL_TLS_SYSTEM_WORKER_CERT": str(sw_cert), "TEMPORAL_TLS_SYSTEM_WORKER_KEY": str(sw_key),
    }


def start_temporal(st: Stack, pki: PKI, tenv: dict, summary: dict) -> dict:
    busy = [p for p in (7234, 7235, 7239, 6933, 6934, 6935, 6939) if not port_free(p)]
    if busy:
        raise RuntimeError(f"fixed Temporal ports busy on {HOST}: {busy}")
    r = subprocess.run([str(TBIN / "temporal-schema.sh")], env=tenv, capture_output=True, text=True, timeout=300)
    (st.logs / "temporal-schema.log").write_text(r.stdout + r.stderr)
    if r.returncode != 0:
        raise RuntimeError("temporal-schema.sh failed:\n" + (r.stdout + r.stderr)[-2000:])
    r2 = subprocess.run([str(TBIN / "temporal-schema.sh")], env=tenv, capture_output=True, text=True, timeout=300)
    (st.logs / "temporal-schema-rerun.log").write_text(r2.stdout + r2.stderr)
    summary["checks"]["temporal_schema_script_idempotent"] = r2.returncode == 0
    st.start("temporal-server", [str(TBIN / "temporal-start.sh")], env=tenv)

    op_cert, op_key = pki.leaf("operator", ca=pki.client_ca, server=False)
    op = {"TEMPORAL_CLI": str(TEMPORAL_CLI), "TEMPORAL_ADDRESS": f"{HOST}:{st.ports['temporal']}",
          "TEMPORAL_TLS_CERT": str(op_cert), "TEMPORAL_TLS_KEY": str(op_key),
          "TEMPORAL_TLS_CA": str(pki.ca_file("server")), "TEMPORAL_TLS_SERVER_NAME": TEMPORAL_NAME,
          "DECA_TEMPORAL_NAMESPACE": NAMESPACE, "PATH": "/usr/bin:/bin", "HOME": str(st.run)}

    def ns():
        st.check_alive()
        r = subprocess.run([str(TBIN / "temporal-namespace.sh")], env=op, capture_output=True, text=True, timeout=60)
        with (st.logs / "temporal-namespace.log").open("a") as f:
            f.write(r.stdout + r.stderr)
        return r.returncode == 0
    wait_for(ns, "temporal frontend + namespace", timeout=180, interval=3)
    summary["checks"]["temporal_server_started_with_production_config"] = True

    def ns_ready():
        st.check_alive()
        return temporal_cli(op, "workflow", "list", "--namespace", NAMESPACE, "--limit", "1").returncode == 0
    wait_for(ns_ready, "namespace usable", timeout=120, interval=2)
    return op


def listening_ports(pgid: int) -> set[int]:
    """TCP ports in LISTEN state held by any process of one process group (read from /proc, no tools)."""
    inodes: set[str] = set()
    for d in Path("/proc").iterdir():
        if not d.name.isdigit():
            continue
        try:
            if int((d / "stat").read_text().rsplit(")", 1)[1].split()[2]) != pgid:
                continue
            for fd in (d / "fd").iterdir():
                link = os.readlink(fd)
                if link.startswith("socket:["):
                    inodes.add(link[8:-1])
        except (OSError, ValueError, IndexError):
            continue
    ports: set[int] = set()
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in Path(table).read_text().splitlines()[1:]:
            f = line.split()
            if f[3] == "0A" and f[9] in inodes:
                ports.add(int(f[1].rsplit(":", 1)[1], 16))
    return ports


def temporal_http_probe(st: Stack, summary: dict) -> None:
    """Review N5: the frontend HTTP API stays closed even though FRONTEND_HTTP_PORT is set in its env."""
    proc = next(p for n, p in st.procs if n == "temporal-server")
    ports = listening_ports(os.getpgid(proc.pid))
    expected = {st.ports["temporal"], 7234, 7235, 7239, 6933, 6934, 6935, 6939}
    http_port = st.ports["temporal_http"]
    refused = {}
    for port in (http_port, 7243):
        try:
            httpx.get(f"http://{HOST}:{port}/api/v1/namespaces", timeout=3)
            refused[port] = False
        except httpx.ConnectError:
            refused[port] = True
    summary["temporal_listeners"] = sorted(ports)
    summary["checks"]["temporal_frontend_http_api_closed"] = (
        bool(ports) and ports <= expected and http_port not in ports and 7243 not in ports and all(refused.values()))


def temporal_cli(op: dict, *args: str) -> subprocess.CompletedProcess:
    tls = ["--address", op["TEMPORAL_ADDRESS"], "--tls-cert-path", op["TEMPORAL_TLS_CERT"], "--tls-key-path",
           op["TEMPORAL_TLS_KEY"], "--tls-ca-path", op["TEMPORAL_TLS_CA"], "--tls-server-name",
           op["TEMPORAL_TLS_SERVER_NAME"]]
    return subprocess.run([op["TEMPORAL_CLI"], *args, *tls], capture_output=True, text=True, timeout=60,
                          env={"PATH": "/usr/bin:/bin", "HOME": op["HOME"]})


def mtls_probes(st: Stack, pki: PKI, summary: dict) -> None:
    """The frontend must refuse a client without a cert and one signed by any CA other than the DECA client CA."""
    from temporalio.client import Client
    from temporalio.service import TLSConfig

    rogue_cert, rogue_key = pki.leaf("rogue", ca=pki.rogue_ca, server=False)
    ca = pki.ca_file("server").read_bytes()
    addr = f"{HOST}:{st.ports['temporal']}"

    async def try_connect(tls) -> bool:
        try:
            c = await asyncio.wait_for(Client.connect(addr, namespace=NAMESPACE, tls=tls), 20)
            await asyncio.wait_for(c.count_workflows(), 20)
            return True
        except Exception:  # noqa: BLE001 - any failure = refused
            return False

    no_cert = asyncio.run(try_connect(TLSConfig(server_root_ca_cert=ca, domain=TEMPORAL_NAME)))
    rogue = asyncio.run(try_connect(TLSConfig(server_root_ca_cert=ca, domain=TEMPORAL_NAME,
                                              client_cert=rogue_cert.read_bytes(),
                                              client_private_key=rogue_key.read_bytes())))
    plaintext = asyncio.run(try_connect(False))
    summary["mtls"] = {"no_client_cert_accepted": no_cert, "foreign_ca_cert_accepted": rogue,
                       "plaintext_accepted": plaintext}
    summary["checks"]["temporal_frontend_requires_deca_client_cert"] = not (no_cert or rogue or plaintext)


# --------------------------------------------------------------------------------------------- DECA

def deca_cli(st: Stack, env: dict, *args: str, ok=(0, 1)) -> dict:
    r = subprocess.run([str(DECA_PY), "-m", "deca_soar.cli", *args], env=env, capture_output=True, text=True,
                       timeout=120)
    with (st.logs / "deca-cli.log").open("a") as f:
        f.write(r.stdout + r.stderr)
    if r.returncode not in ok:
        raise RuntimeError(f"deca-soar {args[0]} failed ({r.returncode}): {r.stderr[-1500:]}")
    lines = r.stdout.strip().splitlines()
    return {"rc": r.returncode, **(json.loads(lines[-1]) if lines and lines[-1].startswith("{") else {})}


def setup_deca(st: Stack, pki: PKI, pg: dict) -> dict:
    base = {"PATH": os.environ["PATH"], "HOME": str(st.run), "DECA_ENV": "e2e",
            "DECA_POLICY_DIR": str(REPO / "policy"), "DECA_MIGRATIONS_DIR": str(REPO / "migrations")}
    urls = {
        "owner": st.secret_file("deca_db_url_owner", db_url(st, pki, "deca_owner", pg["owner"])),
        "gateway": st.secret_file("deca_db_url_gateway", db_url(st, pki, "deca_gw", pg["gw"])),
        "broker": st.secret_file("deca_db_url_broker", db_url(st, pki, "deca_brk", pg["brk"])),
        "auditor": st.secret_file("deca_db_url_auditor", db_url(st, pki, "deca_aud", pg["aud"])),
    }
    owner = {**base, "DECA_DB_URL_FILE": str(urls["owner"])}
    deca_cli(st, owner, "migrate", ok=(0,))
    # RUNBOOK step 2: login users that are members of the NOLOGIN group roles the migration created.
    with psycopg.connect(st.run_admin, autocommit=True) as c:
        for user, group, k in (("deca_gw", "deca_soar_gateway", "gw"), ("deca_brk", "deca_soar_broker", "brk"),
                               ("deca_aud", "deca_soar_auditor", "aud")):
            c.execute(f"CREATE ROLE {user} LOGIN PASSWORD '{pg[k]}' IN ROLE {group}")

    vault_priv = X25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
    keys = {
        "deca_tokenization_key": st.secret(secrets.token_hex(32)),
        "deca_vault_private_key": st.secret(vault_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw,
                                                                     NoEncryption()).hex()),
        "deca_vault_public_key": vault_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        "deca_temporal_payload_key": st.secret(secrets.token_hex(32)),
    }
    kf = {k: st.secret_file(k, v) for k, v in keys.items()}
    tok_file = st.sec / "deca_broker_worker_token"
    deca_cli(st, owner, "create-principal", "--name", "temporal-worker", "--kind", "service", "--role", "analyst",
             "--token-file", str(tok_file), ok=(0,))
    st.secret(tok_file.read_text().strip())

    b_cert, b_key = pki.leaf("broker", ca=pki.server_ca, dns=["broker.deca.internal"], ips=[HOST], server=True)
    gw_cert, gw_key = pki.leaf("temporal-gateway", ca=pki.client_ca, server=False)
    wk_cert, wk_key = pki.leaf("temporal-worker", ca=pki.client_ca, server=False)
    temporal = {"DECA_TEMPORAL_ADDRESS": f"{HOST}:{st.ports['temporal']}", "DECA_TEMPORAL_NAMESPACE": NAMESPACE,
                "DECA_TEMPORAL_TLS_SERVER_NAME": TEMPORAL_NAME, "DECA_TEMPORAL_TLS_CA_FILE": str(pki.ca_file("server")),
                "DECA_TEMPORAL_PAYLOAD_KEY_FILE": str(kf["deca_temporal_payload_key"])}
    return {
        "owner": owner,
        "auditor": {**base, "DECA_DB_URL_FILE": str(urls["auditor"])},
        "broker": {**base, "DECA_DB_URL_FILE": str(urls["broker"]),
                   "DECA_VAULT_PRIVATE_KEY_FILE": str(kf["deca_vault_private_key"]), "DECA_ALLOW_TEST_NETS": "1"},
        "broker_tls": (b_cert, b_key),
        "gateway": {**base, **temporal, "DECA_DB_URL_FILE": str(urls["gateway"]),
                    "DECA_TOKENIZATION_KEY_FILE": str(kf["deca_tokenization_key"]),
                    "DECA_VAULT_PUBLIC_KEY_FILE": str(kf["deca_vault_public_key"]),
                    "DECA_TEMPORAL_TLS_CERT_FILE": str(gw_cert), "DECA_TEMPORAL_TLS_KEY_FILE": str(gw_key)},
        "worker": {**base, **temporal, "DECA_TEMPORAL_TLS_CERT_FILE": str(wk_cert),
                   "DECA_TEMPORAL_TLS_KEY_FILE": str(wk_key),
                   "DECA_BROKER_URL": f"https://{HOST}:{st.ports['broker']}",
                   "DECA_BROKER_TOKEN_FILE": str(tok_file), "DECA_BROKER_CA_FILE": str(pki.ca_file("server"))},
        "worker_token_file": tok_file,
        "urls": urls,
    }


def guard_probes(st: Stack, denv: dict, summary: dict) -> None:
    """Review N4/N7: services refuse a DSN with more privilege than they need; apps cannot pick ledger seq."""
    urls = denv["urls"]
    port = free_port()

    def serve(app: str, env: dict) -> subprocess.CompletedProcess:
        return subprocess.run([str(DECA_PY), "-m", "uvicorn", app, "--host", HOST, "--port", str(port)],
                              env=env, cwd=REPO, capture_output=True, text=True, timeout=60)

    def refused(r: subprocess.CompletedProcess) -> bool:
        return r.returncode != 0 and "refusing to start" in (r.stdout + r.stderr)

    out = {
        "broker_with_owner_dsn": refused(serve("deca_soar.broker.app:app",
                                               {**denv["broker"], "DECA_DB_URL_FILE": str(urls["owner"])})),
        "broker_with_gateway_dsn": refused(serve("deca_soar.broker.app:app",
                                                 {**denv["broker"], "DECA_DB_URL_FILE": str(urls["gateway"])})),
        "gateway_with_owner_dsn": refused(serve("deca_soar.gateway.app:app",
                                                {**denv["gateway"], "DECA_DB_URL_FILE": str(urls["owner"])})),
        "gateway_with_broker_dsn": refused(serve("deca_soar.gateway.app:app",
                                                 {**denv["gateway"], "DECA_DB_URL_FILE": str(urls["broker"])})),
    }
    anchors = st.run / "anchors-guard.ndjson"
    r = deca_cli(st, {**denv["auditor"], "DECA_DB_URL_FILE": str(urls["owner"])}, "anchor-ledger", "--sink",
                 f"file:{anchors}", ok=(2,))
    out["anchor_with_owner_dsn"] = r["rc"] == 2 and not anchors.exists()
    summary["db_login_guard"] = out
    summary["checks"]["services_refuse_overprivileged_db_login"] = all(out.values())

    seq = {}
    for who in ("gateway", "broker"):
        with psycopg.connect(Path(urls[who]).read_text().strip(), autocommit=True) as c:
            try:
                c.execute("INSERT INTO ledger.entry (seq, event_type, actor, payload, canonical, prev_hash, hash)"
                          " VALUES (999999, 'x', 'x', '{}', '{}', repeat('0', 64), repeat('f', 64))")
                seq[who] = False
            except psycopg.errors.InsufficientPrivilege:
                seq[who] = True
    summary["checks"]["app_roles_cannot_insert_ledger_seq"] = all(seq.values())


def owner_conn(denv: dict) -> psycopg.Connection:
    return psycopg.connect(Path(denv["owner"]["DECA_DB_URL_FILE"]).read_text().strip(), autocommit=True)


# --------------------------------------------------------------------------------------------- scenario

def scenario(st: Stack, summary: dict) -> int:
    for p, what in ((PG_BIN / "postgres", "postgres"), (TEMPORAL_BIN_DIR / "temporal-server", "temporal-server"),
                    (TEMPORAL_CLI, "temporal CLI")):
        if not p.exists():
            raise RuntimeError(f"{what} not found at {p}")
    pki = PKI(st.run / "pki")
    pg = start_postgres(st, pki)
    st.run_admin = pg["admin_dsn"]
    tenv = temporal_env(st, pki, pg)
    op = start_temporal(st, pki, tenv, summary)
    mtls_probes(st, pki, summary)
    temporal_http_probe(st, summary)
    denv = setup_deca(st, pki, pg)
    P = st.ports

    # The worker refuses to start with database or vault credentials (review F5 / design 6.3).
    r = subprocess.run([str(DECA_PY), "-m", "deca_soar.cli", "worker"], capture_output=True, text=True, timeout=60,
                       env={**denv["worker"], "DECA_DB_URL_FILE": str(denv["urls"]["broker"])})
    summary["checks"]["worker_refuses_db_credentials"] = r.returncode != 0 and "must not hold" in r.stderr
    guard_probes(st, denv, summary)

    b_cert, b_key = denv["broker_tls"]
    st.start("deca-broker", [str(DECA_PY), "-m", "uvicorn", "deca_soar.broker.app:app", "--host", HOST,
                             "--port", str(P["broker"]), "--no-access-log", "--no-server-header",
                             "--ssl-certfile", str(b_cert), "--ssl-keyfile", str(b_key)],
             env=denv["broker"], cwd=REPO)
    ctx = ssl.create_default_context(cafile=str(pki.ca_file("server")))
    wait_for(lambda: st.check_alive() or httpx.get(f"https://{HOST}:{P['broker']}/healthz", verify=ctx,
                                                   timeout=2).status_code == 200, "broker (TLS)")
    try:
        httpx.get(f"http://{HOST}:{P['broker']}/healthz", timeout=3)
        summary["checks"]["broker_refuses_plain_http"] = False
    except httpx.HTTPError:
        summary["checks"]["broker_refuses_plain_http"] = True

    replay = st.run / "replay.ndjson"
    alerts = [
        # validated (shadow): structured src_ip; the URI carries another IP and an email (review F1).
        {"source": "waf", "rule_id": RULES[0], "severity_hint": "high", "detected_at": "2026-11-24T03:00:10Z",
         "src_ip": RAW_IP, "uri": f"/api/v1/login?email={RAW_EMAIL}&next=http://{URI_IP}/", "ua": "sqlmap/1.7",
         "events": 40},
        # rejected: protected address (high severity, so the mock verdict alone would allow it)
        {"source": "waf", "rule_id": RULES[1], "severity_hint": "high", "detected_at": "2026-11-24T03:01:00Z",
         "src_ip": PROTECTED_IP, "uri": "/.env", "ua": "curl/8", "events": 25},
        # rejected: IPv4-mapped IPv6 form of a protected address (review F2)
        {"source": "waf", "rule_id": RULES[2], "severity_hint": "high", "detected_at": "2026-11-24T03:01:30Z",
         "src_ip": MAPPED_PROTECTED, "uri": "/wp-login.php", "ua": "curl/8", "events": 12},
        # no action: not a WAF alert (no WAF block for it)
        {"source": "sas", "rule_id": RULES[3], "severity_hint": "low", "detected_at": "2026-11-24T03:02:00Z",
         "src_ip": "203.0.113.8", "events": 300},
    ]
    replay.write_text("".join(json.dumps(x) + "\n" for x in alerts))
    genv = {**denv["gateway"], "DECA_GATEWAY_SOURCE": "replay", "DECA_REPLAY_FILE": str(replay),
            "DECA_SOURCE_NAME": "e2e", "DECA_PULL_INTERVAL_S": "2"}
    # Gateway first, worker later: alerts must survive the worker not being there yet.
    st.start("deca-gateway", [str(DECA_PY), "-m", "uvicorn", "deca_soar.gateway.app:app", "--host", HOST,
                              "--port", str(P["gateway"]), "--no-access-log"], env=genv, cwd=REPO)

    def forwarded():
        st.check_alive()
        with owner_conn(denv) as c:
            rows = dict(c.execute("SELECT status, count(*) FROM gateway.inbox_event GROUP BY 1").fetchall())
        return rows if rows.get("forwarded") == len(alerts) else None
    summary["inbox_before_worker"] = wait_for(forwarded, "gateway started all workflows", timeout=120, interval=2)
    with owner_conn(denv) as c:
        ids = [r[0] for r in c.execute("SELECT alert_id::text FROM gateway.inbox_event ORDER BY detected_at")]
        summary["checks"]["no_broker_request_before_worker"] = \
            c.execute("SELECT count(*) FROM broker.action_request").fetchone()[0] == 0
    running = [json.loads(temporal_cli(op, "workflow", "describe", "-w", f"alert-{i}", "-n", NAMESPACE,
                                       "-o", "json").stdout or "{}") for i in ids]
    states = [x.get("workflowExecutionInfo", {}).get("status") for x in running]
    summary["workflows_before_worker"] = states
    summary["checks"]["workflows_wait_while_worker_down"] = states == ["WORKFLOW_EXECUTION_STATUS_RUNNING"] * len(ids)

    time.sleep(3)
    st.start("deca-worker", [str(DECA_PY), "-m", "deca_soar.cli", "worker"], env=denv["worker"], cwd=REPO)

    def completed():
        st.check_alive()
        out = [json.loads(temporal_cli(op, "workflow", "describe", "-w", f"alert-{i}", "-n", NAMESPACE,
                                       "-o", "json").stdout or "{}") for i in ids]
        s = [x.get("workflowExecutionInfo", {}).get("status") for x in out]
        return s if all(v and v != "WORKFLOW_EXECUTION_STATUS_RUNNING" for v in s) else None
    states = wait_for(completed, "workflows completed", timeout=180, interval=2)
    summary["workflows_after_worker"] = states
    summary["checks"]["all_workflows_completed"] = states == ["WORKFLOW_EXECUTION_STATUS_COMPLETED"] * len(ids)

    with owner_conn(denv) as c:
        reqs = c.execute(
            "SELECT e.rule_id, r.action, r.status, r.mode, r.reasons::text, p.name"
            " FROM broker.action_request r JOIN broker.principal p ON p.principal_id = r.requested_by"
            " JOIN gateway.inbox_event e ON e.alert_id = r.alert_id ORDER BY e.detected_at").fetchall()
        decisions = c.execute("SELECT count(*) FROM broker.decision_record").fetchone()[0]
        kinds = dict(c.execute("SELECT event_type, count(*) FROM ledger.entry GROUP BY 1 ORDER BY 1").fetchall())
    by_rule = {r[0]: dict(zip(("action", "status", "mode", "reasons", "requested_by"), r[1:])) for r in reqs}
    summary["flow"] = {"action_requests": by_rule, "decision_records": decisions, "ledger_events": kinds}
    ok_req = by_rule.get(RULES[0], {})
    summary["checks"]["alert_flowed_to_broker_validated_shadow"] = (
        ok_req.get("status") == "validated" and ok_req.get("mode") == "shadow"
        and ok_req.get("requested_by") == "temporal-worker")
    summary["checks"]["protected_target_rejected"] = by_rule.get(RULES[1], {}).get("status") == "rejected" \
        and "protected" in (by_rule.get(RULES[1], {}).get("reasons") or "")
    summary["checks"]["f2_mapped_ipv6_protected_rejected"] = by_rule.get(RULES[2], {}).get("status") == "rejected" \
        and "protected" in (by_rule.get(RULES[2], {}).get("reasons") or "")
    summary["checks"]["non_waf_alert_no_action"] = RULES[3] not in by_rule
    summary["checks"]["decision_records_written"] = decisions >= 3

    f1_probe(st, denv, ids[0], summary, ctx)
    history_checks(st, pki, op, ids, summary)
    temporal_db_scan(st, summary)
    ledger_and_f3(st, denv, summary)
    return 0


def f1_probe(st: Stack, denv: dict, alert_id: str, summary: dict, ctx) -> None:
    """Ask the broker (as the worker principal) to block the IP that only appears in the URI: must be refused."""
    with owner_conn(denv) as c:
        alert, evidence = c.execute("SELECT alert, evidence_tokens FROM gateway.inbox_event WHERE alert_id = %s",
                                    (alert_id,)).fetchone()
    uri = alert["untrusted_fields"]["uri"] or ""
    uri_tokens = sorted({t for t in uri.replace("/", " ").replace("=", " ").replace("&", " ").split()
                         if t.startswith("tok_ip_")} - set(evidence))
    summary["f1"] = {"uri_ip_tokens": len(uri_tokens), "uri_has_raw_ip": URI_IP in uri,
                     "uri_has_raw_email": RAW_EMAIL in uri}
    if not uri_tokens:
        summary["checks"]["f1_uri_ip_not_blockable"] = False
        return
    token = denv["worker_token_file"].read_text().strip()
    body = {"alert_id": alert_id, "action": "waf.ip_blacklist.add",
            "params": {"ip_token": uri_tokens[0], "waf_instance": "waf-jkt-01"},
            "decision": {"verdict": "malicious", "confidence": 0.99, "source": "llm",
                         "rationale_summary": "e2e F1 probe", "evidence_refs": [uri_tokens[0]]},
            "idempotency_key": f"e2e-f1-{alert_id}"}
    r = httpx.post(f"https://{HOST}:{st.ports['broker']}/v1/actions/requests", json=body, verify=ctx, timeout=10,
                   headers={"Authorization": f"Bearer {token}"})
    data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    summary["f1"]["broker_status"] = r.status_code
    summary["f1"]["request_status"] = data.get("status")
    summary["f1"]["reasons"] = data.get("reasons")
    summary["checks"]["f1_uri_ip_not_blockable"] = (
        not summary["f1"]["uri_has_raw_ip"] and not summary["f1"]["uri_has_raw_email"]
        and data.get("status") == "rejected" and "target not in alert evidence" in (data.get("reasons") or []))


def history_checks(st: Stack, pki: PKI, op: dict, ids: list[str], summary: dict) -> None:
    """An operator with a valid cert but no payload key sees only ciphertext in workflow history."""
    from temporalio.client import Client
    from temporalio.service import TLSConfig

    tls = TLSConfig(server_root_ca_cert=pki.ca_file("server").read_bytes(), domain=TEMPORAL_NAME,
                    client_cert=Path(op["TEMPORAL_TLS_CERT"]).read_bytes(),
                    client_private_key=Path(op["TEMPORAL_TLS_KEY"]).read_bytes())

    async def fetch():
        c = await Client.connect(op["TEMPORAL_ADDRESS"], namespace=NAMESPACE, tls=tls)
        out = []
        for i in ids:
            h = await c.get_workflow_handle(f"alert-{i}").fetch_history()
            out.append(h)
        return out

    histories = asyncio.run(fetch())
    encodings: dict[str, int] = {}
    text = ""
    for h in histories:
        text += h.to_json()
        for ev in h.events:
            for p in _payloads(ev):
                enc = p.metadata.get("encoding", b"").decode(errors="replace")
                encodings[enc] = encodings.get(enc, 0) + 1
    needles = (RAW_IP, URI_IP, PROTECTED_IP, RAW_EMAIL, "tok_ip_", *RULES, "mock-phase0", "Bearer")
    hits = {n: text.count(n) for n in needles if n in text}
    control = text.count("AlertShadowWorkflow")  # positive control: the scan does see history text
    summary["history"] = {"workflows": len(histories), "payload_encodings": encodings, "plaintext_hits": hits,
                          "control_workflow_type_mentions": control}
    summary["checks"]["history_payloads_encrypted"] = bool(encodings) and set(encodings) == {"binary/encrypted"} \
        and not hits and control > 0


def _payloads(msg):
    """Every temporal.api.common.v1.Payload inside a protobuf message."""
    from google.protobuf.message import Message
    from temporalio.api.common.v1 import Payload

    if isinstance(msg, Payload):
        yield msg
        return
    for fd, value in msg.ListFields():
        if fd.message_type is None:
            continue
        if fd.message_type.GetOptions().map_entry:
            values = list(value.values())
        elif isinstance(value, Message):
            values = [value]
        else:
            values = list(value)
        for v in values:
            if isinstance(v, Message):
                yield from _payloads(v)


def temporal_db_scan(st: Stack, summary: dict) -> None:
    """Every row of both Temporal databases, bytea included: no raw PII, no tokens, no decision content."""
    needles = [s.encode() for s in (RAW_IP, URI_IP, PROTECTED_IP, RAW_EMAIL, "tok_ip_", *RULES, "mock-phase0")]
    found: dict[str, int] = {}
    scanned = control = 0
    for dbname in ("temporal", "temporal_visibility"):
        dsn = st.run_admin.replace("dbname=postgres", f"dbname={dbname}")
        with psycopg.connect(dsn) as c:
            tables = c.execute(
                "SELECT table_schema, table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE'"
                " AND table_schema NOT IN ('pg_catalog', 'information_schema')").fetchall()
            for schema, name in tables:
                cur = c.execute(psycopg.sql.SQL("SELECT * FROM {}.{}").format(
                    psycopg.sql.Identifier(schema), psycopg.sql.Identifier(name)))
                for row in cur:
                    for v in row:
                        b = bytes(v) if isinstance(v, (bytes, memoryview)) else str(v).encode()
                        scanned += len(b)
                        control += b.count(b"AlertShadowWorkflow")  # positive control
                        for n in needles:
                            if n in b:
                                found[n.decode()] = found.get(n.decode(), 0) + 1
    summary["temporal_db"] = {"scanned_bytes": scanned, "hits": found, "control_workflow_type_mentions": control}
    summary["checks"]["temporal_db_has_no_plaintext_alert_data"] = control > 0 and not found


def ledger_and_f3(st: Stack, denv: dict, summary: dict) -> None:
    v = deca_cli(st, denv["auditor"], "verify-ledger")
    summary["ledger_verify"] = {k: v.get(k) for k in ("ok", "entries", "head_seq", "errors")}
    summary["checks"]["ledger_chain_ok"] = v.get("ok") is True and (v.get("entries") or 0) > 0

    # F3: application roles cannot tamper with the ledger.
    f3: dict[str, dict] = {}
    for who in ("gateway", "broker", "auditor"):
        url = Path(denv["urls"][who]).read_text().strip()
        res = {}
        with psycopg.connect(url, autocommit=True) as c:
            for sql in TAMPER:
                try:
                    c.execute(sql)
                    res[sql] = "ALLOWED"
                except (psycopg.errors.InsufficientPrivilege, psycopg.errors.RaiseException) as e:
                    res[sql] = type(e).__name__
        f3[who] = res
    summary["f3_tamper"] = f3
    summary["checks"]["f3_app_roles_cannot_tamper_ledger"] = all(
        x != "ALLOWED" for r in f3.values() for x in r.values())
    with psycopg.connect(Path(denv["urls"]["gateway"]).read_text().strip(), autocommit=True) as c:
        try:
            c.execute("SELECT ciphertext FROM vault.token_map")
            summary["checks"]["f5_gateway_cannot_read_vault_ciphertext"] = False
        except psycopg.errors.InsufficientPrivilege:
            summary["checks"]["f5_gateway_cannot_read_vault_ciphertext"] = True

    # F3: the daily anchor (auditor role) and detection of a rewrite with the owner credential.
    anchors = st.run / "anchors" / "ledger-anchors.ndjson"
    anchors.parent.mkdir(mode=0o700)
    a1 = deca_cli(st, denv["auditor"], "anchor-ledger", "--sink", f"file:{anchors}")
    summary["checks"]["f3_anchor_written_by_auditor"] = a1["rc"] == 0 and anchors.exists() \
        and anchors.stat().st_mode & 0o777 == 0o600
    with owner_conn(denv) as c, c.transaction():
        c.execute("ALTER TABLE ledger.entry DISABLE TRIGGER USER")
        c.execute("DELETE FROM ledger.entry WHERE seq = (SELECT min(seq) FROM ledger.entry)")
        from deca_soar import ledger as L  # noqa: PLC0415 - only this owner-rewrite step needs it
        prev = L.GENESIS
        for seq, canonical in c.execute("SELECT seq, canonical FROM ledger.entry ORDER BY seq").fetchall():
            h = L.chain_hash(prev, canonical)
            c.execute("UPDATE ledger.entry SET prev_hash = %s, hash = %s WHERE seq = %s", (prev, h, seq))
            prev = h
        c.execute("ALTER TABLE ledger.entry ENABLE TRIGGER USER")
    chain_only = deca_cli(st, denv["auditor"], "verify-ledger")
    with_anchor = deca_cli(st, denv["auditor"], "verify-ledger", "--anchors", f"file:{anchors}")
    summary["f3_owner_rewrite"] = {"chain_only_ok": chain_only.get("ok"), "with_anchors_ok": with_anchor.get("ok"),
                                   "errors": with_anchor.get("errors")}
    summary["checks"]["f3_anchor_detects_owner_rewrite"] = with_anchor["rc"] == 1 and with_anchor.get("ok") is False


if __name__ == "__main__":
    sys.exit(main())
