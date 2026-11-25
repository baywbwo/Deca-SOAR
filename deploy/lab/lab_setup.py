#!/usr/bin/env python3
"""Lab only: create the PKI, keys, DB logins and deca.env for one HyperSoar lab host.

Runs once, as root inside the deca-soar image (it needs `cryptography`), with /etc/deca-soar and
/var/lib/deca-soar bind-mounted. Reads one JSON object on stdin, generated on the operator's machine:

  {"owner_password": "...", "console_hash": "scrypt$..."}

so the owner DSN and the console password never exist on the lab host (only the scrypt hash does).
Every other value is generated here and written to a file; nothing secret is printed. Refuses to run
if /etc/deca-soar already holds secrets. See deploy/lab/README.md.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import secrets
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(os.environ.get("HYPERSOAR_LAB_ROOT", "/etc/deca-soar"))
DATA = Path(os.environ.get("HYPERSOAR_LAB_DATA", "/var/lib/deca-soar"))
SUBNET = ipaddress.ip_network(os.environ.get("HYPERSOAR_LAB_SUBNET", "172.30.124.0/24"))
APP_UID = 10001       # deca-soar image
TEMPORAL_UID = 10002  # deploy/lab/temporal.Dockerfile
PG_UID = 70           # postgres:*-alpine
VALID_DAYS = 90

SEC, TLS, LAB = ROOT / "secrets", ROOT / "tls", ROOT / "lab"


def ip(n: int) -> str:
    return str(SUBNET.network_address + n)


def write(path: Path, data: str | bytes, mode: int, uid: int = 0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data.encode() if isinstance(data, str) else data)
    os.chown(path, uid, uid)
    os.chmod(path, mode)


def pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def ca(name: str):
    key = ec.generate_private_key(ec.SECP256R1())
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


def leaf(name: str, issuer, *, dns: list[str] = (), server: bool):
    ca_cert, ca_key = issuer
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    usages = [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH] if server \
        else [ExtendedKeyUsageOID.CLIENT_AUTH]
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
         .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=VALID_DAYS))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.ExtendedKeyUsage(usages), critical=False))
    if dns:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in dns]), critical=False)
    return b.sign(ca_key, hashes.SHA256()), key


def pw() -> str:
    return secrets.token_urlsafe(32)


def dsn(user: str, password: str) -> str:
    return (f"postgresql://{user}:{password}@postgres:5432/deca_soar"
            "?sslmode=verify-full&sslrootcert=/run/secrets/deca_db_ca\n")


def main() -> int:
    if os.geteuid() != 0:
        print("run as root (it chowns files to the container uids)", file=sys.stderr)
        return 2
    if SEC.exists() and any(SEC.iterdir()):
        print(f"{SEC} is not empty: refusing to overwrite an existing lab", file=sys.stderr)
        return 2
    given = json.loads(sys.stdin.read())
    owner_pw, console_hash = given["owner_password"], given["console_hash"]
    if len(owner_pw) < 24 or not console_hash.startswith("scrypt$"):
        print("stdin must carry a long owner_password and an scrypt console_hash", file=sys.stderr)
        return 2

    for d, mode, uid in ((ROOT, 0o755, 0), (SEC, 0o755, 0), (TLS, 0o755, 0), (LAB, 0o700, 0),
                         (ROOT / "out", 0o700, APP_UID), (DATA / "replay", 0o755, APP_UID),
                         (DATA / "anchors", 0o755, APP_UID)):
        d.mkdir(parents=True, exist_ok=True)
        os.chown(d, uid, uid)
        os.chmod(d, mode)

    # One server CA (Postgres, Temporal, broker, console) and the DECA client CA (Temporal mTLS clients).
    server_ca, client_ca = ca("deca-lab-server-ca"), ca("deca-lab-client-ca")
    write(LAB / "ca/server-ca.key", key_pem(server_ca[1]), 0o400)
    write(LAB / "ca/client-ca.key", key_pem(client_ca[1]), 0o400)
    for name in ("server-ca.pem", "broker-ca.pem", "temporal-server-ca.pem", "db-ca.pem", "console-ca.pem"):
        write(TLS / name, pem(server_ca[0]), 0o444)

    def app_leaf(stem: str, cn: str, dns: list[str], server: bool, issuer) -> None:
        cert, key = leaf(cn, issuer, dns=dns, server=server)
        write(TLS / f"{stem}.pem", pem(cert), 0o444)
        write(SEC / f"{stem}.key", key_pem(key), 0o400, APP_UID)

    app_leaf("broker", "broker", ["broker", "broker.deca.internal"], True, server_ca)
    app_leaf("console", "console", ["console", "console.deca.internal"], True, server_ca)
    app_leaf("temporal-gateway", "temporal-gateway", [], False, client_ca)
    app_leaf("temporal-worker", "temporal-worker", [], False, client_ca)

    # Postgres (stand-in for RDS): TLS with SAN "postgres", hostssl + scram only, superuser via local peer.
    pg_cert, pg_key = leaf("postgres", server_ca, dns=["postgres"], server=True)
    write(LAB / "postgres/server.pem", pem(pg_cert), 0o444)
    write(LAB / "postgres/server.key", key_pem(pg_key), 0o400, PG_UID)
    write(LAB / "postgres/superuser_password", pw() + "\n", 0o400, PG_UID)
    write(LAB / "postgres/pg_hba.conf",
          "local all postgres peer\n"
          f"hostssl all all {SUBNET} scram-sha-256\n", 0o444)

    # Temporal server: frontend/internode cert, system worker + operator client certs.
    tdir = LAB / "temporal"
    t_cert, t_key = leaf("temporal-server", server_ca, dns=["temporal.deca.internal"], server=True)
    sw_cert, sw_key = leaf("temporal-system-worker", client_ca, server=False)
    op_cert, op_key = leaf("operator", client_ca, server=False)
    for stem, cert, key in (("server", t_cert, t_key), ("system-worker", sw_cert, sw_key),
                            ("operator", op_cert, op_key)):
        write(tdir / f"{stem}.pem", pem(cert), 0o444)
        write(tdir / f"{stem}.key", key_pem(key), 0o400, TEMPORAL_UID)
    write(tdir / "server-ca.pem", pem(server_ca[0]), 0o444)
    write(tdir / "client-ca.pem", pem(client_ca[0]), 0o444)
    temporal_pw = pw()
    write(tdir / "db_password", temporal_pw + "\n", 0o400, TEMPORAL_UID)
    os.chown(tdir, TEMPORAL_UID, TEMPORAL_UID)
    os.chmod(tdir, 0o500)

    # Application keys (same set as scripts/gen_secrets.py).
    from hypersoar.broker.integrations.secretbox import derive

    vault = X25519PrivateKey.generate()
    integration_master = secrets.token_hex(32)
    keys = {
        "deca_tokenization_key": secrets.token_hex(32),
        "deca_vault_public_key": vault.public_key().public_bytes(serialization.Encoding.Raw,
                                                                 serialization.PublicFormat.Raw).hex(),
        "deca_vault_private_key": vault.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                      serialization.NoEncryption()).hex(),
        "deca_temporal_payload_key": secrets.token_hex(32),
        "deca_integration_key": integration_master,
        "deca_source_key": derive(bytes.fromhex(integration_master), "source").hex(),
    }
    for name, value in keys.items():
        write(SEC / name, value + "\n", 0o400, APP_UID)

    # One login per service, each a member of the NOLOGIN group role the migrations create.
    logins = {"deca_gw": ("deca_soar_gateway", "gateway"), "deca_brk": ("deca_soar_broker", "broker"),
              "deca_aud": ("deca_soar_auditor", "auditor"), "deca_con": ("deca_soar_viewer", "console")}
    login_sql = []
    for user, (group, svc) in logins.items():
        p = pw()
        write(SEC / f"deca_db_url_{svc}", dsn(user, p), 0o400, APP_UID)
        login_sql.append(f"CREATE ROLE {user} LOGIN PASSWORD '{p}' IN ROLE {group};\n")
    write(LAB / "db-logins.sql", "".join(login_sql), 0o400)
    write(LAB / "db-bootstrap.sql",
          f"CREATE ROLE temporal LOGIN PASSWORD '{temporal_pw}';\n"
          "CREATE DATABASE temporal OWNER temporal;\n"
          "CREATE DATABASE temporal_visibility OWNER temporal;\n"
          f"CREATE ROLE deca_owner LOGIN CREATEROLE PASSWORD '{owner_pw}';\n"
          "CREATE DATABASE deca_soar OWNER deca_owner;\n", 0o400)

    write(SEC / "console_password_hash", console_hash.strip() + "\n", 0o400, APP_UID)
    print(f"lab PKI, keys and DB login files written under {ROOT} (values not shown)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
