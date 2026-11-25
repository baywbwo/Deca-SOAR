"""Preflight gates added for the second security review (N1, N2, N3)."""

import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "python:3.12-slim-bookworm@sha256:" + "ab" * 32


@pytest.fixture
def pf():
    spec = importlib.util.spec_from_file_location("preflight", ROOT / "scripts/preflight.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _status(pf, fragment: str) -> list[str]:
    return [s for s, msg in pf.results if fragment in msg]


def _env(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "deca.env"
    p.write_text(text)
    p.chmod(0o600)
    return p


# N3: base image digest ----------------------------------------------------------------------------

def _dockerfile(tmp_path: Path, value: str) -> Path:
    p = tmp_path / "Dockerfile"
    p.write_text(f"ARG BASE_IMAGE={value}\nFROM ${{BASE_IMAGE}}\n")
    return p


PLACEHOLDER = "python:3.12-slim-bookworm@sha256:REPLACE_WITH_PINNED_DIGEST"


def test_n3_placeholder_digest_fails_in_production(pf, tmp_path):
    pf.base_image(True, None, _dockerfile(tmp_path, PLACEHOLDER))
    assert _status(pf, "HYPERSOAR_BASE_IMAGE pinned") == ["FAIL"]


def test_n3_placeholder_digest_only_warns_outside_production(pf, tmp_path):
    pf.base_image(False, None, _dockerfile(tmp_path, PLACEHOLDER))
    assert _status(pf, "HYPERSOAR_BASE_IMAGE pinned") == ["WARN"]


def test_n3_repo_dockerfile_default_is_pinned(pf):
    pf.base_image(True, None)
    assert _status(pf, "HYPERSOAR_BASE_IMAGE pinned") == ["PASS"]


@pytest.mark.parametrize("value,expect", [
    (DIGEST, "PASS"),
    (PLACEHOLDER, "FAIL"),
    ("python:3.12-slim-bookworm", "FAIL"),
    ("python:3.12-slim-bookworm@sha256:" + "AB" * 32, "FAIL"),
    ("python:3.12-slim-bookworm@sha256:" + "ab" * 31, "FAIL"),
])
def test_n3_digest_from_production_env(pf, tmp_path, value, expect):
    pf.base_image(True, _env(tmp_path, f"HYPERSOAR_BASE_IMAGE={value}\n"))
    assert _status(pf, "HYPERSOAR_BASE_IMAGE pinned") == [expect]


def test_n3_production_flag_is_implied_by_env(pf, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["preflight", "--env", str(_env(tmp_path, f"HYPERSOAR_BIND_IP=10.0.0.9\nHYPERSOAR_BASE_IMAGE={PLACEHOLDER}\n"))])
    assert pf.main() == 1
    assert "FAIL  image: HYPERSOAR_BASE_IMAGE pinned by sha256 digest" in capsys.readouterr().out


# N3: hash locks -----------------------------------------------------------------------------------

def test_n3_repo_locks_pass(pf):
    pf.static_locks()
    assert [s for s, m in pf.results if s != "PASS"] == [], pf.results


def _copy_locks(tmp_path: Path) -> Path:
    d = tmp_path / "req"
    shutil.copytree(ROOT / "deploy/deca/requirements", d)
    return d


def test_n3_range_pin_fails(pf, tmp_path):
    d = _copy_locks(tmp_path)
    (d / "runtime.lock").write_text((d / "runtime.lock").read_text().replace("fastapi==0.", "fastapi>=0.", 1))
    pf.static_locks(d)
    assert _status(pf, "runtime.lock: every package pinned") == ["FAIL"]


def test_n3_missing_hash_fails(pf, tmp_path):
    d = _copy_locks(tmp_path)
    (d / "build.lock").write_text("hatchling==1.33.0\n")
    pf.static_locks(d)
    assert _status(pf, "build.lock: every package pinned") == ["FAIL"]


def test_n3_dependency_missing_from_lock_fails(pf, tmp_path):
    d = _copy_locks(tmp_path)
    py = tmp_path / "pyproject.toml"
    py.write_text((ROOT / "pyproject.toml").read_text().replace('"httpx>=0.27,<1",', '"httpx>=0.27,<1", "requests>=2",'))
    pf.static_locks(d, pyproject=py)
    assert _status(pf, "covers every pyproject dependency") == ["FAIL"]


def test_n3_unlocked_pip_install_in_dockerfile_fails(pf, tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text((ROOT / "deploy/deca/Dockerfile").read_text() + "RUN pip install requests\n")
    pf.static_locks(dockerfile=df)
    assert _status(pf, "only via install-locked.sh") == ["FAIL"]


# N2: owner DSN and off-host anchors --------------------------------------------------------------

def test_n2_repo_owner_dsn_and_anchor_shipping_pass(pf):
    pf.static_owner_dsn()
    pf.static_anchor_shipping()
    bad = [(s, m) for s, m in pf.results if s != "PASS"]
    assert bad == [("WARN", "logtail: config not yet applied or tested against SLS (mock shipper in e2e only)")]


def test_n2_owner_secret_back_in_main_compose_fails(pf, tmp_path):
    c = tmp_path / "compose.yml"
    c.write_text((ROOT / "deploy/deca/docker-compose.yml").read_text()
                 + "  deca_db_url_owner: {file: /etc/deca-soar/secrets/deca_db_url_owner}\n")
    pf.static_owner_dsn(compose=c)
    assert _status(pf, "never references the owner DSN") == ["FAIL"]


def test_n2_owner_compose_with_fixed_secret_path_fails(pf, tmp_path):
    c = tmp_path / "owner.yml"
    text = (ROOT / "deploy/deca/docker-compose.owner.yml").read_text()
    c.write_text(text.split("\nsecrets:\n")[0] + '\nsecrets:\n  deca_db_url_owner: {file: /etc/deca-soar/secrets/deca_db_url_owner}\n')
    pf.static_owner_dsn(owner_compose=c)
    assert _status(pf, "per-run temp file only") == ["FAIL"]


def test_n2_daily_timer_fails(pf, tmp_path):
    t = tmp_path / "t.timer"
    t.write_text("[Timer]\nOnCalendar=*-*-* 00:15:00 Asia/Jakarta\n")
    pf.static_anchor_shipping(timer=t)
    assert _status(pf, "anchor timer: hourly") == ["FAIL"]


def _secrets(tmp_path: Path, owner: bool) -> Path:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

    d = tmp_path / "secrets"
    d.mkdir()
    k = X25519PrivateKey.generate()
    files = {
        "deca_tokenization_key": "11" * 32, "deca_temporal_payload_key": "22" * 32, "deca_integration_key": "33" * 32,
        "deca_vault_private_key": k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
        "deca_vault_public_key": k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
    }
    for name, user in (("gateway", "gw"), ("broker", "brk"), ("auditor", "aud")) + ((("owner", "own"),) if owner else ()):
        files[f"deca_db_url_{name}"] = f"postgresql://{user}:pw@db/deca?sslmode=verify-full"
    for name, value in files.items():
        (d / name).write_text(value + "\n")
        (d / name).chmod(0o600)
    return d


@pytest.mark.parametrize("owner,expect", [(False, "PASS"), (True, "FAIL")])
def test_n2_stored_owner_dsn_fails(pf, tmp_path, owner, expect):
    pf.secrets_dir(_secrets(tmp_path, owner))
    assert _status(pf, "no owner DSN stored on the host") == [expect]
    assert [s for s, m in pf.results if s != "PASS" and "owner DSN" not in m] == []


# N1: Temporal client-CA compensating controls ----------------------------------------------------

def _pki(root: Path, *, days: int = 90, client_ca_is_server_ca: bool = False, foreign_worker: bool = False,
         server_eku: bool = False, ca_key_on_host: bool = False) -> Path:
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = dt.datetime.now(dt.timezone.utc)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def ca(cn):
        k = ec.generate_private_key(ec.SECP256R1())
        c = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(cn)).public_key(k.public_key())
             .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
             .not_valid_after(now + dt.timedelta(days=3650))
             .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(k, hashes.SHA256()))
        return c, k

    def leaf(cn, issuer, eku=ExtendedKeyUsageOID.CLIENT_AUTH):
        c, k = issuer
        lk = ec.generate_private_key(ec.SECP256R1())
        return (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(c.subject).public_key(lk.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
                .not_valid_after(now - dt.timedelta(days=1) + dt.timedelta(days=days))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([eku]), critical=False).sign(k, hashes.SHA256()))

    def write(rel, cert):
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    server, broker, other = ca("server-ca"), ca("broker-ca"), ca("other-ca")
    client = server if client_ca_is_server_ca else ca("temporal-client-ca")
    write("temporal/tls/client-ca.pem", client[0])
    write("temporal/tls/server-ca.pem", server[0])
    write("tls/broker-ca.pem", broker[0])
    write("tls/temporal-gateway.pem", leaf("gateway", client))
    write("tls/temporal-worker.pem", leaf("worker", other if foreign_worker else client))
    write("temporal/tls/system-worker.pem",
          leaf("system-worker", client, ExtendedKeyUsageOID.SERVER_AUTH if server_eku else ExtendedKeyUsageOID.CLIENT_AUTH))
    write("bastion/operator.pem", leaf("operator", client))
    if ca_key_on_host:
        (root / "secrets").mkdir(exist_ok=True)
        (root / "secrets/client-ca.key").write_bytes(client[1].private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return root


def _fails(pf) -> list[str]:
    return [m for s, m in pf.results if s == "FAIL"]


def test_n1_good_pki_passes(pf, tmp_path):
    root = _pki(tmp_path)
    pf.pki(root, root / "bastion/operator.pem")
    assert _fails(pf) == []
    warn = [m for s, m in pf.results if s == "WARN"]
    assert len(warn) == 1 and "issuance register" in warn[0] and warn[0].count("serial") == 4


@pytest.mark.parametrize("kw,expect", [
    ({"days": 91}, "temporal-gateway.pem validity <= 90 days"),
    ({"client_ca_is_server_ca": True}, "client CA is dedicated (not temporal/tls/server-ca.pem)"),
    ({"foreign_worker": True}, "temporal-worker.pem issued by the Temporal client CA"),
    ({"server_eku": True}, "system-worker.pem is a clientAuth leaf"),
    ({"ca_key_on_host": True}, "client CA private key is not on this host"),
])
def test_n1_pki_violations_fail(pf, tmp_path, kw, expect):
    root = _pki(tmp_path, **kw)
    pf.pki(root, root / "bastion/operator.pem")
    assert any(expect in m for m in _fails(pf)), _fails(pf)


def test_n1_expired_cert_fails(pf, tmp_path):
    import datetime as dt

    root = _pki(tmp_path)
    pf.pki(root, now=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=95))
    assert any("currently valid" in m for m in _fails(pf))


# Production database gate (--db-url-file) ---------------------------------------------------------

def _prod_settings():
    ladder = [{"role": r, "timeout_min": t, "approvers": [{"name": n, "lark_user_id": f"ou_{n.lower()}"}]}
              for r, t, n in (("On-call analyst", 5, "Oncall"), ("SOC lead", 10, "Lead"), ("Head of IT", 15, "Head"))]
    route = {"chat_id": "oc_socdob", "chat_name": "SOC DOB", "oncall_dm": False, "delivery": "now"}
    return {
        "lark": {"app_id": "cli_dobprod0001", "routing": {k: route for k in ("critical", "high", "medium", "low")},
                 "ladder": ladder},
        "jira": {"site": "https://dob-test.atlassian.net", "email": "soar-bot@dob.example", "project": "SEC",
                 "issue_type": "Security Incident", "title_template": "[{severity}] {case_id} {case_title}",
                 "priority_map": {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"},
                 "sync": {"comment_on_update": True, "done_on_close": True, "close_case_on_done": False}},
        "ai": {"base_url": "https://router.dob-test.example.net/v1", "triage_model": "deca-triage-v2",
               "fallback_model": "deca-lite", "timeout_s": 20, "daily_token_limit": 2000000},
    }


def _live_stub(req):
    import json as _json

    import httpx
    p = req.url.path
    if p.endswith("/tenant_access_token/internal"):
        return httpx.Response(200, json={"code": 0, "tenant_access_token": "t-dummy", "expire": 7200})
    if p.endswith("/issuetypes"):
        return httpx.Response(200, json={"issueTypes": [{"name": "Security Incident"}]})
    if p.endswith("/priority"):
        return httpx.Response(200, json=[{"name": n} for n in ("Highest", "High", "Medium", "Low")])
    if p.startswith("/rest/api/3/"):
        return httpx.Response(200, json={})
    if p.endswith("/chat/completions"):
        answer = {"verdict": "suspicious", "confidence": 0.7, "rationale_summary": "probe", "evidence_refs": []}
        return httpx.Response(200, json={"choices": [{"message": {"content": _json.dumps(answer)}}],
                                         "usage": {"prompt_tokens": 10, "completion_tokens": 5}})
    return httpx.Response(404)


@pytest.fixture
def prod_db(pg_server):
    """A fresh, empty database installed for production (no synthetic data, nothing seeded)."""
    import uuid

    import psycopg
    from conftest import _with_db
    from hypersoar.common.db import migrate
    name = "p_" + uuid.uuid4().hex[:12]
    with psycopg.connect(pg_server, autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}"')
    url = _with_db(pg_server, name)
    migrate(url, mode="production", entity_id="dob")
    yield url
    with psycopg.connect(pg_server, autocommit=True) as c:
        c.execute(f'DROP DATABASE "{name}" WITH (FORCE)')


def _fails(pf):
    return [m for s, m in pf.results if s == "FAIL"]


def test_db_gate_fails_on_the_sandbox_database(pf, db_url, conn):
    from hypersoar.broker.integrations import config as int_config
    from hypersoar.common import entity as entity_mod
    with conn.transaction():
        int_config.seed(conn, entity_mod.load(ROOT / "entities/dob.yaml", mode="sandbox"))
        conn.execute("INSERT INTO gateway.alert_case (entity_id, case_id, case_no, title, category, max_severity,"
                     " criticality, priority, primary_kind, primary_value, synthetic, opened_at, last_seen_at)"
                     " VALUES ('dob', 'CS-1001', 1001, 't', 'c', 'high', 3, 12, 'ip', 'tok', true, now(), now())")
    pf.database(db_url)
    fails = _fails(pf)
    assert "db: install mode is production (found sandbox)" in fails
    assert "db: no synthetic cases or alerts (1 found)" in fails
    for name in ("lark", "jira", "ai"):
        assert f"db: {name} configured for production" in fails


def test_db_gate_fails_on_mock_placeholder_untested(pf, prod_db):
    import psycopg
    from psycopg.rows import dict_row
    with psycopg.connect(prod_db, row_factory=dict_row) as c, c.transaction():
        for name, s in _prod_settings().items():
            # written directly: the broker's own validation refuses mock in production
            c.execute("INSERT INTO broker.integration_config (entity_id, integration, mode, target, settings,"
                      " updated_by) VALUES ('dob', %s, 'production', 'mock', %s, 'test')",
                      (name, psycopg.types.json.Jsonb({**s, "note": "REPLACE"} if name == "ai" else s)))
    pf.database(prod_db)
    fails = _fails(pf)
    assert "db: lark target is live (found mock)" in fails
    assert any(m.startswith("db: ai settings have no placeholder") for m in fails)
    assert "db: jira required secrets set (api_token missing)" in fails
    assert "db: lark latest connection test passed for settings v1" in fails


def test_db_gate_passes_on_empty_production_db_with_dummy_secrets(pf, prod_db, monkeypatch):
    """Live endpoints are stubbed (httpx MockTransport): this proves the gate, not real connectivity."""
    import httpx
    import psycopg
    from psycopg.rows import dict_row
    from hypersoar.broker.integrations import config as int_config
    from hypersoar.broker.integrations import secretbox
    from hypersoar.broker.integrations.hub import Hub
    from hypersoar.common import entity as entity_mod
    monkeypatch.setenv("HYPERSOAR_MODE", "production")
    monkeypatch.setenv("HYPERSOAR_AI_HOSTS", "router.dob-test.example.net")
    box = secretbox.SecretBox.from_master(b"\x11" * 32)
    connect = lambda: psycopg.connect(prod_db, row_factory=dict_row)  # noqa: E731
    with connect() as c, c.transaction():
        for name, s in _prod_settings().items():
            int_config.save(c, "dob", name, "production", "live", True, s, "test")
            for sec in pf.INTEGRATION_SECRETS[name]:
                secretbox.set_secret(c, box, "dob", name, "production", sec, f"dummy-{sec}-value", "test")
    ent = entity_mod.load(ROOT / "entities/dob.yaml", mode="production")
    hub = Hub(entity=ent, mode="production", box=box,
              transports={n: httpx.MockTransport(_live_stub) for n in ("lark", "jira", "ai")})
    for name in ("lark", "jira", "ai"):
        r = hub.test(connect, name, "test")
        assert r["status"] == "pass", r["steps"]
    pf.database(prod_db)
    assert _fails(pf) == []
    assert sum(1 for s, m in pf.results if s == "PASS" and m.startswith("db: ")) >= 20
    # A settings change after the test makes it stale again.
    with connect() as c, c.transaction():
        int_config.save(c, "dob", "jira", "production", "live", True, {**_prod_settings()["jira"], "project": "SOC"},
                        "test")
    pf.results.clear()
    pf.database(prod_db)
    assert _fails(pf) == ["db: jira latest connection test passed for settings v2"]
