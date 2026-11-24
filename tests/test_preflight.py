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

def test_n3_placeholder_digest_fails_in_production(pf):
    pf.base_image(True, None)
    assert _status(pf, "DECA_BASE_IMAGE pinned") == ["FAIL"]


def test_n3_placeholder_digest_only_warns_outside_production(pf):
    pf.base_image(False, None)
    assert _status(pf, "DECA_BASE_IMAGE pinned") == ["WARN"]


@pytest.mark.parametrize("value,expect", [
    (DIGEST, "PASS"),
    ("python:3.12-slim-bookworm@sha256:REPLACE_WITH_PINNED_DIGEST", "FAIL"),
    ("python:3.12-slim-bookworm", "FAIL"),
    ("python:3.12-slim-bookworm@sha256:" + "AB" * 32, "FAIL"),
    ("python:3.12-slim-bookworm@sha256:" + "ab" * 31, "FAIL"),
])
def test_n3_digest_from_production_env(pf, tmp_path, value, expect):
    pf.base_image(True, _env(tmp_path, f"DECA_BASE_IMAGE={value}\n"))
    assert _status(pf, "DECA_BASE_IMAGE pinned") == [expect]


def test_n3_production_flag_is_implied_by_env(pf, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["preflight", "--env", str(_env(tmp_path, "DECA_BIND_IP=10.0.0.9\n"))])
    assert pf.main() == 1
    assert "FAIL  image: DECA_BASE_IMAGE pinned by sha256 digest" in capsys.readouterr().out


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
        "deca_tokenization_key": "11" * 32, "deca_temporal_payload_key": "22" * 32,
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
