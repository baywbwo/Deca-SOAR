"""Regression tests for the second security review (09-security-review-fase0.md, "Review ulang @ 04c034b")."""

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import errors
from psycopg.rows import dict_row

from deca_soar import cli
from deca_soar.common.config import ConfigError
from deca_soar.common.dbguard import assert_least_privilege_login, login_problems
from deca_soar.common.pii import vault_public_key

from conftest import make_login
from test_broker_api import env, principals  # noqa: F401  (fixtures)

SERVICES = ("gateway", "broker", "auditor")


def _problems(url: str, service: str) -> list[str]:
    with psycopg.connect(url, row_factory=dict_row) as c:
        return login_problems(c, service)


# N4: services refuse a login with more privilege than they need ----------------------------------

@pytest.mark.parametrize("service", SERVICES)
def test_n4_migrated_group_logins_pass(roles, service):
    assert _problems(roles[service], service) == []


@pytest.mark.parametrize("service", SERVICES)
def test_n4_superuser_login_refused(db_url, service):
    p = _problems(db_url, service)
    assert any("SUPERUSER" in x for x in p)
    assert any("owns ledger.entry" in x for x in p)


@pytest.mark.parametrize("service,other", [("gateway", "broker"), ("broker", "auditor"), ("auditor", "gateway")])
def test_n4_wrong_group_refused(roles, service, other):
    p = _problems(roles[other], service)
    assert any(f"not a member of deca_soar_{service}" in x for x in p), p


def test_n4_table_owner_refused(pg_server, db_url, conn):
    """The migration owner (non-superuser, owns the tables) used as an app DSN by mistake."""
    url = make_login(pg_server, db_url, "deca_soar_broker")
    user = url.split("://", 1)[1].split("@", 1)[0]
    conn.execute(f'ALTER TABLE ledger.entry OWNER TO "{user}"')
    p = _problems(url, "broker")
    assert any("owns ledger.entry" in x for x in p), p


@pytest.mark.parametrize("grant,expect", [
    ("GRANT DELETE ON ledger.entry TO deca_soar_broker", "DELETE on ledger.entry"),
    ("GRANT TRUNCATE ON broker.kill_switch TO deca_soar_broker", "TRUNCATE on broker.kill_switch"),
    ("GRANT UPDATE ON SEQUENCE ledger.entry_seq_seq TO deca_soar_broker", "UPDATE on sequence ledger.entry_seq_seq"),
    ("GRANT INSERT (seq) ON ledger.entry TO deca_soar_broker", "ledger.entry.seq"),
    ("GRANT CREATE ON SCHEMA ledger TO deca_soar_broker", "CREATE in schema ledger"),
    ("GRANT CREATE ON SCHEMA public TO PUBLIC", "CREATE in schema public"),
    ("GRANT deca_soar_auditor TO deca_soar_broker", "member of deca_soar_auditor"),
    ("GRANT pg_read_all_data TO deca_soar_broker", "member of pg_read_all_data"),
])
def test_n4_any_extra_privilege_refused(roles, conn, grant, expect):
    conn.execute(grant)
    try:
        p = _problems(roles["broker"], "broker")
    finally:
        if " ON " not in grant:  # role membership is cluster-wide; the test database is not
            conn.execute(grant.replace("GRANT", "REVOKE", 1).replace(" TO ", " FROM "))
    assert any(expect in x for x in p), p


def test_n4_extra_table_privilege_via_public_refused(roles, conn):
    conn.execute("GRANT SELECT ON vault.token_map TO PUBLIC")
    p = _problems(roles["gateway"], "gateway")
    assert any("SELECT on vault.token_map" in x for x in p) and any("ciphertext" in x for x in p), p


def test_n4_role_attributes_refused(pg_server, roles):
    user = roles["auditor"].split("://", 1)[1].split("@", 1)[0]
    with psycopg.connect(pg_server, autocommit=True) as c:
        c.execute(f'ALTER ROLE "{user}" CREATEROLE CREATEDB BYPASSRLS')
    p = _problems(roles["auditor"], "auditor")
    for attr in ("CREATEROLE", "CREATEDB", "BYPASSRLS"):
        assert any(attr in x for x in p), p


def test_n4_broker_refuses_to_start_with_owner_dsn(env, principals, settings):
    env.setenv("DECA_DB_URL", settings.db_url)  # the superuser that owns everything in tests
    from deca_soar.broker.app import app
    with pytest.raises(ConfigError, match="refusing to start"):
        with TestClient(app):
            pass


def test_n4_broker_starts_with_broker_login(env, principals):
    from deca_soar.broker.app import app
    with TestClient(app) as c:
        assert c.get("/healthz").status_code == 200
        assert c.get("/v1/whoami", headers=principals["viewer1"]).status_code == 200


@pytest.mark.parametrize("which", ["owner", "broker"])
def test_n4_gateway_refuses_to_start_with_wrong_dsn(monkeypatch, settings, roles, which):
    monkeypatch.setenv("DECA_DB_URL", settings.db_url if which == "owner" else roles["broker"])
    monkeypatch.setenv("DECA_TOKENIZATION_KEY", (b"\x01" * 32).hex())
    monkeypatch.setenv("DECA_VAULT_PUBLIC_KEY", vault_public_key(b"\x02" * 32).hex())
    from deca_soar.gateway.app import app
    with pytest.raises(ConfigError, match="refusing to start"):
        with TestClient(app):
            pass


@pytest.mark.parametrize("which", ["owner", "gateway"])
def test_n4_anchor_job_refuses_wrong_dsn(monkeypatch, settings, roles, tmp_path, capsys, which):
    monkeypatch.setenv("DECA_DB_URL", settings.db_url if which == "owner" else roles["gateway"])
    assert cli.main(["anchor-ledger", "--sink", f"file:{tmp_path / 'a.ndjson'}"]) == 2
    assert "refusing to start" in capsys.readouterr().err
    assert not (tmp_path / "a.ndjson").exists()


def test_n4_guard_is_plain_function(roles):
    with psycopg.connect(roles["auditor"]) as c:  # tuple rows work too
        assert_least_privilege_login(c, "auditor")


# N7: application roles cannot pick ledger.entry.seq ---------------------------------------------

@pytest.mark.parametrize("who", ["gateway", "broker"])
def test_n7_explicit_seq_insert_refused(roles, who):
    with psycopg.connect(roles[who], autocommit=True) as c:
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("INSERT INTO ledger.entry (seq, event_type, actor, payload, canonical, prev_hash, hash)"
                      " VALUES (1000000, 'x', 'x', '{}', '{}', repeat('0', 64), repeat('1', 64))")
        c.execute("INSERT INTO ledger.entry (event_type, actor, payload, canonical, prev_hash, hash)"
                  " VALUES ('n7', 'x', '{}', '{}', repeat('0', 64), repeat('2', 64))")
