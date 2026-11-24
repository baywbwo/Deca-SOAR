"""Regression tests for the third security review (09-security-review-fase0.md, "@ 69c244a": N8, N9, N10)."""

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.rows import dict_row

from hypersoar.common.config import ConfigError
from hypersoar.common.dbguard import login_problems

from test_broker_api import env, principals  # noqa: F401  (fixtures)
from test_preflight import _secrets, _status, pf  # noqa: F401  (fixture)
from test_review_round2 import owner_run  # noqa: F401  (fixture)


def _problems(url: str, service: str) -> list[str]:
    with psycopg.connect(url, row_factory=dict_row) as c:
        return login_problems(c, service)


def _user(url: str) -> str:
    return url.split("://", 1)[1].split("@", 1)[0]


def _with_options(url: str, role: str) -> str:
    return url + ("&" if "?" in url else "?") + f"options=-c%20role%3D{role}"


# N8: a privileged login that only switched role is refused ---------------------------------------

def test_n8_poc_superuser_with_role_option_refused(db_url, roles):
    """Aldiman's PoC: superuser DSN + options=-c role=<broker login> used to pass the guard."""
    url = _with_options(db_url, _user(roles["broker"]))
    with psycopg.connect(url) as c:
        assert c.execute("SELECT session_user::text, current_user::text").fetchone() == ("postgres", _user(roles["broker"]))
    p = _problems(url, "broker")
    assert any("session user postgres switched to" in x for x in p), p
    assert any("session user postgres has SUPERUSER" in x for x in p), p


def test_n8_owner_with_role_option_refused(pg_server, db_url, roles, conn):
    """A non-superuser table owner that is also a member of the broker login, lowered via options."""
    owner = "own_n8"
    with psycopg.connect(pg_server, autocommit=True) as c:
        c.execute(f'DROP ROLE IF EXISTS "{owner}"')
        c.execute(f'CREATE ROLE "{owner}" LOGIN IN ROLE "{_user(roles["broker"])}"')
    try:
        conn.execute(f'ALTER TABLE ledger.entry OWNER TO "{owner}"')
        url = _with_options(db_url.replace("postgres@", f"{owner}@", 1), _user(roles["broker"]))
        p = _problems(url, "broker")
        assert any(f"session user {owner} switched to" in x for x in p), p
    finally:
        conn.execute("ALTER TABLE ledger.entry OWNER TO postgres")
        with psycopg.connect(pg_server, autocommit=True) as c:
            c.execute(f'DROP OWNED BY "{owner}"')
            c.execute(f'DROP ROLE "{owner}"')


def test_n8_broker_refuses_to_start_with_role_option_dsn(env, principals, settings, roles):  # noqa: F811
    env.setenv("HYPERSOAR_DB_URL", _with_options(settings.db_url, _user(roles["broker"])))
    from hypersoar.broker.app import app
    with pytest.raises(ConfigError, match="refusing to start"):
        with TestClient(app):
            pass


@pytest.mark.parametrize("options,expect", [
    (None, "PASS"),
    ("?sslmode=verify-full&options=-c%20role%3Dbrk", "FAIL"),
    ("?options=-csearch_path%3Dx&sslmode=verify-full", "FAIL"),
])
def test_n8_preflight_rejects_options_in_app_dsn(pf, tmp_path, options, expect):  # noqa: F811
    d = _secrets(tmp_path, owner=False)
    if options:
        (d / "deca_db_url_broker").write_text(f"postgresql://brk:pw@db/deca{options}\n")
    pf.secrets_dir(d)
    assert _status(pf, "deca_db_url_broker has no libpq options") == [expect]


def test_n8_preflight_rejects_pgoptions_in_env(pf, tmp_path):  # noqa: F811
    p = tmp_path / "deca.env"
    p.write_text("PGOPTIONS=-c role=brk\n")
    p.chmod(0o600)
    pf.env_files(p, None)
    assert _status(pf, "no libpq PG* variables") == ["FAIL"]


# N9: column and function grants count as excess privilege ---------------------------------------

@pytest.mark.parametrize("service,grant,expect", [
    ("broker", "GRANT UPDATE (record) ON broker.decision_record TO deca_soar_broker",
     "UPDATE(record) on broker.decision_record"),
    ("broker", "GRANT UPDATE (payload) ON ledger.entry TO deca_soar_broker", "UPDATE(payload) on ledger.entry"),
    ("gateway", "GRANT SELECT (ciphertext) ON vault.token_map TO deca_soar_gateway", "SELECT(ciphertext) on vault.token_map"),
    ("auditor", "GRANT SELECT (token) ON vault.token_map TO deca_soar_auditor", "SELECT(token) on vault.token_map"),
    ("auditor", "GRANT REFERENCES (hash) ON ledger.entry TO PUBLIC", "REFERENCES(hash) on ledger.entry"),
])
def test_n9_column_grants_refused(roles, conn, service, grant, expect):
    conn.execute(grant)
    p = _problems(roles[service], service)
    assert any(expect in x for x in p), p


@pytest.mark.parametrize("schema,secdef", [("ledger", False), ("public", True)])
def test_n9_function_execute_refused(roles, conn, schema, secdef):
    conn.execute(f"CREATE FUNCTION {schema}.n9_probe() RETURNS int LANGUAGE sql"
                 f" {'SECURITY DEFINER' if secdef else ''} AS 'SELECT 1'")
    conn.execute(f"GRANT EXECUTE ON FUNCTION {schema}.n9_probe() TO deca_soar_broker")
    p = _problems(roles["broker"], "broker")
    assert any(f"EXECUTE {schema}.n9_probe()" in x for x in p), p


def test_n9_plain_public_function_is_ignored(roles, conn):
    """Extension-style helpers in public (not SECURITY DEFINER) do not run with elevated rights."""
    conn.execute("CREATE FUNCTION public.n9_plain() RETURNS int LANGUAGE sql AS 'SELECT 1'")
    assert _problems(roles["broker"], "broker") == []


# N10: leftover owner DSN directory after SIGKILL -------------------------------------------------

def test_n10_preflight_fails_on_leftover_owner_dir(pf, tmp_path):  # noqa: F811
    shm = tmp_path / "shm"
    shm.mkdir()
    pf.owner_leftovers(shm)
    assert _status(pf, "no leftover owner DSN directory") == ["PASS"]
    (shm / "deca-owner.Ab12Cd").mkdir(mode=0o700)
    pf.results.clear()
    pf.owner_leftovers(shm)
    assert _status(pf, "no leftover owner DSN directory") == ["FAIL"]
    assert "deca-owner.Ab12Cd" in [m for s, m in pf.results if s == "FAIL"][0]


def test_n10_owner_run_refuses_while_a_leftover_exists(owner_run):
    (owner_run.shm / "deca-owner.Zz99Yy").mkdir()
    r, got = owner_run("migrate")
    assert r.returncode == 65 and "left over" in r.stderr and got is None
    assert "n2-test-pw" not in r.stdout + r.stderr
