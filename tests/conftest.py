"""Test fixtures. DB tests need either DECA_TEST_DB_URL (a superuser URL on a throwaway server)
or DECA_TEST_PG_BIN (a directory with initdb/pg_ctl): then a private server is started on a unix socket."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg.rows import dict_row

from deca_soar.common.config import DEFAULT_INTERNAL_CIDRS, Settings, _cidrs
from deca_soar.common.db import make_pool, migrate
from deca_soar.common.pii import vault_public_key

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def pg_server():
    url = os.environ.get("DECA_TEST_DB_URL")
    if url:
        yield url
        return
    pg_bin = os.environ.get("DECA_TEST_PG_BIN")
    if not pg_bin:
        pytest.skip("no test database (set DECA_TEST_DB_URL or DECA_TEST_PG_BIN)")
    d = Path(tempfile.mkdtemp(prefix="deca-pg-"))
    data, sock = d / "data", d / "sock"
    sock.mkdir()
    subprocess.run([f"{pg_bin}/initdb", "-D", str(data), "-U", "postgres", "--auth=trust", "-E", "UTF8"],
                   check=True, capture_output=True)
    subprocess.run([f"{pg_bin}/pg_ctl", "-D", str(data), "-l", str(d / "pg.log"), "-w", "-o",
                    f"-c listen_addresses='' -c unix_socket_directories={sock} -c fsync=off", "start"],
                   check=True, capture_output=True)
    try:
        yield f"postgresql://postgres@/postgres?host={sock}"
    finally:
        subprocess.run([f"{pg_bin}/pg_ctl", "-D", str(data), "-m", "immediate", "stop"], capture_output=True)
        shutil.rmtree(d, ignore_errors=True)


def _with_db(url: str, db: str) -> str:
    base, _, query = url.partition("?")
    base = base.rsplit("/", 1)[0] + "/" + db
    return f"{base}?{query}" if query else base


@pytest.fixture(scope="session")
def template_db(pg_server):
    with psycopg.connect(pg_server, autocommit=True) as c:
        c.execute("DROP DATABASE IF EXISTS deca_tpl")
        c.execute("CREATE DATABASE deca_tpl")
    migrate(_with_db(pg_server, "deca_tpl"))
    return "deca_tpl"


@pytest.fixture
def db_url(pg_server, template_db):
    name = "t_" + uuid.uuid4().hex[:12]
    with psycopg.connect(pg_server, autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}" TEMPLATE {template_db}')
    yield _with_db(pg_server, name)
    with psycopg.connect(pg_server, autocommit=True) as c:
        c.execute(f'DROP DATABASE "{name}" WITH (FORCE)')


def make_login(pg_server: str, db_url: str, group: str) -> str:
    """A fresh LOGIN user that is a member of one NOLOGIN group role (RUNBOOK step 2)."""
    user = f"{group.removeprefix('deca_soar_')}_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(pg_server, autocommit=True) as c:
        c.execute(f'CREATE ROLE "{user}" LOGIN IN ROLE {group}')
    return db_url.replace("postgres@", f"{user}@", 1)


@pytest.fixture
def roles(pg_server, db_url):
    return {g: make_login(pg_server, db_url, f"deca_soar_{g}") for g in ("gateway", "broker", "auditor")}


@pytest.fixture
def conn(db_url):
    with psycopg.connect(db_url, row_factory=dict_row, autocommit=True) as c:
        yield c


@pytest.fixture
def pool(db_url):
    p = make_pool(db_url, max_size=4)
    yield p
    p.close()


@pytest.fixture
def settings(db_url) -> Settings:
    return Settings(
        db_url=db_url,
        tokenization_key=b"\x01" * 32,
        vault_public_key=vault_public_key(b"\x02" * 32),
        vault_private_key=b"\x02" * 32,
        internal_cidrs=_cidrs(DEFAULT_INTERNAL_CIDRS),
        policy_dir=ROOT / "policy",
    )
