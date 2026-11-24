"""Regression tests for the second security review (09-security-review-fase0.md, "Review ulang @ 04c034b")."""

import json
import os
import stat
import subprocess
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import errors
from psycopg.rows import dict_row

from deca_soar import cli, ledger
from deca_soar.common.config import ConfigError
from deca_soar.common.dbguard import assert_least_privilege_login, login_problems
from deca_soar.common.pii import vault_public_key
from deca_soar.ledger.anchor import SinkError, SlsExport, open_sink

from conftest import make_login
from helpers import ingest, waf_alert
from test_review_fixes import _owner_rewrite
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


# N2: anchors leave the host; the owner DSN is never stored ---------------------------------------

REPO = Path(__file__).resolve().parents[1]
OWNER_RUN = REPO / "deploy/deca/bin/deca-owner-run.sh"


def _ship(anchor_file: Path, export: Path, *, as_array: bool = False) -> None:
    """Mock Logtail -> SLS: each anchor line becomes a log with string fields plus the raw `content`."""
    logs = []
    for line in anchor_file.read_text().splitlines():
        rec = json.loads(line)
        logs.append({"__source__": "10.0.0.5", "__time__": "1764000000", "content": line,
                     **{k: "" if v is None else str(v) for k, v in rec.items()}})
    export.write_text(json.dumps(logs) if as_array else "".join(json.dumps(x) + "\n" for x in logs))


def test_n2_sls_export_formats(tmp_path):
    rec = {"v": 1, "head_seq": 7, "head_hash": "ab" * 32, "entries": 7, "anchored_at": "t"}
    f = tmp_path / "a.ndjson"
    f.write_text(json.dumps(rec) + "\n")
    for as_array in (False, True):
        _ship(f, tmp_path / "x.json", as_array=as_array)
        assert [(a["head_seq"], a["head_hash"]) for a in SlsExport(tmp_path / "x.json").read()] == [(7, "ab" * 32)]
    (tmp_path / "c.json").write_text(json.dumps({"content": json.dumps(rec)}) + "\n")  # only the raw line kept
    assert SlsExport(tmp_path / "c.json").read()[0]["head_seq"] == 7
    (tmp_path / "e.json").write_text(json.dumps({"head_seq": "", "head_hash": "null"}) + "\n")  # empty ledger
    assert SlsExport(tmp_path / "e.json").read()[0]["head_seq"] is None
    assert isinstance(open_sink(f"sls-export:{f}"), SlsExport)


@pytest.mark.parametrize("text,msg", [
    (None, "not found"),
    ("not json", "not JSON"),
    ('{"content": "x"}\n', "content is not an anchor record"),
    ('{"head_hash": "ab"}\n', "not an anchor record"),
    ('{"head_seq": "seven", "head_hash": "ab"}\n', "not an integer"),
    ('[1]', "not an anchor record"),
])
def test_n2_sls_export_rejects_unrecognised_items(tmp_path, text, msg):
    f = tmp_path / "x.json"
    if text is not None:
        f.write_text(text)
    with pytest.raises(SinkError, match=msg):
        SlsExport(f).read()
    with pytest.raises(SinkError, match="read-only"):
        SlsExport(f).append({})


def test_n2_offhost_copy_catches_root_rewrite(pool, settings, tmp_path, conn, roles, monkeypatch, capsys):
    """Root on the host rewrites the ledger AND the local anchor file; only the shipped copy disagrees."""
    ingest(pool, settings, tmp_path, [waf_alert(), waf_alert(ip="203.0.113.51")])
    monkeypatch.setenv("DECA_DB_URL", roles["auditor"])
    host = tmp_path / "ledger-anchors.ndjson"
    export = tmp_path / "sls-export.json"
    assert cli.main(["anchor-ledger", "--sink", f"file:{host}"]) == 0
    _ship(host, export)
    assert cli.main(["verify-ledger", "--anchors", f"sls-export:{export}"]) == 0
    capsys.readouterr()

    _owner_rewrite(conn)
    host.unlink()  # root covers its tracks: a fresh, consistent anchor file
    assert cli.main(["anchor-ledger", "--sink", f"file:{host}"]) == 0
    assert ledger.verify(conn).ok
    assert cli.main(["verify-ledger", "--anchors", f"file:{host}"]) == 0  # the host copy is fooled
    capsys.readouterr()
    assert cli.main(["verify-ledger", "--anchors", f"sls-export:{export}"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert not out["ok"] and any("ledger rewritten" in e for e in out["errors"])


def test_n2_verify_needs_an_anchored_head(roles, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("DECA_DB_URL", roles["auditor"])
    (tmp_path / "empty.ndjson").write_text("")
    assert cli.main(["verify-ledger", "--anchors", f"sls-export:{tmp_path / 'empty.ndjson'}"]) == 1
    assert any("no anchored head" in e for e in json.loads(capsys.readouterr().out)["errors"])
    assert cli.main(["verify-ledger", "--anchors", f"sls-export:{tmp_path / 'missing.json'}"]) == 2


DSN = "postgresql://deca_owner:n2-test-pw@db.internal:5432/deca_soar?sslmode=verify-full"


@pytest.fixture
def owner_run(tmp_path):
    """deca-owner-run.sh with a stand-in `docker` that records what the owner job would have seen."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    seen = tmp_path / "seen"
    fake = bin_dir / "docker"
    fake.write_text(f"""#!/bin/sh
f="$DECA_OWNER_DSN_FILE"
{{ echo "args=$*"; echo "mode=$(stat -c %a "$f")"; echo "dirmode=$(stat -c %a "$(dirname "$f")")"
   echo "content=$(cat "$f")"; echo "file=$f"; }} > {seen}
exit "${{FAKE_DOCKER_RC:-0}}"
""")
    fake.chmod(0o755)
    shm = tmp_path / "shm"
    shm.mkdir()
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    base = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "DECA_OWNER_TMPDIR": str(shm),
            "DECA_SECRETS_DIR": str(secrets), "DECA_ENV_FILE": str(tmp_path / "deca.env")}

    def run(*args, stdin=DSN + "\n", **env):
        r = subprocess.run(["sh", str(OWNER_RUN), *args], input=stdin, capture_output=True, text=True,
                           env={**base, **env}, timeout=30)
        got = dict(x.split("=", 1) for x in seen.read_text().splitlines()) if seen.exists() else None
        return r, got
    run.shm, run.secrets, run.seen = shm, secrets, seen
    return run


def test_n2_owner_dsn_exists_only_during_the_job(owner_run):
    assert os.access(OWNER_RUN, os.X_OK)
    r, got = owner_run("migrate")
    assert r.returncode == 0, r.stderr
    assert got["content"] == DSN and got["mode"] == "400" and got["dirmode"] == "700"
    assert "docker-compose.owner.yml" in got["args"] and got["args"].endswith("run --rm owner-job deca-soar migrate")
    assert Path(got["file"]).parent.parent == owner_run.shm
    assert list(owner_run.shm.iterdir()) == []  # removed after the run
    assert "n2-test-pw" not in r.stdout + r.stderr


def test_n2_owner_dsn_removed_when_the_job_fails(owner_run):
    r, got = owner_run("create-principal", "--name", "x", FAKE_DOCKER_RC="3")
    assert r.returncode == 3 and got["content"] == DSN
    assert list(owner_run.shm.iterdir()) == []


@pytest.mark.parametrize("args,stdin,msg", [
    (["worker"], DSN, "usage"),
    (["migrate"], DSN.replace("verify-full", "require"), "verify-full"),
    (["migrate"], "", "verify-full"),
])
def test_n2_owner_run_refuses(owner_run, args, stdin, msg):
    r, got = owner_run(*args, stdin=stdin)
    assert r.returncode != 0 and msg in r.stderr and got is None
    assert list(owner_run.shm.iterdir()) == []
    assert "n2-test-pw" not in r.stdout + r.stderr


def test_n2_owner_run_refuses_while_owner_dsn_is_stored(owner_run):
    stored = owner_run.secrets / "deca_db_url_owner"
    stored.write_text(DSN)
    r, got = owner_run("migrate")
    assert r.returncode == 65 and "must not be stored" in r.stderr and got is None
