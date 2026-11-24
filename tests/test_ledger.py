import psycopg
import pytest

from deca_soar import ledger


def _fill(conn, n=5):
    with conn.transaction():
        for i in range(n):
            ledger.append(conn, "test.event", "test", {"i": i, "note": "ünïcode", "f": 0.95})


def test_chain_verifies(conn):
    _fill(conn)
    r = ledger.verify(conn)
    assert r.ok and r.entries == 5 and r.head_seq == 5
    first = conn.execute("SELECT prev_hash FROM ledger.entry ORDER BY seq LIMIT 1").fetchone()
    assert first["prev_hash"] == ledger.GENESIS


@pytest.mark.parametrize("stmt", ["UPDATE ledger.entry SET actor = 'x' WHERE seq = 2",
                                  "DELETE FROM ledger.entry WHERE seq = 2",
                                  "TRUNCATE ledger.entry"])
def test_mutation_blocked(conn, stmt):
    _fill(conn, 3)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with conn.transaction():
            conn.execute(stmt)


def _tamper(conn, sql):
    # Simulates someone with table-owner rights bypassing the triggers.
    with conn.transaction():
        conn.execute("ALTER TABLE ledger.entry DISABLE TRIGGER USER")
        conn.execute(sql)
        conn.execute("ALTER TABLE ledger.entry ENABLE TRIGGER USER")


@pytest.mark.parametrize("sql,expect", [
    ("UPDATE ledger.entry SET payload = '{\"i\": 99, \"note\": \"ünïcode\", \"f\": 0.95}' WHERE seq = 3",
     "stored columns differ"),
    ("UPDATE ledger.entry SET canonical = replace(canonical, '\"i\":2', '\"i\":7') WHERE seq = 3", "hash mismatch"),
    ("DELETE FROM ledger.entry WHERE seq = 3", "prev_hash does not link"),
])
def test_tamper_detected(conn, sql, expect):
    _fill(conn)
    _tamper(conn, sql)
    r = ledger.verify(conn)
    assert not r.ok
    assert any(expect in e for e in r.errors), r.errors
