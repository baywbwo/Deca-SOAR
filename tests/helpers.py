import json
from functools import cache
from pathlib import Path

from hypersoar.gateway.service import pull_once
from hypersoar.gateway.sources import ReplayFileSource


def write_ndjson(path: Path, rows: list) -> None:
    with path.open("a") as f:
        for r in rows:
            f.write((r if isinstance(r, str) else json.dumps(r)) + "\n")


def waf_alert(ip="203.0.113.7", ts="2026-11-24T03:00:10Z", **kw):
    r = {"source": "waf", "rule_id": "waf.sqli.burst", "severity_hint": "high", "detected_at": ts,
         "src_ip": ip, "uri": "/api/v1/login?email=a@b.co", "ua": "sqlmap/1.7", "events": 40}
    r.update(kw)
    return r


def ingest(pool, settings, tmp_path, rows, name="replay"):
    f = tmp_path / f"{name}.ndjson"
    write_ndjson(f, rows)
    return pull_once(pool, ReplayFileSource(f, name=name), settings)


PW = "correct horse battery staple 42"


@cache
def pw_hash() -> str:
    from hypersoar.console.auth import hash_password
    return hash_password(PW)


def set_reauth(conn, *names: str) -> None:
    for n in names:
        conn.execute("UPDATE broker.principal SET reauth_hash = %s WHERE name = %s", (pw_hash(), n))
