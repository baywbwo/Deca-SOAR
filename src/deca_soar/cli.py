"""Operator CLI. Secrets are read from env/files and never printed."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from deca_soar import ledger
from deca_soar.ledger.anchor import SinkError, open_sink
from deca_soar.broker import service
from deca_soar.broker.roles import ROLES
from deca_soar.common.config import read_secret
from deca_soar.common.db import MIGRATIONS_DIR, migrate


def _db_url() -> str:
    url = read_secret("DECA_DB_URL")
    assert url is not None
    return url


def cmd_migrate(_: argparse.Namespace) -> int:
    applied = migrate(_db_url(), Path(os.environ.get("DECA_MIGRATIONS_DIR", MIGRATIONS_DIR)))
    print(json.dumps({"applied": applied}))
    return 0


def cmd_create_principal(a: argparse.Namespace) -> int:
    out = Path(a.token_file)
    if out.exists():
        print("token file already exists; refusing to overwrite", file=sys.stderr)
        return 2
    token = secrets.token_urlsafe(32)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token + "\n")
    with psycopg.connect(_db_url(), row_factory=dict_row) as conn, conn.transaction():
        pid = service.create_principal(conn, a.name, a.kind, a.role, token, "cli:operator")
    print(json.dumps({"principal_id": pid, "name": a.name, "kind": a.kind, "role": a.role, "token_file": str(out)}))
    return 0


def cmd_verify_ledger(a: argparse.Namespace) -> int:
    try:
        anchors = open_sink(a.anchors).read() if a.anchors else []
    except SinkError as e:
        print(str(e), file=sys.stderr)
        return 2
    with psycopg.connect(_db_url(), row_factory=dict_row) as conn:
        r = ledger.verify(conn)
        anchor_errors = ledger.check_anchors(conn, anchors)
    ok = r.ok and not anchor_errors
    print(json.dumps({"ok": ok, "entries": r.entries, "head_seq": r.head_seq, "head_hash": r.head_hash,
                      "anchors_checked": len(anchors), "errors": r.errors + anchor_errors}))
    return 0 if ok else 1


def cmd_anchor_ledger(a: argparse.Namespace) -> int:
    """Daily job: verify the chain, then append its head to an external sink (review F3)."""
    try:
        sink = open_sink(a.sink)
        with psycopg.connect(_db_url(), row_factory=dict_row) as conn:
            r, rec = ledger.anchor_record(conn)
            anchor_errors = ledger.check_anchors(conn, sink.read())
        if not r.ok or anchor_errors:
            print(json.dumps({"ok": False, "anchored": False, "errors": r.errors + anchor_errors}))
            return 1
        sink.append(rec)
    except SinkError as e:
        print(str(e), file=sys.stderr)
        return 2
    print(json.dumps({"ok": True, "anchored": True, **rec}))
    return 0


def cmd_kill_switch(a: argparse.Namespace) -> int:
    """On-call break-glass path (design 6.3 item 7): direct DB, attributed to a named principal."""
    with psycopg.connect(_db_url(), row_factory=dict_row) as conn, conn.transaction():
        row = conn.execute(
            "SELECT principal_id FROM broker.principal WHERE name = %s AND active", (a.principal,)
        ).fetchone()
        if row is None:
            print("unknown principal", file=sys.stderr)
            return 2
        service.set_kill_switch(conn, str(row["principal_id"]), f"cli:{a.principal}", a.scope, a.state == "on")
    print(json.dumps({"scope": a.scope, "engaged": a.state == "on"}))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="deca-soar")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate").set_defaults(fn=cmd_migrate)
    cp = sub.add_parser("create-principal")
    cp.add_argument("--name", required=True)
    cp.add_argument("--kind", choices=("service", "human"), required=True)
    cp.add_argument("--role", choices=ROLES, required=True)
    cp.add_argument("--token-file", required=True, help="new 0600 file that receives the bearer token")
    cp.set_defaults(fn=cmd_create_principal)
    vl = sub.add_parser("verify-ledger")
    vl.add_argument("--anchors", help="also compare with anchors from this sink (file:<path>)")
    vl.set_defaults(fn=cmd_verify_ledger)
    al = sub.add_parser("anchor-ledger")
    al.add_argument("--sink", required=True, help="file:<path> (phase 0) or sls:<project>/<logstore> (untested)")
    al.set_defaults(fn=cmd_anchor_ledger)
    ks = sub.add_parser("kill-switch")
    ks.add_argument("state", choices=("on", "off"))
    ks.add_argument("--scope", default="global")
    ks.add_argument("--principal", required=True)
    ks.set_defaults(fn=cmd_kill_switch)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
