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

from hypersoar import ledger
from hypersoar.ledger.anchor import SinkError, open_sink
from hypersoar.broker import service
from hypersoar.broker.roles import ROLES
from hypersoar.common.config import ConfigError, read_secret
from hypersoar.common.db import MIGRATIONS_DIR, migrate
from hypersoar.common.dbguard import assert_least_privilege_login


def _db_url() -> str:
    url = read_secret("HYPERSOAR_DB_URL")
    assert url is not None
    return url


def cmd_migrate(_: argparse.Namespace) -> int:
    applied = migrate(_db_url(), Path(os.environ.get("HYPERSOAR_MIGRATIONS_DIR", MIGRATIONS_DIR)))
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
    if a.anchors and not any(x.get("head_seq") is not None for x in anchors):
        anchor_errors.append("no anchored head to compare with (empty or missing anchor source)")
    ok = r.ok and not anchor_errors
    print(json.dumps({"ok": ok, "entries": r.entries, "head_seq": r.head_seq, "head_hash": r.head_hash,
                      "anchors_checked": len(anchors), "errors": r.errors + anchor_errors}))
    return 0 if ok else 1


def cmd_anchor_ledger(a: argparse.Namespace) -> int:
    """Daily job: verify the chain, then append its head to an external sink (review F3)."""
    try:
        sink = open_sink(a.sink)
        with psycopg.connect(_db_url(), row_factory=dict_row) as conn:
            assert_least_privilege_login(conn, "auditor")
            r, rec = ledger.anchor_record(conn)
            anchor_errors = ledger.check_anchors(conn, sink.read())
        if not r.ok or anchor_errors:
            print(json.dumps({"ok": False, "anchored": False, "errors": r.errors + anchor_errors}))
            return 1
        sink.append(rec)
    except (SinkError, ConfigError) as e:
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


def cmd_worker(_: argparse.Namespace) -> int:
    from hypersoar.workflows.worker import main as worker_main

    return worker_main()


def cmd_console_hash(_: argparse.Namespace) -> int:
    """Read a password on stdin, print its scrypt hash for HYPERSOAR_CONSOLE_PASSWORD_HASH_FILE."""
    from hypersoar.console.auth import hash_password

    password = sys.stdin.readline().rstrip("\n")
    try:
        print(hash_password(password))
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    return 0


def cmd_synth_alerts(a: argparse.Namespace) -> int:
    from hypersoar import synth

    synth.run(Path(a.out), a.interval, a.count, a.seed, log=lambda m: print(m, flush=True))
    return 0


def _integration_ctx(need_box: bool):
    from hypersoar.broker.integrations import config as int_config
    from hypersoar.broker.integrations import secretbox
    from hypersoar.common import entity as entity_mod

    mode = entity_mod.current_mode()
    ent = entity_mod.load(mode=mode)
    box = secretbox.SecretBox.from_env()
    if box is None and (need_box or mode == "production"):
        raise ConfigError("HYPERSOAR_INTEGRATION_KEY_FILE is required")
    with psycopg.connect(_db_url(), row_factory=dict_row) as conn, conn.transaction():
        entity_mod.assert_install(conn, mode, ent.id)
        int_config.seed(conn, ent)
    return mode, ent, box


def cmd_integration_set_secret(a: argparse.Namespace) -> int:
    """Read one integration secret on stdin and seal it. Prints only the name and the time."""
    from hypersoar.broker.integrations import secretbox

    mode, ent, box = _integration_ctx(need_box=True)
    value = sys.stdin.readline().rstrip("\n")
    if not value:
        print("empty secret on stdin", file=sys.stderr)
        return 2
    with psycopg.connect(_db_url(), row_factory=dict_row) as conn, conn.transaction():
        secretbox.set_secret(conn, box, ent.id, a.integration, mode, a.name, value, f"cli:{a.actor}")
    print(json.dumps({"entity": ent.id, "mode": mode, "integration": a.integration, "secret": a.name, "set": True}))
    return 0


def cmd_integration_test(a: argparse.Namespace) -> int:
    from hypersoar.broker.integrations.hub import Hub

    mode, ent, box = _integration_ctx(need_box=False)
    hub = Hub(entity=ent, mode=mode, box=box)
    names = (a.integration,) if a.integration else ("lark", "jira", "ai")
    rc = 0
    for n in names:
        r = hub.test(lambda: psycopg.connect(_db_url(), row_factory=dict_row), n, f"cli:{a.actor}")
        print(json.dumps(r))
        rc |= r["status"] != "pass"
    return rc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hypersoar")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate").set_defaults(fn=cmd_migrate)
    cp = sub.add_parser("create-principal")
    cp.add_argument("--name", required=True)
    cp.add_argument("--kind", choices=("service", "human"), required=True)
    cp.add_argument("--role", choices=ROLES, required=True)
    cp.add_argument("--token-file", required=True, help="new 0600 file that receives the bearer token")
    cp.set_defaults(fn=cmd_create_principal)
    vl = sub.add_parser("verify-ledger")
    vl.add_argument("--anchors", help="also compare with anchors from file:<path> or an off-host copy, sls-export:<path>")
    vl.set_defaults(fn=cmd_verify_ledger)
    al = sub.add_parser("anchor-ledger")
    al.add_argument("--sink", required=True, help="file:<path> (phase 0) or sls:<project>/<logstore> (untested)")
    al.set_defaults(fn=cmd_anchor_ledger)
    ks = sub.add_parser("kill-switch")
    ks.add_argument("state", choices=("on", "off"))
    ks.add_argument("--scope", default="global")
    ks.add_argument("--principal", required=True)
    ks.set_defaults(fn=cmd_kill_switch)
    sub.add_parser("worker", help="run the Temporal alert worker").set_defaults(fn=cmd_worker)
    sub.add_parser("console-hash", help="hash a console password read from stdin").set_defaults(fn=cmd_console_hash)
    sa = sub.add_parser("synth-alerts", help="lab only: append synthetic raw alerts to a replay file")
    sa.add_argument("--out", required=True, help="replay NDJSON file read by the gateway")
    sa.add_argument("--interval", type=float, default=90.0, help="seconds between alerts")
    sa.add_argument("--count", type=int, default=0, help="stop after this many alerts (0 = run forever)")
    sa.add_argument("--seed", type=int, default=None)
    sa.set_defaults(fn=cmd_synth_alerts)
    ig = sub.add_parser("integration", help="Lark / Jira / 9router: seal a secret or run a connection test")
    isub = ig.add_subparsers(dest="icmd", required=True)
    ss = isub.add_parser("set-secret", help="read the secret value from stdin")
    ss.add_argument("--integration", choices=("lark", "jira", "ai"), required=True)
    ss.add_argument("--name", required=True)
    ss.add_argument("--actor", required=True, help="who is doing this (recorded in the ledger)")
    ss.set_defaults(fn=cmd_integration_set_secret)
    it = isub.add_parser("test", help="run the connection test; exit 1 unless every test passes")
    it.add_argument("--integration", choices=("lark", "jira", "ai"))
    it.add_argument("--actor", required=True)
    it.set_defaults(fn=cmd_integration_test)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
