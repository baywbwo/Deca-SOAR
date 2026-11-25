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
from hypersoar.broker.integrations import NAMES
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
        pid = service.create_principal(conn, a.name, a.kind, a.role, token, "cli:operator", a.channel)
    print(json.dumps({"principal_id": pid, "name": a.name, "kind": a.kind, "role": a.role, "channel": a.channel,
                      "token_file": str(out)}))
    return 0


def cmd_set_channel(a: argparse.Namespace) -> int:
    """Mark a principal's token as the console's own ('console', may approve L3) or any other caller ('api')."""
    with psycopg.connect(_db_url(), row_factory=dict_row) as conn, conn.transaction():
        r = conn.execute("SELECT kind FROM broker.principal WHERE name = %s AND active", (a.name,)).fetchone()
        if r is None:
            print("no active principal with that name", file=sys.stderr)
            return 2
        if a.channel == "console" and r["kind"] != "human":
            print("only a person's principal can be a console credential", file=sys.stderr)
            return 2
        conn.execute("UPDATE broker.principal SET channel = %s WHERE name = %s AND active", (a.channel, a.name))
        ledger.append(conn, "principal.channel_set", f"cli:{a.actor}", {"name": a.name, "channel": a.channel})
    print(json.dumps({"name": a.name, "channel": a.channel}))
    return 0


def cmd_derive_source_key(a: argparse.Namespace) -> int:
    """Write the gateway's data-source key, derived from HYPERSOAR_INTEGRATION_KEY(_FILE), to a new 0600 file.
    The gateway gets only this file; the master key (which also derives the Lark/Jira/AI key) stays with the
    broker."""
    import base64

    from hypersoar.broker.integrations import secretbox
    from hypersoar.common.config import read_key32

    out = Path(a.out)
    if out.exists():
        print("output file already exists; refusing to overwrite", file=sys.stderr)
        return 2
    key = secretbox.derive(read_key32("HYPERSOAR_INTEGRATION_KEY"), "source")
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(base64.urlsafe_b64encode(key).decode().rstrip("=") + "\n")
    print(json.dumps({"written": str(out)}))
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
        from hypersoar.common import entity as entity_mod
        service.set_kill_switch(conn, str(row["principal_id"]), f"cli:{a.principal}", a.scope, a.state == "on",
                                entity_mod.load().id, a.reason)
    print(json.dumps({"scope": a.scope, "engaged": a.state == "on"}))
    return 0


def cmd_set_reauth(a: argparse.Namespace) -> int:
    """Set the re-authentication password of a human principal (read from stdin, never echoed).
    The console asks for it again before an approval, a kill-switch change or a revoke."""
    from hypersoar.broker import writes
    from hypersoar.console.auth import hash_password

    password = sys.stdin.readline().rstrip("\n")
    try:
        h = hash_password(password)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    with psycopg.connect(_db_url(), row_factory=dict_row) as conn, conn.transaction():
        try:
            writes.set_reauth_hash(conn, a.name, h, f"cli:{a.actor}")
        except LookupError as e:
            print(str(e), file=sys.stderr)
            return 2
    print(json.dumps({"name": a.name, "reauth_set": True}))
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
    from hypersoar.common.entity import current_mode

    synth.run(Path(a.out), a.interval, a.count, a.seed, log=lambda m: print(m, flush=True), mode=current_mode())
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


def cmd_scenario_run(a: argparse.Namespace) -> int:
    """Sandbox only: play scenarios/*.yaml against the running stack and record each result."""
    from datetime import UTC, datetime

    from hypersoar import scenarios as scn
    from hypersoar import synth
    from hypersoar.broker import catalog as catalog_mod
    from hypersoar.broker.integrations.hub import Hub
    from hypersoar.gateway import detections

    from hypersoar.common import entity as entity_mod

    # Refuse before touching the database: a production install never sees scenario data.
    if entity_mod.current_mode() != "sandbox":
        raise ConfigError("scenario runs are sandbox only (HYPERSOAR_MODE=sandbox)")
    mode, ent, box = _integration_ctx(need_box=False)
    catalog, _ = catalog_mod.load(Path(os.environ.get("HYPERSOAR_POLICY_DIR", "policy")))
    rate_limits = {k: v.rate_per_hour for k, v in catalog.items() if v.rate_per_hour}
    found = scn.load_dir(scn.scenarios_dir(), detections.load())
    if a.only:
        unknown = set(a.only) - set(found)
        if unknown:
            raise ConfigError(f"unknown scenario {sorted(unknown)}")
    chosen = [s for sid, s in found.items() if not a.only or sid in a.only]
    connect = lambda: psycopg.connect(_db_url(), row_factory=dict_row)  # noqa: E731
    hub = Hub(entity=ent, mode=mode, box=box)
    run_id = scn.new_run_id()
    sha = os.environ.get("HYPERSOAR_GIT_SHA")
    with connect() as conn:
        slot = scn.next_slot(conn)
    rc = 0
    for i, s in enumerate(chosen):
        started = datetime.now(UTC)
        if s.kind == "connection_test":
            r = scn.run_connection(lambda n: hub.test(connect, n, f"scenario:{a.actor}"), s)
        else:
            r = scn.run_pipeline(connect, ent.id, run_id, s, slot + i, lambda rows: synth.append(Path(a.replay), rows),
                                 rate_limits=rate_limits, quota_wait_s=a.quota_wait,
                                 log=lambda m: print(json.dumps({"wait": m}), file=sys.stderr, flush=True))
        with connect() as conn, conn.transaction():
            scn.record(conn, run_id, ent.id, r, s, started, sha)
        print(json.dumps({"run_id": run_id, "scenario": r.scenario, "status": r.status, "duration_ms": r.duration_ms,
                          "failures": r.failures, "note": r.note or None}), flush=True)
        rc |= r.status != "pass"
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
    cp.add_argument("--channel", choices=("api", "console"), default="api",
                    help="console = the console's own token for this person (needed to approve L3)")
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
    ks.add_argument("--reason", required=True, help="why (recorded with the change and in the ledger)")
    ks.set_defaults(fn=cmd_kill_switch)
    rs = sub.add_parser("set-reauth", help="set a person's re-authentication password, read from stdin")
    rs.add_argument("--name", required=True, help="human principal name")
    rs.add_argument("--actor", required=True, help="who is doing this (recorded in the ledger)")
    rs.set_defaults(fn=cmd_set_reauth)
    sc_ = sub.add_parser("set-channel", help="set where a principal's token is used (api or console)")
    sc_.add_argument("--name", required=True)
    sc_.add_argument("--channel", choices=("api", "console"), required=True)
    sc_.add_argument("--actor", required=True, help="who is doing this (recorded in the ledger)")
    sc_.set_defaults(fn=cmd_set_channel)
    dk = sub.add_parser("derive-source-key", help="write the gateway's data-source key derived from the master key")
    dk.add_argument("--out", required=True, help="new 0600 file for HYPERSOAR_SOURCE_KEY_FILE")
    dk.set_defaults(fn=cmd_derive_source_key)
    sub.add_parser("worker", help="run the Temporal alert worker").set_defaults(fn=cmd_worker)
    sub.add_parser("console-hash", help="hash a console password read from stdin").set_defaults(fn=cmd_console_hash)
    sa = sub.add_parser("synth-alerts", help="sandbox only: seeding bot, appends synthetic attack campaigns to a replay file")
    sa.add_argument("--out", required=True, help="replay NDJSON file read by the gateway")
    sa.add_argument("--interval", type=float, default=120.0, help="seconds between campaign steps")
    sa.add_argument("--count", type=int, default=0, help="stop after this many alerts (0 = run forever)")
    sa.add_argument("--seed", type=int, default=None)
    sa.set_defaults(fn=cmd_synth_alerts)
    ig = sub.add_parser("integration", help="Lark / Jira / 9router / data sources: seal a secret or run a connection test")
    isub = ig.add_subparsers(dest="icmd", required=True)
    ss = isub.add_parser("set-secret", help="read the secret value from stdin")
    ss.add_argument("--integration", choices=NAMES, required=True)
    ss.add_argument("--name", required=True)
    ss.add_argument("--actor", required=True, help="who is doing this (recorded in the ledger)")
    ss.set_defaults(fn=cmd_integration_set_secret)
    it = isub.add_parser("test", help="run the connection test; exit 1 unless every test passes")
    it.add_argument("--integration", choices=NAMES)
    it.add_argument("--actor", required=True)
    it.set_defaults(fn=cmd_integration_test)
    sc = sub.add_parser("scenario", help="sandbox only: end-to-end scenario runs (scenarios/*.yaml)")
    scsub = sc.add_subparsers(dest="scmd", required=True)
    sr = scsub.add_parser("run", help="play scenarios into the replay file; exit 1 unless every one passes")
    sr.add_argument("--replay", required=True, help="replay NDJSON file read by the gateway")
    sr.add_argument("--only", nargs="+", help="scenario ids (default: all)")
    sr.add_argument("--quota-wait", type=float, default=2100.0,
                    help="seconds to wait for a rate-limited action's hourly quota (default 35 min)")
    sr.add_argument("--actor", default="operator", help="recorded with the connection tests")
    sr.set_defaults(fn=cmd_scenario_run)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
