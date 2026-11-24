"""Start-up check of the database login (review N4).

Each service logs in as its own user, a member of exactly one NOLOGIN group role from migration
0002. Before doing any work it checks that this login cannot do more than that group needs: no
superuser or other role attributes, no membership in the owner (or any other role), no object
ownership and no table, sequence, schema or database privilege outside the expected set. A login
that fails any check makes the process refuse to start, so a mistakenly configured owner or admin
DSN never reaches a running service. There is no switch to turn this off.
"""

from __future__ import annotations

from deca_soar.common.config import ConfigError

DECA_SCHEMAS = ("gateway", "vault", "broker", "ledger")
TABLE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")

# service -> (group role, {table: table-level privileges}). Column-level grants (vault.token_map
# SELECT(token) for the gateway, ledger.entry INSERT without seq) do not show at table level.
EXPECTED: dict[str, tuple[str, dict[str, set[str]]]] = {
    "gateway": ("deca_soar_gateway", {
        "gateway.ingest_cursor": {"SELECT", "INSERT", "UPDATE"},
        "gateway.inbox_event": {"SELECT", "INSERT", "UPDATE"},
        "vault.token_map": {"INSERT"},
        "ledger.entry": {"SELECT"},
    }),
    "broker": ("deca_soar_broker", {
        "gateway.inbox_event": {"SELECT"},
        "vault.token_map": {"SELECT"},
        "broker.principal": {"SELECT"},
        "broker.decision_record": {"SELECT", "INSERT"},
        "broker.action_request": {"SELECT", "INSERT", "UPDATE"},
        "broker.kill_switch": {"SELECT", "INSERT", "UPDATE"},
        "ledger.entry": {"SELECT"},
    }),
    "auditor": ("deca_soar_auditor", {
        "ledger.entry": {"SELECT"},
    }),
}

LEDGER_WRITERS = ("gateway", "broker")


def login_problems(conn, service: str) -> list[str]:
    """Everything this login may do beyond what `service` needs; empty when it is least-privilege."""
    group, tables = EXPECTED[service]
    problems: list[str] = []

    def rows(sql: str, params=()):
        return [tuple(r.values()) if isinstance(r, dict) else tuple(r) for r in conn.execute(sql, params).fetchall()]

    (user, superuser, createrole, createdb, bypassrls, replication), = rows(
        "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication"
        " FROM pg_roles WHERE rolname = current_user"
    )
    for name, value in (("SUPERUSER", superuser), ("CREATEROLE", createrole), ("CREATEDB", createdb),
                        ("BYPASSRLS", bypassrls), ("REPLICATION", replication)):
        if value:
            problems.append(f"login has {name}")

    # Includes indirect membership and pg_database_owner (true when the login owns the database).
    member_of = {r[0] for r in rows(
        "SELECT rolname FROM pg_roles WHERE rolname <> current_user"
        " AND pg_has_role(current_user, oid, 'MEMBER')"
    )}
    if group not in member_of:
        problems.append(f"login is not a member of {group}")
    for extra in sorted(member_of - {group}):
        problems.append(f"login is a member of {extra}")

    for (obj,) in rows(
        "SELECT n.nspname FROM pg_namespace n WHERE n.nspname = ANY(%s)"
        " AND pg_has_role(current_user, n.nspowner, 'MEMBER')"
        " UNION ALL SELECT n.nspname || '.' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
        " WHERE n.nspname = ANY(%s) AND pg_has_role(current_user, c.relowner, 'MEMBER')"
        " UNION ALL SELECT current_database() FROM pg_database d"
        " WHERE d.datname = current_database() AND pg_has_role(current_user, d.datdba, 'MEMBER')",
        (list(DECA_SCHEMAS), list(DECA_SCHEMAS)),
    ):
        problems.append(f"login owns {obj}")

    privs = list(TABLE_PRIVILEGES)
    if rows("SELECT 1 WHERE current_setting('server_version_num')::int >= 170000"):
        privs.append("MAINTAIN")
    for table, priv in rows(
        "SELECT n.nspname || '.' || c.relname, p FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
        " CROSS JOIN unnest(%s::text[]) p"
        " WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')"
        " AND (n.nspname = ANY(%s) OR (n.nspname = 'public' AND c.relname = 'deca_schema_migrations'))"
        " AND has_table_privilege(c.oid, p)",
        (privs, list(DECA_SCHEMAS)),
    ):
        if priv not in tables.get(table, set()):
            problems.append(f"login has {priv} on {table}")

    for seq, priv in rows(
        "SELECT n.nspname || '.' || c.relname, p FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
        " CROSS JOIN unnest(ARRAY['USAGE', 'SELECT', 'UPDATE']) p"
        " WHERE c.relkind = 'S' AND n.nspname = ANY(%s) AND has_sequence_privilege(c.oid, p)",
        (list(DECA_SCHEMAS),),
    ):
        if not (priv == "USAGE" and seq == "ledger.entry_seq_seq" and service in LEDGER_WRITERS):
            problems.append(f"login has {priv} on sequence {seq}")

    for (schema,) in rows(
        "SELECT s FROM unnest(%s::text[]) s WHERE has_schema_privilege(s, 'CREATE')",
        (list(DECA_SCHEMAS) + ["public"],),
    ):
        problems.append(f"login can CREATE in schema {schema}")
    if rows("SELECT 1 WHERE has_database_privilege(current_database(), 'CREATE')"):
        problems.append("login can CREATE schemas in the database")

    if rows("SELECT 1 WHERE has_column_privilege('ledger.entry', 'seq', 'INSERT')"
            " OR has_column_privilege('ledger.entry', 'seq', 'UPDATE')"):
        problems.append("login can write ledger.entry.seq explicitly")
    if service == "gateway" and rows(
        "SELECT 1 WHERE has_column_privilege('vault.token_map', 'ciphertext', 'SELECT')"
    ):
        problems.append("gateway login can read vault ciphertext")

    return [f"{user}: {p}" for p in problems]


def assert_least_privilege_login(conn, service: str) -> None:
    problems = login_problems(conn, service)
    if problems:
        raise ConfigError(
            f"{service} database login has more privilege than it needs; refusing to start: " + "; ".join(problems)
        )
