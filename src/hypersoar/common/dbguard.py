"""Start-up check of the database login (review N4).

Each service logs in as its own user, a member of exactly one NOLOGIN group role from migration
0002. Before doing any work it checks that this login cannot do more than that group needs: no
superuser or other role attributes, no membership in the owner (or any other role), no object
ownership and no table, column, sequence, function, schema or database privilege outside the
expected set. The session user must be the current user: a login that only switched role (for
example `options=-c role=...` in the DSN) could `RESET ROLE` back to its own rights (review N8).
A login that fails any check makes the process refuse to start, so a mistakenly configured owner
or admin DSN never reaches a running service. There is no switch to turn this off.
"""

from __future__ import annotations

from hypersoar.common.config import ConfigError

HYPERSOAR_SCHEMAS = ("gateway", "vault", "broker", "ledger", "qa")
TABLE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")

# service -> (group role, {table: table-level privileges}). Column-level grants are in EXPECTED_COLUMNS.
EXPECTED: dict[str, tuple[str, dict[str, set[str]]]] = {
    "gateway": ("deca_soar_gateway", {
        "gateway.ingest_cursor": {"SELECT", "INSERT", "UPDATE"},
        "gateway.inbox_event": {"SELECT", "INSERT", "UPDATE"},
        "gateway.alert_case": {"SELECT", "INSERT", "UPDATE"},
        "gateway.case_alert": {"SELECT", "INSERT", "UPDATE"},
        "gateway.case_key": {"SELECT", "INSERT", "UPDATE"},
        "gateway.entity_relation": {"SELECT", "INSERT", "UPDATE"},
        "gateway.case_step": {"SELECT", "INSERT", "UPDATE"},
        "vault.token_map": {"INSERT"},
        "ledger.entry": {"SELECT"},
        "public.hypersoar_install": {"SELECT"},
    }),
    "broker": ("deca_soar_broker", {
        "gateway.inbox_event": {"SELECT"},
        "vault.token_map": {"SELECT"},
        "broker.principal": {"SELECT"},
        "broker.decision_record": {"SELECT", "INSERT"},
        "broker.action_request": {"SELECT", "INSERT", "UPDATE"},
        "broker.kill_switch": {"SELECT", "INSERT", "UPDATE"},
        "gateway.alert_case": {"SELECT"},
        "gateway.case_alert": {"SELECT"},
        "gateway.case_step": {"SELECT"},
        "gateway.entity_relation": {"SELECT"},
        "broker.integration_call": {"SELECT", "INSERT"},
        "broker.integration_config_version": {"SELECT", "INSERT"},
        "broker.integration_test_run": {"SELECT", "INSERT"},
        "broker.jira_issue": {"SELECT", "INSERT", "UPDATE"},
        "broker.integration_config": {"SELECT", "INSERT", "UPDATE"},
        "broker.integration_secret": {"SELECT", "INSERT", "UPDATE"},
        "broker.ai_usage": {"SELECT", "INSERT", "UPDATE"},
        "qa.scenario_run": {"SELECT", "INSERT"},
        "ledger.entry": {"SELECT"},
        "public.hypersoar_install": {"SELECT"},
    }),
    "auditor": ("deca_soar_auditor", {
        "ledger.entry": {"SELECT"},
    }),
    # Read-only SOC console (migration 0004).
    "console": ("deca_soar_viewer", {
        "gateway.inbox_event": {"SELECT"},
        "broker.decision_record": {"SELECT"},
        "broker.action_request": {"SELECT"},
        "broker.kill_switch": {"SELECT"},
        "gateway.alert_case": {"SELECT"},
        "gateway.case_alert": {"SELECT"},
        "gateway.case_key": {"SELECT"},
        "gateway.entity_relation": {"SELECT"},
        "gateway.case_step": {"SELECT"},
        "broker.integration_call": {"SELECT"},
        "broker.jira_issue": {"SELECT"},
        "broker.integration_config": {"SELECT"},
        "broker.integration_config_version": {"SELECT"},
        "broker.integration_test_run": {"SELECT"},
        "broker.ai_usage": {"SELECT"},
        "qa.scenario_run": {"SELECT"},
        "ledger.entry": {"SELECT"},
        "public.hypersoar_install": {"SELECT"},
    }),
}

LEDGER_WRITERS = ("gateway", "broker")
COLUMN_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "REFERENCES")
LEDGER_INSERT_COLUMNS = (
    "recorded_at", "event_type", "actor", "payload", "canonical", "prev_hash", "hash", "entity_id",
)

# service -> {(table, column, privilege)} granted per column (migrations 0002 and 0003), on top of EXPECTED.
EXPECTED_COLUMNS: dict[str, set[tuple[str, str, str]]] = {
    "gateway": {("vault.token_map", "token", "SELECT")}
               | {("ledger.entry", c, "INSERT") for c in LEDGER_INSERT_COLUMNS},
    "broker": {("ledger.entry", c, "INSERT") for c in LEDGER_INSERT_COLUMNS},
    "auditor": set(),
    "console": {("broker.integration_secret", c, "SELECT") for c in (
        "entity_id", "integration", "mode", "name", "key_id", "rotated_at", "rotated_by", "expires_at")},
}


def login_problems(conn, service: str) -> list[str]:
    """Everything this login may do beyond what `service` needs; empty when it is least-privilege."""
    group, tables = EXPECTED[service]
    problems: list[str] = []

    def rows(sql: str, params=()):
        return [tuple(r.values()) if isinstance(r, dict) else tuple(r) for r in conn.execute(sql, params).fetchall()]

    (user, session), = rows("SELECT current_user::text, session_user::text")
    if session != user:
        problems.append(f"session user {session} switched to {user}; RESET ROLE would regain {session}'s rights")

    # Attributes and memberships of the session user too: that is what RESET ROLE returns to.
    for login in dict.fromkeys((user, session)):
        who = "login" if login == user else f"session user {login}"
        (superuser, createrole, createdb, bypassrls, replication), = rows(
            "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication"
            " FROM pg_roles WHERE rolname = %s",
            (login,),
        )
        for name, value in (("SUPERUSER", superuser), ("CREATEROLE", createrole), ("CREATEDB", createdb),
                            ("BYPASSRLS", bypassrls), ("REPLICATION", replication)):
            if value:
                problems.append(f"{who} has {name}")

        # Includes indirect membership and pg_database_owner (true when the login owns the database).
        member_of = {r[0] for r in rows(
            "SELECT rolname FROM pg_roles WHERE rolname <> %s AND pg_has_role(%s::name, oid, 'MEMBER')",
            (login, login),
        )}
        if login == user and group not in member_of:
            problems.append(f"login is not a member of {group}")
        for extra in sorted(member_of - {group}):
            problems.append(f"{who} is a member of {extra}")

    for (obj,) in rows(
        "SELECT n.nspname FROM pg_namespace n WHERE n.nspname = ANY(%s)"
        " AND pg_has_role(current_user, n.nspowner, 'MEMBER')"
        " UNION ALL SELECT n.nspname || '.' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
        " WHERE n.nspname = ANY(%s) AND pg_has_role(current_user, c.relowner, 'MEMBER')"
        " UNION ALL SELECT current_database() FROM pg_database d"
        " WHERE d.datname = current_database() AND pg_has_role(current_user, d.datdba, 'MEMBER')",
        (list(HYPERSOAR_SCHEMAS), list(HYPERSOAR_SCHEMAS)),
    ):
        problems.append(f"login owns {obj}")

    privs = list(TABLE_PRIVILEGES)
    if rows("SELECT 1 WHERE current_setting('server_version_num')::int >= 170000"):
        privs.append("MAINTAIN")
    for table, priv in rows(
        "SELECT n.nspname || '.' || c.relname, p FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
        " CROSS JOIN unnest(%s::text[]) p"
        " WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')"
        " AND (n.nspname = ANY(%s)"
        "      OR (n.nspname = 'public' AND c.relname IN ('deca_schema_migrations', 'hypersoar_install')))"
        " AND has_table_privilege(c.oid, p)",
        (privs, list(HYPERSOAR_SCHEMAS)),
    ):
        if priv not in tables.get(table, set()):
            problems.append(f"login has {priv} on {table}")

    # Column grants: has_column_privilege is also true through a table-level grant, already checked above.
    expected_columns = EXPECTED_COLUMNS[service]
    for table, column, priv in rows(
        "SELECT n.nspname || '.' || c.relname, a.attname::text, p FROM pg_class c"
        " JOIN pg_namespace n ON n.oid = c.relnamespace"
        " JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped"
        " CROSS JOIN unnest(%s::text[]) p"
        " WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname = ANY(%s)"
        " AND has_column_privilege(c.oid, a.attnum, p) AND NOT has_table_privilege(c.oid, p)",
        (list(COLUMN_PRIVILEGES), list(HYPERSOAR_SCHEMAS)),
    ):
        if (table, column, priv) not in expected_columns:
            problems.append(f"login has {priv}({column}) on {table}")

    # No service calls functions; a SECURITY DEFINER one would run with its owner's rights.
    for (func,) in rows(
        "SELECT n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'"
        " FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
        " WHERE (n.nspname = ANY(%s) OR (n.nspname = 'public' AND p.prosecdef))"
        " AND p.prokind IN ('f', 'p') AND has_function_privilege(p.oid, 'EXECUTE')",
        (list(HYPERSOAR_SCHEMAS),),
    ):
        problems.append(f"login can EXECUTE {func}")

    for seq, priv in rows(
        "SELECT n.nspname || '.' || c.relname, p FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
        " CROSS JOIN unnest(ARRAY['USAGE', 'SELECT', 'UPDATE']) p"
        " WHERE c.relkind = 'S' AND n.nspname = ANY(%s) AND has_sequence_privilege(c.oid, p)",
        (list(HYPERSOAR_SCHEMAS),),
    ):
        if not (priv == "USAGE" and seq == "ledger.entry_seq_seq" and service in LEDGER_WRITERS):
            problems.append(f"login has {priv} on sequence {seq}")

    for (schema,) in rows(
        "SELECT s FROM unnest(%s::text[]) s WHERE has_schema_privilege(s, 'CREATE')",
        (list(HYPERSOAR_SCHEMAS) + ["public"],),
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
