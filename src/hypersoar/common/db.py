from __future__ import annotations

import os
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

MIGRATIONS_DIR = Path(__file__).resolve().parents[3] / "migrations"


def make_pool(db_url: str, *, min_size: int = 1, max_size: int = 8) -> ConnectionPool:
    return ConnectionPool(
        db_url,
        min_size=min_size,
        max_size=max_size,
        kwargs={"row_factory": dict_row, "autocommit": False},
        open=True,
    )


def migrate(db_url: str, migrations_dir: Path = MIGRATIONS_DIR, *, mode: str | None = None,
            entity_id: str | None = None) -> list[str]:
    """Apply pending SQL migrations in filename order, each in its own transaction.

    Then records which mode and entity this database is for (HYPERSOAR_MODE / HYPERSOAR_ENTITY by
    default). A database already installed for another mode or entity is refused.
    """
    from hypersoar.common.config import ConfigError
    from hypersoar.common.entity import DEFAULT_ENTITY, ENTITY_ID_RE, current_mode

    mode = mode or current_mode()
    entity_id = entity_id or os.environ.get("HYPERSOAR_ENTITY", DEFAULT_ENTITY)
    if not ENTITY_ID_RE.match(entity_id):
        raise ConfigError("HYPERSOAR_ENTITY is not a valid entity id")
    applied: list[str] = []
    with psycopg.connect(db_url, autocommit=False) as conn:
        conn.execute("SELECT pg_advisory_lock(hashtext('deca_soar_migrate'))")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS public.deca_schema_migrations"
            " (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
        )
        conn.commit()
        done = {r[0] for r in conn.execute("SELECT version FROM public.deca_schema_migrations")}
        for path in sorted(migrations_dir.glob("*.sql")):
            if path.stem in done:
                continue
            with conn.transaction():
                conn.execute(path.read_text())
                conn.execute("INSERT INTO public.deca_schema_migrations(version) VALUES (%s)", (path.stem,))
            applied.append(path.stem)
        has_marker = conn.execute("SELECT to_regclass('public.hypersoar_install') IS NOT NULL").fetchone()[0]
        if has_marker:
            conn.execute(
                "INSERT INTO public.hypersoar_install (mode, entity_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (mode, entity_id),
            )
            row = conn.execute("SELECT mode, entity_id FROM public.hypersoar_install").fetchone()
            if tuple(row) != (mode, entity_id):
                conn.rollback()
                raise ConfigError(f"database is installed as {row[0]}/{row[1]}, not {mode}/{entity_id}")
        conn.execute("SELECT pg_advisory_unlock(hashtext('deca_soar_migrate'))")
        conn.commit()
    return applied
