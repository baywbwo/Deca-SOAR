from __future__ import annotations

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


def migrate(db_url: str, migrations_dir: Path = MIGRATIONS_DIR) -> list[str]:
    """Apply pending SQL migrations in filename order, each in its own transaction."""
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
        conn.execute("SELECT pg_advisory_unlock(hashtext('deca_soar_migrate'))")
        conn.commit()
    return applied
