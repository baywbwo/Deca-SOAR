"""gateway.source_spool: records pushed by a webhook or syslog sender wait here until the next pull.

The pull takes and deletes rows in the same transaction that writes the inbox, so a crash keeps the
rows and a commit never leaves them behind (no cursor, so no record is skipped when two inserts
commit out of order). A full spool refuses new records instead of growing without bound.
"""

from __future__ import annotations

from datetime import datetime

from psycopg.types.json import Jsonb

from hypersoar.sources import mapping
from hypersoar.sources.models import SourceSettings

MAX_PENDING = 50_000


class SpoolFull(RuntimeError):
    pass


def pending(conn, entity_id: str, connector: str) -> int:
    return conn.execute(
        "SELECT count(*) AS n FROM (SELECT 1 FROM gateway.source_spool WHERE entity_id = %s AND connector = %s"
        " LIMIT %s) s", (entity_id, connector, MAX_PENDING)).fetchone()["n"]


def put(conn, entity_id: str, connector: str, records: list[dict]) -> int:
    if pending(conn, entity_id, connector) + len(records) > MAX_PENDING:
        raise SpoolFull(connector)
    with conn.cursor() as cur:
        cur.executemany("INSERT INTO gateway.source_spool (entity_id, connector, record) VALUES (%s, %s, %s)",
                        [(entity_id, connector, Jsonb(r)) for r in records])
    return len(records)


class SpoolSource:
    """AlertSource over the spool of one push connector. Settings are read per pull, so a new field
    map applies to everything not yet pulled."""

    uses_conn = True

    def __init__(self, entity_id: str, connector: str, settings: SourceSettings) -> None:
        self.entity_id = entity_id
        self.connector = connector
        self.settings = settings
        self.name = connector

    def pull(self, cursor: str | None, limit: int, conn=None) -> tuple[list[dict], str]:
        # No FOR UPDATE (that needs the UPDATE grant): the DELETE locks the rows itself, and a second
        # pull running at the same time skips rows the first one already deleted.
        rows = conn.execute(
            "DELETE FROM gateway.source_spool WHERE spool_id IN (SELECT spool_id FROM gateway.source_spool"
            " WHERE entity_id = %s AND connector = %s ORDER BY spool_id LIMIT %s)"
            " RETURNING spool_id, record, received_at",
            (self.entity_id, self.connector, limit)).fetchall()
        out = []
        for r in sorted(rows, key=lambda x: x["spool_id"]):
            out.append(map_record(r["record"], self.settings, f"{self.connector}://{r['spool_id']}",
                                  r["received_at"]))
        return out, cursor or ""


def map_record(record, settings: SourceSettings, ref: str, received_at: datetime | None = None) -> dict:
    try:
        return mapping.to_raw(record, settings, ref, received_at)
    except mapping.MappingError as e:
        return {"_invalid": True, "_reason": str(e)}
