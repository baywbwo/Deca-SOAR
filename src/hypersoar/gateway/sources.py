"""Pull sources. Phase 0 ships a replay-file source; the SLS source arrives in phase 1."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol


class AlertSource(Protocol):
    name: str

    def pull(self, cursor: str | None, limit: int) -> tuple[list[dict], str]:
        """Return up to `limit` raw results after `cursor`, and the new cursor."""
        ...


class ReplayFileSource:
    """NDJSON file, one raw detection result per line. Cursor = number of lines consumed.

    Simulates the SLS pull: the gateway asks for anything newer than its saved cursor.
    Appending lines to the file makes them visible on the next pull.
    """

    def __init__(self, path: Path, name: str = "replay") -> None:
        self.path = path
        self.name = name

    def pull(self, cursor: str | None, limit: int) -> tuple[list[dict], str]:
        start = int(cursor or 0)
        out: list[dict] = []
        consumed = start
        with self.path.open() as f:
            for i, line in enumerate(f):
                if i < start:
                    continue
                if len(out) >= limit:
                    break
                consumed = i + 1
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    obj = None
                if not isinstance(obj, dict):
                    obj = {"_invalid": True, "_line": i + 1}
                out.append(obj)
        return out, str(consumed)
