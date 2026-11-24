"""Sinks for daily ledger head anchors.

`file:<path>` appends one JSON line per anchor (0600, O_APPEND, fsync). It is the phase 0
stand-in and only as trustworthy as the host it lives on. `sls:<project>/<logstore>` is the
production target (a logstore SOAR can write but not delete); it is NOT implemented or tested
against SLS in phase 0 and refuses to run.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


class SinkError(RuntimeError):
    pass


class FileSink:
    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, record: dict) -> None:
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (json.dumps(record, sort_keys=True) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    def read(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for i, line in enumerate(self.path.read_text().splitlines(), 1):
            if line.strip():
                try:
                    out.append(json.loads(line))
                except ValueError as e:
                    raise SinkError(f"anchor file line {i} is not valid JSON") from e
        return out


class SlsSink:
    def __init__(self, target: str) -> None:
        self.target = target

    def append(self, record: dict) -> None:
        raise SinkError("SLS anchor sink is not implemented or tested in phase 0; use file: until phase 1")

    def read(self) -> list[dict]:
        raise SinkError("SLS anchor sink is not implemented or tested in phase 0; use file: until phase 1")


def open_sink(spec: str) -> FileSink | SlsSink:
    scheme, _, rest = spec.partition(":")
    if scheme == "file" and rest:
        return FileSink(Path(rest))
    if scheme == "sls" and rest:
        return SlsSink(rest)
    raise SinkError("anchor sink must be file:<path> or sls:<project>/<logstore>")
