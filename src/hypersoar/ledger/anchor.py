"""Sinks for ledger head anchors.

`file:<path>` appends one JSON line per anchor (0600, O_APPEND, fsync). On its own it is only as
trustworthy as the host it lives on, so in production Logtail ships every new line to an SLS
logstore the host cannot delete from (deploy/deca/sls, review N2). `sls-export:<path>` reads
anchors back from an export of that logstore for `verify-ledger --anchors`; it is read-only.
`sls:<project>/<logstore>` (direct API sink) is NOT implemented or tested in phase 0 and refuses to run.
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


class SlsExport:
    """Anchors read back from an SLS logstore export, the off-host copy that Logtail shipped.

    Accepts a JSON array or JSON lines. Each item is either an anchor record itself (fields parsed
    by Logtail, values possibly strings, since SLS stores every field as text) or carries the
    original line in `content`. The exact export layout has not been checked against real SLS yet;
    anything unrecognised is an error rather than silently skipped.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, record: dict) -> None:
        raise SinkError("sls-export: is read-only; Logtail ships anchors to SLS")

    def read(self) -> list[dict]:
        if not self.path.exists():
            raise SinkError("SLS export file not found")
        text = self.path.read_text().strip()
        try:
            items = json.loads(text) if text.startswith("[") else [json.loads(x) for x in text.splitlines() if x.strip()]
        except ValueError as e:
            raise SinkError("SLS export is not JSON / JSON lines") from e
        out = []
        for i, item in enumerate(items, 1):
            rec = item
            if isinstance(item, dict) and "head_hash" not in item and isinstance(item.get("content"), str):
                try:
                    rec = json.loads(item["content"])
                except ValueError as e:
                    raise SinkError(f"SLS export item {i}: content is not an anchor record") from e
            if not isinstance(rec, dict) or "head_hash" not in rec or "head_seq" not in rec:
                raise SinkError(f"SLS export item {i}: not an anchor record")
            try:
                seq = None if rec["head_seq"] in (None, "", "null") else int(rec["head_seq"])
            except (TypeError, ValueError) as e:
                raise SinkError(f"SLS export item {i}: head_seq is not an integer") from e
            out.append({**rec, "head_seq": seq, "head_hash": None if rec["head_hash"] in ("", "null") else rec["head_hash"]})
        return out


def open_sink(spec: str) -> FileSink | SlsSink | SlsExport:
    scheme, _, rest = spec.partition(":")
    if scheme == "file" and rest:
        return FileSink(Path(rest))
    if scheme == "sls-export" and rest:
        return SlsExport(Path(rest))
    if scheme == "sls" and rest:
        return SlsSink(rest)
    raise SinkError("anchor sink must be file:<path>, sls-export:<path> (read-only) or sls:<project>/<logstore>")
