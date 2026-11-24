"""Map an incoming record (JSON from a webhook, a parsed CEF line, an SLS log) to the raw alert
schema normalize() reads. Everything in a record is untrusted: values are looked up by the reviewed
field map only, coerced to strings and clipped; nothing else in the record is passed on."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from hypersoar.sources.models import SourceSettings

VALUE_MAX = 1024
_RULE_BAD = re.compile(r"[^a-z0-9_.]+")
# CEF and most SIEMs use 0-10; Wazuh uses 0-15 (anything above 10 is critical here).
_NUMERIC = ((3, "low"), (6, "medium"), (8, "high"))
_WORDS = {"informational": "info", "info": "info", "low": "low", "medium": "medium", "moderate": "medium",
          "high": "high", "very-high": "critical", "very high": "critical", "critical": "critical"}


class MappingError(ValueError):
    pass


def lookup(record: dict, path: str | None):
    if not path:
        return None
    if path in record:  # flat keys may contain dots ("data.srcip" in an SLS log)
        return record[path]
    cur = record
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _text(v) -> str | None:
    if v is None or isinstance(v, (dict, list)):
        return None
    s = str(v).strip()
    return s[:VALUE_MAX] if s else None


def severity(value, overrides: dict[str, str]) -> str:
    s = _text(value)
    if s is None:
        return "medium"
    low = s.lower()
    if low in overrides:
        return overrides[low]
    if low in _WORDS:
        return _WORDS[low]
    try:
        n = float(low)
    except ValueError:
        return "medium"
    for limit, sev in _NUMERIC:
        if n <= limit:
            return sev
    return "critical"


def timestamp(value, received_at: datetime) -> str:
    """ISO time of the detection. Epoch seconds or milliseconds and ISO 8601 are understood; a missing
    or unreadable time becomes the time the record arrived."""
    s = _text(value)
    if s is None:
        return received_at.isoformat()
    try:
        if re.fullmatch(r"[0-9]{9,13}(\.[0-9]+)?", s):
            n = float(s)
            return datetime.fromtimestamp(n / 1000 if n > 1e11 else n, UTC).isoformat()
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).isoformat()
    except (ValueError, OverflowError, OSError):
        return received_at.isoformat()


def rule_id(value, prefix: str) -> str:
    s = _text(value)
    if s is None:
        raise MappingError("record has no rule id")
    rid = _RULE_BAD.sub("_", s.lower()).strip("._")
    rid = f"{prefix}{rid}" if prefix else rid
    if not rid or len(rid) > 64:
        raise MappingError("rule id is empty or longer than 64 characters")
    return rid


def to_raw(record: dict, s: SourceSettings, raw_ref: str, received_at: datetime | None = None) -> dict:
    if not isinstance(record, dict):
        raise MappingError("record is not an object")
    received_at = received_at or datetime.now(UTC)
    f = s.fields
    raw = {
        "source": s.source_type,
        "rule_id": rule_id(lookup(record, f.rule_id), s.rule_prefix),
        "severity_hint": severity(lookup(record, f.severity), s.severity_map),
        "detected_at": timestamp(lookup(record, f.detected_at), received_at),
        "raw_ref": raw_ref[:512],
    }
    for key in ("src_ip", "principal", "access_key_id", "dst_asset", "uri", "ua"):
        v = _text(lookup(record, getattr(f, key)))
        if v is not None:
            raw[key] = v
    if raw.get("src_ip"):
        import ipaddress
        try:
            ipaddress.ip_address(raw["src_ip"])
        except ValueError:
            del raw["src_ip"]  # a host name or junk is not a blockable address
    ev = _text(lookup(record, f.events))
    if ev and ev.isdigit():
        raw["events"] = min(int(ev), 1_000_000)
    return raw
