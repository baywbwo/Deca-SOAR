"""Syslog lines carrying CEF (ArcSight Common Event Format), as sent by QRadar, Wazuh, FortiGate,
Imperva and most SIEM forwarders:

  <134>Nov 25 01:02:03 host CEF:0|Vendor|Product|1.0|SignatureID|Name|Severity|src=1.2.3.4 dst=...
"""

from __future__ import annotations

import re

MAX_LINE = 8192
_EXT_KEY = re.compile(r"(?:^|(?<=\s))([A-Za-z0-9_.]{1,63})=")


class CefError(ValueError):
    pass


def _split_header(s: str) -> list[str]:
    parts, cur, i = [], [], 0
    while i < len(s) and len(parts) < 7:
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in "|\\":
            cur.append(s[i + 1])
            i += 2
            continue
        if c == "|":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    if len(parts) < 7:
        raise CefError("CEF header needs 7 fields")
    parts.append(s[i:])
    return parts


def _unescape(v: str) -> str:
    return v.replace("\\=", "=").replace("\\n", "\n").replace("\\r", "\r").replace("\\\\", "\\").strip()


def parse(line: str) -> dict:
    """One record: the header fields plus every extension key (src, dst, suser, rt, cnt, request, ...)."""
    if len(line) > MAX_LINE:
        raise CefError("line too long")
    at = line.find("CEF:")
    if at < 0:
        raise CefError("not a CEF line")
    version, vendor, product, dev_version, sig, name, sev, ext = _split_header(line[at + 4:].strip())
    rec = {"cef_version": version, "device_vendor": vendor, "device_product": product,
           "device_version": dev_version, "signature_id": sig, "name": name, "severity": sev}
    keys = list(_EXT_KEY.finditer(ext))
    for n, m in enumerate(keys):
        end = keys[n + 1].start() if n + 1 < len(keys) else len(ext)
        k = m.group(1)
        if k not in rec:
            rec[k] = _unescape(ext[m.end():end])
        if len(rec) > 128:
            break
    return rec
