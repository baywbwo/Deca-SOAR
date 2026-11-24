"""Synthetic alert generator for the lab: appends raw detections to the gateway's replay file.

Every alert carries raw_ref `synthetic://lab` and only documentation addresses (RFC 5737), so
nothing here can be mistaken for, or act on, a real system. The mix exercises each broker path:
  waf high from 203.0.113.0/24      -> verdict malicious, request validated (shadow, not executed)
  waf high from 198.51.100.0/24     -> rejected: protected target (protected.yaml)
  waf medium                        -> verdict suspicious, rejected: verdict not allowed
  sas low                           -> no broker request (non-WAF)
"""

from __future__ import annotations

import json
import os
import random
import time
from datetime import UTC, datetime
from pathlib import Path

RAW_REF = "synthetic://lab"
URIS = ("/api/v1/qris/inquiry", "/api/v1/snap/token", "/login", "/api/v1/merchant/report", "/wp-admin/")
UAS = ("sqlmap/1.8", "python-requests/2.32", "Mozilla/5.0 (synthetic)", "curl/8.5")
MIX = (("waf_block", 50), ("waf_protected", 15), ("waf_medium", 15), ("sas_low", 20))


def make_alert(kind: str, rng: random.Random, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    base = {"detected_at": now.isoformat(), "raw_ref": RAW_REF, "events": rng.randint(20, 900)}
    if kind == "waf_block":
        return {**base, "source": "waf", "rule_id": "waf.sqli.burst", "severity_hint": "high",
                "src_ip": f"203.0.113.{rng.randint(1, 254)}", "uri": rng.choice(URIS), "ua": rng.choice(UAS)}
    if kind == "waf_protected":
        return {**base, "source": "waf", "rule_id": "waf.sqli.burst", "severity_hint": "high",
                "src_ip": f"198.51.100.{rng.randint(1, 254)}", "uri": rng.choice(URIS), "ua": rng.choice(UAS)}
    if kind == "waf_medium":
        return {**base, "source": "waf", "rule_id": "waf.scan.path_enum", "severity_hint": "medium",
                "src_ip": f"203.0.113.{rng.randint(1, 254)}", "uri": rng.choice(URIS), "ua": rng.choice(UAS)}
    if kind == "sas_low":
        return {**base, "source": "sas", "rule_id": "sas.bruteforce", "severity_hint": "low",
                "src_ip": f"203.0.113.{rng.randint(1, 254)}", "dst_asset": "ecs-lab-synthetic"}
    raise ValueError(kind)


def pick(rng: random.Random) -> str:
    kinds, weights = zip(*MIX)
    return rng.choices(kinds, weights=weights)[0]


def append(path: Path, alerts: list[dict]) -> None:
    data = "".join(json.dumps(a, separators=(",", ":")) + "\n" for a in alerts).encode()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
    try:
        os.write(fd, data)  # one write per batch: the gateway never sees half a line
        os.fsync(fd)
    finally:
        os.close(fd)


def run(path: Path, interval_s: float, count: int, seed: int | None, log=print) -> int:
    rng = random.Random(seed)
    written = 0
    # Each kind once at start, so every path is visible right away.
    first = [make_alert(k, rng) for k, _ in MIX]
    append(path, first)
    written += len(first)
    log(json.dumps({"synthetic": True, "written": written}))
    while count == 0 or written < count:
        time.sleep(interval_s)
        batch = [make_alert(pick(rng), rng)]
        append(path, batch)
        written += 1
        log(json.dumps({"synthetic": True, "written": written, "kind_rule": batch[0]["rule_id"]}))
    return written
