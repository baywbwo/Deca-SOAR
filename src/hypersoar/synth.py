"""Sandbox seeding bot: appends synthetic raw detections to the gateway's replay file.

Sandbox only (HYPERSOAR_MODE=sandbox): `run` refuses anything else. Every alert carries raw_ref
`synthetic://lab` and only documentation addresses (RFC 5737), so nothing here can be mistaken for,
or act on, a real system.

The bot plays campaigns, not single alerts. A campaign keeps one source IP, principal and AccessKey
and walks the kill chain a step at a time, so the gateway groups it into one case (G1), links the
entities (G2) and the console can replay the attack path with MITRE tactic and technique per hop:

  ak_lateral        leaked AccessKey: TA0001 -> TA0007 -> TA0008 -> TA0009, L2 AccessKey disable
  account_takeover  credential stuffing -> login after failures -> settlement export
  web_attack        path enumeration -> SQL injection burst, L1 WAF blacklist (shadow)
  ssh_bruteforce    SAS brute force on an ECS host
  protected_source  SQL injection from the protected range: the broker must refuse it
  benign_scan       a scanner the analyst would close (ground truth benign)

The origin IPs come from geo/origins.yaml blocks below 203.0.113.208, so the map shows a city and ASN.
203.0.113.208/28 and up are kept for `hypersoar scenario run`, which must not correlate with this feed.
"""

from __future__ import annotations

import json
import os
import random
import string
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

RAW_REF = "synthetic://lab"
SEED_HOSTS = (1, 206)        # 203.0.113.1-206: the geo blocks the seeding bot may use
URIS = ("/api/v1/qris/inquiry", "/api/v1/snap/token", "/login", "/api/v1/merchant/report", "/wp-admin/")
UAS = ("sqlmap/1.8", "python-requests/2.32", "Mozilla/5.0 (synthetic)", "curl/8.5")

# (rule_id, severity_hint, fixed fields, events range)
CAMPAIGNS: dict[str, tuple[tuple[str, str, dict, tuple[int, int]], ...]] = {
    "ak_lateral": (
        ("actiontrail.ak_unusual_ip", "critical", {}, (1, 3)),
        ("actiontrail.protected_asset_probe", "high", {"dst_asset": "ecs-pay-01"}, (2, 12)),
        ("actiontrail.ram.assume_role_denied", "high", {"dst_asset": "ram-console"}, (1, 6)),
        ("actiontrail.oss.bulk_read", "critical", {"dst_asset": "oss-backup"}, (20, 90)),
    ),
    "account_takeover": (
        ("waf.bot.credential_stuffing", "high", {"dst_asset": "merchant-login.qash"}, (200, 1500)),
        ("internal.portal.login_after_failures", "high", {"dst_asset": "merchant-login.qash"}, (1, 3)),
        ("internal.portal.settlement_export", "high", {"dst_asset": "portal.dob"}, (1, 2)),
    ),
    "web_attack": (
        ("waf.scan.path_enum", "medium", {"dst_asset": "portal.dob"}, (100, 900)),
        ("waf.sqli.burst", "high", {"dst_asset": "api.qash"}, (20, 300)),
    ),
    "ssh_bruteforce": (("sas.bruteforce", "medium", {"dst_asset": "ecs-web-02"}, (100, 900)),),
    "protected_source": (("waf.sqli.burst", "high", {"dst_asset": "api.qash"}, (20, 120)),),
    "benign_scan": (("waf.scan.path_enum", "low", {"dst_asset": "api.qash"}, (30, 120)),),
}
TRUTH = {"benign_scan": "benign"}
WEIGHTS = {"account_takeover": 20, "web_attack": 30, "ssh_bruteforce": 20, "protected_source": 10, "benign_scan": 20}
SERVICE_USERS = ("svc-settlement-report", "svc-recon-batch", "ci-deployer")
AK_EVERY_S = 7200            # ram.access_key.disable is limited to 1/hour: leave room for scenario runs
MAX_ACTIVE = 2


def _ak(rng: random.Random) -> str:
    return "LTAI5tSynth" + "".join(rng.choices(string.ascii_letters + string.digits, k=11))


@dataclass
class Campaign:
    kind: str
    ip: str
    principal: str
    ak: str
    svc: str
    step: int = 0
    due: float = 0.0
    steps: tuple = field(default=())

    @classmethod
    def start(cls, kind: str, rng: random.Random, now: float) -> Campaign:
        ip = (f"198.51.100.{rng.randint(1, 126)}" if kind == "protected_source"
              else f"203.0.113.{rng.randint(*SEED_HOSTS)}")
        return cls(kind, ip, f"m-{rng.randint(10000, 99999)}", _ak(rng), rng.choice(SERVICE_USERS), 0, now,
                   CAMPAIGNS[kind])

    @property
    def done(self) -> bool:
        return self.step >= len(self.steps)

    def next_alert(self, rng: random.Random, now: datetime) -> dict:
        rule_id, sev, fixed, (lo, hi) = self.steps[self.step]
        self.step += 1
        source = rule_id.split(".")[0]
        raw = {"detected_at": now.isoformat(), "raw_ref": RAW_REF, "source": source, "rule_id": rule_id,
               "severity_hint": sev, "src_ip": self.ip, "events": rng.randint(lo, hi), **fixed,
               "truth": TRUTH.get(self.kind, "malicious"), "campaign": self.kind}
        if source == "actiontrail":
            raw.update(principal=self.svc, access_key_id=self.ak)
        elif source == "internal":
            raw["principal"] = self.principal
        elif source == "waf":
            raw.update(uri=rng.choice(URIS), ua=rng.choice(UAS))
        return raw


class Seeder:
    """Deterministic for a given seed: the same campaign order and the same values."""

    def __init__(self, seed: int | None, step_gap_s: float, ak_every_s: float = AK_EVERY_S):
        self.rng = random.Random(seed)
        self.gap = step_gap_s
        self.ak_every = ak_every_s
        self.active: list[Campaign] = []
        self.last_ak: float | None = None

    def _start(self, now: float) -> None:
        if self.last_ak is None or now - self.last_ak >= self.ak_every:
            kind = "ak_lateral"
            self.last_ak = now
        else:
            kinds, weights = zip(*WEIGHTS.items())
            kind = self.rng.choices(kinds, weights=weights)[0]
        self.active.append(Campaign.start(kind, self.rng, now))

    def tick(self, now: float, at: datetime | None = None) -> list[dict]:
        at = at or datetime.now(UTC)
        while len(self.active) < MAX_ACTIVE:
            self._start(now)
        out = []
        for c in self.active:
            if c.due <= now and not c.done:
                out.append(c.next_alert(self.rng, at))
                c.due = now + self.gap
        self.active = [c for c in self.active if not c.done]
        return out


def append(path: Path, alerts: list[dict]) -> None:
    if not alerts:
        return
    data = "".join(json.dumps(a, separators=(",", ":")) + "\n" for a in alerts).encode()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
    try:
        os.write(fd, data)  # one write per batch: the gateway never sees half a line
        os.fsync(fd)
    finally:
        os.close(fd)


def run(path: Path, interval_s: float, count: int, seed: int | None, log=print, mode: str = "sandbox") -> int:
    if mode != "sandbox":
        raise RuntimeError("the seeding bot only runs with HYPERSOAR_MODE=sandbox")
    seeder = Seeder(seed, step_gap_s=interval_s)
    written = 0
    clock = 0.0
    while count == 0 or written < count:
        batch = seeder.tick(clock)
        if count:
            batch = batch[: count - written]
        append(path, batch)
        written += len(batch)
        for a in batch:
            log(json.dumps({"synthetic": True, "written": written, "campaign": a["campaign"], "rule": a["rule_id"]}))
        if count and written >= count:
            break
        time.sleep(interval_s)
        clock += interval_s
    return written
