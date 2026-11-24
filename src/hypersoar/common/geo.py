"""Local IP -> origin table (geo/origins.yaml). Pure lookup, no network."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from hypersoar.common.config import ConfigError
from hypersoar.common.pii import canonical_ip

MAP_W, MAP_H = 1200.0, 508.0


@dataclass(frozen=True)
class Origin:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    city: str
    country: str
    asn: str
    as_name: str
    tor: bool
    x: float
    y: float

    def public(self) -> dict:
        # Never the address or the block: only what the map and the case header show.
        return {"city": self.city, "country": self.country, "asn": self.asn, "as_name": self.as_name,
                "tor": self.tor, "xy": [self.x, self.y]}


def parse(doc: dict) -> tuple[Origin, ...]:
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise ConfigError("geo: version 1 expected")
    out = []
    for e in doc.get("origins") or []:
        try:
            net = ipaddress.ip_network(str(e["cidr"]), strict=True)
            x, y = (float(v) for v in e["xy"])
        except (KeyError, TypeError, ValueError) as err:
            raise ConfigError(f"geo: invalid entry {e.get('cidr')!r}") from err
        if not (0 <= x <= MAP_W and 0 <= y <= MAP_H):
            raise ConfigError(f"geo: {net} xy outside the map")
        out.append(Origin(net, str(e["city"]), str(e["country"]), str(e["asn"]), str(e["as_name"]),
                          bool(e.get("tor", False)), x, y))
    for i, a in enumerate(out):
        for b in out[i + 1:]:
            if a.network.version == b.network.version and a.network.overlaps(b.network):
                raise ConfigError(f"geo: {a.network} overlaps {b.network}")
    return tuple(out)


@lru_cache(maxsize=4)
def load(path: str | None = None) -> tuple[Origin, ...]:
    p = Path(path or os.environ.get("HYPERSOAR_GEO_FILE", "geo/origins.yaml"))
    try:
        return parse(yaml.safe_load(p.read_text()))
    except OSError:
        return ()


def lookup(ip: str, table: tuple[Origin, ...] | None = None) -> Origin | None:
    table = load() if table is None else table
    try:
        addr = canonical_ip(ip)
    except ValueError:
        return None
    return next((o for o in table if addr.version == o.network.version and addr in o.network), None)
