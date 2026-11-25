"""Entity config (entities/<id>.yaml): one install per company, sandbox and production targets.

The integration blocks are only the first version of each integration's settings: the broker copies
them into broker.integration_config on first start, and screen 08 edits them there. No credential is
ever in the file; secrets are set write-only through the broker and stored sealed.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from hypersoar.common.config import ConfigError

MODES = ("sandbox", "production")
ENTITY_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
PLACEHOLDER = "REPLACE"
DEFAULT_ENTITY = "dob"


def current_mode() -> str:
    """HYPERSOAR_MODE, cross-checked with HYPERSOAR_ENV: a production deployment is always production mode.
    There is no default: a service whose mode was left out must not quietly run as sandbox."""
    mode = os.environ.get("HYPERSOAR_MODE", "").strip()
    if not mode:
        raise ConfigError("HYPERSOAR_MODE is not set; set it to sandbox or production explicitly")
    if mode not in MODES:
        raise ConfigError("HYPERSOAR_MODE must be sandbox or production")
    if os.environ.get("HYPERSOAR_ENV") == "production" and mode != "production":
        raise ConfigError("HYPERSOAR_ENV=production requires HYPERSOAR_MODE=production")
    return mode


@dataclass(frozen=True)
class Asset:
    name: str
    kind: str
    criticality: int
    protected: bool = False
    instance_id: str | None = None


@dataclass(frozen=True)
class Integration:
    name: str
    target: str  # mock | live
    settings: dict


@dataclass(frozen=True)
class Entity:
    id: str
    name: str
    short: str
    timezone: str
    region: str
    region_label: str
    map_xy: tuple[float, float]
    window_s: int
    assets: dict[str, Asset]
    default_criticality: int
    mode: str
    alibaba_account: str
    waf_instance: str
    integrations: dict[str, Integration] = field(default_factory=dict)

    def criticality(self, asset: str | None) -> int:
        a = self.assets.get(asset or "")
        return a.criticality if a else self.default_criticality

    def asset_by_instance(self, instance_id: str | None) -> Asset | None:
        return next((a for a in self.assets.values() if instance_id and a.instance_id == instance_id), None)

    def placeholders(self) -> list[str]:
        out = [k for k, v in (("alibaba_account", self.alibaba_account), ("waf_instance", self.waf_instance))
               if PLACEHOLDER in v]
        for i in self.integrations.values():
            out += [f"{i.name}.{k}" for k, v in _flat(i.settings) if isinstance(v, str) and PLACEHOLDER in v]
        return out


def _flat(d, prefix: str = ""):
    if isinstance(d, dict):
        for k, v in d.items():
            yield from _flat(v, f"{prefix}{k}.")
    elif isinstance(d, list):
        for i, v in enumerate(d):
            yield from _flat(v, f"{prefix}{i}.")
    else:
        yield prefix.rstrip("."), d


SECRET_KEY_RE = re.compile(r"(token|secret|password|api_key|webhook|encrypt_key|_file)$")


def _no_secret_keys(name: str, value, path: str = "") -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            if SECRET_KEY_RE.search(str(k)):
                raise ConfigError(f"entity: {name}.{path}{k} looks like a secret; set it through the broker instead")
            _no_secret_keys(name, v, f"{path}{k}.")
    elif isinstance(value, list):
        for v in value:
            _no_secret_keys(name, v, path)


def _integration(name: str, raw: dict, mode: str) -> Integration:
    if not isinstance(raw, dict):
        raise ConfigError(f"entity: targets.{mode}.{name} must be a mapping")
    target = raw.get("target")
    if target not in ("mock", "live"):
        raise ConfigError(f"entity: {name}.target must be mock or live")
    if mode == "production" and target != "live":
        raise ConfigError(f"entity: production {name} cannot be a mock")
    settings = raw.get("settings")
    if not isinstance(settings, dict):
        raise ConfigError(f"entity: {name}.settings must be a mapping")
    _no_secret_keys(name, settings)
    return Integration(name=name, target=target, settings=settings)


def parse(doc: dict, mode: str) -> Entity:
    if mode not in MODES:
        raise ConfigError("mode must be sandbox or production")
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise ConfigError("entity: version 1 expected")
    eid = str(doc.get("id", ""))
    if not ENTITY_ID_RE.match(eid):
        raise ConfigError("entity: id must match ^[a-z][a-z0-9-]{0,31}$")
    cloud = doc.get("cloud") or {}
    assets = {}
    for a in doc.get("assets") or []:
        crit = int(a.get("criticality", 0))
        if not 1 <= crit <= 5:
            raise ConfigError(f"entity: asset {a.get('name')} criticality must be 1..5")
        assets[str(a["name"])] = Asset(str(a["name"]), str(a.get("kind", "other")), crit,
                                       bool(a.get("protected", False)), a.get("instance_id"))
    targets = (doc.get("targets") or {}).get(mode)
    if not isinstance(targets, dict):
        raise ConfigError(f"entity: targets.{mode} missing")
    integrations = {n: _integration(n, targets.get(n), mode) for n in ("jira", "lark", "ai")}
    window = int((doc.get("correlation") or {}).get("window_s", 3600))
    if not 60 <= window <= 7 * 86400:
        raise ConfigError("entity: correlation.window_s must be 60..604800")
    xy = cloud.get("map_xy") or [0, 0]
    return Entity(
        id=eid, name=str(doc.get("name", eid)), short=str(doc.get("short", eid.upper())),
        timezone=str(doc.get("timezone", "UTC")), region=str(cloud.get("region", "")),
        region_label=str(cloud.get("region_label", "")), map_xy=(float(xy[0]), float(xy[1])),
        window_s=window, assets=assets, default_criticality=int(doc.get("default_criticality", 2)),
        mode=mode, alibaba_account=str(targets.get("alibaba_account", "")),
        waf_instance=str(targets.get("waf_instance", "")), integrations=integrations,
    )


def entity_file() -> Path:
    path = os.environ.get("HYPERSOAR_ENTITY_FILE")
    if path:
        return Path(path)
    eid = os.environ.get("HYPERSOAR_ENTITY", DEFAULT_ENTITY)
    if not ENTITY_ID_RE.match(eid):
        raise ConfigError("HYPERSOAR_ENTITY is not a valid entity id")
    return Path(os.environ.get("HYPERSOAR_ENTITIES_DIR", "entities")) / f"{eid}.yaml"


def load(path: Path | None = None, mode: str | None = None) -> Entity:
    path = path or entity_file()
    try:
        doc = yaml.safe_load(path.read_text())
    except OSError as e:
        raise ConfigError(f"entity config {path.name} could not be read") from e
    return parse(doc, mode or current_mode())


def install_row(conn) -> dict | None:
    r = conn.execute("SELECT mode, entity_id FROM public.hypersoar_install").fetchone()
    if r is None:
        return None
    return dict(r) if isinstance(r, dict) else {"mode": r[0], "entity_id": r[1]}


def assert_install(conn, mode: str, entity_id: str) -> None:
    """Refuse to run against a database installed for the other mode or another entity."""
    row = install_row(conn)
    if row is None:
        raise ConfigError("database has no install marker; run `hypersoar migrate` with HYPERSOAR_MODE set")
    if row["mode"] != mode:
        raise ConfigError(f"database is a {row['mode']} install; this service runs in {mode} mode")
    if row["entity_id"] != entity_id:
        raise ConfigError("database belongs to another entity")
