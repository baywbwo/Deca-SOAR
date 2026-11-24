"""Entity config (entities/<id>.yaml): one install per company, sandbox and production targets.

Credentials are never in the file, only the names of files under HYPERSOAR_SECRETS_DIR.
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
SECRET_REF_RE = re.compile(r"^[a-z0-9_]{1,64}$")
PLACEHOLDER = "REPLACE"
DEFAULT_ENTITY = "dob"


def current_mode() -> str:
    """HYPERSOAR_MODE, cross-checked with HYPERSOAR_ENV: a production deployment is always production mode."""
    mode = os.environ.get("HYPERSOAR_MODE", "sandbox").strip()
    if mode not in MODES:
        raise ConfigError("HYPERSOAR_MODE must be sandbox or production")
    if os.environ.get("HYPERSOAR_ENV") == "production" and mode != "production":
        raise ConfigError("HYPERSOAR_ENV=production requires HYPERSOAR_MODE=production")
    return mode


def secrets_dir() -> Path:
    return Path(os.environ.get("HYPERSOAR_SECRETS_DIR", "/run/secrets"))


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
    mode: str  # mock | live
    settings: dict
    dispatch: str = "on"  # on | shadow (live only)

    def get(self, key: str, default=None):
        return self.settings.get(key, default)

    def secret_refs(self) -> dict[str, str]:
        return {k: v for k, v in self.settings.items() if k.endswith("_file")}

    def read_secret(self, key: str) -> str | None:
        ref = self.settings.get(key)
        if not ref:
            return None
        try:
            value = (secrets_dir() / ref).read_text().strip()
        except OSError:
            return None
        return value or None


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
            out += [f"{i.name}.{k}" for k, v in i.settings.items() if isinstance(v, str) and PLACEHOLDER in v]
        return out


def _integration(name: str, raw: dict, mode: str) -> Integration:
    if not isinstance(raw, dict):
        raise ConfigError(f"entity: targets.{mode}.{name} must be a mapping")
    im = raw.get("mode")
    if im not in ("mock", "live"):
        raise ConfigError(f"entity: {name}.mode must be mock or live")
    if mode == "production" and im != "live":
        raise ConfigError(f"entity: production {name} cannot be a mock")
    dispatch = raw.get("dispatch", "on")
    if dispatch not in ("on", "shadow"):
        raise ConfigError(f"entity: {name}.dispatch must be on or shadow")
    for k, v in raw.items():
        if k.endswith("_file") and not (isinstance(v, str) and SECRET_REF_RE.match(v)):
            raise ConfigError(f"entity: {name}.{k} must be a secret file name, not a path or a value")
        if re.search(r"(token|secret|password|api_key|webhook_url)$", k):
            raise ConfigError(f"entity: {name}.{k} looks like a secret value; use {k}_file")
    settings = {k: v for k, v in raw.items() if k not in ("mode", "dispatch")}
    return Integration(name=name, mode=im, settings=settings, dispatch=dispatch)


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
