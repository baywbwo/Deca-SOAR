"""The gateway's view of the data-source connectors configured for this entity and mode.

Settings and sealed secrets come from broker.source_config / broker.source_secret (data sources only)
and are re-read every cycle, so enabling, disabling or re-mapping a source on the integration screen
takes effect within one pull interval. A source whose settings do not validate or whose secrets do
not open is skipped and logged by name; the others keep running.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from hypersoar import sources
from hypersoar.broker.integrations import secretbox
from hypersoar.sources.spool import SpoolSource

log = logging.getLogger("hypersoar.gateway.connectors")
REFRESH_S = 15


@dataclass(frozen=True)
class Active:
    name: str
    version: int
    settings: object
    secrets: dict


class Connectors:
    def __init__(self, pool, entity_id: str, mode: str, box: secretbox.SecretBox | None, transports=None) -> None:
        self.pool = pool
        self.entity_id = entity_id
        self.mode = mode
        self.box = box
        self.transports = transports or {}
        self._active: dict[str, Active] = {}
        self._sources: dict[str, tuple[int, object]] = {}
        self._loaded_at = 0.0
        self._lock = threading.Lock()

    def refresh(self, force: bool = False) -> dict[str, Active]:
        with self._lock:
            if not force and time.monotonic() - self._loaded_at < REFRESH_S:
                return self._active
            active: dict[str, Active] = {}
            with self.pool.connection() as conn:
                rows = conn.execute(
                    "SELECT integration, target, enabled, settings, version FROM broker.source_config"
                    " WHERE entity_id = %s AND mode = %s AND enabled", (self.entity_id, self.mode)).fetchall()
                for r in rows:
                    spec = sources.SPECS.get(r["integration"])
                    if spec is None or r["target"] != "live":
                        continue
                    try:
                        model = spec.model.model_validate(r["settings"])
                        secrets = secretbox.get_secrets(conn, self.box, self.entity_id, spec.name, self.mode,
                                                        table="broker.source_secret")
                    except Exception as e:  # invalid settings or a secret that does not open
                        log.error("source %s v%s skipped: %s", spec.name, r["version"], type(e).__name__)
                        continue
                    active[spec.name] = Active(spec.name, r["version"], model, secrets)
            self._active = active
            self._loaded_at = time.monotonic()
            return active

    def get(self, name: str) -> Active | None:
        return self.refresh().get(name)

    def pull_sources(self) -> list:
        """AlertSources for the enabled connectors; an SLS client is rebuilt only when its version changes."""
        out = []
        for a in self.refresh().values():
            cached = self._sources.get(a.name)
            if cached and cached[0] == a.version:
                out.append(cached[1])
                continue
            if sources.SPECS[a.name].push:
                src = SpoolSource(self.entity_id, a.name, a.settings)
            else:
                from hypersoar.sources.sls import SlsClient, SlsSource
                src = SlsSource(SlsClient(a.settings, a.secrets, self.transports.get(a.name)), name=a.name)
            self._sources[a.name] = (a.version, src)
            out.append(src)
        return out
