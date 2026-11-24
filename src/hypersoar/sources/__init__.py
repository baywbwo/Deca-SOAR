"""Data-source connectors: how alerts from a SIEM or log service reach the gateway.

Each connector has a settings model (non-secret, versioned in broker.integration_config like Lark,
Jira and AI), the names of its sealed secrets, a connection test the broker runs, and a runtime the
gateway runs. Push connectors (generic webhook, syslog/CEF) land records in gateway.source_spool;
pull connectors (Alibaba Cloud SLS) are polled with a cursor. Either way a record is mapped to the
raw alert schema by its field map (mapping.py) and then normalised like any other alert.

Adding Splunk, Elastic, Wazuh, QRadar or Sentinel: usually a webhook (their alert action posts JSON)
or syslog/CEF with a field map is enough. A new pull connector is one module with a settings model,
a `test()` and a source class, registered in SPECS below plus a row in broker.connector_kind.
"""

from __future__ import annotations

from dataclasses import dataclass

from hypersoar.sources import models


@dataclass(frozen=True)
class Spec:
    name: str
    label: str
    model: type
    required_secrets: tuple[str, ...]
    optional_secrets: tuple[str, ...] = ()
    push: bool = False


SPECS: dict[str, Spec] = {
    "webhook": Spec("webhook", "Generic webhook (HMAC)", models.WebhookSettings, ("hmac_secret",), push=True),
    "syslog": Spec("syslog", "Syslog / CEF", models.SyslogSettings, (), push=True),
    "sls": Spec("sls", "Alibaba Cloud SLS", models.SlsSettings, ("access_key_id", "access_key_secret")),
}
NAMES = tuple(SPECS)


SAMPLE_CEF = ("<134>Nov 25 01:02:03 fw01 CEF:0|DECA|ConnectionTest|1.0|test.probe|Connection test|5|"
              "src=203.0.113.9 dhost=portal cnt=1")


def _probe(fields) -> bytes:
    """A sample alert shaped by the configured field map, so the test proves the map is consistent."""
    import json
    rec: dict = {}
    for key, value in (("rule_id", "test.probe"), ("severity", "medium"), ("src_ip", "203.0.113.9"),
                       ("detected_at", "2026-01-01T00:00:00Z")):
        path = getattr(fields, key)
        if not path:
            continue
        *parents, leaf = path.split(".")
        node = rec
        for p in parents:
            node = node.setdefault(p, {})
            if not isinstance(node, dict):  # two fields mapped onto overlapping paths
                break
        else:
            node.setdefault(leaf, value)
    return json.dumps(rec).encode()


def connection_test(name: str, settings, secrets: dict[str, str], transport=None) -> list[dict]:
    """Steps shown on the integration screen; the broker records the run. No secret value is echoed."""
    from hypersoar.sources import cef, mapping, webhook
    steps = [{"step": "settings valid", "ok": True}]
    if name == "sls":
        from hypersoar.sources.sls import SlsClient
        return SlsClient(settings, secrets, transport).test()
    if name == "webhook":
        secret = secrets.get("hmac_secret") or ""
        ok = len(secret) >= webhook.MIN_SECRET
        steps.append({"step": "HMAC secret set (32+ characters)", "ok": ok, "detail": None if ok else "hmac_secret"})
        if not ok:
            return steps
        body = _probe(settings.fields)
        try:
            webhook.verify(secret, "1700000000", webhook.sign(secret, 1700000000, body), body, 300,
                           webhook.SeenSignatures(), now=1700000000)
            steps.append({"step": "signed sample request verifies", "ok": True})
        except webhook.Rejected as e:
            steps.append({"step": "signed sample request verifies", "ok": False, "detail": str(e)})
            return steps
        sample = webhook.records(body)[0]
    else:  # syslog
        steps.append({"step": f"senders limited to {len(settings.allowed_senders)} network(s)", "ok": True})
        try:
            sample = cef.parse(SAMPLE_CEF)
        except cef.CefError as e:
            steps.append({"step": "sample CEF line parses", "ok": False, "detail": str(e)})
            return steps
    try:
        mapping.to_raw(sample, settings, f"{name}://test")
        steps.append({"step": "sample alert maps with this field map", "ok": True})
    except mapping.MappingError as e:
        steps.append({"step": "sample alert maps with this field map", "ok": False, "detail": str(e)})
    return steps
