"""Starting field maps for the "Add integration" catalog on screen 08.

A preset is not a new connector: it fills the settings draft of an existing one (the generic webhook for
a SIEM, the SLS pull for an Alibaba log type) and the person reviews and saves it like any other change.
Each preset carries a sample record in the shape that tool sends, and the tests map every sample with
its preset, so a preset that cannot produce an alert never reaches the screen. Real payloads vary with
how the sender is set up; the connection test (and, for SLS, the latest log) is the check that counts.
"""

from __future__ import annotations

from hypersoar.sources import models


def _p(label: str, connector: str, blurb: str, settings: dict, sample: dict) -> dict:
    # Every field-map key is spelled out (None = not mapped), so applying a preset replaces the whole map.
    fields = {k: settings["fields"].get(k) for k in models.FieldMap.model_fields}
    return {"label": label, "connector": connector, "blurb": blurb, "settings": {**settings, "fields": fields},
            "sample": sample}


PRESETS: dict[str, dict] = {
    # -- SIEMs that post alerts to the generic webhook ---------------------------------------------------
    "splunk": _p("Splunk", "webhook", "Alert action: Webhook, one POST per triggered alert", {
        "source_type": "siem", "rule_prefix": "splunk.",
        "fields": {"rule_id": "search_name", "severity": "result.severity", "detected_at": "result._time",
                   "src_ip": "result.src_ip", "principal": "result.user", "dst_asset": "result.dest",
                   "uri": "result.uri_path", "ua": "result.http_user_agent", "events": "result.count"},
        "severity_map": {}},
        {"search_name": "Brute force on portal", "sid": "scheduler__admin__search__RMD5", "result": {
            "severity": "high", "_time": "1795568523", "src_ip": "203.0.113.9", "user": "budi", "dest": "portal",
            "count": "40"}}),
    "elastic": _p("Elastic Security", "webhook", "Rule action: Webhook connector with the ECS fields of the alert", {
        "source_type": "siem", "rule_prefix": "elastic.",
        "fields": {"rule_id": "kibana.alert.rule.rule_id", "severity": "kibana.alert.severity",
                   "detected_at": "@timestamp", "src_ip": "source.ip", "principal": "user.name",
                   "dst_asset": "host.name", "uri": "url.original", "ua": "user_agent.original", "events": None},
        "severity_map": {}},
        {"@timestamp": "2026-11-25T01:02:03Z", "kibana": {"alert": {"rule": {"rule_id": "credential-access-17"},
                                                                     "severity": "medium"}},
         "source": {"ip": "203.0.113.9"}, "user": {"name": "budi"}, "host": {"name": "portal"}}),
    "wazuh": _p("Wazuh", "webhook", "integrator custom hook posting the alert JSON (rule level 0-15)", {
        "source_type": "siem", "rule_prefix": "wazuh.",
        "fields": {"rule_id": "rule.id", "severity": "rule.level", "detected_at": "timestamp",
                   "src_ip": "data.srcip", "principal": "data.srcuser", "dst_asset": "agent.name",
                   "uri": "data.url", "ua": None, "events": "rule.firedtimes"},
        "severity_map": {}},
        {"timestamp": "2026-11-25T01:02:03.000+0000", "rule": {"id": "5710", "level": 10, "firedtimes": 12},
         "agent": {"name": "bastion"}, "data": {"srcip": "203.0.113.9", "srcuser": "root"}}),
    "qradar": _p("IBM QRadar", "webhook", "Offense rule response posting the offense JSON (severity 0-10)", {
        "source_type": "siem", "rule_prefix": "qradar.",
        "fields": {"rule_id": "offense_type", "severity": "severity", "detected_at": "start_time",
                   "src_ip": "offense_source", "principal": None, "dst_asset": None, "uri": None, "ua": None,
                   "events": "event_count"},
        "severity_map": {}},
        {"id": 4021, "offense_type": 0, "severity": 7, "start_time": 1795568523000, "offense_source": "203.0.113.9",
         "event_count": 88}),
    "sentinel": _p("Microsoft Sentinel", "webhook", "Playbook (Logic App) HTTP action posting the SecurityAlert", {
        "source_type": "siem", "rule_prefix": "sentinel.",
        "fields": {"rule_id": "AlertType", "severity": "AlertSeverity", "detected_at": "TimeGenerated",
                   "src_ip": "SourceIp", "principal": "CompromisedEntity", "dst_asset": None, "uri": None, "ua": None,
                   "events": None},
        "severity_map": {}},
        {"AlertType": "SuspiciousSignin", "AlertSeverity": "High", "TimeGenerated": "2026-11-25T01:02:03Z",
         "SourceIp": "203.0.113.9", "CompromisedEntity": "budi@example.com"}),
    "sls_alert": _p("Alibaba SLS (another project)", "webhook",
                    "SLS alert rule with a webhook notification and JSON content", {
        "source_type": "siem", "rule_prefix": "sls.",
        "fields": {"rule_id": "alert_id", "severity": "severity", "detected_at": "fire_time",
                   "src_ip": "results.src_ip", "principal": None, "access_key_id": "results.access_key_id",
                   "dst_asset": "results.host", "uri": None, "ua": None, "events": "results.count"},
        # SLS alert severity: 2 report, 4 low, 6 medium, 8 high, 10 critical.
        "severity_map": {"2": "info", "4": "low", "6": "medium", "8": "high", "10": "critical"}},
        {"alert_id": "waf-burst-other-project", "severity": 8, "fire_time": 1795568523,
         "results": {"src_ip": "203.0.113.9", "host": "api", "count": 31}}),
    # -- Alibaba log types read by the SLS pull ---------------------------------------------------------
    "sls_waf": _p("WAF 3.0 logs", "sls", "waf-logstore of the WAF 3.0 instance", {
        "source_type": "waf", "rule_prefix": "",
        "fields": {"rule_id": "rule_id", "severity": None, "detected_at": "__time__", "src_ip": "real_client_ip",
                   "principal": None, "access_key_id": None, "dst_asset": "host", "uri": "request_path",
                   "ua": "user_agent", "events": None},
        "severity_map": {}},
        {"__time__": "1795568523", "rule_id": "113004", "real_client_ip": "203.0.113.9", "host": "portal.example.co.id",
         "request_path": "/login", "final_action": "block"}),
    "sls_actiontrail": _p("ActionTrail", "sls", "Trail delivered to an SLS logstore", {
        "source_type": "actiontrail", "rule_prefix": "",
        "fields": {"rule_id": "event.eventName", "severity": None, "detected_at": "event.eventTime",
                   "src_ip": "event.sourceIpAddress", "principal": "event.userIdentity.userName",
                   "access_key_id": "event.userIdentity.accessKeyId", "dst_asset": "event.serviceName", "uri": None,
                   "ua": "event.userAgent", "events": None},
        "severity_map": {}},
        {"event.eventName": "CreateAccessKey", "event.eventTime": "2026-11-25T01:02:03Z",
         "event.sourceIpAddress": "203.0.113.9", "event.userIdentity.userName": "ops",
         "event.userIdentity.accessKeyId": "LTAI5tExampleExample", "event.serviceName": "Ram"}),
    "sls_sas": _p("Security Center alerts", "sls", "Security Center alert log delivered to SLS", {
        "source_type": "sas", "rule_prefix": "",
        "fields": {"rule_id": "alert_type", "severity": "level", "detected_at": "__time__", "src_ip": "src_ip",
                   "principal": None, "access_key_id": None, "dst_asset": "instance_name", "uri": None, "ua": None,
                   "events": None},
        "severity_map": {"serious": "high", "suspicious": "medium", "remind": "low"}},
        {"__time__": "1795568523", "alert_type": "webshell", "level": "serious", "src_ip": "203.0.113.9",
         "instance_name": "web-01"}),
}

# The tokenised alert fields: the gateway replaces these values with tokens before anything is stored.
TOKENIZED = ("src_ip", "principal", "access_key_id")


def view() -> dict:
    """What the console shows: everything except the sample record."""
    return {k: {x: v for x, v in p.items() if x != "sample"} for k, p in PRESETS.items()}


def apply(name: str, settings: dict | None) -> dict:
    """A preset laid over existing settings: the connector's own fields (endpoint, project, limits) stay."""
    return {**(settings or {}), **PRESETS[name]["settings"]}
