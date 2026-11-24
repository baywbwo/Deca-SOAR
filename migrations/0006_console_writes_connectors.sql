-- HyperSoar v0.8: the console's write path (through the broker) and the connector registry.
--
-- Cases: a human may assign a case, move it between open, waiting and closed, and comment on it.
-- The gateway still owns correlation; the broker may only change the triage columns below.
-- Every write the console makes goes through the broker with an Idempotency-Key, stored in
-- broker.write_op so a retried click returns the first answer instead of acting twice.

ALTER TABLE gateway.alert_case DROP CONSTRAINT alert_case_status_check;
ALTER TABLE gateway.alert_case ADD CONSTRAINT alert_case_status_check
    CHECK (status IN ('open', 'waiting', 'closed'));
ALTER TABLE gateway.alert_case ADD COLUMN assignee text CHECK (length(assignee) <= 80);
ALTER TABLE gateway.alert_case ADD COLUMN status_by text;

CREATE TABLE broker.case_comment (
    comment_id  uuid PRIMARY KEY,
    entity_id   text NOT NULL,
    case_id     text NOT NULL,
    author      text NOT NULL,
    body        text NOT NULL CHECK (length(body) BETWEEN 1 AND 2000),
    created_at  timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (entity_id, case_id) REFERENCES gateway.alert_case (entity_id, case_id)
);
CREATE INDEX case_comment_case_idx ON broker.case_comment (entity_id, case_id, created_at);

CREATE TABLE broker.write_op (
    principal_id    uuid NOT NULL REFERENCES broker.principal (principal_id),
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 128),
    operation       text NOT NULL,
    request_sha256  char(64) NOT NULL,
    status_code     smallint NOT NULL,
    response        jsonb NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id, idempotency_key)
);

-- Re-authentication for human principals: the scrypt hash of that person's console password. A
-- write from a human (approve, kill switch, case changes, revoke) carries the password again and
-- the broker checks it here. The viewer role is never granted this column.
ALTER TABLE broker.principal ADD COLUMN reauth_hash text;

-- Revoking a time-boxed action early (screen 06 "Expiring soon").
ALTER TABLE broker.action_request ADD COLUMN revoked_at timestamptz;
ALTER TABLE broker.action_request ADD COLUMN revoked_by text;
-- Why an approver said yes to an L3 request (and, optionally, to anything else).
ALTER TABLE broker.action_request ADD COLUMN decision_reason text CHECK (length(decision_reason) <= 500);
ALTER TABLE broker.kill_switch ADD COLUMN reason text CHECK (length(reason) <= 500);

-- Connector registry: data sources (generic webhook, syslog/CEF, Alibaba Cloud SLS) next to the
-- outbound integrations. Settings and secrets reuse integration_config/_secret per mode.
ALTER TABLE broker.integration_config DROP CONSTRAINT integration_config_integration_check;
ALTER TABLE broker.integration_config ADD CONSTRAINT integration_config_integration_check
    CHECK (integration ~ '^[a-z][a-z0-9_]{1,31}$');
ALTER TABLE broker.integration_secret DROP CONSTRAINT integration_secret_integration_check;
ALTER TABLE broker.integration_secret ADD CONSTRAINT integration_secret_integration_check
    CHECK (integration ~ '^[a-z][a-z0-9_]{1,31}$');
ALTER TABLE broker.integration_call DROP CONSTRAINT integration_call_integration_check;
ALTER TABLE broker.integration_call ADD CONSTRAINT integration_call_integration_check
    CHECK (integration ~ '^[a-z][a-z0-9_]{1,31}$');

-- The gateway reads the settings and sealed secrets of data sources only (category 'source' in the
-- registry), never Lark/Jira/AI ones: the views below are all it is granted.
CREATE TABLE broker.connector_kind (
    integration text PRIMARY KEY CHECK (integration ~ '^[a-z][a-z0-9_]{1,31}$'),
    category    text NOT NULL CHECK (category IN ('source', 'notify', 'ticketing', 'ai'))
);
INSERT INTO broker.connector_kind VALUES ('lark', 'notify'), ('jira', 'ticketing'), ('ai', 'ai'),
    ('webhook', 'source'), ('syslog', 'source'), ('sls', 'source');
CREATE VIEW broker.source_config WITH (security_barrier) AS
    SELECT c.entity_id, c.integration, c.mode, c.target, c.enabled, c.settings, c.version
    FROM broker.integration_config c JOIN broker.connector_kind k USING (integration)
    WHERE k.category = 'source';
CREATE VIEW broker.source_secret WITH (security_barrier) AS
    SELECT s.entity_id, s.integration, s.mode, s.name, s.key_id, s.nonce, s.ciphertext
    FROM broker.integration_secret s JOIN broker.connector_kind k USING (integration)
    WHERE k.category = 'source';
REVOKE ALL ON broker.connector_kind, broker.source_config, broker.source_secret FROM PUBLIC;
GRANT SELECT ON broker.source_config, broker.source_secret TO deca_soar_gateway;
GRANT SELECT ON broker.connector_kind TO deca_soar_gateway, deca_soar_broker, deca_soar_viewer;

GRANT UPDATE (status, status_by, closed_at, close_reason, assignee, updated_at) ON gateway.alert_case
    TO deca_soar_broker;
GRANT SELECT, INSERT ON broker.case_comment, broker.write_op TO deca_soar_broker;
GRANT SELECT ON broker.case_comment TO deca_soar_viewer;
-- Who can be assigned a case: names of human principals only, never token hashes.
GRANT SELECT (principal_id, name, kind, role, active, entity_id) ON broker.principal TO deca_soar_viewer;

-- Alerts from any third-party SIEM carry source 'siem'.
ALTER TABLE gateway.inbox_event DROP CONSTRAINT inbox_event_source_check;
ALTER TABLE gateway.inbox_event ADD CONSTRAINT inbox_event_source_check
    CHECK (source IN ('waf', 'actiontrail', 'sas', 'internal', 'siem'));

-- Records pushed by the webhook and syslog connectors, waiting for the next pull. The pull deletes
-- them in the transaction that writes the inbox. An identity column needs no sequence grant.
CREATE TABLE gateway.source_spool (
    spool_id    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    entity_id   text NOT NULL,
    connector   text NOT NULL CHECK (connector ~ '^[a-z][a-z0-9_]{1,31}$'),
    record      jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX source_spool_connector_idx ON gateway.source_spool (entity_id, connector, spool_id);
GRANT SELECT, INSERT, DELETE ON gateway.source_spool TO deca_soar_gateway;
