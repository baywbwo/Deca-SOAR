-- HyperSoar v0.9: integration hardening (review of v0.8, findings 1-6).
--
-- 1. A secret is sealed for the host it was entered for (the host is part of its associated data)
--    and saving another host deletes it, so a changed or rolled-back host never receives the old
--    secret. The broker may now delete secret rows; the gateway's view gains the host column.
ALTER TABLE broker.integration_secret ADD COLUMN host text NOT NULL DEFAULT '' CHECK (length(host) <= 253);
GRANT DELETE ON broker.integration_secret TO deca_soar_broker;
CREATE OR REPLACE VIEW broker.source_secret WITH (security_barrier) AS
    SELECT s.entity_id, s.integration, s.mode, s.name, s.key_id, s.nonce, s.ciphertext, s.host
    FROM broker.integration_secret s JOIN broker.connector_kind k USING (integration)
    WHERE k.category = 'source';

-- 2. A saved live version becomes the active one (what the runtime uses) only after its connection
--    test passes. Mock and disabled versions are active at once. Existing rows: active when mock,
--    disabled, or when the latest test of that integration passed for exactly this version.
ALTER TABLE broker.integration_config ADD COLUMN active_version integer;
UPDATE broker.integration_config c SET active_version = c.version
    WHERE c.target = 'mock' OR NOT c.enabled OR (
        SELECT t.status = 'pass' AND t.config_version = c.version FROM broker.integration_test_run t
        WHERE t.entity_id = c.entity_id AND t.integration = c.integration AND t.mode = c.mode
        ORDER BY t.finished_at DESC LIMIT 1);
-- The gateway sees only the active version of a data source.
CREATE OR REPLACE VIEW broker.source_config WITH (security_barrier) AS
    SELECT c.entity_id, c.integration, c.mode, v.target, v.enabled, v.settings, v.version
    FROM broker.integration_config c JOIN broker.connector_kind k USING (integration)
    JOIN broker.integration_config_version v ON v.entity_id = c.entity_id AND v.integration = c.integration
        AND v.mode = c.mode AND v.version = c.active_version
    WHERE k.category = 'source';

-- 3. The channel a principal's credential belongs to. L3 approvals need 'console': the console's
--    own principal token, never an API token handed to a script.
ALTER TABLE broker.principal ADD COLUMN channel text NOT NULL DEFAULT 'api' CHECK (channel IN ('api', 'console'));

-- LOW: webhook signatures already accepted, shared by every gateway process and kept across restarts.
CREATE TABLE gateway.webhook_seen (
    entity_id   text NOT NULL,
    sig_sha256  char(64) NOT NULL,
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (entity_id, sig_sha256)
);
CREATE INDEX webhook_seen_expires_idx ON gateway.webhook_seen (expires_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON gateway.webhook_seen TO deca_soar_gateway;
