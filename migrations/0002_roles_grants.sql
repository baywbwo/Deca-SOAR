-- Least-privilege database roles (security review F3) and per-principal idempotency (F6).
--
-- The login user that runs migrations owns every object and is used for nothing else.
-- Applications log in as separate users that are members of one of these NOLOGIN group roles:
--   deca_soar_gateway  inbox + cursor, write-only vault, append-only ledger
--   deca_soar_broker   reads inbox/vault, broker tables, append-only ledger
--   deca_soar_auditor  reads the ledger (verify + daily anchor)
-- None of them owns a table, so none can ALTER TABLE ... DISABLE TRIGGER, DELETE, UPDATE or
-- TRUNCATE the ledger. Group roles are cluster-wide; creating them needs CREATEROLE once.

DO $$
DECLARE r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['deca_soar_gateway', 'deca_soar_broker', 'deca_soar_auditor'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN', r);
        END IF;
    END LOOP;
END $$;

REVOKE ALL ON SCHEMA gateway, vault, broker, ledger FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA gateway, vault, broker, ledger FROM PUBLIC;
REVOKE ALL ON FUNCTION ledger.reject_mutation() FROM PUBLIC;

-- Gateway ---------------------------------------------------------------------
GRANT USAGE ON SCHEMA gateway, vault, ledger TO deca_soar_gateway;
GRANT SELECT, INSERT, UPDATE ON gateway.ingest_cursor, gateway.inbox_event TO deca_soar_gateway;
-- Write-only vault: sealed boxes go in, nothing comes out. SELECT on the token column alone is
-- what INSERT ... ON CONFLICT (token) needs; tokens are pseudonyms, not secrets.
GRANT INSERT ON vault.token_map TO deca_soar_gateway;
GRANT SELECT (token) ON vault.token_map TO deca_soar_gateway;
GRANT SELECT, INSERT ON ledger.entry TO deca_soar_gateway;
GRANT USAGE ON SEQUENCE ledger.entry_seq_seq TO deca_soar_gateway;

-- Broker ----------------------------------------------------------------------
GRANT USAGE ON SCHEMA gateway, vault, broker, ledger TO deca_soar_broker;
GRANT SELECT ON gateway.inbox_event TO deca_soar_broker;
GRANT SELECT ON vault.token_map TO deca_soar_broker;
GRANT SELECT ON broker.principal TO deca_soar_broker;
GRANT SELECT, INSERT ON broker.decision_record TO deca_soar_broker;
GRANT SELECT, INSERT, UPDATE ON broker.action_request, broker.kill_switch TO deca_soar_broker;
GRANT SELECT, INSERT ON ledger.entry TO deca_soar_broker;
GRANT USAGE ON SEQUENCE ledger.entry_seq_seq TO deca_soar_broker;

-- Auditor ---------------------------------------------------------------------
GRANT USAGE ON SCHEMA ledger TO deca_soar_auditor;
GRANT SELECT ON ledger.entry TO deca_soar_auditor;

-- Idempotency keys are scoped to the requesting principal --------------------
ALTER TABLE broker.action_request DROP CONSTRAINT action_request_idempotency_key_key;
ALTER TABLE broker.action_request
    ADD CONSTRAINT action_request_principal_idem_key UNIQUE (requested_by, idempotency_key);
