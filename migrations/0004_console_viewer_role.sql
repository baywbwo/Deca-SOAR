-- Read-only role for the owner's SOC console (lab and later production).
--
-- deca_soar_viewer reads the alert inbox, broker decisions and requests, the kill switch state and
-- the ledger, nothing else: no vault (sealed PII), no broker.principal (token hashes), no cursor, and
-- no write privilege anywhere. The console logs in as its own user, a member of this role only.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'deca_soar_viewer') THEN
        CREATE ROLE deca_soar_viewer NOLOGIN;
    END IF;
END $$;

GRANT USAGE ON SCHEMA gateway, broker, ledger TO deca_soar_viewer;
GRANT SELECT ON gateway.inbox_event, broker.decision_record, broker.action_request, broker.kill_switch,
    ledger.entry TO deca_soar_viewer;
