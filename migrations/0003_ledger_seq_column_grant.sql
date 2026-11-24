-- Review N7: application roles may append to the ledger but never choose `seq` themselves.
-- Table-level INSERT is replaced with INSERT on every column except `seq`, so an explicit
-- INSERT ... (seq, ...) fails with insufficient_privilege and `seq` always comes from the sequence.

REVOKE INSERT ON ledger.entry FROM deca_soar_gateway, deca_soar_broker;
GRANT INSERT (recorded_at, event_type, actor, payload, canonical, prev_hash, hash)
    ON ledger.entry TO deca_soar_gateway, deca_soar_broker;
