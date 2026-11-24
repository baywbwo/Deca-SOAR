-- DECA SOAR phase 0 schema: gateway inbox, token vault, broker, audit ledger.

CREATE SCHEMA IF NOT EXISTS gateway;
CREATE SCHEMA IF NOT EXISTS vault;
CREATE SCHEMA IF NOT EXISTS broker;
CREATE SCHEMA IF NOT EXISTS ledger;

-- Gateway --------------------------------------------------------------------

CREATE TABLE gateway.ingest_cursor (
    source_name text PRIMARY KEY,
    cursor      text NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE gateway.inbox_event (
    alert_id         uuid PRIMARY KEY,
    fingerprint      char(64) NOT NULL UNIQUE,
    source           text NOT NULL CHECK (source IN ('waf', 'actiontrail', 'sas', 'internal')),
    rule_id          text NOT NULL,
    severity_hint    text NOT NULL CHECK (severity_hint IN ('info', 'low', 'medium', 'high', 'critical')),
    detected_at      timestamptz NOT NULL,
    ingested_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz NOT NULL DEFAULT now(),
    event_count      integer NOT NULL DEFAULT 1 CHECK (event_count > 0),
    -- Tokenised, normalised alert (schema 7.1). Never contains raw PII.
    alert            jsonb NOT NULL,
    -- Tokens extracted deterministically from source fields; the broker only accepts targets from here.
    evidence_tokens  text[] NOT NULL DEFAULT '{}',
    status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'forwarded', 'dead')),
    attempts         integer NOT NULL DEFAULT 0,
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    forwarded_at     timestamptz,
    downstream_ref   text,
    last_error       text
);
CREATE INDEX inbox_event_pending_idx ON gateway.inbox_event (next_attempt_at) WHERE status = 'pending';

-- Token vault ----------------------------------------------------------------

CREATE TABLE vault.token_map (
    token       text PRIMARY KEY,
    kind        text NOT NULL,
    key_id      text NOT NULL,
    nonce       bytea NOT NULL,
    ciphertext  bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Broker ---------------------------------------------------------------------

CREATE TABLE broker.principal (
    principal_id  uuid PRIMARY KEY,
    name          text NOT NULL UNIQUE,
    kind          text NOT NULL CHECK (kind IN ('service', 'human')),
    role          text NOT NULL CHECK (role IN ('viewer', 'analyst', 'approver', 'admin')),
    token_sha256  char(64) NOT NULL UNIQUE,
    active        boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE broker.decision_record (
    decision_id  uuid PRIMARY KEY,
    alert_id     uuid NOT NULL REFERENCES gateway.inbox_event (alert_id),
    case_id      text,
    record       jsonb NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE broker.action_request (
    request_id       uuid PRIMARY KEY,
    idempotency_key  text NOT NULL UNIQUE,
    request_sha256   char(64) NOT NULL,
    decision_id      uuid NOT NULL REFERENCES broker.decision_record (decision_id),
    alert_id         uuid NOT NULL REFERENCES gateway.inbox_event (alert_id),
    action           text NOT NULL,
    params           jsonb NOT NULL,
    level            text NOT NULL CHECK (level IN ('L0', 'L1', 'L2', 'L3')),
    mode             text NOT NULL CHECK (mode IN ('shadow', 'auto', 'approval')),
    status           text NOT NULL CHECK (status IN ('validated', 'rejected', 'pending_approval', 'executed',
                                                     'rolled_back', 'expired', 'failed')),
    reasons          jsonb NOT NULL DEFAULT '[]',
    would_execute    text,
    rate_scope       text,
    requested_by     uuid NOT NULL REFERENCES broker.principal (principal_id),
    approver         uuid REFERENCES broker.principal (principal_id),
    rollback_at      timestamptz,
    executed_at      timestamptz,
    error            text,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX action_request_rate_idx ON broker.action_request (action, rate_scope, created_at)
    WHERE status IN ('validated', 'pending_approval');

CREATE TABLE broker.kill_switch (
    scope       text PRIMARY KEY,  -- 'global' or an action id
    engaged     boolean NOT NULL,
    changed_by  uuid NOT NULL REFERENCES broker.principal (principal_id),
    changed_at  timestamptz NOT NULL DEFAULT now()
);

-- Audit ledger (append-only hash chain, design 6.5) -----------------------------

CREATE TABLE ledger.entry (
    seq          bigserial PRIMARY KEY,
    recorded_at  timestamptz NOT NULL DEFAULT now(),
    event_type   text NOT NULL,
    actor        text NOT NULL,
    payload      jsonb NOT NULL,
    canonical    text NOT NULL,
    prev_hash    char(64) NOT NULL,
    hash         char(64) NOT NULL UNIQUE
);

CREATE FUNCTION ledger.reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ledger.entry is append-only (% blocked)', TG_OP USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE TRIGGER entry_no_update_delete BEFORE UPDATE OR DELETE ON ledger.entry
    FOR EACH ROW EXECUTE FUNCTION ledger.reject_mutation();
CREATE TRIGGER entry_no_truncate BEFORE TRUNCATE ON ledger.entry
    FOR EACH STATEMENT EXECUTE FUNCTION ledger.reject_mutation();
