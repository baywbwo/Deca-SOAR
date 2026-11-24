-- HyperSoar v0.7: one install per entity, sandbox/production marker, case correlation (G1),
-- entity relations (G2), attack path steps, integration settings/secrets/calls (Jira, Lark, 9router),
-- approval escalation and scenario runs.
--
-- entity_id defaults to 'dob' (PT Delta Omega Beta), so existing rows belong to it. Scenario runs
-- use their own entity ids (scn-...), which keeps their cases, kill switch and rate limits apart
-- from the live sandbox feed.

-- Install marker ---------------------------------------------------------------
-- Written once by `hypersoar migrate` from HYPERSOAR_MODE / HYPERSOAR_ENTITY. Every service compares
-- it with its own mode at start-up, so a sandbox service can never run against the production
-- database (and the other way round).
CREATE TABLE public.hypersoar_install (
    singleton   boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    mode        text NOT NULL CHECK (mode IN ('sandbox', 'production')),
    entity_id   text NOT NULL CHECK (entity_id ~ '^[a-z][a-z0-9-]{0,31}$'),
    created_at  timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON public.hypersoar_install FROM PUBLIC;

-- entity_id on every data table -------------------------------------------------
ALTER TABLE gateway.ingest_cursor   ADD COLUMN entity_id text NOT NULL DEFAULT 'dob';
ALTER TABLE gateway.inbox_event     ADD COLUMN entity_id text NOT NULL DEFAULT 'dob';
ALTER TABLE vault.token_map         ADD COLUMN entity_id text NOT NULL DEFAULT 'dob';
ALTER TABLE broker.principal        ADD COLUMN entity_id text NOT NULL DEFAULT 'dob';
ALTER TABLE broker.decision_record  ADD COLUMN entity_id text NOT NULL DEFAULT 'dob';
ALTER TABLE broker.action_request   ADD COLUMN entity_id text NOT NULL DEFAULT 'dob';
ALTER TABLE broker.kill_switch      ADD COLUMN entity_id text NOT NULL DEFAULT 'dob';
-- Ledger rows are immutable; adding a column with a constant default rewrites no row and fires no
-- row trigger. New entries also carry entity_id inside the hashed envelope.
ALTER TABLE ledger.entry            ADD COLUMN entity_id text NOT NULL DEFAULT 'dob';

ALTER TABLE gateway.inbox_event DROP CONSTRAINT inbox_event_fingerprint_key;
ALTER TABLE gateway.inbox_event ADD CONSTRAINT inbox_event_entity_fingerprint_key UNIQUE (entity_id, fingerprint);
CREATE INDEX inbox_event_entity_ingested_idx ON gateway.inbox_event (entity_id, ingested_at DESC);
CREATE INDEX inbox_event_entity_detected_idx ON gateway.inbox_event (entity_id, detected_at DESC);

ALTER TABLE broker.kill_switch DROP CONSTRAINT kill_switch_pkey;
ALTER TABLE broker.kill_switch ADD PRIMARY KEY (entity_id, scope);

ALTER TABLE broker.action_request DROP CONSTRAINT action_request_principal_idem_key;
ALTER TABLE broker.action_request
    ADD CONSTRAINT action_request_entity_principal_idem_key UNIQUE (entity_id, requested_by, idempotency_key);

-- Approval TTL and escalation ---------------------------------------------------
ALTER TABLE broker.action_request ADD COLUMN case_id text;
ALTER TABLE broker.action_request ADD COLUMN expires_at timestamptz;
ALTER TABLE broker.action_request ADD COLUMN escalation_level smallint NOT NULL DEFAULT 0
    CHECK (escalation_level BETWEEN 0 AND 3);
ALTER TABLE broker.action_request ADD COLUMN escalated_at timestamptz;
CREATE INDEX action_request_entity_case_idx ON broker.action_request (entity_id, case_id);
CREATE INDEX action_request_pending_idx ON broker.action_request (entity_id, expires_at)
    WHERE status = 'pending_approval';
CREATE INDEX decision_record_entity_case_idx ON broker.decision_record (entity_id, case_id);

-- G1: cases ---------------------------------------------------------------------
CREATE TABLE gateway.alert_case (
    entity_id      text NOT NULL,
    case_id        text NOT NULL CHECK (case_id ~ '^CS-[0-9]{1,9}$'),
    case_no        integer NOT NULL,
    status         text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    title          text NOT NULL,
    category       text NOT NULL,
    max_severity   text NOT NULL CHECK (max_severity IN ('info', 'low', 'medium', 'high', 'critical')),
    criticality    smallint NOT NULL CHECK (criticality BETWEEN 1 AND 5),
    priority       smallint NOT NULL CHECK (priority BETWEEN 1 AND 25),
    alert_count    integer NOT NULL DEFAULT 0,
    event_count    integer NOT NULL DEFAULT 0,
    tactics        text[] NOT NULL DEFAULT '{}',
    primary_kind   text NOT NULL,
    primary_value  text NOT NULL,
    origin_city    text,
    origin_country text,
    origin_asn     text,
    sources        text[] NOT NULL DEFAULT '{}',
    assets         text[] NOT NULL DEFAULT '{}',
    synthetic      boolean NOT NULL DEFAULT false,
    opened_at      timestamptz NOT NULL,
    closed_at      timestamptz,
    close_reason   text,
    last_seen_at   timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (entity_id, case_id),
    UNIQUE (entity_id, case_no)
);
CREATE INDEX alert_case_open_idx ON gateway.alert_case (entity_id, status, priority DESC, last_seen_at DESC);

CREATE TABLE gateway.case_alert (
    alert_id   uuid PRIMARY KEY REFERENCES gateway.inbox_event (alert_id),
    entity_id  text NOT NULL,
    case_id    text NOT NULL,
    added_at   timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (entity_id, case_id) REFERENCES gateway.alert_case (entity_id, case_id)
);
CREATE INDEX case_alert_case_idx ON gateway.case_alert (entity_id, case_id);

-- Correlation keys: the tokenised entities that tie alerts to a case (src IP, principal, AccessKey).
CREATE TABLE gateway.case_key (
    entity_id     text NOT NULL,
    key_kind      text NOT NULL CHECK (key_kind IN ('ip', 'user', 'ak')),
    key_value     text NOT NULL,
    case_id       text NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    PRIMARY KEY (entity_id, key_kind, key_value, case_id),
    FOREIGN KEY (entity_id, case_id) REFERENCES gateway.alert_case (entity_id, case_id)
);
CREATE INDEX case_key_lookup_idx ON gateway.case_key (entity_id, key_kind, key_value, last_seen_at DESC);

-- G2: entity relations, filled by the gateway --------------------------------------
CREATE TABLE gateway.entity_relation (
    entity_id      text NOT NULL,
    case_id        text NOT NULL,
    src_kind       text NOT NULL CHECK (src_kind IN ('ip', 'user', 'ak', 'asset')),
    src_value      text NOT NULL,
    rel            text NOT NULL CHECK (rel IN ('targets', 'authenticates_as', 'uses_key', 'owns_key', 'moves_to')),
    dst_kind       text NOT NULL CHECK (dst_kind IN ('ip', 'user', 'ak', 'asset')),
    dst_value      text NOT NULL,
    first_seen     timestamptz NOT NULL,
    last_seen      timestamptz NOT NULL,
    seen_count     integer NOT NULL DEFAULT 1,
    last_alert_id  uuid NOT NULL,
    PRIMARY KEY (entity_id, case_id, src_kind, src_value, rel, dst_kind, dst_value),
    FOREIGN KEY (entity_id, case_id) REFERENCES gateway.alert_case (entity_id, case_id)
);

-- Attack path: one step per alert in a case, in time order, with its MITRE mapping (from the
-- detections catalog) and the entity path it describes. Labels are display-safe (asset names,
-- masked keys, tokens), never a raw address.
CREATE TABLE gateway.case_step (
    entity_id    text NOT NULL,
    case_id      text NOT NULL,
    alert_id     uuid NOT NULL REFERENCES gateway.inbox_event (alert_id),
    at           timestamptz NOT NULL,
    rule_id      text NOT NULL,
    tactic       text,
    tactic_name  text,
    technique    text,
    title        text NOT NULL,
    outcome      text NOT NULL CHECK (outcome IN ('attempted', 'allowed', 'blocked')),
    src_kind     text,
    src_value    text,
    rel          text,
    dst_kind     text,
    dst_value    text,
    events       integer NOT NULL DEFAULT 1,
    PRIMARY KEY (alert_id),
    FOREIGN KEY (entity_id, case_id) REFERENCES gateway.alert_case (entity_id, case_id)
);
CREATE INDEX case_step_case_idx ON gateway.case_step (entity_id, case_id, at);

-- Integrations (Jira, Lark, AI): every outbound call the broker makes or would make --------
CREATE TABLE broker.integration_call (
    call_id        uuid PRIMARY KEY,
    entity_id      text NOT NULL,
    integration    text NOT NULL CHECK (integration IN ('jira', 'lark', 'ai')),
    operation      text NOT NULL,
    target         text NOT NULL CHECK (target IN ('mock', 'live', 'shadow')),
    status         text NOT NULL CHECK (status IN ('ok', 'duplicate', 'error', 'skipped')),
    case_id        text,
    alert_id       uuid,
    request_id     uuid,
    external_ref   text,
    detail         jsonb NOT NULL DEFAULT '{}',
    duration_ms    integer,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX integration_call_entity_idx ON broker.integration_call (entity_id, created_at DESC);
CREATE INDEX integration_call_case_idx ON broker.integration_call (entity_id, case_id);

-- One Jira issue per case (label hypersoar-<case_id>); the row is taken before the call is made.
CREATE TABLE broker.jira_issue (
    entity_id    text NOT NULL,
    case_id      text NOT NULL,
    label        text NOT NULL,
    issue_key    text,
    status       text NOT NULL CHECK (status IN ('pending', 'created', 'closed', 'error')),
    attempts     integer NOT NULL DEFAULT 0,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (entity_id, case_id)
);

-- Integration settings (screen 08). One row per entity, integration and mode; every save keeps the
-- previous version for rollback. Settings hold no secret: secrets live in integration_secret,
-- AES-256-GCM sealed with a master key only the broker mounts.
CREATE TABLE broker.integration_config (
    entity_id    text NOT NULL,
    integration  text NOT NULL CHECK (integration IN ('jira', 'lark', 'ai')),
    mode         text NOT NULL CHECK (mode IN ('sandbox', 'production')),
    target       text NOT NULL CHECK (target IN ('mock', 'live')),
    enabled      boolean NOT NULL DEFAULT true,
    settings     jsonb NOT NULL,
    version      integer NOT NULL DEFAULT 1,
    updated_by   text NOT NULL,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (entity_id, integration, mode)
);
CREATE TABLE broker.integration_config_version (
    entity_id    text NOT NULL,
    integration  text NOT NULL,
    mode         text NOT NULL,
    version      integer NOT NULL,
    target       text NOT NULL,
    enabled      boolean NOT NULL,
    settings     jsonb NOT NULL,
    changed_by   text NOT NULL,
    changed_at   timestamptz NOT NULL DEFAULT now(),
    note         text,
    PRIMARY KEY (entity_id, integration, mode, version)
);
CREATE TABLE broker.integration_secret (
    entity_id    text NOT NULL,
    integration  text NOT NULL CHECK (integration IN ('jira', 'lark', 'ai')),
    mode         text NOT NULL CHECK (mode IN ('sandbox', 'production')),
    name         text NOT NULL CHECK (name ~ '^[a-z_]{1,40}$'),
    key_id       text NOT NULL,
    nonce        bytea NOT NULL,
    ciphertext   bytea NOT NULL,
    rotated_at   timestamptz NOT NULL DEFAULT now(),
    rotated_by   text NOT NULL,
    expires_at   timestamptz,
    PRIMARY KEY (entity_id, integration, mode, name)
);
CREATE TABLE broker.integration_test_run (
    run_id       uuid PRIMARY KEY,
    entity_id    text NOT NULL,
    integration  text NOT NULL,
    mode         text NOT NULL,
    target       text NOT NULL,
    config_version integer NOT NULL,
    status       text NOT NULL CHECK (status IN ('pass', 'fail')),
    steps        jsonb NOT NULL,
    actor        text NOT NULL,
    started_at   timestamptz NOT NULL,
    finished_at  timestamptz NOT NULL
);
CREATE INDEX integration_test_run_idx ON broker.integration_test_run (entity_id, integration, mode, finished_at DESC);

-- AI (9router) token budget per day and model.
CREATE TABLE broker.ai_usage (
    entity_id    text NOT NULL,
    day          date NOT NULL,
    model        text NOT NULL,
    calls        integer NOT NULL DEFAULT 0,
    failures     integer NOT NULL DEFAULT 0,
    tokens_in    bigint NOT NULL DEFAULT 0,
    tokens_out   bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (entity_id, day, model)
);

-- Outbound work for Lark and Jira, written in the same transaction as the event that causes it and
-- sent afterwards by the broker's sync loop. A crash between the two loses nothing; a failed call
-- is retried with backoff and ends as 'error' after max attempts.
CREATE TABLE broker.integration_outbox (
    outbox_id    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    entity_id    text NOT NULL,
    integration  text NOT NULL CHECK (integration IN ('jira', 'lark')),
    operation    text NOT NULL CHECK (operation ~ '^[a-z_.]{1,40}$'),
    case_id      text,
    request_id   uuid,
    payload      jsonb NOT NULL DEFAULT '{}',
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'done', 'error')),
    attempts     integer NOT NULL DEFAULT 0,
    next_at      timestamptz NOT NULL DEFAULT now(),
    created_at   timestamptz NOT NULL DEFAULT now(),
    done_at      timestamptz
);
CREATE INDEX integration_outbox_due_idx ON broker.integration_outbox (next_at) WHERE status = 'pending';

-- Inbound "issue moved to Done in Jira" (flag HYPERSOAR_JIRA_INBOUND, off). The broker only records
-- the request; the gateway, which owns cases, applies it on its next pull.
CREATE TABLE broker.case_close_request (
    entity_id     text NOT NULL,
    case_id       text NOT NULL,
    source        text NOT NULL CHECK (source IN ('jira')),
    external_ref  text NOT NULL,
    requested_at  timestamptz NOT NULL DEFAULT now(),
    applied_at    timestamptz,
    PRIMARY KEY (entity_id, case_id, source)
);

-- Who approved from Lark: the Lark user id on the ladder (there is no broker principal for them).
ALTER TABLE broker.action_request ADD COLUMN approver_ref text;

-- What an approver sees: impact, rollback and evidence, frozen when the request is made.
ALTER TABLE broker.action_request ADD COLUMN impact text;
ALTER TABLE broker.action_request ADD COLUMN rollback_plan text;
ALTER TABLE broker.action_request ADD COLUMN evidence jsonb NOT NULL DEFAULT '[]';

-- Scenario tests ------------------------------------------------------------------
CREATE SCHEMA qa;
CREATE TABLE qa.scenario_run (
    run_id       uuid NOT NULL,
    scenario     text NOT NULL,
    entity_id    text NOT NULL,
    title        text NOT NULL,
    status       text NOT NULL CHECK (status IN ('pass', 'fail', 'error')),
    expected     jsonb NOT NULL,
    got          jsonb NOT NULL,
    failures     jsonb NOT NULL DEFAULT '[]',
    checks       jsonb NOT NULL DEFAULT '[]',
    duration_ms  integer NOT NULL DEFAULT 0,
    git_sha      text,
    started_at   timestamptz NOT NULL,
    finished_at  timestamptz NOT NULL,
    PRIMARY KEY (run_id, scenario)
);
CREATE INDEX scenario_run_recent_idx ON qa.scenario_run (scenario, finished_at DESC);
REVOKE ALL ON SCHEMA qa FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA gateway, vault, broker, ledger, qa FROM PUBLIC;

-- Grants --------------------------------------------------------------------------
GRANT SELECT ON public.hypersoar_install TO deca_soar_gateway, deca_soar_broker, deca_soar_viewer;

GRANT SELECT, INSERT, UPDATE ON gateway.alert_case, gateway.case_alert, gateway.case_key,
    gateway.entity_relation, gateway.case_step TO deca_soar_gateway;
GRANT INSERT (entity_id) ON ledger.entry TO deca_soar_gateway;
GRANT USAGE ON SCHEMA broker TO deca_soar_gateway;
GRANT SELECT ON broker.case_close_request TO deca_soar_gateway;
GRANT UPDATE (applied_at) ON broker.case_close_request TO deca_soar_gateway;

GRANT SELECT ON gateway.alert_case, gateway.case_alert, gateway.case_step, gateway.entity_relation
    TO deca_soar_broker;
GRANT SELECT, INSERT ON broker.integration_call, broker.integration_config_version, broker.integration_test_run,
    broker.case_close_request TO deca_soar_broker;
GRANT SELECT, INSERT, UPDATE ON broker.integration_outbox, broker.jira_issue, broker.integration_config, broker.integration_secret,
    broker.ai_usage TO deca_soar_broker;
GRANT USAGE ON SCHEMA qa TO deca_soar_broker;
GRANT SELECT, INSERT ON qa.scenario_run TO deca_soar_broker;
GRANT INSERT (entity_id) ON ledger.entry TO deca_soar_broker;

GRANT USAGE ON SCHEMA qa TO deca_soar_viewer;
GRANT SELECT ON gateway.alert_case, gateway.case_alert, gateway.case_key, gateway.entity_relation,
    gateway.case_step, broker.integration_call, broker.jira_issue, broker.integration_config,
    broker.integration_config_version, broker.integration_test_run, broker.ai_usage, qa.scenario_run,
    broker.integration_outbox, broker.case_close_request TO deca_soar_viewer;
-- The console sees whether a secret is set and when it was rotated, never the sealed value.
GRANT SELECT (entity_id, integration, mode, name, key_id, rotated_at, rotated_by, expires_at)
    ON broker.integration_secret TO deca_soar_viewer;
