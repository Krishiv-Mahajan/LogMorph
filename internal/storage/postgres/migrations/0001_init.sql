-- 0001_init.sql — normalized event store + quarantine store (Phase 1).
--
-- Idempotency is enforced by the primary key on event_id in both tables:
-- re-processing the same event can never create a duplicate record.

-- ── Normalized store ─────────────────────────────────────────────────────────
-- One row per successfully validated UniversalEvent. The full canonical event
-- is kept in `payload`; scalar columns are extracted so operators can query
-- without unpacking JSON. The original raw payload is NOT duplicated here —
-- `raw_object_key` points at the immutable object in MinIO.
CREATE TABLE IF NOT EXISTS normalized_events (
    event_id          TEXT        PRIMARY KEY,
    schema_version    TEXT        NOT NULL,
    event_timestamp   TIMESTAMPTZ,
    received_at       TIMESTAMPTZ,
    source_type       TEXT,
    source_vendor     TEXT,
    source_product    TEXT,
    source_identifier TEXT,
    event_category    TEXT,
    event_action      TEXT,
    event_severity    TEXT,
    src_ip            TEXT,
    src_port          INTEGER,
    dst_ip            TEXT,
    dst_port          INTEGER,
    protocol          TEXT,
    username          TEXT,
    raw_format        TEXT        NOT NULL,
    raw_object_key    TEXT        NOT NULL,
    parser_version    TEXT,
    ingested_at       TIMESTAMPTZ,
    stored_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    payload           JSONB       NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_normalized_events_timestamp
    ON normalized_events (event_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_normalized_events_src_ip
    ON normalized_events (src_ip);

CREATE INDEX IF NOT EXISTS idx_normalized_events_action
    ON normalized_events (event_action);

CREATE INDEX IF NOT EXISTS idx_normalized_events_severity
    ON normalized_events (event_severity);

CREATE INDEX IF NOT EXISTS idx_normalized_events_payload
    ON normalized_events USING GIN (payload);

-- ── Quarantine / dead-letter store ───────────────────────────────────────────
-- One row per event that failed permanently. Holds enough context to
-- investigate without re-reading the original Redis message: the failure
-- stage/type, the error, the MinIO reference, and the raw payload itself
-- (which may predate the MinIO write if that is where processing failed).
CREATE TABLE IF NOT EXISTS quarantined_events (
    event_id       TEXT        PRIMARY KEY,
    failure_stage  TEXT        NOT NULL,
    failure_type   TEXT        NOT NULL,
    failure_class  TEXT        NOT NULL,
    error_message  TEXT        NOT NULL,
    attempts       INTEGER     NOT NULL DEFAULT 1,
    raw_object_key TEXT,
    raw_format     TEXT,
    raw_source     TEXT,
    stream_id      TEXT,
    consumer_name  TEXT,
    received_at    TIMESTAMPTZ,
    raw_payload    JSONB,
    quarantined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_quarantined_events_stage
    ON quarantined_events (failure_stage);

CREATE INDEX IF NOT EXISTS idx_quarantined_events_type
    ON quarantined_events (failure_type);

CREATE INDEX IF NOT EXISTS idx_quarantined_events_quarantined_at
    ON quarantined_events (quarantined_at DESC);
