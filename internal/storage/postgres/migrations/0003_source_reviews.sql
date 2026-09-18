-- 0003_source_reviews.sql — review queue for unsafe drift (Phase 3).
--
-- A review item records that a SOURCE SCHEMA needs a mapping decision. It is
-- not a quarantine record: quarantine captures events that could not be
-- processed at all, while a review captures a decision that is owed. The same
-- event can produce both, and neither references the other.
--
-- Rows are deduplicated on (fingerprint, drift_signature), so a source emitting
-- thousands of events with the same drift produces one row with an occurrence
-- count rather than thousands of rows.

CREATE TABLE IF NOT EXISTS source_reviews (
    review_id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    -- Identity of the decision. The signature is computed from structure only
    -- (source, mapping version, sorted change kind+field) and never from
    -- observed values, so it is stable across every event carrying the same
    -- drift.
    fingerprint       TEXT    NOT NULL,
    drift_signature   TEXT    NOT NULL,

    -- The contract in force when the drift was observed. NULL for a source that
    -- has no contract at all.
    mapping_id        TEXT,
    mapping_version   INTEGER,

    -- Evidence, recorded once at first sighting and never rewritten.
    category          TEXT    NOT NULL,
    drift_status      TEXT    NOT NULL,
    reason            TEXT    NOT NULL,
    changes           JSONB   NOT NULL,

    -- Resolution. The proposal is supplied by whoever resolves the item; an
    -- approval turns it into a new registry mapping version. Every item starts
    -- pending; the writer never chooses an initial lifecycle state.
    proposed_contract JSONB,
    status            TEXT    NOT NULL DEFAULT 'pending',
    resulting_mapping_version INTEGER,

    -- Volume and audit.
    occurrences       INTEGER NOT NULL DEFAULT 1,
    origin            TEXT    NOT NULL DEFAULT 'drift_engine',
    sample_event_id   TEXT,
    first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at        TIMESTAMPTZ,
    decided_by        TEXT,
    decision_notes    TEXT,

    CONSTRAINT uq_source_reviews_signature UNIQUE (fingerprint, drift_signature)
);

-- The pending queue is the hot path for operators.
CREATE INDEX IF NOT EXISTS idx_source_reviews_status
    ON source_reviews (status, last_seen_at DESC);
