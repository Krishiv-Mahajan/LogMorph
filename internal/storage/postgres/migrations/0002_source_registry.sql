-- 0002_source_registry.sql — source registry + processing provenance (Phase 1).
--
-- The registry is append-only: every adaptation writes a NEW row, and the
-- previous version is marked 'superseded' rather than edited or deleted. That
-- is what keeps an event processed last week explainable against the exact
-- parser/mapping version that processed it.

CREATE TABLE IF NOT EXISTS source_registry (
    fingerprint     TEXT        NOT NULL,
    mapping_id      TEXT        NOT NULL,
    mapping_version INTEGER     NOT NULL,

    -- Source identity (from the parser descriptor / detection).
    vendor          TEXT,
    product         TEXT,
    source_type     TEXT,
    format          TEXT        NOT NULL,

    -- Processing identity.
    parser_id       TEXT        NOT NULL,
    parser_version  TEXT        NOT NULL,

    status          TEXT        NOT NULL,

    -- The declared field contract for this version, and a stable hash of it.
    contract        JSONB       NOT NULL,
    contract_hash   TEXT        NOT NULL,

    -- Lineage: which version this one was derived from, and why it exists.
    parent_version  INTEGER     NOT NULL DEFAULT 0,
    drift_status    TEXT,
    rationale       TEXT,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (fingerprint, mapping_id, mapping_version)
);

-- At most one active version per source and mapping. A partial unique index is
-- what makes the "supersede then insert" sequence meaningful rather than
-- advisory.
CREATE UNIQUE INDEX IF NOT EXISTS uq_source_registry_active
    ON source_registry (fingerprint, mapping_id)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_source_registry_fingerprint
    ON source_registry (fingerprint);

-- Lets the writer detect that an identical contract already exists for a
-- source, so a repeated drift does not pile up duplicate versions.
CREATE INDEX IF NOT EXISTS idx_source_registry_contract_hash
    ON source_registry (fingerprint, contract_hash);

-- ── Processing provenance on stored events ───────────────────────────────────
-- Which fingerprint, parser and mapping version produced this row. Combined
-- with raw_object_key this closes the chain:
--   raw object -> event -> parser version -> mapping version
ALTER TABLE normalized_events
    ADD COLUMN IF NOT EXISTS source_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS parser_id          TEXT,
    ADD COLUMN IF NOT EXISTS mapping_id         TEXT,
    ADD COLUMN IF NOT EXISTS mapping_version    INTEGER,
    ADD COLUMN IF NOT EXISTS drift_status       TEXT;

CREATE INDEX IF NOT EXISTS idx_normalized_events_fingerprint
    ON normalized_events (source_fingerprint);

CREATE INDEX IF NOT EXISTS idx_normalized_events_mapping
    ON normalized_events (mapping_id, mapping_version);

-- Quarantined events carry the same provenance: an event rejected because a
-- required field vanished is exactly the case an operator needs to trace back
-- to a drift decision.
ALTER TABLE quarantined_events
    ADD COLUMN IF NOT EXISTS source_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS parser_id          TEXT,
    ADD COLUMN IF NOT EXISTS mapping_id         TEXT,
    ADD COLUMN IF NOT EXISTS mapping_version    INTEGER,
    ADD COLUMN IF NOT EXISTS drift_status       TEXT;

CREATE INDEX IF NOT EXISTS idx_quarantined_events_fingerprint
    ON quarantined_events (source_fingerprint);
