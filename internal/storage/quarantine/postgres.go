package quarantine

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// PostgresStore persists quarantined events in PostgreSQL.
//
// event_id is the primary key, so quarantining an already-quarantined event
// updates the existing row instead of creating a duplicate. The pool is owned
// by the caller and is not closed by Close.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore wraps an open database handle.
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

const insertEntrySQL = `
INSERT INTO quarantined_events (
    event_id, failure_stage, failure_type, failure_class, error_message,
    attempts, raw_object_key, raw_format, raw_source, stream_id, consumer_name,
    received_at, raw_payload
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9, $10, $11,
    $12, $13::jsonb
)
ON CONFLICT (event_id) DO UPDATE SET
    failure_stage  = EXCLUDED.failure_stage,
    failure_type   = EXCLUDED.failure_type,
    failure_class  = EXCLUDED.failure_class,
    error_message  = EXCLUDED.error_message,
    attempts       = GREATEST(quarantined_events.attempts, EXCLUDED.attempts),
    raw_object_key = EXCLUDED.raw_object_key,
    raw_format     = EXCLUDED.raw_format,
    raw_source     = EXCLUDED.raw_source,
    stream_id      = EXCLUDED.stream_id,
    consumer_name  = EXCLUDED.consumer_name,
    raw_payload    = EXCLUDED.raw_payload,
    last_seen_at   = now()`

// Add quarantines an event.
func (p *PostgresStore) Add(ctx context.Context, entry Entry) error {
	if entry.EventID == "" {
		return fmt.Errorf("cannot quarantine event with empty event_id")
	}

	attempts := entry.Attempts
	if attempts <= 0 {
		attempts = 1
	}

	var receivedAt any
	if !entry.ReceivedAt.IsZero() {
		receivedAt = entry.ReceivedAt.UTC()
	}

	var rawPayload any
	if entry.RawPayload != nil {
		data, err := json.Marshal(entry.RawPayload)
		if err != nil {
			return fmt.Errorf("failed to marshal raw payload for %s: %w", entry.EventID, err)
		}
		rawPayload = string(data)
	}

	_, err := p.db.ExecContext(ctx, insertEntrySQL,
		entry.EventID,
		entry.Stage,
		entry.Type,
		entry.Class,
		entry.Message,
		attempts,
		nullable(entry.RawObjectKey),
		nullable(entry.RawFormat),
		nullable(entry.RawSource),
		nullable(entry.StreamID),
		nullable(entry.ConsumerName),
		receivedAt,
		rawPayload,
	)
	if err != nil {
		return fmt.Errorf("failed to quarantine event %s: %w", entry.EventID, err)
	}

	return nil
}

const selectEntrySQL = `
SELECT event_id, failure_stage, failure_type, failure_class, error_message,
       attempts, raw_object_key, raw_format, raw_source, stream_id, consumer_name,
       received_at, raw_payload, quarantined_at
FROM quarantined_events
WHERE event_id = $1`

// Get returns the quarantine entry for eventID.
func (p *PostgresStore) Get(ctx context.Context, eventID string) (*Entry, error) {
	var (
		entry        Entry
		rawObjectKey sql.NullString
		rawFormat    sql.NullString
		rawSource    sql.NullString
		streamID     sql.NullString
		consumerName sql.NullString
		receivedAt   sql.NullTime
		rawPayload   []byte
	)

	err := p.db.QueryRowContext(ctx, selectEntrySQL, eventID).Scan(
		&entry.EventID,
		&entry.Stage,
		&entry.Type,
		&entry.Class,
		&entry.Message,
		&entry.Attempts,
		&rawObjectKey,
		&rawFormat,
		&rawSource,
		&streamID,
		&consumerName,
		&receivedAt,
		&rawPayload,
		&entry.QuarantinedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("event %s is not quarantined", eventID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query quarantine entry %s: %w", eventID, err)
	}

	entry.RawObjectKey = rawObjectKey.String
	entry.RawFormat = rawFormat.String
	entry.RawSource = rawSource.String
	entry.StreamID = streamID.String
	entry.ConsumerName = consumerName.String
	if receivedAt.Valid {
		entry.ReceivedAt = receivedAt.Time
	}

	if len(rawPayload) > 0 {
		var raw models.RawEvent
		if err := json.Unmarshal(rawPayload, &raw); err != nil {
			return nil, fmt.Errorf("failed to unmarshal raw payload for %s: %w", eventID, err)
		}
		entry.RawPayload = &raw
	}

	return &entry, nil
}

// Count returns the number of quarantined events.
func (p *PostgresStore) Count(ctx context.Context) (int64, error) {
	var total int64
	if err := p.db.QueryRowContext(ctx, `SELECT count(*) FROM quarantined_events`).Scan(&total); err != nil {
		return 0, fmt.Errorf("failed to count quarantined events: %w", err)
	}
	return total, nil
}

// Ping verifies the database is reachable.
func (p *PostgresStore) Ping(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

// Close is a no-op: the connection pool is owned by the caller.
func (p *PostgresStore) Close() error { return nil }

// nullable maps an empty string to SQL NULL.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
