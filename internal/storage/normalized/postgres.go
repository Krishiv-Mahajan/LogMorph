package normalized

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/postgres"
)

// PostgresStore persists normalized events in PostgreSQL.
//
// Idempotency comes from the primary key on event_id combined with
// ON CONFLICT (event_id) DO NOTHING: a re-delivered event never creates a
// second row. The pool is owned by the caller and is not closed by Close.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore wraps an open database handle.
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

const insertEventSQL = `
INSERT INTO normalized_events (
    event_id, schema_version, event_timestamp, received_at,
    source_type, source_vendor, source_product, source_identifier,
    event_category, event_action, event_severity,
    src_ip, src_port, dst_ip, dst_port, protocol, username,
    raw_format, raw_object_key, parser_version, ingested_at, payload
) VALUES (
    $1, $2, $3, $4,
    $5, $6, $7, $8,
    $9, $10, $11,
    $12, $13, $14, $15, $16, $17,
    $18, $19, $20, $21, $22::jsonb
)
ON CONFLICT (event_id) DO NOTHING`

// Save inserts the record, ignoring duplicates.
func (p *PostgresStore) Save(ctx context.Context, rec Record) (bool, error) {
	if rec.Event == nil {
		return false, fmt.Errorf("cannot store nil event")
	}
	if rec.Event.EventID == "" {
		return false, fmt.Errorf("cannot store event with empty event_id")
	}

	payload, err := json.Marshal(rec.Event)
	if err != nil {
		return false, fmt.Errorf("failed to marshal universal event: %w", err)
	}

	evt := rec.Event
	var (
		network  = evt.Network
		srcIP    any
		srcPort  any
		dstIP    any
		dstPort  any
		proto    any
		username any
	)
	if network != nil {
		srcIP = nullable(network.SrcIP)
		srcPort = portOrNil(network.SrcPort)
		dstIP = nullable(network.DstIP)
		dstPort = portOrNil(network.DstPort)
		proto = nullable(network.Protocol)
	}
	if evt.User != nil && evt.User.Username != nil {
		username = nullable(*evt.User.Username)
	}

	var receivedAt any
	if !rec.ReceivedAt.IsZero() {
		receivedAt = rec.ReceivedAt.UTC()
	}

	res, err := p.db.ExecContext(ctx, insertEventSQL,
		evt.EventID,
		evt.SchemaVersion,
		postgres.TimestampOrNil(evt.Timestamp),
		receivedAt,
		nullable(evt.Source.Type),
		nullable(evt.Source.Vendor),
		nullable(evt.Source.Product),
		nullable(evt.Source.Identifier),
		nullable(evt.Event.Category),
		nullable(evt.Event.Action),
		nullable(evt.Event.Severity),
		srcIP,
		srcPort,
		dstIP,
		dstPort,
		proto,
		username,
		evt.Raw.Format,
		rec.RawObjectKey,
		nullable(evt.Metadata.ParserVersion),
		postgres.TimestampOrNil(evt.Metadata.IngestedAt),
		string(payload),
	)
	if err != nil {
		return false, fmt.Errorf("failed to insert normalized event %s: %w", evt.EventID, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read insert result for %s: %w", evt.EventID, err)
	}

	return affected > 0, nil
}

const selectEventSQL = `
SELECT payload, raw_object_key, received_at
FROM normalized_events
WHERE event_id = $1`

// Get returns the stored record for eventID.
func (p *PostgresStore) Get(ctx context.Context, eventID string) (*Record, error) {
	var (
		payload      []byte
		rawObjectKey string
		receivedAt   sql.NullTime
	)

	err := p.db.QueryRowContext(ctx, selectEventSQL, eventID).
		Scan(&payload, &rawObjectKey, &receivedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("normalized event %s not found", eventID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query normalized event %s: %w", eventID, err)
	}

	var evt models.UniversalEvent
	if err := json.Unmarshal(payload, &evt); err != nil {
		return nil, fmt.Errorf("failed to unmarshal stored event %s: %w", eventID, err)
	}

	rec := &Record{Event: &evt, RawObjectKey: rawObjectKey}
	if receivedAt.Valid {
		rec.ReceivedAt = receivedAt.Time
	}

	return rec, nil
}

// Count returns the number of stored normalized events.
func (p *PostgresStore) Count(ctx context.Context) (int64, error) {
	var total int64
	if err := p.db.QueryRowContext(ctx, `SELECT count(*) FROM normalized_events`).Scan(&total); err != nil {
		return 0, fmt.Errorf("failed to count normalized events: %w", err)
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

// portOrNil returns SQL NULL for absent or out-of-range ports. Bounding here as
// well as in schema validation keeps a malformed value from turning into a
// database error, which would be retried as if it were an outage.
func portOrNil(port *int) any {
	if port == nil || *port < 0 || *port > 65535 {
		return nil
	}
	return *port
}
