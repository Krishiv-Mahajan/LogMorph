package review

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Krishiv-Mahajan/LogMorph/internal/contract"
)

// PostgresStore persists review items in PostgreSQL.
//
// The pool is owned by the caller and is not closed by Close.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore wraps an open database handle.
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

const itemColumns = `
    review_id, fingerprint, drift_signature, mapping_id, mapping_version,
    category, drift_status, reason, changes, proposed_contract,
    status, resulting_mapping_version, occurrences, origin, sample_event_id,
    first_seen_at, last_seen_at, decided_at, decided_by, decision_notes`

// upsertSQL records an escalation.
//
// The conflict target is the unconditional unique constraint on
// (fingerprint, drift_signature). A repeated observation increments the
// occurrence count and refreshes last_seen_at; the original evidence and any
// decision are left untouched. RETURNING yields the row in both cases, so the
// caller always learns the review id.
const upsertSQL = `
INSERT INTO source_reviews (
    fingerprint, drift_signature, mapping_id, mapping_version,
    category, drift_status, reason, changes, origin, sample_event_id
) VALUES (
    $1, $2, $3, $4,
    $5, $6, $7, $8::jsonb, $9, $10
)
ON CONFLICT (fingerprint, drift_signature) DO UPDATE SET
    occurrences  = source_reviews.occurrences + 1,
    last_seen_at = now()
RETURNING ` + itemColumns

// Upsert creates or refreshes the item for a drift signature.
func (p *PostgresStore) Upsert(ctx context.Context, item Item) (*Item, error) {
	if item.Fingerprint == "" {
		return nil, &ValidationError{Message: "fingerprint is required"}
	}

	// The store owns the deduplication key so a caller cannot supply an
	// inconsistent one.
	signature := Signature(item.Fingerprint, item.MappingID, item.MappingVersion, item.Changes)

	changes, err := json.Marshal(item.Changes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal review changes: %w", err)
	}

	origin := item.Origin
	if origin == "" {
		origin = OriginDriftEngine
	}

	return scanItem(p.db.QueryRowContext(ctx, upsertSQL,
		item.Fingerprint,
		signature,
		nullable(item.MappingID),
		nullableVersion(item.MappingVersion),
		string(item.Category),
		item.DriftStatus,
		item.Reason,
		string(changes),
		origin,
		nullable(item.SampleEventID),
	))
}

// Get returns one item by id.
func (p *PostgresStore) Get(ctx context.Context, reviewID int64) (*Item, error) {
	query := `SELECT ` + itemColumns + ` FROM source_reviews WHERE review_id = $1`

	return scanItem(p.db.QueryRowContext(ctx, query, reviewID))
}

// List returns items matching a filter, newest first.
func (p *PostgresStore) List(ctx context.Context, filter Filter) ([]Item, error) {
	query := `SELECT ` + itemColumns + ` FROM source_reviews`
	conditions := make([]string, 0, 2)
	args := make([]any, 0, 3)

	if filter.Status != "" {
		args = append(args, string(filter.Status))
		conditions = append(conditions, fmt.Sprintf("status = $%d", len(args)))
	}
	if filter.Fingerprint != "" {
		args = append(args, filter.Fingerprint)
		conditions = append(conditions, fmt.Sprintf("fingerprint = $%d", len(args)))
	}
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY last_seen_at DESC, review_id DESC"

	if filter.Limit > 0 {
		args = append(args, filter.Limit)
		query += fmt.Sprintf(" LIMIT $%d", len(args))
	}

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list review items: %w", err)
	}
	defer rows.Close()

	items := make([]Item, 0, 8)
	for rows.Next() {
		item, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate review items: %w", err)
	}

	return items, nil
}

// decideSQL applies a terminal decision only while the item is still pending.
// The WHERE clause is the compare-and-set: a concurrent decider sees zero rows
// affected and is reported as a transition error.
const decideSQL = `
UPDATE source_reviews SET
    status = $2,
    decided_at = now(),
    decided_by = $3,
    decision_notes = $4,
    resulting_mapping_version = COALESCE($5, resulting_mapping_version)
WHERE review_id = $1 AND status = 'pending'
RETURNING ` + itemColumns

// Decide applies a terminal decision using compare-and-set semantics.
func (p *PostgresStore) Decide(ctx context.Context, reviewID int64, decision Decision) (*Item, error) {
	if decision.Status != StatusApproved && decision.Status != StatusRejected {
		return nil, &ValidationError{Message: "decision status must be approved or rejected"}
	}

	item, err := scanItem(p.db.QueryRowContext(ctx, decideSQL,
		reviewID,
		string(decision.Status),
		nullable(decision.By),
		nullable(decision.Notes),
		nullableVersion(decision.ResultingMappingVersion),
	))
	if err == nil {
		return item, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	// No row was updated: either the item does not exist or it is no longer
	// pending. Re-read to report which.
	current, getErr := p.Get(ctx, reviewID)
	if getErr != nil {
		return nil, getErr
	}

	return nil, &TransitionError{ReviewID: reviewID, From: current.Status, To: decision.Status}
}

const reopenSQL = `
UPDATE source_reviews SET
    status = 'pending',
    decided_at = now(),
    decided_by = $2,
    decision_notes = $3
WHERE review_id = $1 AND status IN ('approved', 'rejected')
RETURNING ` + itemColumns

// Reopen returns a decided item to pending.
func (p *PostgresStore) Reopen(ctx context.Context, reviewID int64, by, notes string) (*Item, error) {
	comment := "reopened by " + orUnknown(by)
	if notes != "" {
		comment += ": " + notes
	}

	item, err := scanItem(p.db.QueryRowContext(ctx, reopenSQL, reviewID, nullable(by), comment))
	if err == nil {
		return item, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	current, getErr := p.Get(ctx, reviewID)
	if getErr != nil {
		return nil, getErr
	}

	return nil, &TransitionError{ReviewID: reviewID, From: current.Status, To: StatusPending}
}

// Ping verifies the database is reachable.
func (p *PostgresStore) Ping(ctx context.Context) error { return p.db.PingContext(ctx) }

// Close is a no-op: the connection pool is owned by the caller.
func (p *PostgresStore) Close() error { return nil }

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanItem(scanner rowScanner) (*Item, error) {
	var (
		item           Item
		category       string
		status         string
		changes        []byte
		proposed       []byte
		mappingID      sql.NullString
		mappingVersion sql.NullInt64
		resulting      sql.NullInt64
		sampleEventID  sql.NullString
		decidedAt      sql.NullTime
		decidedBy      sql.NullString
		decisionNotes  sql.NullString
		origin         string
	)

	err := scanner.Scan(
		&item.ReviewID,
		&item.Fingerprint,
		&item.Signature,
		&mappingID,
		&mappingVersion,
		&category,
		&item.DriftStatus,
		&item.Reason,
		&changes,
		&proposed,
		&status,
		&resulting,
		&item.Occurrences,
		&origin,
		&sampleEventID,
		&item.FirstSeenAt,
		&item.LastSeenAt,
		&decidedAt,
		&decidedBy,
		&decisionNotes,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	item.Category = Category(category)
	item.Status = Status(status)
	item.Origin = origin
	item.MappingID = mappingID.String
	item.MappingVersion = int(mappingVersion.Int64)
	item.ResultingMappingVersion = int(resulting.Int64)
	item.SampleEventID = sampleEventID.String
	item.DecidedBy = decidedBy.String
	item.DecisionNotes = decisionNotes.String
	if decidedAt.Valid {
		decided := decidedAt.Time
		item.DecidedAt = &decided
	}

	if len(changes) > 0 {
		if err := json.Unmarshal(changes, &item.Changes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal changes for review %d: %w", item.ReviewID, err)
		}
	}
	if len(proposed) > 0 {
		var fieldContract contract.Contract
		if err := json.Unmarshal(proposed, &fieldContract); err != nil {
			return nil, fmt.Errorf("failed to unmarshal proposed contract for review %d: %w", item.ReviewID, err)
		}
		item.ProposedContract = &fieldContract
	}

	return &item, nil
}

// nullable maps an empty string to SQL NULL.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableVersion maps a zero version to SQL NULL, so "no mapping yet" is not
// confused with version 0.
func nullableVersion(v int) any {
	if v <= 0 {
		return nil
	}
	return v
}
