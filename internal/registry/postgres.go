package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/contract"
)

// PostgresStore persists registry entries in PostgreSQL.
//
// The pool is owned by the caller and is not closed by Close.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore wraps an open database handle.
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// Entry is the registry row as stored; kept local to the SQL mapping.
type row struct {
	fingerprint    string
	mappingID      string
	mappingVersion int
	vendor         sql.NullString
	product        sql.NullString
	sourceType     sql.NullString
	format         string
	parserID       string
	parserVersion  string
	status         string
	contractJSON   []byte
	contractHash   string
	parentVersion  int
	driftStatus    sql.NullString
	rationale      sql.NullString
	createdAt      time.Time
	updatedAt      time.Time
}

const selectColumns = `
    fingerprint, mapping_id, mapping_version, vendor, product, source_type, format,
    parser_id, parser_version, status, contract, contract_hash, parent_version,
    drift_status, rationale, created_at, updated_at`

// ActiveFor returns the active version for a fingerprint.
func (p *PostgresStore) ActiveFor(ctx context.Context, fingerprint string) (*Entry, error) {
	query := `SELECT ` + selectColumns + `
        FROM source_registry
        WHERE fingerprint = $1 AND status = $2
        ORDER BY mapping_version DESC
        LIMIT 1`

	return queryEntry(ctx, p.db.QueryRowContext(ctx, query, fingerprint, string(StatusActive)))
}

// VersionsFor returns every version for a fingerprint, newest first.
func (p *PostgresStore) VersionsFor(ctx context.Context, fingerprint string) ([]Entry, error) {
	query := `SELECT ` + selectColumns + `
        FROM source_registry
        WHERE fingerprint = $1
        ORDER BY mapping_version DESC`

	rows, err := p.db.QueryContext(ctx, query, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to query registry versions for %s: %w", fingerprint, err)
	}
	defer rows.Close()

	entries := make([]Entry, 0, 4)
	for rows.Next() {
		entry, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate registry versions for %s: %w", fingerprint, err)
	}

	if len(entries) == 0 {
		return nil, ErrNotFound
	}

	return entries, nil
}

// GetVersion returns one specific version.
func (p *PostgresStore) GetVersion(ctx context.Context, ref VersionRef) (*Entry, error) {
	query := `SELECT ` + selectColumns + `
        FROM source_registry
        WHERE fingerprint = $1 AND mapping_id = $2 AND mapping_version = $3`

	return queryEntry(ctx, p.db.QueryRowContext(ctx, query, ref.Fingerprint, ref.MappingID, ref.MappingVersion))
}

// SaveVersion appends a new version and supersedes the previously active one.
//
// The whole sequence runs in one transaction behind a per-fingerprint advisory
// lock, so two workers that observe the same drift concurrently cannot both
// allocate the same version number.
func (p *PostgresStore) SaveVersion(ctx context.Context, entry Entry) (*Entry, error) {
	if entry.Fingerprint == "" {
		return nil, &ValidationError{Message: "fingerprint is required"}
	}
	if entry.MappingID == "" {
		return nil, &ValidationError{Message: "mapping_id is required"}
	}
	if entry.Status == "" {
		entry.Status = StatusActive
	}

	contractJSON, err := json.Marshal(entry.Contract.Normalized())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal contract: %w", err)
	}
	contractHash := entry.Contract.Hash()

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin registry transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, entry.Fingerprint); err != nil {
		return nil, fmt.Errorf("failed to lock registry for %s: %w", entry.Fingerprint, err)
	}

	// An identical contract already recorded for this source means there is
	// nothing to adapt: return the existing version rather than duplicating it.
	var existingVersion int
	err = tx.QueryRowContext(ctx,
		`SELECT mapping_version FROM source_registry
         WHERE fingerprint = $1 AND mapping_id = $2 AND contract_hash = $3
         ORDER BY mapping_version DESC LIMIT 1`,
		entry.Fingerprint, entry.MappingID, contractHash).Scan(&existingVersion)
	if err == nil {
		existing, err := p.getVersionTx(ctx, tx, VersionRef{
			Fingerprint:    entry.Fingerprint,
			MappingID:      entry.MappingID,
			MappingVersion: existingVersion,
		})
		if err != nil {
			return nil, err
		}
		return existing, nil
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to check for an existing contract: %w", err)
	}

	var maxVersion int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(mapping_version), 0) FROM source_registry
         WHERE fingerprint = $1 AND mapping_id = $2`,
		entry.Fingerprint, entry.MappingID).Scan(&maxVersion); err != nil {
		return nil, fmt.Errorf("failed to read the current mapping version: %w", err)
	}

	nextVersion := maxVersion + 1

	// Supersede before inserting: the partial unique index permits only one
	// active row per (fingerprint, mapping_id).
	if entry.Status == StatusActive {
		if _, err := tx.ExecContext(ctx,
			`UPDATE source_registry
             SET status = $3, updated_at = now()
             WHERE fingerprint = $1 AND mapping_id = $2 AND status = $4`,
			entry.Fingerprint, entry.MappingID, string(StatusSuperseded), string(StatusActive)); err != nil {
			return nil, fmt.Errorf("failed to supersede the previous mapping version: %w", err)
		}
	}

	now := time.Now().UTC()
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = now
	}
	entry.UpdatedAt = now
	entry.MappingVersion = nextVersion

	if _, err := tx.ExecContext(ctx, `
        INSERT INTO source_registry (
            fingerprint, mapping_id, mapping_version, vendor, product, source_type, format,
            parser_id, parser_version, status, contract, contract_hash, parent_version,
            drift_status, rationale, created_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11::jsonb, $12, $13,
            $14, $15, $16, $17
        )`,
		entry.Fingerprint, entry.MappingID, entry.MappingVersion,
		nullable(entry.Vendor), nullable(entry.Product), nullable(entry.SourceType), entry.Format,
		entry.ParserID, entry.ParserVersion, string(entry.Status), string(contractJSON), contractHash,
		entry.ParentVersion, nullable(entry.DriftStatus), nullable(entry.Rationale),
		entry.CreatedAt, entry.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("failed to insert registry version %d: %w", entry.MappingVersion, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit registry version: %w", err)
	}

	stored := entry
	return &stored, nil
}

// getVersionTx reads one version inside an open transaction.
func (p *PostgresStore) getVersionTx(ctx context.Context, tx *sql.Tx, ref VersionRef) (*Entry, error) {
	query := `SELECT ` + selectColumns + `
        FROM source_registry
        WHERE fingerprint = $1 AND mapping_id = $2 AND mapping_version = $3`

	return queryEntry(ctx, tx.QueryRowContext(ctx, query, ref.Fingerprint, ref.MappingID, ref.MappingVersion))
}

// Ping verifies the database is reachable.
func (p *PostgresStore) Ping(ctx context.Context) error { return p.db.PingContext(ctx) }

// Close is a no-op: the connection pool is owned by the caller.
func (p *PostgresStore) Close() error { return nil }

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func queryEntry(_ context.Context, scanner rowScanner) (*Entry, error) {
	entry, err := scanEntry(scanner)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return entry, nil
}

func scanEntry(scanner rowScanner) (*Entry, error) {
	var r row

	if err := scanner.Scan(
		&r.fingerprint, &r.mappingID, &r.mappingVersion, &r.vendor, &r.product, &r.sourceType, &r.format,
		&r.parserID, &r.parserVersion, &r.status, &r.contractJSON, &r.contractHash, &r.parentVersion,
		&r.driftStatus, &r.rationale, &r.createdAt, &r.updatedAt,
	); err != nil {
		return nil, err
	}

	var fieldContract contract.Contract
	if err := json.Unmarshal(r.contractJSON, &fieldContract); err != nil {
		return nil, fmt.Errorf("failed to unmarshal stored contract for %s: %w", r.fingerprint, err)
	}

	return &Entry{
		Fingerprint:    r.fingerprint,
		Vendor:         r.vendor.String,
		Product:        r.product.String,
		SourceType:     r.sourceType.String,
		Format:         r.format,
		ParserID:       r.parserID,
		ParserVersion:  r.parserVersion,
		MappingID:      r.mappingID,
		MappingVersion: r.mappingVersion,
		Status:         Status(r.status),
		Contract:       fieldContract,
		ParentVersion:  r.parentVersion,
		DriftStatus:    r.driftStatus.String,
		Rationale:      r.rationale.String,
		CreatedAt:      r.createdAt,
		UpdatedAt:      r.updatedAt,
	}, nil
}

// nullable maps an empty string to SQL NULL.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
