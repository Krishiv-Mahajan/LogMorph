// Package quarantine stores events that failed permanently so they can be
// investigated instead of silently disappearing.
package quarantine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// Entry is a single quarantined event with everything needed to investigate it
// without re-reading the original Redis message.
type Entry struct {
	// EventID is the event_id of the failed event.
	EventID string

	// Stage is the pipeline stage that failed (parsing, normalization,
	// validation, raw_store, persistence, ...).
	Stage string

	// Type is the machine-readable failure code (e.g. "parse_failed").
	Type string

	// Class records why the event was quarantined: a permanent data failure,
	// or a retryable failure that exhausted its attempts.
	Class string

	// Message is the human-readable error.
	Message string

	// Attempts is the number of delivery attempts consumed before quarantine.
	Attempts int64

	// RawObjectKey references the immutable raw payload in MinIO.
	RawObjectKey string

	// RawFormat is the format hint carried by the raw event.
	RawFormat string

	// RawSource is the source hint carried by the raw event.
	RawSource string

	// StreamID is the Redis stream message id, useful for tracing.
	StreamID string

	// ConsumerName is the worker that quarantined the event.
	ConsumerName string

	// ReceivedAt is when ingestion accepted the raw event. Zero when unknown.
	ReceivedAt time.Time

	// RawPayload is the original raw event. It is retained here because a
	// quarantine record is the last-resort copy: an event may have been
	// quarantined before (or because) its MinIO write failed.
	RawPayload *models.RawEvent

	// QuarantinedAt is when the event was first quarantined.
	QuarantinedAt time.Time

	// Provenance identifies the source, parser, mapping version and drift
	// classification in force when the event failed.
	Provenance models.Provenance
}

// Store persists quarantined events.
//
// Implementations MUST be idempotent: quarantining the same event_id again
// updates the existing entry rather than creating a second one.
type Store interface {
	// Add quarantines an event. Re-quarantining the same event_id updates the
	// existing entry (attempt count is incremented, last_seen_at refreshed).
	Add(ctx context.Context, entry Entry) error

	// Get returns the quarantine entry for eventID, or an error when absent.
	Get(ctx context.Context, eventID string) (*Entry, error)

	// Count returns the number of quarantined events.
	Count(ctx context.Context) (int64, error)

	// Ping verifies connectivity to the backing store.
	Ping(ctx context.Context) error

	// Close releases resources.
	Close() error
}

// MemoryStore is an in-memory Store for tests and local development.
type MemoryStore struct {
	mu      sync.RWMutex
	entries map[string]Entry
}

// NewMemoryStore creates an empty in-memory quarantine store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{entries: make(map[string]Entry)}
}

// Add quarantines an event, updating the entry when it already exists.
func (m *MemoryStore) Add(_ context.Context, entry Entry) error {
	if entry.EventID == "" {
		return fmt.Errorf("cannot quarantine event with empty event_id")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.entries[entry.EventID]; ok {
		// Keep the first quarantine time; the attempt count is monotonic so a
		// re-quarantine never makes it look like fewer attempts were made.
		entry.QuarantinedAt = existing.QuarantinedAt
		if entry.Attempts < existing.Attempts {
			entry.Attempts = existing.Attempts
		}
	} else if entry.QuarantinedAt.IsZero() {
		entry.QuarantinedAt = time.Now().UTC()
	}

	if entry.Attempts <= 0 {
		entry.Attempts = 1
	}

	m.entries[entry.EventID] = entry

	return nil
}

// Get returns the quarantine entry for eventID.
func (m *MemoryStore) Get(_ context.Context, eventID string) (*Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.entries[eventID]
	if !ok {
		return nil, fmt.Errorf("event %s is not quarantined", eventID)
	}

	return &entry, nil
}

// Count returns the number of quarantined events.
func (m *MemoryStore) Count(_ context.Context) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return int64(len(m.entries)), nil
}

// Ping always succeeds for the in-memory store.
func (m *MemoryStore) Ping(_ context.Context) error { return nil }

// Close is a no-op for the in-memory store.
func (m *MemoryStore) Close() error { return nil }
