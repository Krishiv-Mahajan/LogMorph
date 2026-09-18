// Package normalized persists successfully validated UniversalEvents to the
// canonical event store.
package normalized

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// Record pairs a validated UniversalEvent with the metadata the store needs
// that is not part of the canonical event itself.
type Record struct {
	// Event is the validated UniversalEvent (never nil).
	Event *models.UniversalEvent

	// RawObjectKey is the object key of the immutable raw payload in MinIO.
	// The raw payload is referenced, not duplicated.
	RawObjectKey string

	// ReceivedAt is when ingestion accepted the raw event. Zero when unknown.
	ReceivedAt time.Time

	// Provenance identifies the source, parser and mapping version that
	// produced this event.
	Provenance models.Provenance
}

// Store persists normalized UniversalEvents.
//
// Implementations MUST be idempotent: saving the same event_id twice must not
// create a second record. Save reports whether a new record was inserted.
type Store interface {
	// Save persists the record. inserted is false when a record for the same
	// event_id already existed (a duplicate delivery), which is not an error.
	Save(ctx context.Context, rec Record) (inserted bool, err error)

	// Get returns the stored record, or an error when absent.
	Get(ctx context.Context, eventID string) (*Record, error)

	// Count returns the number of stored events (used by verification tools).
	Count(ctx context.Context) (int64, error)

	// Ping verifies connectivity to the backing store.
	Ping(ctx context.Context) error

	// Close releases resources.
	Close() error
}

// MemoryStore is an in-memory Store for tests and local development.
type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]Record
}

// NewMemoryStore creates an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]Record)}
}

// Save stores the record, keyed by event_id.
func (m *MemoryStore) Save(_ context.Context, rec Record) (bool, error) {
	if rec.Event == nil {
		return false, fmt.Errorf("cannot store nil event")
	}
	if rec.Event.EventID == "" {
		return false, fmt.Errorf("cannot store event with empty event_id")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.records[rec.Event.EventID]; exists {
		return false, nil
	}

	copiedEvent := *rec.Event
	rec.Event = &copiedEvent
	m.records[rec.Event.EventID] = rec

	return true, nil
}

// Get returns the stored record.
func (m *MemoryStore) Get(_ context.Context, eventID string) (*Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rec, ok := m.records[eventID]
	if !ok {
		return nil, fmt.Errorf("normalized event %s not found", eventID)
	}

	copiedEvent := *rec.Event
	rec.Event = &copiedEvent

	return &rec, nil
}

// Count returns the number of stored events.
func (m *MemoryStore) Count(_ context.Context) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return int64(len(m.records)), nil
}

// Ping always succeeds for the in-memory store.
func (m *MemoryStore) Ping(_ context.Context) error { return nil }

// Close is a no-op for the in-memory store.
func (m *MemoryStore) Close() error { return nil }
