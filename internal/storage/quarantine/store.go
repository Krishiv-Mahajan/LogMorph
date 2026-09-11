package quarantine

import (
	"context"
	"sync"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// Store defines the interface for persisting quarantined events.
type Store interface {
	Put(ctx context.Context, record *models.QuarantineRecord) error
}

// MemoryQuarantineStore is an in-memory implementation of the quarantine Store for testing.
type MemoryQuarantineStore struct {
	mu      sync.RWMutex
	records map[string]*models.QuarantineRecord
}

// NewMemoryQuarantineStore creates a new MemoryQuarantineStore.
func NewMemoryQuarantineStore() *MemoryQuarantineStore {
	return &MemoryQuarantineStore{
		records: make(map[string]*models.QuarantineRecord),
	}
}

// Put stores a QuarantineRecord in memory.
func (m *MemoryQuarantineStore) Put(ctx context.Context, record *models.QuarantineRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[record.EventID] = record
	return nil
}

// Get retrieves a QuarantineRecord from memory (used in testing).
func (m *MemoryQuarantineStore) Get(eventID string) (*models.QuarantineRecord, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	record, exists := m.records[eventID]
	return record, exists
}
