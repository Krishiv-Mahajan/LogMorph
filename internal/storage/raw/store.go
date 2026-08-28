package raw

import (
	"context"
	"fmt"
	"sync"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// RawEventStore provides an immutable storage interface for ingested raw events.
type RawEventStore interface {
	Put(ctx context.Context, event *models.RawEvent) error
	Get(ctx context.Context, eventID string) (*models.RawEvent, error)
	Close() error
}

// MemoryRawStore is an in-memory implementation for testing and fallback.
type MemoryRawStore struct {
	events map[string]*models.RawEvent
	mu     sync.RWMutex
}

// NewMemoryRawStore creates a new in-memory store.
func NewMemoryRawStore() *MemoryRawStore {
	return &MemoryRawStore{
		events: make(map[string]*models.RawEvent),
	}
}

func (m *MemoryRawStore) Put(ctx context.Context, event *models.RawEvent) error {
	if event == nil || event.EventID == "" {
		return fmt.Errorf("invalid raw event or missing event_id")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clone to preserve immutability
	copied := *event
	m.events[event.EventID] = &copied
	return nil
}

func (m *MemoryRawStore) Get(ctx context.Context, eventID string) (*models.RawEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	event, exists := m.events[eventID]
	if !exists {
		return nil, fmt.Errorf("raw event %s not found", eventID)
	}
	copied := *event
	return &copied, nil
}

func (m *MemoryRawStore) Close() error {
	return nil
}
