package review

import (
	"context"
	"sort"
	"strconv"
	"sync"
	"time"
)

// MemoryStore is an in-memory Store for tests and local development. It mirrors
// the deduplication and compare-and-set semantics of the PostgreSQL store.
type MemoryStore struct {
	mu sync.Mutex

	items map[int64]*Item

	// bySignature indexes the deduplication key, mirroring the UNIQUE
	// constraint on (fingerprint, drift_signature).
	bySignature map[string]int64

	nextID int64
	now    func() time.Time
}

// NewMemoryStore creates an empty review queue.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		items:       make(map[int64]*Item),
		bySignature: make(map[string]int64),
		nextID:      1,
		now:         func() time.Time { return time.Now().UTC() },
	}
}

// Upsert creates or refreshes the item for a drift signature.
func (m *MemoryStore) Upsert(_ context.Context, item Item) (*Item, error) {
	if item.Fingerprint == "" {
		return nil, &ValidationError{Message: "fingerprint is required"}
	}

	signature := Signature(item.Fingerprint, item.MappingID, item.MappingVersion, item.Changes)

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()

	if existingID, ok := m.bySignature[signature]; ok {
		existing := m.items[existingID]
		existing.Occurrences++
		existing.LastSeenAt = now
		stored := *existing
		return &stored, nil
	}

	item.ReviewID = m.nextID
	m.nextID++
	item.Signature = signature
	item.Status = StatusPending
	item.Occurrences = 1
	item.FirstSeenAt = now
	item.LastSeenAt = now
	if item.Origin == "" {
		item.Origin = OriginDriftEngine
	}

	m.items[item.ReviewID] = &item
	m.bySignature[signature] = item.ReviewID

	stored := item
	return &stored, nil
}

// Get returns one item by id.
func (m *MemoryStore) Get(_ context.Context, reviewID int64) (*Item, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	item, ok := m.items[reviewID]
	if !ok {
		return nil, ErrNotFound
	}

	stored := *item
	return &stored, nil
}

// List returns items matching a filter, newest first.
func (m *MemoryStore) List(_ context.Context, filter Filter) ([]Item, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]Item, 0, len(m.items))
	for _, item := range m.items {
		if filter.Status != "" && item.Status != filter.Status {
			continue
		}
		if filter.Fingerprint != "" && item.Fingerprint != filter.Fingerprint {
			continue
		}
		out = append(out, *item)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeenAt.Equal(out[j].LastSeenAt) {
			return out[i].ReviewID < out[j].ReviewID
		}
		return out[i].LastSeenAt.After(out[j].LastSeenAt)
	})

	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}

	return out, nil
}

// Decide applies a terminal decision using compare-and-set semantics.
func (m *MemoryStore) Decide(_ context.Context, reviewID int64, decision Decision) (*Item, error) {
	if decision.Status != StatusApproved && decision.Status != StatusRejected {
		return nil, &ValidationError{Message: "decision status must be approved or rejected"}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	return m.decideLocked(reviewID, decision)
}

func (m *MemoryStore) decideLocked(reviewID int64, decision Decision) (*Item, error) {
	item, ok := m.items[reviewID]
	if !ok {
		return nil, ErrNotFound
	}
	if !CanTransition(item.Status, decision.Status) {
		return nil, &TransitionError{ReviewID: reviewID, From: item.Status, To: decision.Status}
	}

	now := m.now()
	item.Status = decision.Status
	item.DecidedAt = &now
	item.DecidedBy = decision.By
	item.DecisionNotes = decision.Notes
	if decision.ResultingMappingVersion > 0 {
		item.ResultingMappingVersion = decision.ResultingMappingVersion
	}

	stored := *item
	return &stored, nil
}

// Reopen returns a decided item to pending.
func (m *MemoryStore) Reopen(_ context.Context, reviewID int64, by, notes string) (*Item, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	item, ok := m.items[reviewID]
	if !ok {
		return nil, ErrNotFound
	}
	if !CanTransition(item.Status, StatusPending) {
		return nil, &TransitionError{ReviewID: reviewID, From: item.Status, To: StatusPending}
	}

	previous := ""
	if item.DecidedBy != "" {
		previous = " (previously " + string(item.Status) + " by " + item.DecidedBy + ")"
	}

	now := m.now()
	item.Status = StatusPending
	item.DecidedAt = &now
	item.DecidedBy = by
	item.DecisionNotes = "reopened" + previous
	if notes != "" {
		item.DecisionNotes += ": " + notes
	}

	stored := *item
	return &stored, nil
}

// Ping always succeeds for the in-memory queue.
func (m *MemoryStore) Ping(_ context.Context) error { return nil }

// Close is a no-op for the in-memory queue.
func (m *MemoryStore) Close() error { return nil }

// ValidationError reports an invalid item or decision.
type ValidationError struct{ Message string }

func (e *ValidationError) Error() string { return "invalid review item: " + e.Message }

// TransitionError reports an illegal lifecycle move.
type TransitionError struct {
	ReviewID int64
	From, To Status
}

func (e *TransitionError) Error() string {
	return "invalid review state transition for item " +
		strconv.FormatInt(e.ReviewID, 10) + ": " + string(e.From) + " -> " + string(e.To)
}

// Unwrap lets TransitionError satisfy errors.Is(err, ErrInvalidTransition).
func (e *TransitionError) Unwrap() error { return ErrInvalidTransition }
