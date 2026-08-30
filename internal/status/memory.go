package status

import (
	"context"
	"encoding/json"
	"sync"
)

// MemoryStatusStore implements Store using an in-memory map protected by a
// mutex. It is intended for unit tests that do not have a live Redis instance.
//
// It mirrors the Redis store's behaviour precisely, including:
//   - ErrNotFound when a key does not exist
//   - Atomic stage updates (deep-copy prevents aliasing bugs)
//   - Atomic overall-field patches without overwriting stage state
type MemoryStatusStore struct {
	mu   sync.RWMutex
	data map[string]*EventStatus // keyed by eventID
}

// NewMemoryStatusStore returns an empty in-memory status store.
func NewMemoryStatusStore() *MemoryStatusStore {
	return &MemoryStatusStore{
		data: make(map[string]*EventStatus),
	}
}

// Create stores s under its EventID. It overwrites any existing entry.
func (m *MemoryStatusStore) Create(_ context.Context, s *EventStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[s.EventID] = deepCopy(s)
	return nil
}

// Get retrieves a deep copy of the EventStatus for eventID.
// Returns ErrNotFound when no entry exists.
func (m *MemoryStatusStore) Get(_ context.Context, eventID string) (*EventStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.data[eventID]
	if !ok {
		return nil, ErrNotFound
	}
	return deepCopy(s), nil
}

// UpdateStage replaces the named stage within the EventStatus for eventID.
// All other stages and top-level fields are preserved.
// Returns ErrNotFound when no entry exists.
func (m *MemoryStatusStore) UpdateStage(_ context.Context, eventID string, stage StageResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.data[eventID]
	if !ok {
		return ErrNotFound
	}
	if s.Stages == nil {
		s.Stages = make(map[string]StageResult)
	}
	s.Stages[stage.ID] = stage
	return nil
}

// UpdateOverall patches top-level EventStatus fields without touching the
// Stages map.
// Returns ErrNotFound when no entry exists.
func (m *MemoryStatusStore) UpdateOverall(_ context.Context, eventID string, u OverallUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.data[eventID]
	if !ok {
		return ErrNotFound
	}
	applyOverall(s, u)
	return nil
}

// Delete removes the EventStatus for eventID. It is a no-op when not found.
func (m *MemoryStatusStore) Delete(_ context.Context, eventID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, eventID)
	return nil
}

// applyOverall patches only the non-zero fields from OverallUpdate into s.
// DriftDetected is always written because false is a valid value.
func applyOverall(s *EventStatus, u OverallUpdate) {
	if u.DriftDetected != nil {
		s.DriftDetected = *u.DriftDetected
	}
	if u.Status != "" {
		s.Status = u.Status
	}
	if u.FormatName != "" {
		s.FormatName = u.FormatName
	}
	if u.Source != "" {
		s.Source = u.Source
	}
	if u.Action != "" {
		s.Action = u.Action
	}
	if u.ErrorMessage != "" {
		s.ErrorMessage = u.ErrorMessage
	}
	if u.ConfidenceScore != 0 {
		s.ConfidenceScore = u.ConfidenceScore
	}
	if u.ParserName != "" {
		s.ParserName = u.ParserName
	}
	if u.UniversalEvent != nil {
		s.UniversalEvent = u.UniversalEvent
	}
}

// deepCopy returns a deep copy of s by round-tripping through JSON.
// This is simple, correct, and cheap enough for test usage.
func deepCopy(s *EventStatus) *EventStatus {
	data, err := json.Marshal(s)
	if err != nil {
		// Should never happen with well-formed EventStatus; panic is acceptable
		// in test code, and the caller controls the input.
		panic("status: deepCopy marshal failed: " + err.Error())
	}
	var out EventStatus
	if err := json.Unmarshal(data, &out); err != nil {
		panic("status: deepCopy unmarshal failed: " + err.Error())
	}
	return &out
}
