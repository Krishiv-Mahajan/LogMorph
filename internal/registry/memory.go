package registry

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemoryStore is an in-memory Store for tests and local development. It mirrors
// the append-only, single-active-version semantics of the PostgreSQL store.
type MemoryStore struct {
	mu sync.RWMutex

	// entries maps fingerprint -> ordered list of versions (append-only).
	entries map[string][]Entry
}

// NewMemoryStore creates an empty in-memory registry.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{entries: make(map[string][]Entry)}
}

// ActiveFor returns the active version for a fingerprint.
func (m *MemoryStore) ActiveFor(_ context.Context, fingerprint string) (*Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	versions := m.entries[fingerprint]
	for i := len(versions) - 1; i >= 0; i-- {
		if versions[i].Status == StatusActive {
			entry := versions[i]
			return &entry, nil
		}
	}

	return nil, ErrNotFound
}

// VersionsFor returns every version for a fingerprint, newest first.
func (m *MemoryStore) VersionsFor(_ context.Context, fingerprint string) ([]Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	versions := m.entries[fingerprint]
	if len(versions) == 0 {
		return nil, ErrNotFound
	}

	out := make([]Entry, 0, len(versions))
	for i := len(versions) - 1; i >= 0; i-- {
		out = append(out, versions[i])
	}

	return out, nil
}

// GetVersion returns one specific version.
func (m *MemoryStore) GetVersion(_ context.Context, ref VersionRef) (*Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, entry := range m.entries[ref.Fingerprint] {
		if entry.MappingID == ref.MappingID && entry.MappingVersion == ref.MappingVersion {
			found := entry
			return &found, nil
		}
	}

	return nil, ErrNotFound
}

// SaveVersion appends a new version and supersedes the previous active one.
func (m *MemoryStore) SaveVersion(_ context.Context, entry Entry) (*Entry, error) {
	if entry.Fingerprint == "" {
		return nil, errInvalid("fingerprint is required")
	}
	if entry.MappingID == "" {
		return nil, errInvalid("mapping_id is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	versions := m.entries[entry.Fingerprint]

	next := 1
	for _, existing := range versions {
		if existing.MappingID == entry.MappingID && existing.MappingVersion >= next {
			next = existing.MappingVersion + 1
		}
	}

	now := time.Now().UTC()
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = now
	}
	entry.UpdatedAt = now
	entry.MappingVersion = next

	if entry.Status == "" {
		entry.Status = StatusActive
	}

	// Supersede the previously active version of the same mapping.
	if entry.Status == StatusActive {
		for i := range versions {
			if versions[i].MappingID == entry.MappingID && versions[i].Status == StatusActive {
				versions[i].Status = StatusSuperseded
				versions[i].UpdatedAt = now
			}
		}
	}

	// A review-required version is recorded but must never become the active
	// mapping by accident.
	m.entries[entry.Fingerprint] = append(versions, entry)

	stored := entry
	return &stored, nil
}

// Ping always succeeds for the in-memory registry.
func (m *MemoryStore) Ping(_ context.Context) error { return nil }

// Close is a no-op for the in-memory registry.
func (m *MemoryStore) Close() error { return nil }

// ContractHistory returns the distinct contract hashes seen for a fingerprint,
// oldest first. It is a test helper used to assert that previous versions stay
// available after an adaptation.
func (m *MemoryStore) ContractHistory(_ context.Context, fingerprint string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	versions := make([]Entry, len(m.entries[fingerprint]))
	copy(versions, m.entries[fingerprint])
	sort.SliceStable(versions, func(i, j int) bool {
		return versions[i].MappingVersion < versions[j].MappingVersion
	})

	hashes := make([]string, 0, len(versions))
	for _, entry := range versions {
		hashes = append(hashes, entry.Contract.Hash())
	}

	return hashes
}

func errInvalid(message string) error {
	return &ValidationError{Message: message}
}

// ValidationError reports an invalid registry entry.
type ValidationError struct{ Message string }

func (e *ValidationError) Error() string { return "invalid registry entry: " + e.Message }
