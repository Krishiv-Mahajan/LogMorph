package buffer

import (
	"context"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

const (
	// DefaultProcKeyPrefix is the Redis key prefix for the processing lock.
	// Key format: ulpf:proc:{event_id}
	DefaultProcKeyPrefix = "ulpf:proc:"
	// DefaultDoneKeyPrefix is the Redis key prefix for the completion marker.
	// Key format: ulpf:done:{event_id}
	DefaultDoneKeyPrefix = "ulpf:done:"
	// DefaultAttemptKeyPrefix is the Redis key prefix for the per-event
	// delivery-attempt counter. Key format: ulpf:attempt:{event_id}
	DefaultAttemptKeyPrefix = "ulpf:attempt:"
)

// IdempotencyStore provides atomic idempotency tracking backed by Redis.
//
// Design: two-phase approach.
//
//  1. Processing lock (SET NX):
//     Atomically claims the right to process an event. Only ONE worker can
//     acquire the lock for a given event_id. Short TTL so a crashed worker's
//     lock automatically expires and allows retry via XAUTOCLAIM.
//
//  2. Completion marker (SET):
//     Permanently records that an event was successfully processed. Written
//     only after successful pipeline execution. Prevents duplicate side-effects
//     on subsequent re-deliveries.
type IdempotencyStore interface {
	// TryClaimProcessing atomically acquires a processing lock for eventID via
	// Redis SET NX with a TTL. Returns (true, nil) when this caller has
	// acquired the exclusive lock, (false, nil) when another caller holds it.
	TryClaimProcessing(ctx context.Context, eventID string, ttl time.Duration) (bool, error)

	// ReleaseProcessing deletes the processing lock (e.g., on processing
	// failure) so another worker can retry via XAUTOCLAIM.
	ReleaseProcessing(ctx context.Context, eventID string) error

	// MarkDone records that eventID was successfully processed. Subsequent
	// calls to IsDone will return true until the TTL expires.
	MarkDone(ctx context.Context, eventID string, ttl time.Duration) error

	// IsDone reports whether eventID was already successfully processed.
	IsDone(ctx context.Context, eventID string) (bool, error)

	// RecordAttempt increments and returns the number of processing attempts
	// made for eventID. It bounds how long a retryable failure may keep a
	// message circulating: once the count reaches the configured maximum the
	// worker quarantines the event instead of retrying it again.
	RecordAttempt(ctx context.Context, eventID string, ttl time.Duration) (int64, error)
}

// ── Redis implementation ──────────────────────────────────────────────────────

// RedisIdempotencyStore implements IdempotencyStore backed by go-redis.
// It reuses the client from an existing RedisRawBuffer — no extra connection.
type RedisIdempotencyStore struct {
	client *goredis.Client
}

// NewRedisIdempotencyStore creates a RedisIdempotencyStore that shares the
// underlying Redis connection of the supplied RedisRawBuffer.
func NewRedisIdempotencyStore(buf *RedisRawBuffer) *RedisIdempotencyStore {
	return &RedisIdempotencyStore{client: buf.client}
}

// TryClaimProcessing runs: SET ulpf:proc:{eventID} 1 EX {ttl} NX
// Atomic: only one caller can succeed for the same eventID at a time.
func (r *RedisIdempotencyStore) TryClaimProcessing(ctx context.Context, eventID string, ttl time.Duration) (bool, error) {
	return r.client.SetNX(ctx, DefaultProcKeyPrefix+eventID, 1, ttl).Result()
}

// ReleaseProcessing deletes the processing lock key so another worker can
// claim it. Should be called when processing fails so XAUTOCLAIM retries work.
func (r *RedisIdempotencyStore) ReleaseProcessing(ctx context.Context, eventID string) error {
	return r.client.Del(ctx, DefaultProcKeyPrefix+eventID).Err()
}

// MarkDone sets ulpf:done:{eventID} with the given TTL. This is written
// only after successful processing to prevent future duplicate side-effects.
func (r *RedisIdempotencyStore) MarkDone(ctx context.Context, eventID string, ttl time.Duration) error {
	return r.client.Set(ctx, DefaultDoneKeyPrefix+eventID, 1, ttl).Err()
}

// IsDone returns true if a done marker exists for eventID.
func (r *RedisIdempotencyStore) IsDone(ctx context.Context, eventID string) (bool, error) {
	n, err := r.client.Exists(ctx, DefaultDoneKeyPrefix+eventID).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// RecordAttempt runs INCR ulpf:attempt:{eventID} and sets a TTL on first
// increment, returning the new attempt count. When Redis is unavailable it
// returns (0, err); callers treat 0 as "attempt count unknown" rather than as a
// reason to stop processing.
func (r *RedisIdempotencyStore) RecordAttempt(ctx context.Context, eventID string, ttl time.Duration) (int64, error) {
	key := DefaultAttemptKeyPrefix + eventID

	count, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}

	// Refresh the TTL only on the first attempt so the window cannot be
	// extended indefinitely by a retry loop.
	if count == 1 && ttl > 0 {
		if err := r.client.Expire(ctx, key, ttl).Err(); err != nil {
			return count, err
		}
	}

	return count, nil
}

// ── In-memory implementation (for tests and local dev) ───────────────────────

// MemoryIdempotencyStore implements IdempotencyStore in memory.
// It correctly mirrors the SET NX semantics of the Redis implementation so
// tests cover real concurrency behaviour without requiring a live Redis.
type MemoryIdempotencyStore struct {
	mu         sync.Mutex
	processing map[string]bool
	done       map[string]bool
	attempts   map[string]int64
}

// NewMemoryIdempotencyStore returns an in-memory IdempotencyStore.
func NewMemoryIdempotencyStore() *MemoryIdempotencyStore {
	return &MemoryIdempotencyStore{
		processing: make(map[string]bool),
		done:       make(map[string]bool),
		attempts:   make(map[string]int64),
	}
}

// TryClaimProcessing atomically acquires the processing lock using a mutex,
// mirroring Redis SET NX semantics. Returns (true, nil) on first acquisition.
func (m *MemoryIdempotencyStore) TryClaimProcessing(_ context.Context, eventID string, _ time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.processing[eventID] {
		return false, nil
	}
	m.processing[eventID] = true
	return true, nil
}

// ReleaseProcessing removes the in-memory processing lock.
func (m *MemoryIdempotencyStore) ReleaseProcessing(_ context.Context, eventID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.processing, eventID)
	return nil
}

// MarkDone marks an event as successfully processed and releases the lock.
func (m *MemoryIdempotencyStore) MarkDone(_ context.Context, eventID string, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.done[eventID] = true
	delete(m.processing, eventID) // implicit lock release
	return nil
}

// IsDone reports whether the event has been successfully processed.
func (m *MemoryIdempotencyStore) IsDone(_ context.Context, eventID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.done[eventID], nil
}

// RecordAttempt increments and returns the in-memory attempt counter.
func (m *MemoryIdempotencyStore) RecordAttempt(_ context.Context, eventID string, _ time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempts[eventID]++
	return m.attempts[eventID], nil
}
