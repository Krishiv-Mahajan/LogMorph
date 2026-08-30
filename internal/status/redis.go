package status

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/Krishiv-Mahajan/LogMorph/internal/buffer"
)

const (
	redisKeyPrefix       = "event_status:"
	DefaultStatusTTLSecs = 3600
)

// RedisStatusStore implements Store backed by go-redis.
//
// It reuses the underlying Redis connection from an existing *buffer.RedisRawBuffer
// (the same pattern used by RedisIdempotencyStore) so no extra connection is needed.
//
// Concurrency safety for UpdateStage / UpdateOverall:
//
//	The Worker processes stages for a single event sequentially (Detection →
//	Drift → Parsing → Normalization → Validation) so there is no concurrent
//	writer for the same stage. However, two workers could theoretically race on
//	the same event (one retrying, one holding the lock). To prevent one writer
//	from overwriting another's stage changes we use a Lua script that performs
//	a read-modify-write atomically inside Redis, ensuring no interleaved writes.
type RedisStatusStore struct {
	client *goredis.Client
	ttl    time.Duration

	// Compiled Lua scripts for atomic stage/overall updates.
	updateStageScript   *goredis.Script
	updateOverallScript *goredis.Script
}

// Lua script: atomically read, merge a single stage change, and re-write with TTL.
//
// KEYS[1] = event_status key
// ARGV[1] = stage key (e.g. "detection")
// ARGV[2] = stage JSON blob
// ARGV[3] = TTL in seconds
var luaUpdateStage = goredis.NewScript(`
local raw = redis.call("GET", KEYS[1])
if raw == false then
  return redis.error_reply("NOT_FOUND")
end
local obj = cjson.decode(raw)
if obj["stages"] == nil then
  obj["stages"] = {}
end
obj["stages"][ARGV[1]] = cjson.decode(ARGV[2])
redis.call("SET", KEYS[1], cjson.encode(obj), "EX", ARGV[3])
return 1
`)

// Lua script: atomically read, patch top-level fields, and re-write with TTL.
//
// KEYS[1] = event_status key
// ARGV[1] = JSON patch object (only non-empty fields are patched)
// ARGV[2] = TTL in seconds
var luaUpdateOverall = goredis.NewScript(`
local raw = redis.call("GET", KEYS[1])
if raw == false then
  return redis.error_reply("NOT_FOUND")
end
local obj = cjson.decode(raw)
local patch = cjson.decode(ARGV[1])
for k, v in pairs(patch) do
  obj[k] = v
end
redis.call("SET", KEYS[1], cjson.encode(obj), "EX", ARGV[2])
return 1
`)

// NewRedisStatusStore creates a RedisStatusStore that shares the underlying
// Redis connection of the supplied *buffer.RedisRawBuffer.
// ttl is the key expiry duration; pass 0 to use the DefaultStatusTTLSecs.
func NewRedisStatusStore(buf *buffer.RedisRawBuffer, ttl time.Duration) *RedisStatusStore {
	if ttl <= 0 {
		ttl = DefaultStatusTTLSecs * time.Second
	}
	return &RedisStatusStore{
		client:              buf.Client(),
		ttl:                 ttl,
		updateStageScript:   luaUpdateStage,
		updateOverallScript: luaUpdateOverall,
	}
}

func (r *RedisStatusStore) key(eventID string) string {
	return redisKeyPrefix + eventID
}

func (r *RedisStatusStore) ttlSeconds() string {
	return fmt.Sprintf("%d", int64(r.ttl.Seconds()))
}

// Create writes the initial EventStatus to Redis with the configured TTL.
func (r *RedisStatusStore) Create(ctx context.Context, s *EventStatus) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("status: marshal failed: %w", err)
	}
	if err := r.client.Set(ctx, r.key(s.EventID), data, r.ttl).Err(); err != nil {
		return fmt.Errorf("status: redis SET failed: %w", err)
	}
	return nil
}

// Get retrieves the EventStatus for eventID.
// Returns ErrNotFound when the key does not exist.
func (r *RedisStatusStore) Get(ctx context.Context, eventID string) (*EventStatus, error) {
	raw, err := r.client.Get(ctx, r.key(eventID)).Result()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("status: redis GET failed: %w", err)
	}
	var s EventStatus
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return nil, fmt.Errorf("status: unmarshal failed: %w", err)
	}
	return &s, nil
}

// UpdateStage atomically replaces a single stage entry within the EventStatus
// using a Lua script to prevent concurrent writers from clobbering each other.
func (r *RedisStatusStore) UpdateStage(ctx context.Context, eventID string, stage StageResult) error {
	stageJSON, err := json.Marshal(stage)
	if err != nil {
		return fmt.Errorf("status: marshal stage failed: %w", err)
	}
	err = r.updateStageScript.Run(ctx, r.client,
		[]string{r.key(eventID)},
		stage.ID, string(stageJSON), r.ttlSeconds(),
	).Err()
	if err != nil {
		if err.Error() == "NOT_FOUND" {
			return ErrNotFound
		}
		return fmt.Errorf("status: UpdateStage Lua failed: %w", err)
	}
	return nil
}

// UpdateOverall atomically patches the top-level fields of an EventStatus
// without touching the stages map, using a Lua script.
func (r *RedisStatusStore) UpdateOverall(ctx context.Context, eventID string, u OverallUpdate) error {
	// Build a map with only the fields we intend to patch.
	patch := buildOverallPatch(u)
	patchJSON, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("status: marshal patch failed: %w", err)
	}
	err = r.updateOverallScript.Run(ctx, r.client,
		[]string{r.key(eventID)},
		string(patchJSON), r.ttlSeconds(),
	).Err()
	if err != nil {
		if err.Error() == "NOT_FOUND" {
			return ErrNotFound
		}
		return fmt.Errorf("status: UpdateOverall Lua failed: %w", err)
	}
	return nil
}

// Delete removes the EventStatus key for eventID. It is a no-op when the key
// does not exist (used for best-effort cleanup after a failed publish).
func (r *RedisStatusStore) Delete(ctx context.Context, eventID string) error {
	return r.client.Del(ctx, r.key(eventID)).Err()
}

// buildOverallPatch converts an OverallUpdate into a JSON-serialisable map
// containing only the fields that should be patched in the Lua script.
// DriftDetected is always included (bool zero value is intentional).
func buildOverallPatch(u OverallUpdate) map[string]interface{} {
	m := map[string]interface{}{}
	if u.DriftDetected != nil {
		m["drift_detected"] = *u.DriftDetected
	}
	if u.Status != "" {
		m["status"] = u.Status
	}
	if u.FormatName != "" {
		m["format_name"] = u.FormatName
	}
	if u.Source != "" {
		m["source"] = u.Source
	}
	if u.Action != "" {
		m["action"] = u.Action
	}
	if u.ErrorMessage != "" {
		m["error_message"] = u.ErrorMessage
	}
	if u.ConfidenceScore != 0 {
		m["confidence_score"] = u.ConfidenceScore
	}
	if u.ParserName != "" {
		m["parser_name"] = u.ParserName
	}
	if u.UniversalEvent != nil {
		m["universal_event"] = u.UniversalEvent
	}
	return m
}
