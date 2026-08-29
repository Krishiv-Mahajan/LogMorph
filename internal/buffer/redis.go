package buffer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

const (
	DefaultRawStreamName = "raw_events"
	DefaultGroupName     = "ulpf-worker-group"
)

// RawMessage contains an event consumed from Redis Streams with its stream ID.
type RawMessage struct {
	ID    string
	Event models.RawEvent
}

// RawBuffer defines the interface for the raw event Redis buffer.
type RawBuffer interface {
	PublishRaw(ctx context.Context, stream string, event *models.RawEvent) (string, error)
	EnsureGroup(ctx context.Context, stream string, group string) error
	ReadGroup(ctx context.Context, stream, group, consumer string, count int64, block time.Duration) ([]RawMessage, error)
	Ack(ctx context.Context, stream, group string, ids ...string) error
	// ClaimPending reclaims messages that have been idle for longer than minIdleTime
	// from any consumer in the group. Used for crash recovery when a worker dies
	// before ACKing. Implemented via XAUTOCLAIM (requires Redis ≥ 6.2).
	ClaimPending(ctx context.Context, stream, group, consumer string, minIdleTime time.Duration, count int64) ([]RawMessage, error)
	Ping(ctx context.Context) error
	Close() error
}

// RedisRawBuffer implements RawBuffer backed by go-redis.
type RedisRawBuffer struct {
	client *goredis.Client
	// maxLen caps the Redis stream length approximately. 0 means no limit.
	maxLen int64
}

// NewRedisRawBuffer initializes a connection to Redis.
// maxLen sets the approximate stream retention cap (0 = unlimited).
func NewRedisRawBuffer(addr, password string, db int, maxLen int64) (*RedisRawBuffer, error) {
	rdb := goredis.NewClient(&goredis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	return &RedisRawBuffer{client: rdb, maxLen: maxLen}, nil
}

// Ping checks if Redis is reachable.
func (r *RedisRawBuffer) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// PublishRaw serializes RawEvent and adds it to the raw_events Redis stream.
// When maxLen > 0 the stream is approximately trimmed to that many entries
// (XADD ... MAXLEN ~ maxLen ...) so Redis memory is bounded.
func (r *RedisRawBuffer) PublishRaw(ctx context.Context, stream string, event *models.RawEvent) (string, error) {
	if stream == "" {
		stream = DefaultRawStreamName
	}

	payloadJSON, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("failed to marshal raw event: %w", err)
	}

	args := &goredis.XAddArgs{
		Stream: stream,
		// Approx trimming (MAXLEN ~) is cheap at write time; exact trimming is O(N).
		MaxLen: r.maxLen,
		Approx: r.maxLen > 0,
		Values: map[string]interface{}{
			"event_id": event.EventID,
			"payload":  string(payloadJSON),
		},
	}

	id, err := r.client.XAdd(ctx, args).Result()
	if err != nil {
		return "", fmt.Errorf("failed to XAdd to stream %s: %w", stream, err)
	}

	return id, nil
}

// EnsureGroup creates the consumer group if it does not already exist.
func (r *RedisRawBuffer) EnsureGroup(ctx context.Context, stream string, group string) error {
	if stream == "" {
		stream = DefaultRawStreamName
	}
	if group == "" {
		group = DefaultGroupName
	}

	err := r.client.XGroupCreateMkStream(ctx, stream, group, "$").Err()
	if err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}
	return nil
}

// ReadGroup reads raw event messages from the consumer group stream.
func (r *RedisRawBuffer) ReadGroup(ctx context.Context, stream, group, consumer string, count int64, block time.Duration) ([]RawMessage, error) {
	if stream == "" {
		stream = DefaultRawStreamName
	}
	if group == "" {
		group = DefaultGroupName
	}

	streams, err := r.client.XReadGroup(ctx, &goredis.XReadGroupArgs{
		Group:    group,
		Consumer: consumer,
		Streams:  []string{stream, ">"},
		Count:    count,
		Block:    block,
	}).Result()

	if err != nil {
		if err == goredis.Nil {
			return nil, nil
		}
		return nil, err
	}

	var rawMessages []RawMessage
	if len(streams) > 0 {
		for _, msg := range streams[0].Messages {
			rm, ok := parseXMessage(msg)
			if !ok {
				continue
			}
			rawMessages = append(rawMessages, rm)
		}
	}

	return rawMessages, nil
}

// ClaimPending uses XAUTOCLAIM to reclaim messages that have been idle for longer
// than minIdleTime across the consumer group. This recovers events that were
// delivered to a crashed worker that never sent XACK.
//
// The caller should supply "0-0" semantics are handled internally; each call
// scans from the beginning of the pending list so no cursor state is required
// for the MVP use-case.
func (r *RedisRawBuffer) ClaimPending(ctx context.Context, stream, group, consumer string, minIdleTime time.Duration, count int64) ([]RawMessage, error) {
	if stream == "" {
		stream = DefaultRawStreamName
	}
	if group == "" {
		group = DefaultGroupName
	}

	// XAutoClaim scans the pending-entries list (PEL) and reassigns messages that
	// have been idle for > minIdleTime to the named consumer.
	messages, _, err := r.client.XAutoClaim(ctx, &goredis.XAutoClaimArgs{
		Stream:   stream,
		Group:    group,
		Consumer: consumer,
		MinIdle:  minIdleTime,
		Start:    "0-0", // always scan from the start of the PEL
		Count:    count,
	}).Result()

	if err != nil {
		if err == goredis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("XAUTOCLAIM failed on stream %s: %w", stream, err)
	}

	var rawMessages []RawMessage
	for _, msg := range messages {
		rm, ok := parseXMessage(msg)
		if !ok {
			continue
		}
		rawMessages = append(rawMessages, rm)
	}

	return rawMessages, nil
}

// Ack marks messages as processed in the consumer group.
func (r *RedisRawBuffer) Ack(ctx context.Context, stream, group string, ids ...string) error {
	if stream == "" {
		stream = DefaultRawStreamName
	}
	if group == "" {
		group = DefaultGroupName
	}
	return r.client.XAck(ctx, stream, group, ids...).Err()
}

// Close closes the Redis connection.
func (r *RedisRawBuffer) Close() error {
	return r.client.Close()
}

// parseXMessage extracts a RawMessage from a raw Redis XMessage.
// Returns (msg, true) on success; (zero, false) if the message is malformed.
func parseXMessage(msg goredis.XMessage) (RawMessage, bool) {
	payloadStr, ok := msg.Values["payload"].(string)
	if !ok {
		return RawMessage{}, false
	}
	var rawEvent models.RawEvent
	if err := json.Unmarshal([]byte(payloadStr), &rawEvent); err != nil {
		return RawMessage{}, false
	}
	return RawMessage{ID: msg.ID, Event: rawEvent}, true
}
