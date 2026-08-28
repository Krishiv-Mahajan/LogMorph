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
	Ping(ctx context.Context) error
	Close() error
}

// RedisRawBuffer implements RawBuffer backed by go-redis.
type RedisRawBuffer struct {
	client *goredis.Client
}

// NewRedisRawBuffer initializes a connection to Redis.
func NewRedisRawBuffer(addr, password string, db int) (*RedisRawBuffer, error) {
	rdb := goredis.NewClient(&goredis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	return &RedisRawBuffer{client: rdb}, nil
}

// Ping checks if Redis is reachable.
func (r *RedisRawBuffer) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// PublishRaw serializes RawEvent and adds it to the raw_events Redis stream.
func (r *RedisRawBuffer) PublishRaw(ctx context.Context, stream string, event *models.RawEvent) (string, error) {
	if stream == "" {
		stream = DefaultRawStreamName
	}

	payloadJSON, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("failed to marshal raw event: %w", err)
	}

	id, err := r.client.XAdd(ctx, &goredis.XAddArgs{
		Stream: stream,
		Values: map[string]interface{}{
			"event_id": event.EventID,
			"payload":  string(payloadJSON),
		},
	}).Result()

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
			payloadStr, ok := msg.Values["payload"].(string)
			if !ok {
				continue
			}

			var rawEvent models.RawEvent
			if err := json.Unmarshal([]byte(payloadStr), &rawEvent); err != nil {
				continue
			}

			rawMessages = append(rawMessages, RawMessage{
				ID:    msg.ID,
				Event: rawEvent,
			})
		}
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
