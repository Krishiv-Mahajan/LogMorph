package redis

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
	DefaultStreamName = "normalized_events"
	DefaultGroupName  = "ulpf-worker-group"
)

// StreamClient defines interface for publishing and consuming events from Redis Streams.
type StreamClient interface {
	PublishEvent(ctx context.Context, stream string, event *models.WorkerEvent) (string, error)
	EnsureConsumerGroup(ctx context.Context, stream string, group string) error
	ReadGroup(ctx context.Context, stream, group, consumer string, count int64, block time.Duration) ([]goredis.XMessage, error)
	Ack(ctx context.Context, stream, group string, ids ...string) error
	Close() error
	Ping(ctx context.Context) error
}

// RedisStreamClient implements StreamClient backed by go-redis.
type RedisStreamClient struct {
	client *goredis.Client
}

// NewStreamClient initializes a connection to Redis.
func NewStreamClient(addr, password string, db int) (*RedisStreamClient, error) {
	rdb := goredis.NewClient(&goredis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	return &RedisStreamClient{client: rdb}, nil
}

// Ping checks if Redis is reachable.
func (r *RedisStreamClient) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// PublishEvent serializes WorkerEvent and adds it to the specified stream.
func (r *RedisStreamClient) PublishEvent(ctx context.Context, stream string, event *models.WorkerEvent) (string, error) {
	if stream == "" {
		stream = DefaultStreamName
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("failed to serialize worker event: %w", err)
	}

	id, err := r.client.XAdd(ctx, &goredis.XAddArgs{
		Stream: stream,
		Values: map[string]interface{}{
			"event_id":       event.EventID,
			"schema_version": event.SchemaVersion,
			"payload":        string(payload),
		},
	}).Result()

	if err != nil {
		return "", fmt.Errorf("failed to XAdd to stream %s: %w", stream, err)
	}
	return id, nil
}

// EnsureConsumerGroup creates the stream and consumer group if it doesn't already exist.
func (r *RedisStreamClient) EnsureConsumerGroup(ctx context.Context, stream string, group string) error {
	if stream == "" {
		stream = DefaultStreamName
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

// ReadGroup reads new messages from the consumer group stream.
func (r *RedisStreamClient) ReadGroup(ctx context.Context, stream, group, consumer string, count int64, block time.Duration) ([]goredis.XMessage, error) {
	if stream == "" {
		stream = DefaultStreamName
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

	if len(streams) > 0 {
		return streams[0].Messages, nil
	}
	return nil, nil
}

// Ack marks messages as processed in the consumer group.
func (r *RedisStreamClient) Ack(ctx context.Context, stream, group string, ids ...string) error {
	if stream == "" {
		stream = DefaultStreamName
	}
	if group == "" {
		group = DefaultGroupName
	}
	return r.client.XAck(ctx, stream, group, ids...).Err()
}

// Close closes the underlying Redis connection.
func (r *RedisStreamClient) Close() error {
	return r.client.Close()
}
