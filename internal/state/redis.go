package state

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

const (
	EventStateKeyPrefix = "event:state:"
	MetricsKey          = "events:metrics"
	RecentEventsKey     = "events:recent"
	
	// Metrics fields
	MetricProcessed = "processed"
	MetricStable    = "stable"
	MetricDrift     = "drift"
	MetricErrors    = "errors"
)

type RedisStateStore struct {
	client *goredis.Client
}

// NewRedisStateStore creates a new Redis-backed state store.
func NewRedisStateStore(addr, password string, db int) (*RedisStateStore, error) {
	rdb := goredis.NewClient(&goredis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	return &RedisStateStore{client: rdb}, nil
}

// Ping checks connectivity.
func (r *RedisStateStore) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// UpdateEventState serializes and sets the event state in Redis.
// Expire the key after 24 hours so it doesn't leak memory forever.
func (r *RedisStateStore) UpdateEventState(ctx context.Context, state EventState) error {
	key := EventStateKeyPrefix + state.EventID
	
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal event state: %w", err)
	}

	return r.client.Set(ctx, key, data, 24*time.Hour).Err()
}

// GetEventState fetches and deserializes the event state.
func (r *RedisStateStore) GetEventState(ctx context.Context, eventID string) (EventState, error) {
	key := EventStateKeyPrefix + eventID
	
	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == goredis.Nil {
			return EventState{}, fmt.Errorf("event state not found for %s", eventID)
		}
		return EventState{}, err
	}

	var state EventState
	if err := json.Unmarshal(data, &state); err != nil {
		return EventState{}, fmt.Errorf("failed to unmarshal event state: %w", err)
	}

	return state, nil
}

// IncrementMetric atomically increments a field in the global metrics hash.
func (r *RedisStateStore) IncrementMetric(ctx context.Context, metric string) error {
	return r.client.HIncrBy(ctx, MetricsKey, metric, 1).Err()
}

// GetMetrics fetches all counters from the metrics hash.
func (r *RedisStateStore) GetMetrics(ctx context.Context) (DashboardMetrics, error) {
	res, err := r.client.HGetAll(ctx, MetricsKey).Result()
	if err != nil && err != goredis.Nil {
		return DashboardMetrics{}, err
	}

	var m DashboardMetrics
	if val, ok := res[MetricProcessed]; ok {
		m.TotalProcessed, _ = strconv.ParseInt(val, 10, 64)
	}
	if val, ok := res[MetricStable]; ok {
		m.Stable, _ = strconv.ParseInt(val, 10, 64)
	}
	if val, ok := res[MetricDrift]; ok {
		m.DriftDetected, _ = strconv.ParseInt(val, 10, 64)
	}
	if val, ok := res[MetricErrors]; ok {
		m.Errors, _ = strconv.ParseInt(val, 10, 64)
	}

	return m, nil
}

// PushRecentEvent adds an event to the head of the recent list, capping at 50.
func (r *RedisStateStore) PushRecentEvent(ctx context.Context, state EventState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal event state: %w", err)
	}

	pipe := r.client.Pipeline()
	pipe.LPush(ctx, RecentEventsKey, data)
	pipe.LTrim(ctx, RecentEventsKey, 0, 49) // Keep 50
	_, err = pipe.Exec(ctx)
	return err
}

// GetRecentEvents retrieves the recent events from the list.
func (r *RedisStateStore) GetRecentEvents(ctx context.Context, limit int64) ([]EventState, error) {
	if limit <= 0 {
		limit = 50
	}
	
	res, err := r.client.LRange(ctx, RecentEventsKey, 0, limit-1).Result()
	if err != nil {
		return nil, err
	}

	var events []EventState
	for _, item := range res {
		var state EventState
		if err := json.Unmarshal([]byte(item), &state); err != nil {
			// Skip corrupted entries
			continue
		}
		events = append(events, state)
	}

	return events, nil
}

// Close closes the Redis connection.
func (r *RedisStateStore) Close() error {
	return r.client.Close()
}
