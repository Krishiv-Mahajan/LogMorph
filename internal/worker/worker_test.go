package worker

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

type mockWorkerStreamClient struct {
	messages []goredis.XMessage
	acked    []string
}

func (m *mockWorkerStreamClient) PublishEvent(ctx context.Context, stream string, event *models.WorkerEvent) (string, error) {
	return "mock_id", nil
}

func (m *mockWorkerStreamClient) EnsureConsumerGroup(ctx context.Context, stream string, group string) error {
	return nil
}

func (m *mockWorkerStreamClient) ReadGroup(ctx context.Context, stream, group, consumer string, count int64, block time.Duration) ([]goredis.XMessage, error) {
	if len(m.messages) > 0 {
		msgs := m.messages
		m.messages = nil
		return msgs, nil
	}
	time.Sleep(50 * time.Millisecond)
	return nil, nil
}

func (m *mockWorkerStreamClient) Ack(ctx context.Context, stream, group string, ids ...string) error {
	m.acked = append(m.acked, ids...)
	return nil
}

func (m *mockWorkerStreamClient) Close() error {
	return nil
}

func (m *mockWorkerStreamClient) Ping(ctx context.Context) error {
	return nil
}

func TestWorker_ProcessingLoop(t *testing.T) {
	evt := models.WorkerEvent{
		EventID:       "evt_worker_1",
		SchemaVersion: "1.0",
		Event: models.UniversalEvent{
			EventID:       "evt_worker_1",
			SchemaVersion: "1.0",
			Timestamp:     "2026-08-28T18:30:12Z",
			Event: models.EventInfo{
				Action: "deny",
			},
			Raw: models.RawInfo{
				Format:  "syslog",
				Message: "raw log",
			},
		},
	}
	payloadBytes, _ := json.Marshal(evt)

	mockClient := &mockWorkerStreamClient{
		messages: []goredis.XMessage{
			{
				ID: "1670000000000-0",
				Values: map[string]interface{}{
					"payload": string(payloadBytes),
				},
			},
		},
	}

	var processedCount int32
	worker := NewWorker(mockClient, Config{
		ProcessFunc: func(ctx context.Context, event *models.WorkerEvent) error {
			if event.EventID == "evt_worker_1" {
				atomic.AddInt32(&processedCount, 1)
			}
			return nil
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_ = worker.Start(ctx)

	if atomic.LoadInt32(&processedCount) != 1 {
		t.Errorf("expected 1 processed event, got %d", processedCount)
	}
	if len(mockClient.acked) != 1 || mockClient.acked[0] != "1670000000000-0" {
		t.Errorf("expected message to be acked, got: %v", mockClient.acked)
	}
}
