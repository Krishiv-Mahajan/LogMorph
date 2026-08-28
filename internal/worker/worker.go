package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/redis"
)

// ProcessFunc is the handler function invoked for every received worker event.
type ProcessFunc func(ctx context.Context, event *models.WorkerEvent) error

// Worker consumes and processes normalized events from Redis Streams.
type Worker struct {
	client       redis.StreamClient
	streamName   string
	groupName    string
	consumerName string
	processFunc  ProcessFunc
}

// Config contains worker configuration options.
type Config struct {
	StreamName   string
	GroupName    string
	ConsumerName string
	ProcessFunc  ProcessFunc
}

// NewWorker initializes a new stream worker.
func NewWorker(client redis.StreamClient, cfg Config) *Worker {
	if cfg.StreamName == "" {
		cfg.StreamName = redis.DefaultStreamName
	}
	if cfg.GroupName == "" {
		cfg.GroupName = redis.DefaultGroupName
	}
	if cfg.ConsumerName == "" {
		cfg.ConsumerName = "worker-1"
	}
	if cfg.ProcessFunc == nil {
		cfg.ProcessFunc = DefaultProcessFunc
	}

	return &Worker{
		client:       client,
		streamName:   cfg.StreamName,
		groupName:    cfg.GroupName,
		consumerName: cfg.ConsumerName,
		processFunc:  cfg.ProcessFunc,
	}
}

// DefaultProcessFunc performs standard MVP logging for normalized events.
func DefaultProcessFunc(ctx context.Context, event *models.WorkerEvent) error {
	netDetails := "n/a"
	if event.Event.Network != nil {
		srcPort := 0
		if event.Event.Network.SrcPort != nil {
			srcPort = *event.Event.Network.SrcPort
		}
		dstPort := 0
		if event.Event.Network.DstPort != nil {
			dstPort = *event.Event.Network.DstPort
		}
		netDetails = fmt.Sprintf("%s:%d -> %s:%d (proto: %s)",
			event.Event.Network.SrcIP, srcPort,
			event.Event.Network.DstIP, dstPort,
			event.Event.Network.Protocol)
	}

	log.Printf("[Worker] Processed event %s | format: %s | action: %s | net: %s | timestamp: %s",
		event.EventID,
		event.Event.Raw.Format,
		event.Event.Event.Action,
		netDetails,
		event.Event.Timestamp,
	)
	return nil
}

// Start begins the event processing loop until context cancellation.
func (w *Worker) Start(ctx context.Context) error {
	if err := w.client.EnsureConsumerGroup(ctx, w.streamName, w.groupName); err != nil {
		return fmt.Errorf("failed to ensure consumer group: %w", err)
	}

	log.Printf("[Worker] Started listening on stream %q as group %q consumer %q",
		w.streamName, w.groupName, w.consumerName)

	for {
		select {
		case <-ctx.Done():
			log.Println("[Worker] Context cancelled, stopping worker...")
			return nil
		default:
		}

		messages, err := w.client.ReadGroup(ctx, w.streamName, w.groupName, w.consumerName, 10, 2*time.Second)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("[Worker] Error reading stream: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}

		for _, msg := range messages {
			payloadStr, ok := msg.Values["payload"].(string)
			if !ok {
				log.Printf("[Worker] Message %s missing payload value", msg.ID)
				_ = w.client.Ack(ctx, w.streamName, w.groupName, msg.ID)
				continue
			}

			var event models.WorkerEvent
			if err := json.Unmarshal([]byte(payloadStr), &event); err != nil {
				log.Printf("[Worker] Failed to unmarshal message %s: %v", msg.ID, err)
				_ = w.client.Ack(ctx, w.streamName, w.groupName, msg.ID)
				continue
			}

			if err := w.processFunc(ctx, &event); err != nil {
				log.Printf("[Worker] Error processing event %s: %v", event.EventID, err)
			}

			if err := w.client.Ack(ctx, w.streamName, w.groupName, msg.ID); err != nil {
				log.Printf("[Worker] Failed to ack message %s: %v", msg.ID, err)
			}
		}
	}
}
