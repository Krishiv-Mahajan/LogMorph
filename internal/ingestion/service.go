package ingestion

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/Krishiv-Mahajan/LogMorph/internal/buffer"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/status"
)

// IngestRequest represents the HTTP payload sent to /ingest or elements in /ingest/batch.
type IngestRequest struct {
	Format  string `json:"format,omitempty"`
	Source  string `json:"source,omitempty"`
	Payload string `json:"payload"`
}

// BatchIngestResponse is returned on successful batch event acceptance.
type BatchIngestResponse struct {
	Status   string   `json:"status"`
	Count    int      `json:"count"`
	EventIDs []string `json:"event_ids"`
}

// Service handles inbound event ingestion into the raw buffer.
type Service interface {
	Ingest(ctx context.Context, req IngestRequest) (string, error)
	IngestBatch(ctx context.Context, reqs []IngestRequest) ([]string, error)
}

// IngestionService constructs RawEvents and buffers them to Redis.
type IngestionService struct {
	rawBuffer   buffer.RawBuffer
	stream      string
	statusStore status.Store // optional; nil disables status tracking
}

// NewService creates a new IngestionService without status tracking.
// Existing callers (including all tests) continue to work unchanged.
func NewService(rawBuffer buffer.RawBuffer, stream string) *IngestionService {
	return NewServiceWithStatus(rawBuffer, stream, nil)
}

// NewServiceWithStatus creates a new IngestionService with status tracking.
// When statusStore is nil the service behaves identically to NewService.
func NewServiceWithStatus(rawBuffer buffer.RawBuffer, stream string, statusStore status.Store) *IngestionService {
	if stream == "" {
		stream = buffer.DefaultRawStreamName
	}
	return &IngestionService{
		rawBuffer:   rawBuffer,
		stream:      stream,
		statusStore: statusStore,
	}
}

// Ingest generates event metadata and publishes the RawEvent to the Redis stream buffer.
//
// When a statusStore is configured the flow is:
//  1. Generate eventID
//  2. Create initial EventStatus (ingestion=success, rest=idle)
//  3. Publish RawEvent to Redis Stream
//  4. On publish failure: best-effort delete the status, return the error
func (s *IngestionService) Ingest(ctx context.Context, req IngestRequest) (string, error) {
	if req.Payload == "" {
		return "", fmt.Errorf("payload must not be empty")
	}

	eventID := fmt.Sprintf("evt_%s", uuid.New().String())
	rawEvent := &models.RawEvent{
		EventID:    eventID,
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		Format:     req.Format,
		Source:     req.Source,
		Payload:    req.Payload,
	}

	// Create initial status before publishing so the frontend can immediately
	// poll and receive a "Processing" response.
	if s.statusStore != nil {
		initialStatus := status.NewInitialStatus(eventID)
		if err := s.statusStore.Create(ctx, initialStatus); err != nil {
			// Non-fatal: log and continue without status tracking for this event.
			log.Printf("[Ingestion] Warning: failed to create status for %s: %v", eventID, err)
		}
	}

	if s.rawBuffer != nil {
		if _, err := s.rawBuffer.PublishRaw(ctx, s.stream, rawEvent); err != nil {
			// Best-effort cleanup: remove the orphan status so the frontend
			// doesn't see a permanently-stuck "Processing" entry.
			if s.statusStore != nil {
				if delErr := s.statusStore.Delete(ctx, eventID); delErr != nil {
					log.Printf("[Ingestion] Warning: failed to cleanup status for %s after publish failure: %v", eventID, delErr)
				}
			}
			return "", fmt.Errorf("failed to buffer raw event to Redis: %w", err)
		}
	}

	return eventID, nil
}

// IngestBatch validates and publishes multiple RawEvents in a single batch.
// Each event gets its own unique event_id and received_at timestamp while
// preserving the exact original payload.
func (s *IngestionService) IngestBatch(ctx context.Context, reqs []IngestRequest) ([]string, error) {
	if len(reqs) == 0 {
		return nil, fmt.Errorf("batch must not be empty")
	}

	for i, req := range reqs {
		if req.Payload == "" {
			return nil, fmt.Errorf("item at index %d has empty payload", i)
		}
	}

	eventIDs := make([]string, 0, len(reqs))
	for _, req := range reqs {
		eventID := fmt.Sprintf("evt_%s", uuid.New().String())
		rawEvent := &models.RawEvent{
			EventID:    eventID,
			ReceivedAt: time.Now().UTC().Format(time.RFC3339),
			Format:     req.Format,
			Source:     req.Source,
			Payload:    req.Payload,
		}

		// Create initial status before publishing (same ordering as single ingest).
		if s.statusStore != nil {
			initialStatus := status.NewInitialStatus(eventID)
			if err := s.statusStore.Create(ctx, initialStatus); err != nil {
				log.Printf("[Ingestion] Warning: failed to create status for batch event %s: %v", eventID, err)
			}
		}

		if s.rawBuffer != nil {
			if _, err := s.rawBuffer.PublishRaw(ctx, s.stream, rawEvent); err != nil {
				// Best-effort cleanup for this event.
				if s.statusStore != nil {
					if delErr := s.statusStore.Delete(ctx, eventID); delErr != nil {
						log.Printf("[Ingestion] Warning: failed to cleanup status for %s: %v", eventID, delErr)
					}
				}
				return nil, fmt.Errorf("failed to buffer raw event to Redis: %w", err)
			}
		}

		eventIDs = append(eventIDs, eventID)
	}

	return eventIDs, nil
}
