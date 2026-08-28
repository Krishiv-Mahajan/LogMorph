package ingestion

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Krishiv-Mahajan/LogMorph/internal/buffer"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// IngestRequest represents the HTTP payload sent to /ingest.
type IngestRequest struct {
	Format  string `json:"format,omitempty"`
	Source  string `json:"source,omitempty"`
	Payload string `json:"payload"`
}

// Service handles inbound event ingestion into the raw buffer.
type Service interface {
	Ingest(ctx context.Context, req IngestRequest) (string, error)
}

// IngestionService constructs RawEvents and buffers them to Redis.
type IngestionService struct {
	rawBuffer buffer.RawBuffer
	stream    string
}

// NewService creates a new IngestionService.
func NewService(rawBuffer buffer.RawBuffer, stream string) *IngestionService {
	if stream == "" {
		stream = buffer.DefaultRawStreamName
	}
	return &IngestionService{
		rawBuffer: rawBuffer,
		stream:    stream,
	}
}

// Ingest generates event metadata and publishes the RawEvent to the Redis stream buffer.
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

	if s.rawBuffer != nil {
		if _, err := s.rawBuffer.PublishRaw(ctx, s.stream, rawEvent); err != nil {
			return "", fmt.Errorf("failed to buffer raw event to Redis: %w", err)
		}
	}

	return eventID, nil
}
