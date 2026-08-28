package normalization

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// Normalizer transforms structured ParsedEvents into canonical UniversalEvents (Schema v1.0).
type Normalizer struct{}

// NewNormalizer creates a new Normalizer instance.
func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

// Normalize combines raw log metadata and parsed fields into a canonical UniversalEvent.
func (n *Normalizer) Normalize(raw models.RawEvent, parsed *models.ParsedEvent, detection models.DetectionResult) (*models.UniversalEvent, error) {
	if parsed == nil {
		return nil, fmt.Errorf("cannot normalize nil parsed event")
	}

	eventID := raw.EventID
	if eventID == "" {
		eventID = fmt.Sprintf("evt_%s", uuid.New().String())
	}

	ts := parsed.Timestamp
	if ts == "" {
		ts = raw.ReceivedAt
	}
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}

	format := detection.Format
	if format == "" {
		format = raw.Format
	}
	if format == "" {
		format = "unknown"
	}

	return &models.UniversalEvent{
		EventID:       eventID,
		SchemaVersion: "1.0",
		Timestamp:     ts,
		Source:        parsed.Source,
		Event:         parsed.Event,
		Network:       parsed.Network,
		User:          parsed.User,
		Raw: models.RawInfo{
			Format:  format,
			Message: raw.Payload,
		},
		Metadata: models.MetadataInfo{
			ParserVersion: "1.0",
			IngestedAt:    time.Now().UTC().Format(time.RFC3339),
		},
	}, nil
}
