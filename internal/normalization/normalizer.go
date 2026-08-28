package normalization

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Krishiv-Mahajan/LogMorph/internal/detection"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// Normalizer orchestrates detection, parser selection, and canonical field assignment.
type Normalizer struct {
	detector detection.Detector
	registry *Registry
}

// NewNormalizer creates a new Normalizer instance.
func NewNormalizer(detector detection.Detector, registry *Registry) *Normalizer {
	return &Normalizer{
		detector: detector,
		registry: registry,
	}
}

// Normalize processes a RawEvent into a normalized UniversalEvent.
func (n *Normalizer) Normalize(raw models.RawEvent) (*models.UniversalEvent, error) {
	// 1. Detect format
	detectResult := n.detector.Detect(raw.Payload, raw.Format)
	if detectResult.Format == detection.FormatUnknown {
		return nil, fmt.Errorf("format detection failed: %s", detectResult.Reason)
	}

	// 2. Select parser
	parser, err := n.registry.Get(detectResult.Format)
	if err != nil {
		return nil, fmt.Errorf("parser lookup failed: %w", err)
	}

	// 3. Parse raw payload
	event, err := parser.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing failed (%s): %w", detectResult.Format, err)
	}

	// 4. Canonical field enrichment
	if raw.EventID != "" {
		event.EventID = raw.EventID
	} else if event.EventID == "" {
		event.EventID = fmt.Sprintf("evt_%s", uuid.New().String())
	}

	event.SchemaVersion = "1.0"

	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	event.Raw.Format = detectResult.Format
	if event.Raw.Message == "" {
		event.Raw.Message = raw.Payload
	}

	if event.Metadata.ParserVersion == "" {
		event.Metadata.ParserVersion = "1.0"
	}
	event.Metadata.IngestedAt = time.Now().UTC().Format(time.RFC3339)

	return event, nil
}
