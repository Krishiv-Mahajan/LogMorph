package parsing

import (
	"context"
	"fmt"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// Engine defines the parser engine interface.
type Engine interface {
	Parse(ctx context.Context, raw models.RawEvent, detection models.DetectionResult) (*models.ParsedEvent, error)
}

// DefaultEngine coordinates parser lookup and execution.
type DefaultEngine struct {
	registry *Registry
}

// NewEngine creates a new parser engine with the given registry.
func NewEngine(registry *Registry) *DefaultEngine {
	return &DefaultEngine{
		registry: registry,
	}
}

// Parse selects the appropriate format parser and extracts domain fields.
func (e *DefaultEngine) Parse(ctx context.Context, raw models.RawEvent, detection models.DetectionResult) (*models.ParsedEvent, error) {
	parser, err := e.registry.Get(detection.Format)
	if err != nil {
		return nil, fmt.Errorf("parser selection failed: %w", err)
	}

	parsed, err := parser.Parse(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("parsing failed for format %s: %w", detection.Format, err)
	}

	return parsed, nil
}
