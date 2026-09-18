package parsing

import (
	"context"
	"fmt"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// Engine defines the parser engine interface.
type Engine interface {
	Parse(ctx context.Context, raw models.RawEvent, detection models.DetectionResult) (*models.ParsedEvent, error)

	// ParseWith runs a specific parser, selected by ID. It exists so a caller
	// that has already resolved the source's parser through the registry does
	// not have to re-derive it from the detected format. An empty or unknown
	// parser ID falls back to format-based selection.
	ParseWith(ctx context.Context, raw models.RawEvent, detection models.DetectionResult, parserID string) (*models.ParsedEvent, error)
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

// ParseWith runs the parser identified by parserID, falling back to the parser
// registered for the detected format when the ID is empty or unknown.
func (e *DefaultEngine) ParseWith(ctx context.Context, raw models.RawEvent, detection models.DetectionResult, parserID string) (*models.ParsedEvent, error) {
	if parserID == "" {
		return e.Parse(ctx, raw, detection)
	}

	parser, err := e.registry.GetByID(parserID)
	if err != nil {
		// A registry entry naming a parser this build does not have is a
		// configuration problem, not a reason to reject the event: fall back to
		// format selection and let the format parser try.
		return e.Parse(ctx, raw, detection)
	}

	parsed, err := parser.Parse(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("parsing failed for parser %s: %w", parserID, err)
	}

	return parsed, nil
}
