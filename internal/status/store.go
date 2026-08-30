package status

import (
	"context"
	"errors"
)

// ErrNotFound is returned when an event status does not exist in the store.
var ErrNotFound = errors.New("event status not found")

// Store is the interface for reading and writing event pipeline status records.
//
// All implementations must be safe for concurrent use.
type Store interface {
	// Create writes the initial EventStatus for a newly ingested event.
	// Returns an error if the write fails.
	Create(ctx context.Context, status *EventStatus) error

	// Get retrieves the current EventStatus for eventID.
	// Returns ErrNotFound if no status exists for that ID.
	Get(ctx context.Context, eventID string) (*EventStatus, error)

	// UpdateStage atomically updates a single pipeline stage within the
	// EventStatus for eventID. Other stages and top-level fields are preserved.
	// Returns ErrNotFound if the status record does not exist.
	UpdateStage(ctx context.Context, eventID string, stage StageResult) error

	// UpdateOverall patches the top-level EventStatus fields supplied in update.
	// The Stages map is left untouched; only non-zero fields from OverallUpdate
	// are applied (except DriftDetected which is always written).
	// Returns ErrNotFound if the status record does not exist.
	UpdateOverall(ctx context.Context, eventID string, update OverallUpdate) error

	// Delete removes the EventStatus for eventID. Used for cleanup when
	// ingestion publishing fails after status creation. A no-op if not found.
	Delete(ctx context.Context, eventID string) error
}
