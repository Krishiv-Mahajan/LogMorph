package state

import (
	"context"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// StageState represents the execution status of a pipeline stage.
type StageState string

const (
	StageIdle       StageState = "idle"
	StageProcessing StageState = "processing"
	StageSuccess    StageState = "success"
	StageWarning    StageState = "warning"
	StageError      StageState = "error"
)

// StageResult captures the outcome of a pipeline stage.
type StageResult struct {
	ID     string     `json:"id"`
	Label  string     `json:"label"`
	State  StageState `json:"state"`
	Detail string     `json:"detail,omitempty"`
	Error  string     `json:"error,omitempty"`
}

// EventState tracks the real-time processing journey of an event.
type EventState struct {
	EventID         string                  `json:"event_id"`
	Timestamp       string                  `json:"timestamp"`
	FormatName      string                  `json:"format_name"`
	RawPayload      string                  `json:"raw_payload"`
	Source          string                  `json:"source"`
	Action          string                  `json:"action"`
	Status          string                  `json:"status"` // "Processing", "Parsed", "Drift", "Error"
	Stages          map[string]StageResult  `json:"stages"`
	UniversalEvent  *models.UniversalEvent  `json:"universal_event,omitempty"`
	DriftDetected   bool                    `json:"drift_detected"`
	ErrorMessage    string                  `json:"error_message,omitempty"`
	ParserName      string                  `json:"parser_name,omitempty"`
	ConfidenceScore float64                 `json:"confidence_score,omitempty"`
}

// DashboardMetrics represents the overall processing counters.
type DashboardMetrics struct {
	TotalProcessed int64 `json:"total_processed"`
	Stable         int64 `json:"stable"`
	DriftDetected  int64 `json:"drift_detected"`
	Errors         int64 `json:"errors"`
}

// Store defines the interface for tracking pipeline execution state and metrics.
type Store interface {
	// UpdateEventState atomically updates the state of an event.
	UpdateEventState(ctx context.Context, state EventState) error
	
	// GetEventState retrieves the current state of an event.
	GetEventState(ctx context.Context, eventID string) (EventState, error)
	
	// IncrementMetric increments a specific counter (e.g., "processed", "drift", "errors").
	IncrementMetric(ctx context.Context, metric string) error
	
	// GetMetrics retrieves all dashboard metrics.
	GetMetrics(ctx context.Context) (DashboardMetrics, error)
	
	// PushRecentEvent adds a terminal event to the recent list.
	PushRecentEvent(ctx context.Context, state EventState) error
	
	// GetRecentEvents retrieves up to 'limit' recent events.
	GetRecentEvents(ctx context.Context, limit int64) ([]EventState, error)
	
	// Ping checks if the store is reachable.
	Ping(ctx context.Context) error
}
