package status

import "github.com/Krishiv-Mahajan/LogMorph/internal/models"

// Pipeline stage name constants.
const (
	StageIngestion     = "ingestion"
	StageDetection     = "detection"
	StageDrift         = "drift"
	StageParsing       = "parsing"
	StageNormalization = "normalization"
	StageValidation    = "validation"
)

// Stage state constants.
const (
	StateIdle       = "idle"
	StateProcessing = "processing"
	StateSuccess    = "success"
	StateWarning    = "warning"
	StateError      = "error"
)

// Overall event status constants.
const (
	StatusProcessing = "Processing"
	StatusParsed     = "Parsed"
	StatusDrift      = "Drift"
	StatusError      = "Error"
)

// StageResult tracks the state of a single pipeline stage.
type StageResult struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
	Error  string `json:"error,omitempty"`
}

// EventStatus is the full tracking record for a single event as it moves
// through the backend pipeline. It is stored in Redis and exposed via
// GET /events/{event_id}/status.
type EventStatus struct {
	EventID         string                 `json:"event_id"`
	Status          string                 `json:"status"`
	FormatName      string                 `json:"format_name,omitempty"`
	Source          string                 `json:"source,omitempty"`
	Action          string                 `json:"action,omitempty"`
	DriftDetected   bool                   `json:"drift_detected"`
	ErrorMessage    string                 `json:"error_message,omitempty"`
	ConfidenceScore float64                `json:"confidence_score,omitempty"`
	ParserName      string                 `json:"parser_name,omitempty"`
	Stages          map[string]StageResult `json:"stages"`
	UniversalEvent  *models.UniversalEvent `json:"universal_event,omitempty"`
}

// OverallUpdate carries the set of top-level EventStatus fields to patch
// without touching the stage map.
type OverallUpdate struct {
	Status          string
	FormatName      string
	Source          string
	Action          string
	DriftDetected   *bool
	ErrorMessage    string
	ConfidenceScore float64
	ParserName      string
	UniversalEvent  *models.UniversalEvent
}

// BoolPtr returns a pointer to a bool value, useful for setting DriftDetected in OverallUpdate.
func BoolPtr(v bool) *bool {
	return &v
}

// initialStages returns the pipeline stages in their starting (idle/success)
// state as produced right after ingestion.
func initialStages() map[string]StageResult {
	return map[string]StageResult{
		StageIngestion: {
			ID:     StageIngestion,
			Label:  "Ingestion",
			State:  StateSuccess,
			Detail: "Accepted",
		},
		StageDetection: {
			ID:    StageDetection,
			Label: "Detection",
			State: StateIdle,
		},
		StageDrift: {
			ID:    StageDrift,
			Label: "Drift",
			State: StateIdle,
		},
		StageParsing: {
			ID:    StageParsing,
			Label: "Parsing",
			State: StateIdle,
		},
		StageNormalization: {
			ID:    StageNormalization,
			Label: "Normalization",
			State: StateIdle,
		},
		StageValidation: {
			ID:    StageValidation,
			Label: "Validation",
			State: StateIdle,
		},
	}
}

// NewInitialStatus builds the EventStatus written to Redis immediately after
// a RawEvent is accepted by the ingestion service.
func NewInitialStatus(eventID string) *EventStatus {
	return &EventStatus{
		EventID: eventID,
		Status:  StatusProcessing,
		Stages:  initialStages(),
	}
}
