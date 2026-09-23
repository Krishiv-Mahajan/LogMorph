package models

// QuarantineRecord captures a failed event and its metadata.
type QuarantineRecord struct {
	EventID          string `json:"event_id"`
	ReceivedAt       string `json:"received_at"`
	QuarantinedAt    string `json:"quarantined_at"`
	DetectedFormat   string `json:"detected_format"`
	FailureStage     string `json:"failure_stage"` // e.g., "parsing", "normalization", "validation"
	FailureReason    string `json:"failure_reason"`
	ValidationErrors []any  `json:"validation_errors,omitempty"` // Slice of validation.ValidationError
	RawEventRef      string `json:"raw_event_ref"`               // e.g., "minio://raw-events/<event_id>.json"

	// Preserved if the pipeline made it past normalization but failed validation
	PartialEvent *UniversalEvent `json:"partial_event,omitempty"`
}
