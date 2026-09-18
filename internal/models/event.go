package models

// RawEvent represents incoming unparsed log data buffered immediately after ingestion.
type RawEvent struct {
	EventID    string `json:"event_id"`
	ReceivedAt string `json:"received_at"`
	Format     string `json:"format,omitempty"`
	Source     string `json:"source,omitempty"`
	Payload    string `json:"payload"`
}

// DetectionResult encapsulates the detected format, source category, and confidence.
type DetectionResult struct {
	Format     string  `json:"format"`
	SourceType string  `json:"source_type"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// DriftStatus classifies the schema stability of an incoming event.
type DriftStatus string

const (
	DriftStatusStable     DriftStatus = "stable"
	DriftStatusMinorDrift DriftStatus = "minor_drift"
	DriftStatusMajorDrift DriftStatus = "major_drift"
	DriftStatusUnknown    DriftStatus = "unknown"
)

// DriftResult represents the outcome of drift evaluation.
type DriftResult struct {
	Status          DriftStatus `json:"status"`
	Confidence      float64     `json:"confidence"`
	Message         string      `json:"message"`
	SuggestedAction string      `json:"suggested_action,omitempty"`
}

// SourceInfo contains metadata about the log producer.
type SourceInfo struct {
	Type       string `json:"type,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	Product    string `json:"product,omitempty"`
	Identifier string `json:"identifier,omitempty"`
}

// EventInfo categorizes the security or system action.
type EventInfo struct {
	Category string `json:"category,omitempty"`
	Action   string `json:"action,omitempty"`
	Severity string `json:"severity,omitempty"`
}

// NetworkInfo contains normalized L3/L4 network attributes.
type NetworkInfo struct {
	SrcIP    string `json:"src_ip,omitempty"`
	SrcPort  *int   `json:"src_port,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	DstPort  *int   `json:"dst_port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// UserInfo represents user identity context.
type UserInfo struct {
	Username *string `json:"username"`
}

// RawInfo preserves the original input string and detected format.
type RawInfo struct {
	Format  string `json:"format"`
	Message string `json:"message"`
}

// MetadataInfo tracks parsing and processing lineage.
//
// The provenance block (fingerprint, parser id, mapping id/version, drift
// status) is what makes a stored event explainable after the registry has moved
// on: it names the exact parser and mapping version that produced the event, so
// a later registry change cannot rewrite history. The fields are optional and
// additive, so existing consumers and the v1.0 schema keep working.
type MetadataInfo struct {
	ParserVersion string `json:"parser_version"`
	IngestedAt    string `json:"ingested_at"`

	// SourceFingerprint identifies the log source this event came from.
	SourceFingerprint string `json:"source_fingerprint,omitempty"`

	// ParserID identifies the parser that consumed the event.
	ParserID string `json:"parser_id,omitempty"`

	// MappingID / MappingVersion identify the field contract that was applied.
	MappingID      string `json:"mapping_id,omitempty"`
	MappingVersion int    `json:"mapping_version,omitempty"`

	// DriftStatus is the drift classification observed for this event.
	DriftStatus string `json:"drift_status,omitempty"`
}

// ParsedEvent represents the structured domain fields extracted by a format parser.
type ParsedEvent struct {
	Timestamp string       `json:"timestamp"`
	Source    SourceInfo   `json:"source"`
	Event     EventInfo    `json:"event"`
	Network   *NetworkInfo `json:"network,omitempty"`
	User      *UserInfo    `json:"user,omitempty"`
}

// UniversalEvent is the canonical schema for all normalized logs (Schema v1.0).
type UniversalEvent struct {
	EventID       string       `json:"event_id"`
	SchemaVersion string       `json:"schema_version"`
	Timestamp     string       `json:"timestamp"`
	Source        SourceInfo   `json:"source"`
	Event         EventInfo    `json:"event"`
	Network       *NetworkInfo `json:"network,omitempty"`
	User          *UserInfo    `json:"user,omitempty"`
	Raw           RawInfo      `json:"raw"`
	Metadata      MetadataInfo `json:"metadata"`
}

// WorkerEvent is the envelope used for downstream processing tasks.
type WorkerEvent struct {
	EventID       string         `json:"event_id"`
	SchemaVersion string         `json:"schema_version"`
	Event         UniversalEvent `json:"event"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}
