package models

// RawEvent represents incoming unparsed log data.
type RawEvent struct {
	EventID    string `json:"event_id,omitempty"`
	ReceivedAt string `json:"received_at,omitempty"`
	Format     string `json:"format,omitempty"`
	Source     string `json:"source,omitempty"`
	Payload    string `json:"payload"`
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
type MetadataInfo struct {
	ParserVersion string `json:"parser_version"`
	IngestedAt    string `json:"ingested_at"`
}

// UniversalEvent is the canonical schema for all normalized logs.
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

// WorkerEvent is the envelope transported through Redis Streams to workers.
type WorkerEvent struct {
	EventID       string         `json:"event_id"`
	SchemaVersion string         `json:"schema_version"`
	Event         UniversalEvent `json:"event"`
	Metadata      map[string]any `json:"metadata"`
}
