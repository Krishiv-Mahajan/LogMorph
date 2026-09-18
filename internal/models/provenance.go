package models

// Provenance records how an event was processed.
//
// It is the join key between a stored event and the registry: given a
// normalized or quarantined row, these fields identify the exact source, parser
// and mapping version that produced it, alongside the raw object key on the
// same row. Together they make the chain
//
//	raw object -> event -> parser version -> mapping version
//
// reproducible even after the registry has moved on to newer versions.
type Provenance struct {
	// SourceFingerprint identifies the log source.
	SourceFingerprint string `json:"source_fingerprint,omitempty"`

	// ParserID / ParserVersion identify the parser that consumed the event.
	ParserID      string `json:"parser_id,omitempty"`
	ParserVersion string `json:"parser_version,omitempty"`

	// MappingID / MappingVersion identify the field contract applied.
	MappingID      string `json:"mapping_id,omitempty"`
	MappingVersion int    `json:"mapping_version,omitempty"`

	// DriftStatus is the drift classification observed while processing.
	DriftStatus string `json:"drift_status,omitempty"`
}

// IsZero reports whether no provenance was recorded.
func (p Provenance) IsZero() bool {
	return p.SourceFingerprint == "" && p.ParserID == "" &&
		p.MappingID == "" && p.MappingVersion == 0 && p.DriftStatus == ""
}

// Apply writes the provenance into an event's metadata block.
func (p Provenance) Apply(metadata *MetadataInfo) {
	if metadata == nil {
		return
	}
	if p.SourceFingerprint != "" {
		metadata.SourceFingerprint = p.SourceFingerprint
	}
	if p.ParserID != "" {
		metadata.ParserID = p.ParserID
	}
	if p.ParserVersion != "" {
		metadata.ParserVersion = p.ParserVersion
	}
	if p.MappingID != "" {
		metadata.MappingID = p.MappingID
	}
	if p.MappingVersion != 0 {
		metadata.MappingVersion = p.MappingVersion
	}
	if p.DriftStatus != "" {
		metadata.DriftStatus = p.DriftStatus
	}
}
