package contract

// ParserDescriptor is a parser's declared identity and field contract.
//
// It exists so the rest of the system does not have to guess what a parser
// supports: the registry records it per source, and the drift engine compares
// incoming payloads against it.
type ParserDescriptor struct {
	// ParserID is a stable identifier (e.g. "generic_json"). It is what gets
	// recorded as provenance on every processed event.
	ParserID string

	// ParserVersion is the version of the parser implementation.
	ParserVersion string

	// MappingID identifies the mapping this parser ships with. It stays stable
	// across drift adaptations; only the mapping version increments.
	MappingID string

	// Vendor / Product / SourceType describe the kind of source this parser
	// handles. They are placeholders today (the parsers are generic rather than
	// vendor-specific) but they are the fields the registry is shaped around.
	Vendor     string
	Product    string
	SourceType string

	// Contract is the declared field contract: which fields the source is
	// expected to send, their types, and where they bind.
	Contract Contract
}

// Describable is implemented by parsers that declare their identity and field
// contract. Parsers that do not implement it keep working; they simply cannot
// participate in registry-backed drift analysis.
type Describable interface {
	Descriptor() ParserDescriptor
}
