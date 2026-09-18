package parsing

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Krishiv-Mahajan/LogMorph/internal/contract"
)

// ErrParserNotFound marks a lookup for a format that has no registered parser.
// Callers wrap it so the failure can be classified apart from a payload that a
// parser rejected.
var ErrParserNotFound = errors.New("parser not found")

// normalizeFormat trims whitespace and converts to lower case for defensive lookup.
func normalizeFormat(format string) string {
	return strings.ToLower(strings.TrimSpace(format))
}

// Registry manages registered format parsers.
type Registry struct {
	parsers map[string]Parser

	// descriptors holds the declared contract of parsers that implement
	// Describable, keyed by parser ID.
	descriptors map[string]contract.ParserDescriptor

	// parserFormats maps a parser ID back to the format it handles, so a
	// registry-selected parser ID resolves to the parser instance.
	parserFormats map[string]string

	mu sync.RWMutex
}

// NewRegistry creates a new parser registry.
func NewRegistry() *Registry {
	return &Registry{
		parsers:       make(map[string]Parser),
		descriptors:   make(map[string]contract.ParserDescriptor),
		parserFormats: make(map[string]string),
	}
}

// Register adds or updates a parser in the registry. When the parser declares a
// descriptor, its contract is indexed by parser ID at the same time.
func (r *Registry) Register(parser Parser) {
	if parser == nil {
		return
	}
	key := normalizeFormat(parser.Format())
	if key == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.parsers[key] = parser

	if descriptor, ok := DescriptorFor(parser); ok {
		id := normalizeFormat(descriptor.ParserID)
		if id != "" {
			r.descriptors[id] = descriptor
			r.parserFormats[id] = key
		}
	}
}

// Get retrieves a parser by format name, using case-insensitive and whitespace-trimmed matching.
func (r *Registry) Get(format string) (Parser, error) {
	key := normalizeFormat(format)
	if key == "" {
		return nil, fmt.Errorf("format cannot be empty")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	p, exists := r.parsers[key]
	if !exists {
		return nil, fmt.Errorf("%w for format: %s", ErrParserNotFound, format)
	}
	return p, nil
}

// GetByID retrieves a parser by its declared parser ID.
//
// Registry-backed processing selects a parser by ID rather than by detected
// format, because the source registry already decided which parser owns the
// source.
func (r *Registry) GetByID(parserID string) (Parser, error) {
	key := normalizeFormat(parserID)
	if key == "" {
		return nil, fmt.Errorf("%w for parser id: %s", ErrParserNotFound, parserID)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	format, ok := r.parserFormats[key]
	if !ok {
		return nil, fmt.Errorf("%w for parser id: %s", ErrParserNotFound, parserID)
	}
	parser, ok := r.parsers[format]
	if !ok {
		return nil, fmt.Errorf("%w for parser id: %s", ErrParserNotFound, parserID)
	}

	return parser, nil
}

// DescriptorForFormat returns the declared descriptor of the parser registered
// for a format. It reports false when the format has no parser or the parser
// does not declare a contract.
func (r *Registry) DescriptorForFormat(format string) (contract.ParserDescriptor, bool) {
	key := normalizeFormat(format)
	if key == "" {
		return contract.ParserDescriptor{}, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	parser, ok := r.parsers[key]
	if !ok {
		return contract.ParserDescriptor{}, false
	}

	return DescriptorFor(parser)
}

// DescriptorForID returns the descriptor registered for a parser ID.
func (r *Registry) DescriptorForID(parserID string) (contract.ParserDescriptor, bool) {
	key := normalizeFormat(parserID)
	if key == "" {
		return contract.ParserDescriptor{}, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	descriptor, ok := r.descriptors[key]
	return descriptor, ok
}

// Descriptors returns every registered descriptor, ordered by parser ID, for
// startup logging and diagnostics.
func (r *Registry) Descriptors() []contract.ParserDescriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.descriptors))
	for id := range r.descriptors {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]contract.ParserDescriptor, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.descriptors[id])
	}

	return out
}
