package parsing

import (
	"fmt"
	"strings"
	"sync"
)

// normalizeFormat trims whitespace and converts to lower case for defensive lookup.
func normalizeFormat(format string) string {
	return strings.ToLower(strings.TrimSpace(format))
}

// Registry manages registered format parsers.
type Registry struct {
	parsers map[string]Parser
	mu      sync.RWMutex
}

// NewRegistry creates a new parser registry.
func NewRegistry() *Registry {
	return &Registry{
		parsers: make(map[string]Parser),
	}
}

// Register adds or updates a parser in the registry.
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
		return nil, fmt.Errorf("no parser registered for format: %s", format)
	}
	return p, nil
}
