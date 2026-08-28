package parsing

import (
	"fmt"
	"sync"
)

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

// Register adds a parser to the registry.
func (r *Registry) Register(parser Parser) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.parsers[parser.Format()] = parser
}

// Get retrieves a parser by format name.
func (r *Registry) Get(format string) (Parser, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, exists := r.parsers[format]
	if !exists {
		return nil, fmt.Errorf("no parser registered for format: %s", format)
	}
	return p, nil
}
