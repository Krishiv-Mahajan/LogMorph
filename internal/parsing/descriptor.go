package parsing

import "github.com/Krishiv-Mahajan/LogMorph/internal/contract"

// Describable is implemented by parsers that declare their identity and field
// contract. Parsers that do not implement it keep working; they simply cannot
// participate in registry-backed drift analysis.
type Describable interface {
	Descriptor() contract.ParserDescriptor
}

// DescriptorFor returns the declared descriptor of a parser, if it has one.
func DescriptorFor(p Parser) (contract.ParserDescriptor, bool) {
	if p == nil {
		return contract.ParserDescriptor{}, false
	}
	describable, ok := p.(Describable)
	if !ok {
		return contract.ParserDescriptor{}, false
	}
	return describable.Descriptor(), true
}
