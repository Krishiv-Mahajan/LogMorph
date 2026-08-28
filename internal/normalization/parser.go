package normalization

import "github.com/Krishiv-Mahajan/LogMorph/internal/models"

// Parser defines the contract for format-specific log parsers.
type Parser interface {
	Name() string
	Parse(raw models.RawEvent) (*models.UniversalEvent, error)
}
