package parsing

import (
	"context"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// Parser defines the contract for format-specific log parsing into domain fields.
type Parser interface {
	Format() string
	Parse(ctx context.Context, raw models.RawEvent) (*models.ParsedEvent, error)
}
