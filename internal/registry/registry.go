// Package registry stores the source registry: which parser and mapping apply
// to which log source, at which version.
//
// Every entry is a version. When the minor-drift handler safely adapts a
// mapping it appends a new version rather than editing an existing one, so an
// event processed yesterday stays explainable against the exact contract that
// processed it.
package registry

import (
	"context"
	"errors"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/contract"
)

// ErrNotFound is returned when no registry entry matches a lookup.
var ErrNotFound = errors.New("registry entry not found")

// Status tracks the lifecycle of a mapping version.
type Status string

const (
	// StatusActive is the version used to process new events for the source.
	StatusActive Status = "active"

	// StatusSuperseded is a previous version. It is retained forever so events
	// processed under it remain explainable and reproducible.
	StatusSuperseded Status = "superseded"

	// StatusReviewRequired marks a mapping version that could not be created
	// automatically because the drift was unsafe. It is never selected for
	// parsing; it records that a human — or a future AI escalation step — must
	// decide. No AI is involved in this path today.
	StatusReviewRequired Status = "review_required"
)

// Entry is one version of a source's parser/mapping binding.
type Entry struct {
	// Fingerprint identifies the source. All versions of a source share it.
	Fingerprint string

	// Vendor / Product / SourceType describe the source. They originate from
	// the parser descriptor and are recorded on the registry row so a source is
	// addressable by name rather than by hash alone.
	Vendor     string
	Product    string
	SourceType string
	Format     string

	// ParserID / ParserVersion identify the parser that consumes this source.
	ParserID      string
	ParserVersion string

	// MappingID is stable across versions (e.g. "generic_json"); MappingVersion
	// increments each time the contract changes (1, 2, 3, ...).
	MappingID      string
	MappingVersion int

	Status Status

	// Contract is the declared field contract for this version.
	Contract contract.Contract

	// ParentVersion is the version this one was derived from (0 for the base
	// mapping produced by the parser descriptor).
	ParentVersion int

	// DriftStatus records how this version came into existence: the drift
	// classification that produced it ("stable" for the base mapping,
	// "minor_drift" for an adaptation).
	DriftStatus string

	// Rationale is a human-readable note explaining the adaptation.
	Rationale string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// VersionRef identifies one mapping version.
type VersionRef struct {
	Fingerprint    string
	MappingID      string
	MappingVersion int
}

// Ref returns the identity of this entry.
func (e Entry) Ref() VersionRef {
	return VersionRef{
		Fingerprint:    e.Fingerprint,
		MappingID:      e.MappingID,
		MappingVersion: e.MappingVersion,
	}
}

// Store persists source registry entries.
//
// Implementations MUST guarantee that:
//   - versions are append-only: an existing (fingerprint, mapping_id,
//     mapping_version) is never rewritten in place;
//   - at most one version per fingerprint is StatusActive at a time;
//   - SaveVersion assigns the next version number atomically, so two workers
//     racing on the same source cannot create conflicting versions.
type Store interface {
	// ActiveFor returns the active mapping version for a fingerprint, or
	// ErrNotFound when the source has never been seen.
	ActiveFor(ctx context.Context, fingerprint string) (*Entry, error)

	// VersionsFor returns every version of a fingerprint, newest first.
	VersionsFor(ctx context.Context, fingerprint string) ([]Entry, error)

	// GetVersion returns one specific version, or ErrNotFound.
	GetVersion(ctx context.Context, ref VersionRef) (*Entry, error)

	// SaveVersion appends entry as the next version of its mapping and
	// supersedes the previously active version. The version number on entry is
	// ignored: the store assigns it and returns the stored entry.
	SaveVersion(ctx context.Context, entry Entry) (*Entry, error)

	// Ping verifies connectivity to the backing store.
	Ping(ctx context.Context) error

	// Close releases resources.
	Close() error
}
