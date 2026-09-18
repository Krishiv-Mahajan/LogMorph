// Package review implements the review queue: durable work items raised when the
// deterministic drift engine cannot decide a source's mapping on its own.
//
// The queue is NOT quarantine. Quarantine records events that could not be
// processed at all; a review records that a source's schema needs a mapping
// decision. The same event can legitimately appear in both.
package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/contract"
	"github.com/Krishiv-Mahajan/LogMorph/internal/registry"
)

// Category says why the item exists, and therefore what can resolve it.
type Category string

const (
	// CategoryMappingConflict is an unsafe change against a mapping that exists:
	// a required field vanished, a type changed incompatibly, a structure
	// changed, or two names disagree about one target.
	CategoryMappingConflict Category = "mapping_conflict"

	// CategoryUnmappedSource is a source with no parser contract at all. It
	// cannot be approved into a mapping, because there is no parser to honour
	// the contract; it is recorded so the gap is visible.
	CategoryUnmappedSource Category = "unmapped_source"
)

// Status is the lifecycle state of an item.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

// Origin records what raised the item, so an item created by a future AI step
// is distinguishable from one raised by the deterministic engine without a
// schema change.
const (
	OriginDriftEngine = "drift_engine"
	OriginHuman       = "human"
	OriginAI          = "ai"
)

// Errors returned by the queue.
var (
	ErrNotFound          = errors.New("review item not found")
	ErrInvalidTransition = errors.New("invalid review state transition")
	ErrUnmappedSource    = errors.New("cannot approve an unmapped source: no parser exists for its format")
	ErrInvalidContract   = errors.New("proposed contract is invalid")
)

// Change is one observed structural difference, in machine-readable form.
//
// It deliberately does not carry drift.Change.Detail: the detail string for an
// ambiguous mapping embeds the conflicting payload values, and the queue must
// not become a second store of payload data. The raw payload is one lookup away
// via SampleEventID.
type Change struct {
	Kind   string `json:"kind"`
	Field  string `json:"field"`
	Target string `json:"target,omitempty"`
	Safe   bool   `json:"safe"`
}

// Item is one review queue entry.
type Item struct {
	ReviewID       int64
	Fingerprint    string
	Signature      string
	MappingID      string
	MappingVersion int
	Category       Category
	DriftStatus    string
	Reason         string
	Changes        []Change

	// ProposedContract is filled by whoever resolves the item. Nil until then.
	ProposedContract *contract.Contract

	Status                  Status
	ResultingMappingVersion int
	Occurrences             int
	Origin                  string
	SampleEventID           string

	FirstSeenAt   time.Time
	LastSeenAt    time.Time
	DecidedAt     *time.Time
	DecidedBy     string
	DecisionNotes string
}

// Decision is a terminal decision applied to a pending item.
type Decision struct {
	Status Status
	By     string
	Notes  string

	// ResultingMappingVersion is the registry version created by an approval.
	ResultingMappingVersion int
}

// Filter narrows a List call. Zero values mean "no constraint".
type Filter struct {
	Status      Status
	Fingerprint string
	Limit       int
}

// Signature is the deduplication key of an escalation.
//
// It is computed from structure only — the source, the mapping version in
// force, and the sorted (change kind, field) pairs. It must never include
// Change.Detail or any observed value: for an ambiguous mapping the detail
// embeds the conflicting values, so a value-dependent signature would mint a
// new review item for every event whose values differ, which is exactly the
// row explosion the queue exists to prevent.
func Signature(fingerprint, mappingID string, mappingVersion int, changes []Change) string {
	parts := make([]string, 0, len(changes))
	for _, change := range changes {
		parts = append(parts, change.Kind+"|"+contract.NormalizeName(change.Field))
	}
	sort.Strings(parts)

	// Collapse duplicates so two identical changes cannot change the key.
	unique := parts[:0]
	for i, part := range parts {
		if i == 0 || part != parts[i-1] {
			unique = append(unique, part)
		}
	}

	canonical := strings.Join([]string{
		fingerprint,
		contract.NormalizeName(mappingID),
		strconv.Itoa(mappingVersion),
		strings.Join(unique, ","),
	}, "\x1f")

	sum := sha256.Sum256([]byte(canonical))

	return hex.EncodeToString(sum[:])[:32]
}

// CanTransition reports whether a lifecycle move from one status to another is
// legal:
//
//	pending  -> approved | rejected
//	approved -> pending            (reopen)
//	rejected -> pending            (reopen)
func CanTransition(from, to Status) bool {
	switch from {
	case StatusPending:
		return to == StatusApproved || to == StatusRejected
	case StatusApproved, StatusRejected:
		return to == StatusPending
	default:
		return false
	}
}

// Store persists review queue items.
//
// Implementations MUST guarantee that:
//   - Upsert deduplicates on (fingerprint, signature): repeated observations of
//     the same drift update one row rather than creating another;
//   - Decide and Reopen are compare-and-set: a caller can only move an item out
//     of the state it actually observed, so concurrent decisions cannot both
//     win.
type Store interface {
	// Upsert records an escalation. The signature is computed by the store from
	// the item's fingerprint, mapping and changes, so a caller cannot supply an
	// inconsistent key. The first observation creates a pending item; later
	// observations increment Occurrences and refresh LastSeenAt, leaving the
	// original evidence and any decision untouched.
	Upsert(ctx context.Context, item Item) (*Item, error)

	// Get returns one item by id, or ErrNotFound.
	Get(ctx context.Context, reviewID int64) (*Item, error)

	// List returns items matching a filter, newest first.
	List(ctx context.Context, filter Filter) ([]Item, error)

	// Decide applies a terminal decision to a pending item.
	Decide(ctx context.Context, reviewID int64, decision Decision) (*Item, error)

	// Reopen returns a decided item to pending.
	Reopen(ctx context.Context, reviewID int64, by, notes string) (*Item, error)

	// Ping verifies connectivity to the backing store.
	Ping(ctx context.Context) error

	// Close releases resources.
	Close() error
}

// Approve activates a proposed contract for the item's source.
//
// The registry is append-only and is never mutated here: the proposal becomes a
// NEW mapping version, and the version that was active when the drift was
// observed is superseded by the existing registry logic. A crash between the
// registry write and the decision is safe to retry, because the registry
// deduplicates identical contracts and will return the version it already
// created rather than adding a second one.
func Approve(
	ctx context.Context,
	store Store,
	mappings registry.Store,
	reviewID int64,
	proposed contract.Contract,
	by, notes string,
) (*Item, error) {
	item, err := store.Get(ctx, reviewID)
	if err != nil {
		return nil, err
	}
	if item.Status != StatusPending {
		return nil, fmt.Errorf("%w: review %d is %s", ErrInvalidTransition, reviewID, item.Status)
	}
	if item.Category == CategoryUnmappedSource {
		// No parser exists for the format, so no contract could be honoured.
		// Writing one would make the registry claim a mapping the pipeline
		// cannot apply.
		return nil, fmt.Errorf("%w (review %d)", ErrUnmappedSource, reviewID)
	}
	if err := validateContract(proposed); err != nil {
		return nil, err
	}

	base, err := baseEntry(ctx, mappings, item)
	if err != nil {
		return nil, err
	}

	stored, err := mappings.SaveVersion(ctx, registry.Entry{
		Fingerprint:   item.Fingerprint,
		Vendor:        base.Vendor,
		Product:       base.Product,
		SourceType:    base.SourceType,
		Format:        base.Format,
		ParserID:      base.ParserID,
		ParserVersion: base.ParserVersion,
		MappingID:     base.MappingID,
		Status:        registry.StatusActive,
		Contract:      proposed,
		ParentVersion: base.MappingVersion,
		DriftStatus:   item.DriftStatus,
		Rationale:     fmt.Sprintf("approved review %d by %s", item.ReviewID, orUnknown(by)),
	})
	if err != nil {
		return nil, err
	}

	return store.Decide(ctx, reviewID, Decision{
		Status:                  StatusApproved,
		By:                      by,
		Notes:                   notes,
		ResultingMappingVersion: stored.MappingVersion,
	})
}

// Reject records that the source's current mapping stays as it is.
func Reject(ctx context.Context, store Store, reviewID int64, by, notes string) (*Item, error) {
	return store.Decide(ctx, reviewID, Decision{Status: StatusRejected, By: by, Notes: notes})
}

// baseEntry returns the mapping version the decision is made against: the
// currently active one, so the new version's lineage points at what it actually
// replaces. It falls back to the version recorded on the item when the source
// has no active version.
func baseEntry(ctx context.Context, mappings registry.Store, item *Item) (*registry.Entry, error) {
	active, err := mappings.ActiveFor(ctx, item.Fingerprint)
	if err == nil {
		return active, nil
	}
	if !errors.Is(err, registry.ErrNotFound) {
		return nil, err
	}

	recorded, getErr := mappings.GetVersion(ctx, registry.VersionRef{
		Fingerprint:    item.Fingerprint,
		MappingID:      item.MappingID,
		MappingVersion: item.MappingVersion,
	})
	if getErr != nil {
		return nil, fmt.Errorf("no mapping to base an approval on: %w", getErr)
	}

	return recorded, nil
}

// validateContract rejects a proposal that could not be applied safely.
func validateContract(proposed contract.Contract) error {
	if len(proposed.Fields) == 0 {
		return fmt.Errorf("%w: the contract declares no fields", ErrInvalidContract)
	}

	seen := make(map[string]bool, len(proposed.Fields))
	for _, field := range proposed.Fields {
		name := contract.NormalizeName(field.Name)
		if name == "" {
			return fmt.Errorf("%w: a field has an empty name", ErrInvalidContract)
		}
		if !field.Type.Known() {
			return fmt.Errorf("%w: field %q has unknown type %q", ErrInvalidContract, name, field.Type)
		}
		if seen[name] {
			return fmt.Errorf("%w: field %q is declared twice", ErrInvalidContract, name)
		}
		seen[name] = true
	}

	return nil
}

func orUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
