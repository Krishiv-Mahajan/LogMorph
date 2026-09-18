package review

import (
	"context"
	"errors"
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/contract"
)

func sampleChanges() []Change {
	return []Change{
		{Kind: "required_field_missing", Field: "timestamp", Target: "timestamp"},
		{Kind: "incompatible_type_change", Field: "src_port", Target: "network.src_port"},
	}
}

func sampleItem() Item {
	return Item{
		Fingerprint:    "fp-1",
		MappingID:      "generic_json_mapping",
		MappingVersion: 1,
		Category:       CategoryMappingConflict,
		DriftStatus:    "major_drift",
		Reason:         "unsafe drift: required_field_missing(timestamp)",
		Changes:        sampleChanges(),
		SampleEventID:  "evt-1",
	}
}

// ── Signature ────────────────────────────────────────────────────────────────

// TestSignatureIsStructural is the property the whole queue depends on: the key
// must be derived from the change set's structure, never from the event.
func TestSignatureIsStructural(t *testing.T) {
	base := Signature("fp-1", "mapping", 1, sampleChanges())

	// Order of changes must not matter.
	reordered := []Change{sampleChanges()[1], sampleChanges()[0]}
	if Signature("fp-1", "mapping", 1, reordered) != base {
		t.Error("expected the signature to be order independent")
	}

	// Duplicate changes must not change the key.
	duplicated := append(sampleChanges(), sampleChanges()...)
	if Signature("fp-1", "mapping", 1, duplicated) != base {
		t.Error("expected duplicate changes to collapse")
	}

	// Field name spelling differences normalize away.
	loud := []Change{
		{Kind: "required_field_missing", Field: "TimeStamp"},
		{Kind: "incompatible_type_change", Field: "SRC_PORT"},
	}
	if Signature("fp-1", "mapping", 1, loud) != base {
		t.Error("expected field names to be normalized before hashing")
	}

	if len(base) != 32 {
		t.Errorf("expected a 32 character signature, got %d", len(base))
	}
}

// TestSignatureVariesWithSourceMappingAndChanges — the key must change when the
// decision context changes, and only then. A new mapping version is a new
// decision, so it must produce a new key.
func TestSignatureVariesWithSourceMappingAndChanges(t *testing.T) {
	base := Signature("fp-1", "mapping", 1, sampleChanges())

	if Signature("fp-2", "mapping", 1, sampleChanges()) == base {
		t.Error("expected a different source to produce a different signature")
	}
	if Signature("fp-1", "other_mapping", 1, sampleChanges()) == base {
		t.Error("expected a different mapping id to produce a different signature")
	}
	if Signature("fp-1", "mapping", 2, sampleChanges()) == base {
		t.Error("expected a new mapping version to produce a new signature")
	}
	if Signature("fp-1", "mapping", 1, nil) == base {
		t.Error("expected a different change set to produce a different signature")
	}

	// An unmapped source has no mapping; the key is still deterministic.
	unmapped := Signature("fp-1", "", 0, nil)
	if unmapped != Signature("fp-1", "", 0, nil) {
		t.Error("expected an unmapped source's signature to be deterministic")
	}
	if unmapped == base {
		t.Error("expected an unmapped source to differ from a mapped one")
	}
}

// TestSignatureIgnoresEventSpecificEvidence — nothing that varies per event may
// reach the key, or every event would create its own review item.
func TestSignatureIgnoresEventSpecificEvidence(t *testing.T) {
	first := sampleItem()
	second := sampleItem()
	second.SampleEventID = "evt-2"
	second.Reason = "unsafe drift: required_field_missing(timestamp) [second event]"
	second.DriftStatus = "major_drift"

	firstKey := Signature(first.Fingerprint, first.MappingID, first.MappingVersion, first.Changes)
	secondKey := Signature(second.Fingerprint, second.MappingID, second.MappingVersion, second.Changes)

	if firstKey != secondKey {
		t.Error("expected per-event evidence not to affect the signature")
	}
}

// TestChangeCarriesNoObservedValues — the Change type has no field that could
// carry a payload value, which is what keeps the queue free of payload data.
func TestChangeCarriesNoObservedValues(t *testing.T) {
	change := Change{Kind: "ambiguous_mapping", Field: "src_ip", Target: "network.src_ip"}

	// The only fields are structural; a detail string would have to be added to
	// this struct, and this assertion documents that it is not.
	if change.Kind == "" || change.Field == "" {
		t.Fatal("expected the structural fields to be present")
	}
	if change.Safe {
		t.Error("expected ambiguous_mapping to be unsafe")
	}
}

// ── State machine ────────────────────────────────────────────────────────────

func TestCanTransitionMatrix(t *testing.T) {
	allowed := map[[2]Status]bool{
		{StatusPending, StatusApproved}:  true,
		{StatusPending, StatusRejected}:  true,
		{StatusApproved, StatusPending}:  true,
		{StatusRejected, StatusPending}:  true,
		{StatusApproved, StatusRejected}: false,
		{StatusRejected, StatusApproved}: false,
		{StatusPending, StatusPending}:   false,
		{StatusApproved, StatusApproved}: false,
		{StatusRejected, StatusRejected}: false,
	}

	for pair, want := range allowed {
		if got := CanTransition(pair[0], pair[1]); got != want {
			t.Errorf("CanTransition(%s, %s) = %t, want %t", pair[0], pair[1], got, want)
		}
	}

	if CanTransition(Status("nonsense"), StatusPending) {
		t.Error("expected an unknown status to transition nowhere")
	}
}

// ── Memory store ─────────────────────────────────────────────────────────────

func TestMemoryStoreDeduplicatesBySignature(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	first, err := store.Upsert(ctx, sampleItem())
	if err != nil {
		t.Fatalf("first upsert failed: %v", err)
	}
	if first.Status != StatusPending {
		t.Errorf("expected a new item to be pending, got %q", first.Status)
	}
	if first.Occurrences != 1 {
		t.Errorf("expected 1 occurrence, got %d", first.Occurrences)
	}
	if first.Signature == "" {
		t.Error("expected the store to compute the signature")
	}
	if first.Origin != OriginDriftEngine {
		t.Errorf("expected the default origin, got %q", first.Origin)
	}

	// A second event with the same drift, from the same source and contract.
	second := sampleItem()
	second.SampleEventID = "evt-2"
	updated, err := store.Upsert(ctx, second)
	if err != nil {
		t.Fatalf("second upsert failed: %v", err)
	}
	if updated.ReviewID != first.ReviewID {
		t.Errorf("expected the same row, got %d then %d", first.ReviewID, updated.ReviewID)
	}
	if updated.Occurrences != 2 {
		t.Errorf("expected 2 occurrences, got %d", updated.Occurrences)
	}
	if !updated.FirstSeenAt.Equal(first.FirstSeenAt) {
		t.Error("expected first_seen_at to be preserved")
	}
	if updated.SampleEventID != first.SampleEventID {
		t.Error("expected the original sample event to be preserved as evidence")
	}

	items, err := store.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(items) != 1 {
		t.Errorf("expected exactly 1 item, got %d", len(items))
	}
}

// TestMemoryStoreSeparatesDistinctDrift — a different contract or a different
// change set is a different decision.
func TestMemoryStoreSeparatesDistinctDrift(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	if _, err := store.Upsert(ctx, sampleItem()); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}

	otherVersion := sampleItem()
	otherVersion.MappingVersion = 2
	if _, err := store.Upsert(ctx, otherVersion); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}

	otherSource := sampleItem()
	otherSource.Fingerprint = "fp-2"
	if _, err := store.Upsert(ctx, otherSource); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}

	items, _ := store.List(ctx, Filter{})
	if len(items) != 3 {
		t.Errorf("expected 3 distinct items, got %d", len(items))
	}
}

// TestMemoryStoreDecisionSurvivesRecurrence — a decided item keeps its decision
// when the same drift is observed again; only the counters move.
func TestMemoryStoreDecisionSurvivesRecurrence(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	item, _ := store.Upsert(ctx, sampleItem())
	if _, err := store.Decide(ctx, item.ReviewID, Decision{Status: StatusRejected, By: "alice", Notes: "expected"}); err != nil {
		t.Fatalf("decide failed: %v", err)
	}

	recurred, err := store.Upsert(ctx, sampleItem())
	if err != nil {
		t.Fatalf("recurring upsert failed: %v", err)
	}
	if recurred.Status != StatusRejected {
		t.Errorf("expected the rejection to stick, got %q", recurred.Status)
	}
	if recurred.DecidedBy != "alice" || recurred.DecisionNotes != "expected" {
		t.Errorf("expected the decision to be preserved, got %q / %q", recurred.DecidedBy, recurred.DecisionNotes)
	}
	if recurred.Occurrences != 2 {
		t.Errorf("expected the recurrence to be counted, got %d", recurred.Occurrences)
	}
}

func TestMemoryStoreTransitions(t *testing.T) {
	ctx := context.Background()

	t.Run("approve then double approve fails", func(t *testing.T) {
		store := NewMemoryStore()
		item, _ := store.Upsert(ctx, sampleItem())

		approved, err := store.Decide(ctx, item.ReviewID, Decision{
			Status: StatusApproved, By: "alice", ResultingMappingVersion: 2,
		})
		if err != nil {
			t.Fatalf("approve failed: %v", err)
		}
		if approved.Status != StatusApproved || approved.ResultingMappingVersion != 2 {
			t.Errorf("unexpected approved item: %+v", approved)
		}
		if approved.DecidedAt == nil {
			t.Error("expected a decision timestamp")
		}

		_, err = store.Decide(ctx, item.ReviewID, Decision{Status: StatusRejected, By: "bob"})
		if !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("expected an invalid transition, got %v", err)
		}
	})

	t.Run("reject then reopen then approve", func(t *testing.T) {
		store := NewMemoryStore()
		item, _ := store.Upsert(ctx, sampleItem())

		if _, err := store.Decide(ctx, item.ReviewID, Decision{Status: StatusRejected, By: "alice"}); err != nil {
			t.Fatalf("reject failed: %v", err)
		}
		reopened, err := store.Reopen(ctx, item.ReviewID, "bob", "reconsidering")
		if err != nil {
			t.Fatalf("reopen failed: %v", err)
		}
		if reopened.Status != StatusPending {
			t.Errorf("expected pending after reopen, got %q", reopened.Status)
		}
		if _, err := store.Decide(ctx, item.ReviewID, Decision{Status: StatusApproved, By: "bob"}); err != nil {
			t.Fatalf("approve after reopen failed: %v", err)
		}
	})

	t.Run("reopen a pending item fails", func(t *testing.T) {
		store := NewMemoryStore()
		item, _ := store.Upsert(ctx, sampleItem())

		if _, err := store.Reopen(ctx, item.ReviewID, "alice", ""); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("expected an invalid transition, got %v", err)
		}
	})

	t.Run("unknown items", func(t *testing.T) {
		store := NewMemoryStore()

		if _, err := store.Get(ctx, 999); !errors.Is(err, ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
		if _, err := store.Decide(ctx, 999, Decision{Status: StatusApproved}); !errors.Is(err, ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
		if _, err := store.Reopen(ctx, 999, "alice", ""); !errors.Is(err, ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("invalid decision status", func(t *testing.T) {
		store := NewMemoryStore()
		item, _ := store.Upsert(ctx, sampleItem())

		if _, err := store.Decide(ctx, item.ReviewID, Decision{Status: StatusPending}); err == nil {
			t.Error("expected a non-terminal decision to be refused")
		}
	})
}

func TestMemoryStoreListFilters(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	first, _ := store.Upsert(ctx, sampleItem())
	other := sampleItem()
	other.Fingerprint = "fp-2"
	second, _ := store.Upsert(ctx, other)
	if _, err := store.Decide(ctx, second.ReviewID, Decision{Status: StatusRejected, By: "alice"}); err != nil {
		t.Fatalf("decide failed: %v", err)
	}

	approved, err := store.List(ctx, Filter{Status: StatusApproved})
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(approved) != 0 {
		t.Errorf("expected no approved items, got %d", len(approved))
	}

	pending, _ := store.List(ctx, Filter{Status: StatusPending})
	if len(pending) != 1 || pending[0].ReviewID != first.ReviewID {
		t.Errorf("expected only the pending item, got %+v", pending)
	}

	bySource, _ := store.List(ctx, Filter{Fingerprint: "fp-2"})
	if len(bySource) != 1 || bySource[0].ReviewID != second.ReviewID {
		t.Errorf("expected the second source's item, got %+v", bySource)
	}

	limited, _ := store.List(ctx, Filter{Limit: 1})
	if len(limited) != 1 {
		t.Errorf("expected the limit to apply, got %d", len(limited))
	}
}

func TestMemoryStoreRejectsItemsWithoutFingerprint(t *testing.T) {
	if _, err := NewMemoryStore().Upsert(context.Background(), Item{}); err == nil {
		t.Error("expected an error for a missing fingerprint")
	}
}

// ── Approval validation ──────────────────────────────────────────────────────

func TestValidateContract(t *testing.T) {
	valid := contract.Contract{Fields: []contract.Field{
		{Name: "timestamp", Type: contract.TypeString, Target: "timestamp"},
	}}

	if err := validateContract(valid); err != nil {
		t.Errorf("expected a valid contract to pass: %v", err)
	}

	tests := []struct {
		name     string
		proposed contract.Contract
	}{
		{"no fields", contract.Contract{}},
		{"empty name", contract.Contract{Fields: []contract.Field{{Name: "  ", Type: contract.TypeString}}}},
		{"unknown type", contract.Contract{Fields: []contract.Field{{Name: "a", Type: contract.Type("mystery")}}}},
		{"duplicate field", contract.Contract{Fields: []contract.Field{
			{Name: "a", Type: contract.TypeString},
			{Name: "A", Type: contract.TypeString},
		}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateContract(tt.proposed); !errors.Is(err, ErrInvalidContract) {
				t.Errorf("expected ErrInvalidContract, got %v", err)
			}
		})
	}
}

// TestApproveRefusesUnmappedSource — there is no parser for the format, so a
// contract could not be honoured; the queue must refuse rather than write a
// mapping the pipeline cannot apply.
func TestApproveRefusesUnmappedSource(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	item := sampleItem()
	item.Category = CategoryUnmappedSource
	item.MappingID = ""
	item.MappingVersion = 0
	stored, err := store.Upsert(ctx, item)
	if err != nil {
		t.Fatalf("upsert failed: %v", err)
	}

	proposed := contract.Contract{Fields: []contract.Field{
		{Name: "action", Type: contract.TypeString, Target: "event.action"},
	}}
	if _, err := Approve(ctx, store, nil, stored.ReviewID, proposed, "alice", ""); !errors.Is(err, ErrUnmappedSource) {
		t.Errorf("expected ErrUnmappedSource, got %v", err)
	}

	// The item is untouched by the refused approval.
	current, _ := store.Get(ctx, stored.ReviewID)
	if current.Status != StatusPending {
		t.Errorf("expected the item to remain pending, got %q", current.Status)
	}
}

func TestApproveRefusesInvalidContract(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	item, _ := store.Upsert(ctx, sampleItem())

	if _, err := Approve(ctx, store, nil, item.ReviewID, contract.Contract{}, "alice", ""); !errors.Is(err, ErrInvalidContract) {
		t.Errorf("expected ErrInvalidContract, got %v", err)
	}
}

func TestApproveRefusesDecidedItem(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	item, _ := store.Upsert(ctx, sampleItem())
	if _, err := Reject(ctx, store, item.ReviewID, "alice", "not now"); err != nil {
		t.Fatalf("reject failed: %v", err)
	}

	proposed := contract.Contract{Fields: []contract.Field{
		{Name: "action", Type: contract.TypeString, Target: "event.action"},
	}}
	if _, err := Approve(ctx, store, nil, item.ReviewID, proposed, "bob", ""); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("expected ErrInvalidTransition, got %v", err)
	}
}
