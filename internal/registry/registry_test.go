package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/contract"
)

func sampleEntry(fingerprint, mappingID string) Entry {
	return Entry{
		Fingerprint:   fingerprint,
		Vendor:        "generic",
		Product:       "json-firewall",
		SourceType:    "firewall",
		Format:        "json",
		ParserID:      "generic_json",
		ParserVersion: "1.0",
		MappingID:     mappingID,
		Status:        StatusActive,
		Contract: contract.Contract{Fields: []contract.Field{
			{Name: "timestamp", Type: contract.TypeString, Target: "timestamp"},
		}},
	}
}

// TestFingerprintIsStableAcrossSchemaChanges is the property that makes minor
// drift detectable at all: the fingerprint is derived from transport identity,
// never from the payload's field structure.
func TestFingerprintIsStableAcrossSchemaChanges(t *testing.T) {
	base := Fingerprint(FingerprintInput{Format: "json", Source: "firewall-01", SourceType: "firewall"})

	// Same source, different payload structure: the identity must not move.
	same := Fingerprint(FingerprintInput{Format: "json", Source: "firewall-01", SourceType: "firewall"})
	if base != same {
		t.Error("expected the fingerprint to be deterministic")
	}

	// Formatting differences in the hint must not fork the identity.
	padded := Fingerprint(FingerprintInput{Format: " JSON ", Source: "Firewall-01", SourceType: "FIREWALL"})
	if base != padded {
		t.Error("expected the fingerprint to normalize case and whitespace")
	}

	// Different sources must not collide.
	other := Fingerprint(FingerprintInput{Format: "json", Source: "firewall-02", SourceType: "firewall"})
	if base == other {
		t.Error("expected different sources to have different fingerprints")
	}

	if len(base) != 32 {
		t.Errorf("expected a 32 character fingerprint, got %d", len(base))
	}
}

func TestMemoryStoreVersionChain(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	fingerprint := "fp-test"

	if _, err := store.ActiveFor(ctx, fingerprint); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for an unknown source, got %v", err)
	}

	v1, err := store.SaveVersion(ctx, sampleEntry(fingerprint, "mapping"))
	if err != nil {
		t.Fatalf("failed to save v1: %v", err)
	}
	if v1.MappingVersion != 1 {
		t.Errorf("expected the first version to be 1, got %d", v1.MappingVersion)
	}
	if v1.Status != StatusActive {
		t.Errorf("expected the first version to be active, got %q", v1.Status)
	}

	v2 := sampleEntry(fingerprint, "mapping")
	v2.Contract = v2.Contract.WithField(contract.Field{Name: "device_uuid", Type: contract.TypeString, Optional: true})
	savedV2, err := store.SaveVersion(ctx, v2)
	if err != nil {
		t.Fatalf("failed to save v2: %v", err)
	}
	if savedV2.MappingVersion != 2 {
		t.Errorf("expected the second version to be 2, got %d", savedV2.MappingVersion)
	}
	if savedV2.ParentVersion != 0 {
		t.Errorf("expected the store to leave lineage to the caller, got parent %d", savedV2.ParentVersion)
	}

	// The previous version is superseded but still available.
	v1Reloaded, err := store.GetVersion(ctx, VersionRef{Fingerprint: fingerprint, MappingID: "mapping", MappingVersion: 1})
	if err != nil {
		t.Fatalf("expected v1 to remain available: %v", err)
	}
	if v1Reloaded.Status != StatusSuperseded {
		t.Errorf("expected v1 to be superseded, got %q", v1Reloaded.Status)
	}
	if len(v1Reloaded.Contract.Fields) != 1 {
		t.Error("expected v1's contract to be unchanged")
	}

	// Only the newest version is active.
	active, err := store.ActiveFor(ctx, fingerprint)
	if err != nil {
		t.Fatalf("failed to read the active version: %v", err)
	}
	if active.MappingVersion != 2 {
		t.Errorf("expected v2 to be active, got %d", active.MappingVersion)
	}

	versions, err := store.VersionsFor(ctx, fingerprint)
	if err != nil {
		t.Fatalf("failed to list versions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(versions))
	}
	if versions[0].MappingVersion != 2 || versions[1].MappingVersion != 1 {
		t.Errorf("expected newest-first ordering, got %d then %d", versions[0].MappingVersion, versions[1].MappingVersion)
	}
}

// TestMemoryStoreKeepsMappingsIndependent — two mappings for one source version
// separately.
func TestMemoryStoreKeepsMappingsIndependent(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	if _, err := store.SaveVersion(ctx, sampleEntry("fp", "mapping_a")); err != nil {
		t.Fatalf("save a: %v", err)
	}
	if _, err := store.SaveVersion(ctx, sampleEntry("fp", "mapping_b")); err != nil {
		t.Fatalf("save b: %v", err)
	}
	saved, err := store.SaveVersion(ctx, sampleEntry("fp", "mapping_a"))
	if err != nil {
		t.Fatalf("save a again: %v", err)
	}
	if saved.MappingVersion != 2 {
		t.Errorf("expected mapping_a to reach version 2, got %d", saved.MappingVersion)
	}
}

func TestMemoryStoreRejectsInvalidEntries(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	if _, err := store.SaveVersion(ctx, Entry{MappingID: "m"}); err == nil {
		t.Error("expected an error for a missing fingerprint")
	}
	if _, err := store.SaveVersion(ctx, Entry{Fingerprint: "fp"}); err == nil {
		t.Error("expected an error for a missing mapping id")
	}
}

func TestContractHistoryHelper(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	fingerprint := "fp-history"

	v1, _ := store.SaveVersion(ctx, sampleEntry(fingerprint, "mapping"))
	v2 := sampleEntry(fingerprint, "mapping")
	v2.Contract = v2.Contract.WithField(contract.Field{Name: "extra", Type: contract.TypeString, Optional: true})
	_, _ = store.SaveVersion(ctx, v2)

	history := store.ContractHistory(ctx, fingerprint)
	if len(history) != 2 {
		t.Fatalf("expected 2 contract versions, got %d", len(history))
	}
	if history[0] != v1.Contract.Hash() {
		t.Error("expected the history to start with the original contract")
	}
	if history[0] == history[1] {
		t.Error("expected the adapted contract to differ")
	}
}
