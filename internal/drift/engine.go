package drift

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/contract"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/registry"
)

// ChangeKind names a specific structural difference.
type ChangeKind string

const (
	// ChangeFieldAdded: the payload carries a field the contract does not
	// declare. Additive and safe, provided it is a scalar.
	ChangeFieldAdded ChangeKind = "field_added"

	// ChangeRequiredMissing: a field the contract declares as required is gone.
	ChangeRequiredMissing ChangeKind = "required_field_missing"

	// ChangeTypeChanged: a declared field arrived with an incompatible type.
	ChangeTypeChanged ChangeKind = "incompatible_type_change"

	// ChangeStructural: a container appeared where a scalar was declared, or a
	// container-shaped field was added.
	ChangeStructural ChangeKind = "structural_change"

	// ChangeAmbiguous: the payload resolves the same target through two names
	// with different values, so no mapping can be chosen deterministically.
	ChangeAmbiguous ChangeKind = "ambiguous_mapping"
)

// Change is one structural difference between a payload and a contract.
type Change struct {
	Kind   ChangeKind
	Field  string
	Detail string
	Safe   bool
	Target string
}

// Result is the outcome of a drift analysis.
type Result struct {
	// Fingerprint identifies the source.
	Fingerprint string

	// Classification is the drift verdict, using the existing status enum.
	Classification models.DriftStatus

	// Entry is the mapping that must be used to parse this event. It is nil
	// only when the source has no parser contract at all.
	Entry *registry.Entry

	// Observation is the observed payload structure, used by the binder.
	Observation Observation

	// Changes lists the differences that were found. Informational only: a
	// stable result has no changes even when the payload used a declared alias.
	Changes []Change

	// Adapted reports that a new mapping version was created for this event.
	Adapted bool

	// EscalationRequired reports that the change was unsafe. Nothing is adapted
	// in that case; a human — or, later, the AI escalation path — must decide.
	EscalationRequired bool

	// Reason is a human-readable summary.
	Reason string
}

// ParserCatalog supplies the declared contract of a parser by format.
type ParserCatalog interface {
	DescriptorForFormat(format string) (contract.ParserDescriptor, bool)
}

// Analyzer classifies drift and resolves the mapping for an event.
type Analyzer interface {
	Analyze(ctx context.Context, raw models.RawEvent, detection models.DetectionResult) (*Result, error)
}

// Engine performs deterministic drift analysis against the source registry.
//
// Its safety model is deliberately asymmetric: an additive scalar field can be
// adapted automatically because ignoring an extra field cannot change the
// meaning of the fields already mapped. Anything that could change meaning —
// a missing required field, an incompatible type, a structural change, or an
// ambiguous mapping — is never adapted.
type Engine struct {
	store   registry.Store
	catalog ParserCatalog
	now     func() time.Time
}

// NewEngine creates a drift engine over a registry store and parser catalog.
func NewEngine(store registry.Store, catalog ParserCatalog) *Engine {
	return &Engine{store: store, catalog: catalog, now: time.Now}
}

// Analyze resolves the mapping for an event and classifies its drift.
//
// It returns an error only when the registry itself cannot be read or written;
// a payload that simply cannot be compared is reported as an unknown result so
// the caller can carry on processing the event.
func (e *Engine) Analyze(ctx context.Context, raw models.RawEvent, detection models.DetectionResult) (*Result, error) {
	input := registry.FingerprintInput{
		Format:     detection.Format,
		Source:     raw.Source,
		SourceType: detection.SourceType,
	}
	fingerprint := registry.Fingerprint(input)

	active, err := e.store.ActiveFor(ctx, fingerprint)
	switch {
	case errors.Is(err, registry.ErrNotFound):
		active, err = e.bootstrap(ctx, fingerprint, detection)
		if err != nil {
			return nil, err
		}
		if active == nil {
			return &Result{
				Fingerprint:        fingerprint,
				Classification:     models.DriftStatusUnknown,
				EscalationRequired: true,
				Reason: fmt.Sprintf(
					"no parser contract declared for format %q; the source cannot be mapped deterministically",
					detection.Format),
			}, nil
		}
	case err != nil:
		return nil, err
	}

	return e.evaluate(ctx, active, raw)
}

// evaluate compares a payload against the source's active contract.
func (e *Engine) evaluate(ctx context.Context, active *registry.Entry, raw models.RawEvent) (*Result, error) {
	result := &Result{
		Fingerprint:    active.Fingerprint,
		Entry:          active,
		Classification: models.DriftStatusStable,
	}

	observation, err := Observe(active.Format, raw.Payload)
	if err != nil {
		// The payload cannot be structurally compared (malformed, or a format
		// with no observer). That is not a reason to discard an event: it is a
		// reason to say so and let the existing parsing path decide.
		result.Classification = models.DriftStatusUnknown
		result.EscalationRequired = true
		result.Reason = "payload could not be structurally observed: " + err.Error()
		return result, nil
	}
	result.Observation = observation

	changes := compare(active.Contract, observation)
	result.Changes = changes

	unsafeChanges := filterChanges(changes, false)
	if len(unsafeChanges) > 0 {
		// Unsafe changes are never adapted. The active mapping is kept, the
		// event is still parsed with it, and the escalation flag records that
		// this source needs review.
		result.Classification = models.DriftStatusMajorDrift
		result.EscalationRequired = true
		result.Reason = "unsafe drift: " + describe(unsafeChanges)
		return result, nil
	}

	safeChanges := filterChanges(changes, true)
	if len(safeChanges) == 0 {
		result.Reason = "payload matches the active mapping contract"
		return result, nil
	}

	adapted, err := e.adapt(ctx, active, safeChanges, observation)
	if err != nil {
		return nil, err
	}

	result.Entry = adapted
	result.Adapted = true
	result.Classification = models.DriftStatusMinorDrift
	result.Reason = "minor drift auto-adapted: " + describe(safeChanges)

	return result, nil
}

// bootstrap registers the first mapping version for a source from the parser's
// declared contract.
func (e *Engine) bootstrap(ctx context.Context, fingerprint string, detection models.DetectionResult) (*registry.Entry, error) {
	descriptor, ok := e.catalog.DescriptorForFormat(detection.Format)
	if !ok {
		return nil, nil
	}

	entry := registry.Entry{
		Fingerprint:   fingerprint,
		Vendor:        descriptor.Vendor,
		Product:       descriptor.Product,
		SourceType:    detection.SourceType,
		Format:        detection.Format,
		ParserID:      descriptor.ParserID,
		ParserVersion: descriptor.ParserVersion,
		MappingID:     descriptor.MappingID,
		Status:        registry.StatusActive,
		Contract:      descriptor.Contract.Normalized(),
		ParentVersion: 0,
		DriftStatus:   string(models.DriftStatusStable),
		Rationale:     "base mapping declared by parser " + descriptor.ParserID + " " + descriptor.ParserVersion,
	}

	return e.store.SaveVersion(ctx, entry)
}

// adapt creates the next mapping version by recording safe additions.
//
// Every adapted field is recorded as optional and without a target: the field
// is observed and versioned, but it is never bound to a Universal Event
// attribute, because binding requires knowing what the field means.
func (e *Engine) adapt(
	ctx context.Context,
	active *registry.Entry,
	safeChanges []Change,
	observation Observation,
) (*registry.Entry, error) {
	next := active.Contract
	added := make([]string, 0, len(safeChanges))

	for _, change := range safeChanges {
		if change.Kind != ChangeFieldAdded {
			continue
		}
		observed, ok := observation.Lookup(change.Field)
		if !ok {
			continue
		}

		next = next.WithField(contract.Field{
			Name:        observed.Name,
			Type:        observed.Type,
			Optional:    true,
			Target:      "",
			Description: "auto-adapted optional field (minor drift, " + e.now().UTC().Format(time.RFC3339) + ")",
		})
		added = append(added, observed.Name)
	}

	if len(added) == 0 || next.Hash() == active.Contract.Hash() {
		return active, nil
	}

	stored, err := e.store.SaveVersion(ctx, registry.Entry{
		Fingerprint:   active.Fingerprint,
		Vendor:        active.Vendor,
		Product:       active.Product,
		SourceType:    active.SourceType,
		Format:        active.Format,
		ParserID:      active.ParserID,
		ParserVersion: active.ParserVersion,
		MappingID:     active.MappingID,
		Status:        registry.StatusActive,
		Contract:      next,
		ParentVersion: active.MappingVersion,
		DriftStatus:   string(models.DriftStatusMinorDrift),
		Rationale:     "auto-adapted additive field(s): " + strings.Join(added, ", "),
	})
	if err != nil {
		return nil, err
	}

	return stored, nil
}

// compare diffs an observation against a contract.
func compare(c contract.Contract, observation Observation) []Change {
	changes := make([]Change, 0, 4)

	// Which contract field each observed name resolved to, so a target reached
	// through two different names can be checked for conflicting values.
	resolved := map[string]ObservedField{}
	conflicts := map[string]bool{}

	for _, observed := range observation.Fields {
		field, _, declared := c.Resolve(observed.Name)
		if !declared {
			// A container the contract already describes through its nested
			// fields (e.g. "network" because "network.src_ip" is declared) is
			// expected structure, not drift.
			if observed.Type.IsContainer() && c.HasNestedField(observed.Name) {
				continue
			}

			structural := observed.Type.IsContainer()
			change := Change{
				Kind:   ChangeFieldAdded,
				Field:  observed.Name,
				Safe:   !structural,
				Target: "",
			}
			if structural {
				change.Kind = ChangeStructural
				change.Detail = fmt.Sprintf(
					"field %q is a %s; a nested structure cannot be added to a mapping automatically",
					observed.Name, observed.Type)
			} else {
				change.Detail = fmt.Sprintf(
					"field %q (%s) is not declared; it can be recorded as an optional, unbound field",
					observed.Name, observed.Type)
			}
			changes = append(changes, change)
			continue
		}

		canonical := contract.NormalizeName(field.Name)

		if !typesCompatible(field.Type, observed.Type) {
			changes = append(changes, Change{
				Kind:   ChangeTypeChanged,
				Field:  observed.Name,
				Detail: fmt.Sprintf("field %q is declared %s but arrived as %s", observed.Name, field.Type, observed.Type),
				Safe:   false,
				Target: field.Target,
			})
			continue
		}

		if previous, seen := resolved[canonical]; seen {
			if previous.Value != "" && observed.Value != "" && previous.Value != observed.Value && !conflicts[canonical] {
				conflicts[canonical] = true
				changes = append(changes, Change{
					Kind:  ChangeAmbiguous,
					Field: canonical,
					Detail: fmt.Sprintf(
						"%q and %q both map to %q but carry different values (%q vs %q); no mapping can be chosen deterministically",
						previous.Name, observed.Name, field.Target, previous.Value, observed.Value),
					Safe:   false,
					Target: field.Target,
				})
			}
			continue
		}

		resolved[canonical] = observed
	}

	for _, field := range c.Required() {
		if _, present := resolved[contract.NormalizeName(field.Name)]; present {
			continue
		}
		if observedViaAlias(field, observation) {
			continue
		}
		changes = append(changes, Change{
			Kind:   ChangeRequiredMissing,
			Field:  field.Name,
			Detail: fmt.Sprintf("required field %q is absent from the payload", field.Name),
			Safe:   false,
			Target: field.Target,
		})
	}

	return suppressNestedAdditions(changes)
}

// suppressNestedAdditions drops additive changes that are only a consequence of
// an unsafe change to an enclosing field.
//
// When a scalar field turns into an object, the walk sees both the type change
// on the field and its newly appearing leaves. Reporting the leaves as
// adaptible additions would misrepresent one structural change as several
// harmless ones.
func suppressNestedAdditions(changes []Change) []Change {
	unsafePrefixes := make([]string, 0, 2)
	for _, change := range changes {
		if !change.Safe && change.Kind == ChangeTypeChanged {
			unsafePrefixes = append(unsafePrefixes, change.Field+".")
		}
	}
	if len(unsafePrefixes) == 0 {
		return changes
	}

	kept := make([]Change, 0, len(changes))
	for _, change := range changes {
		nested := false
		if change.Safe {
			for _, prefix := range unsafePrefixes {
				if strings.HasPrefix(change.Field, prefix) {
					nested = true
					break
				}
			}
		}
		if nested {
			continue
		}
		kept = append(kept, change)
	}

	return kept
}

// observedViaAlias reports whether any declared alias of a field was observed.
func observedViaAlias(field contract.Field, observation Observation) bool {
	for _, alias := range field.Aliases {
		if _, ok := observation.Lookup(alias); ok {
			return true
		}
	}
	return false
}

// typesCompatible applies the safety asymmetry: a declared string accepts any
// scalar (strings hold text, and CSV cells are all text), while a declared
// numeric or container type is strict.
func typesCompatible(declared, observed contract.Type) bool {
	if observed == contract.TypeUnknown || declared == contract.TypeUnknown || !declared.Known() {
		return true
	}
	if declared == observed {
		return true
	}
	if declared == contract.TypeString {
		return !observed.IsContainer()
	}
	if declared == contract.TypeFloat && observed == contract.TypeInteger {
		return true
	}
	return false
}

func filterChanges(changes []Change, safe bool) []Change {
	out := make([]Change, 0, len(changes))
	for _, change := range changes {
		if change.Safe == safe {
			out = append(out, change)
		}
	}
	return out
}

func describe(changes []Change) string {
	parts := make([]string, 0, len(changes))
	for _, change := range changes {
		parts = append(parts, string(change.Kind)+"("+change.Field+")")
	}
	return strings.Join(parts, ", ")
}
