// Package contract defines the declarative field contract — the "mapping" — that
// describes which fields a log source is expected to send, how they are typed,
// and where they bind in the Universal Event.
//
// A contract is the baseline the drift engine compares incoming payloads
// against. It is declared by the parser that knows the format (see
// parsing.Descriptor) and versioned by the source registry; an event's mapping
// version therefore identifies exactly which contract it was processed under.
package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Type is the structural type of a source field. It is intentionally small: the
// drift engine only needs enough resolution to tell a compatible value from an
// incompatible one.
type Type string

const (
	TypeString  Type = "string"
	TypeInteger Type = "integer"
	TypeFloat   Type = "float"
	TypeBoolean Type = "boolean"
	TypeObject  Type = "object"
	TypeArray   Type = "array"
	TypeUnknown Type = "unknown"
)

// IsContainer reports whether the type holds nested structure. Container fields
// signal structural change rather than additive drift.
func (t Type) IsContainer() bool {
	return t == TypeObject || t == TypeArray
}

// Known reports whether the type is one this package understands.
func (t Type) Known() bool {
	switch t {
	case TypeString, TypeInteger, TypeFloat, TypeBoolean, TypeObject, TypeArray:
		return true
	default:
		return false
	}
}

// Field declares one source field.
type Field struct {
	// Name is the canonical name as it appears in the source payload. Dotted
	// names denote nested paths for structured formats (e.g. "network.src_ip").
	Name string `json:"name"`

	// Aliases are alternative spellings the parser accepts for this field.
	// A new payload field that matches an alias binds to the same Target, which
	// is what makes an alias substitution a safe change.
	Aliases []string `json:"aliases,omitempty"`

	// Type is the declared type. An observed value of an incompatible type is
	// an unsafe change.
	Type Type `json:"type"`

	// Target is the Universal Event path this field populates (e.g.
	// "network.src_ip"). Empty means the field is observed and versioned but
	// deliberately not bound to any Universal Event attribute.
	Target string `json:"target,omitempty"`

	// Optional reports whether the field may be absent. A missing required
	// field is an unsafe change; a missing optional field is not drift at all.
	Optional bool `json:"optional"`

	// Description is free-form operator documentation.
	Description string `json:"description,omitempty"`
}

// Names returns the canonical name plus every alias, normalized.
func (f Field) Names() []string {
	names := make([]string, 0, len(f.Aliases)+1)
	names = append(names, NormalizeName(f.Name))
	for _, alias := range f.Aliases {
		names = append(names, NormalizeName(alias))
	}
	return names
}

// MatchesName reports whether name is the canonical name or one of the aliases.
func (f Field) MatchesName(name string) bool {
	normalized := NormalizeName(name)
	for _, candidate := range f.Names() {
		if candidate == normalized {
			return true
		}
	}
	return false
}

// IsCanonical reports whether name is the canonical name (not an alias).
func (f Field) IsCanonical(name string) bool {
	return NormalizeName(f.Name) == NormalizeName(name)
}

// Contract is an ordered, normalized set of field declarations.
type Contract struct {
	Fields []Field `json:"fields"`
}

// NormalizeName canonicalizes a field name for comparison: lower-case, trimmed,
// with dashes folded to underscores. Dots are preserved because they delimit
// nested paths.
func NormalizeName(name string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "-", "_")
}

// Normalized returns a copy with every field name and alias normalized, fields
// sorted by canonical name, and duplicates removed. Registry storage and
// contract hashing both depend on this being deterministic.
func (c Contract) Normalized() Contract {
	fields := make([]Field, 0, len(c.Fields))
	for _, f := range c.Fields {
		normalized := f
		normalized.Name = NormalizeName(f.Name)
		if len(f.Aliases) > 0 {
			aliases := make([]string, 0, len(f.Aliases))
			seen := map[string]bool{}
			for _, alias := range f.Aliases {
				a := NormalizeName(alias)
				if a == "" || a == normalized.Name || seen[a] {
					continue
				}
				seen[a] = true
				aliases = append(aliases, a)
			}
			sort.Strings(aliases)
			normalized.Aliases = aliases
		}
		fields = append(fields, normalized)
	}

	sort.SliceStable(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })

	deduped := fields[:0]
	seen := map[string]bool{}
	for _, f := range fields {
		if seen[f.Name] {
			continue
		}
		seen[f.Name] = true
		deduped = append(deduped, f)
	}

	return Contract{Fields: deduped}
}

// Lookup finds the declaration that a payload field name corresponds to,
// matching the canonical name first and then the aliases.
func (c Contract) Lookup(name string) (Field, bool) {
	normalized := NormalizeName(name)
	if normalized == "" {
		return Field{}, false
	}

	for _, f := range c.Fields {
		if NormalizeName(f.Name) == normalized {
			return f, true
		}
	}
	for _, f := range c.Fields {
		for _, alias := range f.Aliases {
			if alias == normalized {
				return f, true
			}
		}
	}

	return Field{}, false
}

// Resolve returns the declaration for a payload field name together with a flag
// reporting whether the match was made through an alias.
func (c Contract) Resolve(name string) (field Field, viaAlias bool, ok bool) {
	normalized := NormalizeName(name)
	if normalized == "" {
		return Field{}, false, false
	}

	for _, f := range c.Fields {
		if NormalizeName(f.Name) == normalized {
			return f, false, true
		}
	}
	for _, f := range c.Fields {
		for _, alias := range f.Aliases {
			if alias == normalized {
				return f, true, true
			}
		}
	}

	return Field{}, false, false
}

// HasNestedField reports whether any declared name lives under prefix.
//
// It distinguishes expected structure from a structural change: a payload
// carrying "network" is only expected because the contract declares
// "network.src_ip" and friends. A container with nothing declared beneath it is
// genuinely new structure.
//
// Aliases count as declared names. A contract that declares "firewall.action"
// as an alias of "action" has already described the "firewall" container, so a
// payload carrying it is not structural drift.
func (c Contract) HasNestedField(prefix string) bool {
	normalized := NormalizeName(prefix)
	if normalized == "" {
		return false
	}

	dotted := normalized + "."
	for _, f := range c.Fields {
		for _, name := range f.Names() {
			if strings.HasPrefix(name, dotted) {
				return true
			}
		}
	}

	return false
}

// Required returns the declared fields that must be present.
func (c Contract) Required() []Field {
	required := make([]Field, 0, len(c.Fields))
	for _, f := range c.Fields {
		if !f.Optional {
			required = append(required, f)
		}
	}
	return required
}

// WithField returns a copy of the contract with the field added or replaced.
func (c Contract) WithField(f Field) Contract {
	next := Contract{Fields: make([]Field, 0, len(c.Fields)+1)}
	replaced := false

	for _, existing := range c.Fields {
		if NormalizeName(existing.Name) == NormalizeName(f.Name) {
			next.Fields = append(next.Fields, f)
			replaced = true
			continue
		}
		next.Fields = append(next.Fields, existing)
	}
	if !replaced {
		next.Fields = append(next.Fields, f)
	}

	return next.Normalized()
}

// Hash returns a stable fingerprint of the contract's content. Two contracts
// hash equally iff they declare the same fields, types, targets and aliases.
func (c Contract) Hash() string {
	normalized := c.Normalized()

	builder := &strings.Builder{}
	for _, f := range normalized.Fields {
		// Aliases are already sorted by Normalized().
		fmt.Fprintf(builder, "%s|%s|%s|%t|%s\n",
			f.Name, f.Type, f.Target, f.Optional, strings.Join(f.Aliases, ","))
	}

	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

// FieldNames returns the normalized canonical names, for logging and evidence.
func (c Contract) FieldNames() []string {
	names := make([]string, 0, len(c.Fields))
	for _, f := range c.Fields {
		names = append(names, NormalizeName(f.Name))
	}
	return names
}
