// Package drift implements deterministic schema-drift analysis: it compares the
// structure an event actually arrived with against the contract the source
// registry holds, and decides whether the difference is safe to adapt.
package drift

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Krishiv-Mahajan/LogMorph/internal/contract"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing/parsers"
)

// ErrUnsupportedFormat is returned when no observer exists for a format. It is
// not a processing error: it means the payload cannot be structurally compared.
var ErrUnsupportedFormat = errors.New("no schema observer for format")

// maxFlattenDepth bounds how deep nested structures are expanded, so a
// pathological payload cannot turn observation into an unbounded walk.
const maxFlattenDepth = 4

// maxObservedFields bounds the observed field set for the same reason.
const maxObservedFields = 256

// ObservedField is one field present in a payload.
type ObservedField struct {
	// Name is the normalized field name (dotted path for structured formats).
	Name string

	// Type is the type inferred from the value. Empty values contribute no type
	// evidence and are reported as TypeUnknown.
	Type contract.Type

	// Value is the raw scalar value, used only to detect conflicting mappings.
	// It is never written to the registry: contracts record structure, not data.
	Value string
}

// Observation is the structural summary of one payload.
type Observation struct {
	Format string
	Fields []ObservedField
}

// Names returns the normalized field names in order.
func (o Observation) Names() []string {
	names := make([]string, 0, len(o.Fields))
	for _, f := range o.Fields {
		names = append(names, f.Name)
	}
	return names
}

// Lookup returns the observed field with the given name.
func (o Observation) Lookup(name string) (ObservedField, bool) {
	normalized := contract.NormalizeName(name)
	for _, f := range o.Fields {
		if f.Name == normalized {
			return f, true
		}
	}
	return ObservedField{}, false
}

// Observe builds the observed field set for a payload.
//
// Observation is intentionally shallow: it records which fields exist and what
// type each holds. It never interprets meaning, which is precisely why the
// drift engine can only auto-adapt changes it can prove are additive.
func Observe(format, payload string) (Observation, error) {
	switch contract.NormalizeName(format) {
	case "json":
		return observeJSON(payload)
	case "csv":
		return observeCSV(payload)
	case "syslog":
		return observeSyslog(payload)
	default:
		return Observation{}, fmt.Errorf("%w: %q", ErrUnsupportedFormat, format)
	}
}

// observeJSON flattens a JSON object into dotted field paths.
func observeJSON(payload string) (Observation, error) {
	trimmed := strings.TrimSpace(payload)
	if trimmed == "" {
		return Observation{}, fmt.Errorf("empty JSON payload")
	}

	var decoded any
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		return Observation{}, fmt.Errorf("invalid JSON payload: %w", err)
	}

	fieldMap := map[string]ObservedField{}

	switch root := decoded.(type) {
	case map[string]any:
		flattenJSON("", root, 0, fieldMap)
	default:
		// A top-level array or scalar cannot be compared against an object
		// contract. It is reported as a single structural field so the drift
		// engine classifies it as a structural change rather than silence.
		fieldMap["$"] = ObservedField{Name: "$", Type: jsonTypeOf(root)}
	}

	return Observation{Format: "json", Fields: sortedFields(fieldMap)}, nil
}

func flattenJSON(prefix string, object map[string]any, depth int, out map[string]ObservedField) {
	if depth > maxFlattenDepth {
		return
	}

	for name, value := range object {
		if len(out) >= maxObservedFields {
			return
		}

		path := contract.NormalizeName(name)
		if prefix != "" {
			path = prefix + "." + path
		}

		nested, isObject := value.(map[string]any)
		if isObject && depth < maxFlattenDepth {
			// Record the container itself and descend: a nested object appearing
			// where a scalar used to be must be visible as a structural change.
			out[path] = ObservedField{Name: path, Type: contract.TypeObject, Value: ""}
			flattenJSON(path, nested, depth+1, out)
			continue
		}

		out[path] = ObservedField{
			Name:  path,
			Type:  jsonTypeOf(value),
			Value: scalarString(value),
		}
	}
}

// jsonTypeOf maps a decoded JSON value to a contract type.
//
// Strings are inspected for content: "443" is typed as an integer so that a
// port arriving as a JSON string is not misread as a type change. A field
// declared as a string accepts any scalar, so this cannot produce a false
// positive on string fields.
func jsonTypeOf(value any) contract.Type {
	switch v := value.(type) {
	case nil:
		return contract.TypeUnknown
	case bool:
		return contract.TypeBoolean
	case float64:
		if v == float64(int64(v)) {
			return contract.TypeInteger
		}
		return contract.TypeFloat
	case json.Number:
		if _, err := v.Int64(); err == nil {
			return contract.TypeInteger
		}
		return contract.TypeFloat
	case string:
		return inferScalarType(v)
	case map[string]any:
		return contract.TypeObject
	case []any:
		return contract.TypeArray
	default:
		return contract.TypeUnknown
	}
}

// observeCSV treats the header row as the field set and infers each column's
// type from its data cells.
func observeCSV(payload string) (Observation, error) {
	trimmed := strings.TrimSpace(payload)
	if trimmed == "" {
		return Observation{}, fmt.Errorf("empty CSV payload")
	}

	reader := csv.NewReader(strings.NewReader(trimmed))
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		return Observation{}, fmt.Errorf("invalid CSV payload: %w", err)
	}
	if len(records) == 0 {
		return Observation{}, fmt.Errorf("CSV payload has no header row")
	}

	header := records[0]
	fieldMap := make(map[string]ObservedField, len(header))

	for index, column := range header {
		name := contract.NormalizeName(column)
		if name == "" || len(fieldMap) >= maxObservedFields {
			continue
		}

		inferred := contract.TypeUnknown
		value := ""

		for rowIndex, record := range records[1:] {
			if index >= len(record) {
				continue
			}

			// Empty cells carry no evidence: a blank value today must not look
			// like a type change.
			inferred = mergeTypes(inferred, inferScalarType(record[index]))

			// The value comes from the first data row, because that is the row
			// the CSV parser reads as the event.
			if rowIndex == 0 {
				value = strings.TrimSpace(record[index])
			}
		}

		fieldMap[name] = ObservedField{Name: name, Type: inferred, Value: value}
	}

	return Observation{Format: "csv", Fields: sortedFields(fieldMap)}, nil
}

// observeSyslog treats key=value pairs as the field set. Syslog's positional
// parts (timestamp, host, free text) carry no field names, so they cannot drift.
func observeSyslog(payload string) (Observation, error) {
	trimmed := strings.TrimSpace(payload)
	if trimmed == "" {
		return Observation{}, fmt.Errorf("empty syslog payload")
	}

	fieldMap := map[string]ObservedField{}
	for _, pair := range parsers.SyslogKeyValues(trimmed) {
		if len(fieldMap) >= maxObservedFields {
			continue
		}

		name := contract.NormalizeName(pair.Key)
		value := pair.Value

		// A key that appears twice with different values is not something to
		// silently pick a winner for.
		if existing, ok := fieldMap[name]; ok && existing.Value != "" && existing.Value != value {
			existing.Type = contract.TypeUnknown
			existing.Value = ""
			fieldMap[name] = existing
			continue
		}

		fieldMap[name] = ObservedField{
			Name:  name,
			Type:  inferScalarType(value),
			Value: value,
		}
	}

	return Observation{Format: "syslog", Fields: sortedFields(fieldMap)}, nil
}

// inferScalarType classifies a textual value by content, widest-last: a value
// that is not a boolean, integer or float is a string.
func inferScalarType(value string) contract.Type {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return contract.TypeUnknown
	}

	switch strings.ToLower(trimmed) {
	case "true", "false":
		return contract.TypeBoolean
	}

	if _, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return contract.TypeInteger
	}
	if _, err := strconv.ParseFloat(trimmed, 64); err == nil {
		return contract.TypeFloat
	}

	return contract.TypeString
}

// mergeTypes combines the evidence from several values of the same field:
// identical types stay, integer+float widens to float, and any other mix has no
// consistent type and is reported as a string.
func mergeTypes(current, next contract.Type) contract.Type {
	if next == contract.TypeUnknown {
		return current
	}
	if current == contract.TypeUnknown {
		return next
	}
	if current == next {
		return current
	}
	if (current == contract.TypeInteger && next == contract.TypeFloat) ||
		(current == contract.TypeFloat && next == contract.TypeInteger) {
		return contract.TypeFloat
	}
	return contract.TypeString
}

func sortedFields(fieldMap map[string]ObservedField) []ObservedField {
	fields := make([]ObservedField, 0, len(fieldMap))
	for _, field := range fieldMap {
		fields = append(fields, field)
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
	return fields
}

// scalarString renders a value for conflict comparison. Structurally nested
// values compare as empty: only leaves carry comparable values.
func scalarString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		return v.String()
	default:
		return ""
	}
}
