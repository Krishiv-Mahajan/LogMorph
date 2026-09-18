package drift

import (
	"strconv"
	"strings"

	"github.com/Krishiv-Mahajan/LogMorph/internal/contract"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// Binding records one value the binder contributed.
type Binding struct {
	// Field is the observed payload field that supplied the value.
	Field string
	// Canonical is the contract field it resolved to.
	Canonical string
	// Target is the Universal Event attribute that was filled.
	Target string
}

// Bind fills Universal Event attributes from declared aliases.
//
// The parsers implement the canonical field names for their format. A contract
// may additionally declare aliases — equivalent spellings a source is known to
// use. This function applies those aliases so the declaration has an effect on
// extraction instead of being documentation.
//
// It is deliberately conservative:
//   - only declared aliases are considered; an unknown field is never bound,
//     because binding requires knowing what the field means;
//   - only empty attributes are filled, so a parser's own value always wins;
//   - a value that cannot be converted to the declared type is skipped.
func Bind(parsed *models.ParsedEvent, observation Observation, fieldContract contract.Contract) []Binding {
	if parsed == nil {
		return nil
	}

	bindings := make([]Binding, 0, 2)

	for _, observed := range observation.Fields {
		field, viaAlias, ok := fieldContract.Resolve(observed.Name)
		if !ok || !viaAlias || field.Target == "" {
			continue
		}
		if !typesCompatible(field.Type, observed.Type) {
			continue
		}

		value := strings.TrimSpace(observed.Value)
		if value == "" {
			continue
		}

		if applyBinding(parsed, field.Target, field.Type, value) {
			bindings = append(bindings, Binding{
				Field:     observed.Name,
				Canonical: contract.NormalizeName(field.Name),
				Target:    field.Target,
			})
		}
	}

	return bindings
}

// applyBinding writes a value into a Universal Event attribute. It reports
// whether the attribute was empty and therefore filled.
func applyBinding(parsed *models.ParsedEvent, target string, fieldType contract.Type, value string) bool {
	switch target {
	case "timestamp":
		if parsed.Timestamp != "" {
			return false
		}
		parsed.Timestamp = value
		return true

	case "event.action":
		if parsed.Event.Action != "" {
			return false
		}
		parsed.Event.Action = value
		return true

	case "event.category":
		if parsed.Event.Category != "" {
			return false
		}
		parsed.Event.Category = value
		return true

	case "event.severity":
		if parsed.Event.Severity != "" {
			return false
		}
		parsed.Event.Severity = value
		return true

	case "source.identifier":
		if parsed.Source.Identifier != "" {
			return false
		}
		parsed.Source.Identifier = value
		return true

	case "source.vendor":
		if parsed.Source.Vendor != "" {
			return false
		}
		parsed.Source.Vendor = value
		return true

	case "source.product":
		if parsed.Source.Product != "" {
			return false
		}
		parsed.Source.Product = value
		return true

	case "source.type":
		if parsed.Source.Type != "" {
			return false
		}
		parsed.Source.Type = value
		return true

	case "network.protocol":
		network := ensureNetwork(parsed)
		if network.Protocol != "" {
			return false
		}
		network.Protocol = value
		return true

	case "network.src_ip":
		network := ensureNetwork(parsed)
		if network.SrcIP != "" {
			return false
		}
		network.SrcIP = value
		return true

	case "network.src_port":
		network := ensureNetwork(parsed)
		if network.SrcPort != nil {
			return false
		}
		port, ok := parsePortValue(value, fieldType)
		if !ok {
			return false
		}
		network.SrcPort = &port
		return true

	case "network.dst_ip":
		network := ensureNetwork(parsed)
		if network.DstIP != "" {
			return false
		}
		network.DstIP = value
		return true

	case "network.dst_port":
		network := ensureNetwork(parsed)
		if network.DstPort != nil {
			return false
		}
		port, ok := parsePortValue(value, fieldType)
		if !ok {
			return false
		}
		network.DstPort = &port
		return true

	case "user.username":
		if parsed.User == nil {
			parsed.User = &models.UserInfo{}
		}
		if parsed.User.Username != nil && *parsed.User.Username != "" {
			return false
		}
		username := value
		parsed.User.Username = &username
		return true

	default:
		// A contract that declares a target the binder does not know about is
		// skipped rather than guessed at.
		return false
	}
}

func ensureNetwork(parsed *models.ParsedEvent) *models.NetworkInfo {
	if parsed.Network == nil {
		parsed.Network = &models.NetworkInfo{}
	}
	return parsed.Network
}

// parsePortValue converts a bound value to a port. It refuses anything that is
// not a usable port rather than writing a meaningless value.
func parsePortValue(value string, fieldType contract.Type) (int, bool) {
	if fieldType != contract.TypeInteger && fieldType != contract.TypeFloat {
		return 0, false
	}

	port, err := strconv.Atoi(value)
	if err != nil || port < 0 || port > 65535 {
		return 0, false
	}

	return port, true
}
