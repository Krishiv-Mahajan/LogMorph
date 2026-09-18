package parsers

import (
	"github.com/Krishiv-Mahajan/LogMorph/internal/contract"
)

// This file declares the field contract for each parser. It is deliberately
// separate from the parser implementations: the parsers already encode these
// rules in Go, and this file states them as data so the registry can version
// them and the drift engine can compare payloads against them.
//
// The rules for declaring a contract field:
//
//   - A canonical field is declared iff the parser actually reads it. Nothing
//     is declared speculatively.
//   - An alias declares a spelling that means the same thing as a canonical
//     field. Where the parser already accepts the alias it applies it directly;
//     where it does not (the CSV parser reads exact column names), the drift
//     binder applies it after parsing. Aliases are therefore part of the
//     contract, not merely documentation of the parser.
//   - Where a parser applies precedence rather than equivalence, the names are
//     declared as aliases anyway and the drift engine escalates when they
//     disagree, because a payload carrying two different values for one target
//     has no deterministic answer.
//   - Required means "this source contract is violated without it". Fields the
//     parser can default are optional, because their absence is not drift.

// Descriptor implements contract.ParserDescriptor for the JSON parser.
//
// Field names are dotted paths into the JSON document, matching the nested
// structures the parser reads.
func (p *JSONParser) Descriptor() contract.ParserDescriptor {
	return contract.ParserDescriptor{
		ParserID:      "generic_json",
		ParserVersion: "1.0",
		MappingID:     "generic_json_mapping",
		Vendor:        "generic",
		Product:       "json-firewall",
		SourceType:    "firewall",
		Contract: contract.Contract{Fields: []contract.Field{
			{
				Name:        "timestamp",
				Type:        contract.TypeString,
				Target:      "timestamp",
				Description: "Event time; the parser substitutes the ingestion time when absent.",
			},
			{
				Name:     "action",
				Aliases:  []string{"firewall.action"},
				Type:     contract.TypeString,
				Target:   "event.action",
				Optional: true,
			},
			{
				Name:     "category",
				Aliases:  []string{"firewall.category"},
				Type:     contract.TypeString,
				Target:   "event.category",
				Optional: true,
			},
			{
				Name:     "severity",
				Aliases:  []string{"firewall.severity"},
				Type:     contract.TypeString,
				Target:   "event.severity",
				Optional: true,
			},
			{
				// The parser reads all three spellings for the same target.
				Name:     "protocol",
				Aliases:  []string{"network.protocol", "firewall.protocol"},
				Type:     contract.TypeString,
				Target:   "network.protocol",
				Optional: true,
			},
			{
				// The parser prefers the nested forms when both are present, so
				// supplying both with different values is a conflicting mapping.
				Name:     "src_ip",
				Aliases:  []string{"source_ip", "network.src_ip", "network.source.ip"},
				Type:     contract.TypeString,
				Target:   "network.src_ip",
				Optional: true,
			},
			{
				Name:     "src_port",
				Aliases:  []string{"source_port", "network.src_port", "network.source.port"},
				Type:     contract.TypeInteger,
				Target:   "network.src_port",
				Optional: true,
			},
			{
				Name:     "dst_ip",
				Aliases:  []string{"destination_ip", "network.dst_ip", "network.destination.ip"},
				Type:     contract.TypeString,
				Target:   "network.dst_ip",
				Optional: true,
			},
			{
				Name:     "dst_port",
				Aliases:  []string{"destination_port", "network.dst_port", "network.destination.port"},
				Type:     contract.TypeInteger,
				Target:   "network.dst_port",
				Optional: true,
			},
			{
				Name:     "source.identifier",
				Type:     contract.TypeString,
				Target:   "source.identifier",
				Optional: true,
			},
			{
				Name:     "source.vendor",
				Type:     contract.TypeString,
				Target:   "source.vendor",
				Optional: true,
			},
			{
				Name:     "source.product",
				Type:     contract.TypeString,
				Target:   "source.product",
				Optional: true,
			},
			{
				Name:     "source.type",
				Type:     contract.TypeString,
				Target:   "source.type",
				Optional: true,
			},
			{
				Name:     "user.username",
				Type:     contract.TypeString,
				Target:   "user.username",
				Optional: true,
			},
		}},
	}
}

// Descriptor implements contract.ParserDescriptor for the CSV parser.
//
// Field names are header column names, matched case-insensitively after
// trimming and folding dashes to underscores.
func (p *CSVParser) Descriptor() contract.ParserDescriptor {
	return contract.ParserDescriptor{
		ParserID:      "generic_csv",
		ParserVersion: "1.0",
		MappingID:     "generic_csv_mapping",
		Vendor:        "generic",
		Product:       "csv-firewall",
		SourceType:    "firewall",
		Contract: contract.Contract{Fields: []contract.Field{
			{
				Name:        "timestamp",
				Type:        contract.TypeString,
				Target:      "timestamp",
				Description: "Event time column; substituted with the ingestion time when absent.",
			},
			{
				Name:     "action",
				Type:     contract.TypeString,
				Target:   "event.action",
				Optional: true,
			},
			{
				Name:     "category",
				Type:     contract.TypeString,
				Target:   "event.category",
				Optional: true,
			},
			{
				Name:     "severity",
				Type:     contract.TypeString,
				Target:   "event.severity",
				Optional: true,
			},
			{
				Name:     "protocol",
				Type:     contract.TypeString,
				Target:   "network.protocol",
				Optional: true,
			},
			{
				Name:     "src_ip",
				Aliases:  []string{"source_ip"},
				Type:     contract.TypeString,
				Target:   "network.src_ip",
				Optional: true,
			},
			{
				// Declared integer because the parser converts it with Atoi; a
				// non-numeric value is a change in the column's meaning.
				Name:     "src_port",
				Aliases:  []string{"source_port"},
				Type:     contract.TypeInteger,
				Target:   "network.src_port",
				Optional: true,
			},
			{
				Name:     "dst_ip",
				Aliases:  []string{"destination_ip"},
				Type:     contract.TypeString,
				Target:   "network.dst_ip",
				Optional: true,
			},
			{
				Name:     "dst_port",
				Aliases:  []string{"destination_port"},
				Type:     contract.TypeInteger,
				Target:   "network.dst_port",
				Optional: true,
			},
			{
				Name:     "source",
				Type:     contract.TypeString,
				Target:   "source.identifier",
				Optional: true,
			},
			{
				Name:     "username",
				Type:     contract.TypeString,
				Target:   "user.username",
				Optional: true,
			},
		}},
	}
}

// Descriptor implements contract.ParserDescriptor for the Syslog parser.
//
// A syslog line is positional (timestamp, host, free text); the only named
// fields it can carry are key=value pairs, so those are what the contract
// describes. Nothing is required: a well-formed syslog message may legitimately
// carry no key=value pair at all, and declaring one required would flag every
// such message as drift.
func (p *SyslogParser) Descriptor() contract.ParserDescriptor {
	return contract.ParserDescriptor{
		ParserID:      "generic_syslog",
		ParserVersion: "1.0",
		MappingID:     "generic_syslog_mapping",
		Vendor:        "generic",
		Product:       "syslog-firewall",
		SourceType:    "firewall",
		Contract: contract.Contract{Fields: []contract.Field{
			{
				Name:        "SRC",
				Type:        contract.TypeString,
				Target:      "network.src_ip",
				Optional:    true,
				Description: "May carry an embedded port (host:port).",
			},
			{
				Name:     "SPT",
				Type:     contract.TypeInteger,
				Target:   "network.src_port",
				Optional: true,
			},
			{
				Name:     "DST",
				Type:     contract.TypeString,
				Target:   "network.dst_ip",
				Optional: true,
			},
			{
				Name:     "DPT",
				Type:     contract.TypeInteger,
				Target:   "network.dst_port",
				Optional: true,
			},
			{
				Name:     "ACTION",
				Type:     contract.TypeString,
				Target:   "event.action",
				Optional: true,
			},
			{
				Name:     "PROTO",
				Type:     contract.TypeString,
				Target:   "network.protocol",
				Optional: true,
			},
		}},
	}
}
