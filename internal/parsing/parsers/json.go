package parsers

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// JSONParser parses structured JSON logs into a ParsedEvent.
type JSONParser struct{}

func NewJSONParser() *JSONParser {
	return &JSONParser{}
}

func (p *JSONParser) Format() string {
	return "json"
}

type jsonLogSchema struct {
	Timestamp string `json:"timestamp"`
	Source    *struct {
		Identifier string `json:"identifier"`
		Vendor     string `json:"vendor"`
		Product    string `json:"product"`
		Type       string `json:"type"`
	} `json:"source"`
	Firewall *struct {
		Action   string `json:"action"`
		Protocol string `json:"protocol"`
		Category string `json:"category"`
		Severity string `json:"severity"`
	} `json:"firewall"`
	Network *struct {
		Protocol    string      `json:"protocol"`
		SrcIP       string      `json:"src_ip"`
		SrcPort     interface{} `json:"src_port"`
		DstIP       string      `json:"dst_ip"`
		DstPort     interface{} `json:"dst_port"`
		Source      *struct {
			IP   string      `json:"ip"`
			Port interface{} `json:"port"`
		} `json:"source"`
		Destination *struct {
			IP   string      `json:"ip"`
			Port interface{} `json:"port"`
		} `json:"destination"`
	} `json:"network"`
	User *struct {
		Username *string `json:"username"`
	} `json:"user"`

	// Flat top-level fields
	Action          string      `json:"action"`
	Protocol        string      `json:"protocol"`
	Category        string      `json:"category"`
	Severity        string      `json:"severity"`
	SrcIP           string      `json:"src_ip"`
	SrcPort         interface{} `json:"src_port"`
	DstIP           string      `json:"dst_ip"`
	DstPort         interface{} `json:"dst_port"`
	SourceIP        string      `json:"source_ip"`
	DestinationIP   string      `json:"destination_ip"`
	SourcePort      interface{} `json:"source_port"`
	DestinationPort interface{} `json:"destination_port"`
}

func (p *JSONParser) Parse(ctx context.Context, raw models.RawEvent) (*models.ParsedEvent, error) {
	trimmed := strings.TrimSpace(raw.Payload)
	if trimmed == "" {
		return nil, fmt.Errorf("empty JSON payload")
	}

	var data jsonLogSchema
	if err := json.Unmarshal([]byte(trimmed), &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	ts := data.Timestamp
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}

	action := "unknown"
	protocol := "unknown"
	category := "network"
	severity := "info"

	if data.Firewall != nil {
		if data.Firewall.Action != "" {
			action = strings.ToLower(data.Firewall.Action)
		}
		if data.Firewall.Protocol != "" {
			protocol = strings.ToUpper(data.Firewall.Protocol)
		}
		if data.Firewall.Category != "" {
			category = data.Firewall.Category
		}
		if data.Firewall.Severity != "" {
			severity = data.Firewall.Severity
		}
	}
	if data.Action != "" {
		action = strings.ToLower(data.Action)
	}
	if data.Protocol != "" {
		protocol = strings.ToUpper(data.Protocol)
	}
	if data.Category != "" {
		category = data.Category
	}
	if data.Severity != "" {
		severity = data.Severity
	}

	if (action == "deny" || action == "block" || action == "drop") && (data.Firewall == nil || data.Firewall.Severity == "") && data.Severity == "" {
		severity = "high"
	}

	srcType := "firewall"
	srcVendor := "generic"
	srcProduct := "json-firewall"
	srcIdentifier := raw.Source
	if srcIdentifier == "" {
		srcIdentifier = "json-source"
	}

	if data.Source != nil {
		if data.Source.Type != "" {
			srcType = data.Source.Type
		}
		if data.Source.Vendor != "" {
			srcVendor = data.Source.Vendor
		}
		if data.Source.Product != "" {
			srcProduct = data.Source.Product
		}
		if data.Source.Identifier != "" {
			srcIdentifier = data.Source.Identifier
		}
	}

	// Extract Network Fields from root and nested structures
	var srcIP, dstIP string
	var srcPort, dstPort *int

	// 1. Top-level fields
	if data.SrcIP != "" {
		srcIP = data.SrcIP
	} else if data.SourceIP != "" {
		srcIP = data.SourceIP
	}
	if p := parsePort(data.SrcPort); p != nil {
		srcPort = p
	} else if p := parsePort(data.SourcePort); p != nil {
		srcPort = p
	}

	if data.DstIP != "" {
		dstIP = data.DstIP
	} else if data.DestinationIP != "" {
		dstIP = data.DestinationIP
	}
	if p := parsePort(data.DstPort); p != nil {
		dstPort = p
	} else if p := parsePort(data.DestinationPort); p != nil {
		dstPort = p
	}

	// 2. Nested data.Network fields (if present, override or fill)
	if data.Network != nil {
		if data.Network.Protocol != "" {
			protocol = strings.ToUpper(data.Network.Protocol)
		}
		if data.Network.SrcIP != "" {
			srcIP = data.Network.SrcIP
		}
		if p := parsePort(data.Network.SrcPort); p != nil {
			srcPort = p
		}
		if data.Network.DstIP != "" {
			dstIP = data.Network.DstIP
		}
		if p := parsePort(data.Network.DstPort); p != nil {
			dstPort = p
		}

		if data.Network.Source != nil {
			if data.Network.Source.IP != "" {
				srcIP = data.Network.Source.IP
			}
			if p := parsePort(data.Network.Source.Port); p != nil {
				srcPort = p
			}
		}
		if data.Network.Destination != nil {
			if data.Network.Destination.IP != "" {
				dstIP = data.Network.Destination.IP
			}
			if p := parsePort(data.Network.Destination.Port); p != nil {
				dstPort = p
			}
		}
	}

	netInfo := &models.NetworkInfo{
		Protocol: protocol,
		SrcIP:    srcIP,
		SrcPort:  srcPort,
		DstIP:    dstIP,
		DstPort:  dstPort,
	}

	var user *models.UserInfo
	if data.User != nil {
		user = &models.UserInfo{
			Username: data.User.Username,
		}
	} else {
		user = &models.UserInfo{Username: nil}
	}

	return &models.ParsedEvent{
		Timestamp: ts,
		Source: models.SourceInfo{
			Type:       srcType,
			Vendor:     srcVendor,
			Product:    srcProduct,
			Identifier: srcIdentifier,
		},
		Event: models.EventInfo{
			Category: category,
			Action:   action,
			Severity: severity,
		},
		Network: netInfo,
		User:    user,
	}, nil
}

func parsePort(val interface{}) *int {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case float64:
		p := int(v)
		return &p
	case int:
		p := v
		return &p
	case json.Number:
		if n, err := v.Int64(); err == nil {
			p := int(n)
			return &p
		}
	case string:
		if p, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return &p
		}
	}
	return nil
}
