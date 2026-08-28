package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// JSONParser parses structured JSON logs into UniversalEvent.
type JSONParser struct{}

func NewJSONParser() *JSONParser {
	return &JSONParser{}
}

func (p *JSONParser) Name() string {
	return "json"
}

// jsonLogSchema defines the expected nested JSON structure for network/firewall logs.
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
		Protocol    string `json:"protocol"`
		SrcIP       string `json:"src_ip"`
		SrcPort     *int   `json:"src_port"`
		DstIP       string `json:"dst_ip"`
		DstPort     *int   `json:"dst_port"`
		Source      *struct {
			IP   string `json:"ip"`
			Port *int   `json:"port"`
		} `json:"source"`
		Destination *struct {
			IP   string `json:"ip"`
			Port *int   `json:"port"`
		} `json:"destination"`
	} `json:"network"`
	User *struct {
		Username *string `json:"username"`
	} `json:"user"`
	Action   string `json:"action"`
	Protocol string `json:"protocol"`
}

func (p *JSONParser) Parse(raw models.RawEvent) (*models.UniversalEvent, error) {
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

	if action == "deny" && (data.Firewall == nil || data.Firewall.Severity == "") {
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

	netInfo := &models.NetworkInfo{
		Protocol: protocol,
	}

	if data.Network != nil {
		if data.Network.Protocol != "" {
			netInfo.Protocol = strings.ToUpper(data.Network.Protocol)
		}
		if data.Network.SrcIP != "" {
			netInfo.SrcIP = data.Network.SrcIP
		}
		if data.Network.SrcPort != nil {
			netInfo.SrcPort = data.Network.SrcPort
		}
		if data.Network.DstIP != "" {
			netInfo.DstIP = data.Network.DstIP
		}
		if data.Network.DstPort != nil {
			netInfo.DstPort = data.Network.DstPort
		}

		if data.Network.Source != nil {
			if data.Network.Source.IP != "" {
				netInfo.SrcIP = data.Network.Source.IP
			}
			if data.Network.Source.Port != nil {
				netInfo.SrcPort = data.Network.Source.Port
			}
		}
		if data.Network.Destination != nil {
			if data.Network.Destination.IP != "" {
				netInfo.DstIP = data.Network.Destination.IP
			}
			if data.Network.Destination.Port != nil {
				netInfo.DstPort = data.Network.Destination.Port
			}
		}
	}

	var user *models.UserInfo
	if data.User != nil {
		user = &models.UserInfo{
			Username: data.User.Username,
		}
	} else {
		user = &models.UserInfo{Username: nil}
	}

	return &models.UniversalEvent{
		SchemaVersion: "1.0",
		Timestamp:     ts,
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
		Raw: models.RawInfo{
			Format:  "json",
			Message: raw.Payload,
		},
		Metadata: models.MetadataInfo{
			ParserVersion: "1.0",
		},
	}, nil
}
