package parsers

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// CSVParser parses CSV security/network records.
type CSVParser struct{}

func NewCSVParser() *CSVParser {
	return &CSVParser{}
}

func (p *CSVParser) Name() string {
	return "csv"
}

func (p *CSVParser) Parse(raw models.RawEvent) (*models.UniversalEvent, error) {
	trimmed := strings.TrimSpace(raw.Payload)
	if trimmed == "" {
		return nil, fmt.Errorf("empty CSV payload")
	}

	reader := csv.NewReader(bytes.NewBufferString(trimmed))
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("invalid CSV format: %w", err)
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("CSV must contain at least a header row and one data row")
	}

	header := records[0]
	row := records[1] // Use first data record for event normalization

	if len(header) != len(row) {
		return nil, fmt.Errorf("header column count (%d) does not match data row column count (%d)", len(header), len(row))
	}

	colMap := make(map[string]string)
	for i, col := range header {
		cleanCol := strings.ToLower(strings.TrimSpace(col))
		colMap[cleanCol] = strings.TrimSpace(row[i])
	}

	ts := colMap["timestamp"]
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}

	action := strings.ToLower(colMap["action"])
	if action == "" {
		action = "unknown"
	}

	protocol := strings.ToUpper(colMap["protocol"])
	if protocol == "" {
		protocol = "unknown"
	}

	category := colMap["category"]
	if category == "" {
		category = "network"
	}

	severity := colMap["severity"]
	if severity == "" {
		if action == "deny" {
			severity = "high"
		} else {
			severity = "info"
		}
	}

	identifier := raw.Source
	if id, ok := colMap["source"]; ok && id != "" {
		identifier = id
	}
	if identifier == "" {
		identifier = "csv-source"
	}

	netInfo := &models.NetworkInfo{
		Protocol: protocol,
		SrcIP:    colMap["src_ip"],
		DstIP:    colMap["dst_ip"],
	}

	if srcPortStr, ok := colMap["src_port"]; ok && srcPortStr != "" {
		if p, err := strconv.Atoi(srcPortStr); err == nil {
			netInfo.SrcPort = &p
		}
	}

	if dstPortStr, ok := colMap["dst_port"]; ok && dstPortStr != "" {
		if p, err := strconv.Atoi(dstPortStr); err == nil {
			netInfo.DstPort = &p
		}
	}

	var user *models.UserInfo
	if username, ok := colMap["username"]; ok && username != "" {
		user = &models.UserInfo{Username: &username}
	} else {
		user = &models.UserInfo{Username: nil}
	}

	return &models.UniversalEvent{
		SchemaVersion: "1.0",
		Timestamp:     ts,
		Source: models.SourceInfo{
			Type:       "firewall",
			Vendor:     "generic",
			Product:    "csv-firewall",
			Identifier: identifier,
		},
		Event: models.EventInfo{
			Category: category,
			Action:   action,
			Severity: severity,
		},
		Network: netInfo,
		User:    user,
		Raw: models.RawInfo{
			Format:  "csv",
			Message: raw.Payload,
		},
		Metadata: models.MetadataInfo{
			ParserVersion: "1.0",
		},
	}, nil
}
