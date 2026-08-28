package parsers

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

var (
	syslogHeaderRegex = regexp.MustCompile(`^(?:<\d+>)?([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$`)
	kvRegex           = regexp.MustCompile(`(?i)\b([A-Z_]+)=([^\s]+)`)
)

// SyslogParser parses security and firewall Syslog messages into a ParsedEvent.
type SyslogParser struct{}

func NewSyslogParser() *SyslogParser {
	return &SyslogParser{}
}

func (p *SyslogParser) Format() string {
	return "syslog"
}

func (p *SyslogParser) Parse(ctx context.Context, raw models.RawEvent) (*models.ParsedEvent, error) {
	trimmed := strings.TrimSpace(raw.Payload)
	if trimmed == "" {
		return nil, fmt.Errorf("empty syslog payload")
	}

	matches := syslogHeaderRegex.FindStringSubmatch(trimmed)
	var timestampStr, host, body string
	if len(matches) == 4 {
		timestampStr = matches[1]
		host = matches[2]
		body = matches[3]
	} else {
		body = trimmed
		host = raw.Source
		if host == "" {
			host = "unknown-host"
		}
	}

	normalizedTime := parseSyslogTimestamp(timestampStr)

	kvMap := make(map[string]string)
	for _, kv := range kvRegex.FindAllStringSubmatch(body, -1) {
		if len(kv) == 3 {
			kvMap[strings.ToUpper(kv[1])] = kv[2]
		}
	}

	action := "unknown"
	protocol := "unknown"
	tokens := strings.Fields(body)
	for _, tok := range tokens {
		tUpper := strings.ToUpper(tok)
		if tUpper == "DENY" || tUpper == "DROP" || tUpper == "BLOCK" {
			action = "deny"
		} else if tUpper == "ALLOW" || tUpper == "ACCEPT" || tUpper == "PERMIT" {
			action = "allow"
		} else if tUpper == "TCP" || tUpper == "UDP" || tUpper == "ICMP" {
			protocol = tUpper
		}
	}

	if act, ok := kvMap["ACTION"]; ok {
		action = strings.ToLower(act)
	}
	if proto, ok := kvMap["PROTO"]; ok {
		protocol = strings.ToUpper(proto)
	}

	netInfo := &models.NetworkInfo{
		Protocol: protocol,
	}

	if src, ok := kvMap["SRC"]; ok {
		ip, port := splitIPAndPort(src)
		netInfo.SrcIP = ip
		if port != nil {
			netInfo.SrcPort = port
		}
	}
	if spt, ok := kvMap["SPT"]; ok {
		if p, err := strconv.Atoi(spt); err == nil {
			netInfo.SrcPort = &p
		}
	}

	if dst, ok := kvMap["DST"]; ok {
		ip, port := splitIPAndPort(dst)
		netInfo.DstIP = ip
		if port != nil {
			netInfo.DstPort = port
		}
	}
	if dpt, ok := kvMap["DPT"]; ok {
		if p, err := strconv.Atoi(dpt); err == nil {
			netInfo.DstPort = &p
		}
	}

	severity := "info"
	if action == "deny" {
		severity = "high"
	}

	identifier := host
	if raw.Source != "" {
		identifier = raw.Source
	}

	return &models.ParsedEvent{
		Timestamp: normalizedTime,
		Source: models.SourceInfo{
			Type:       "firewall",
			Vendor:     "generic",
			Product:    "syslog-firewall",
			Identifier: identifier,
		},
		Event: models.EventInfo{
			Category: "network",
			Action:   action,
			Severity: severity,
		},
		Network: netInfo,
		User:    &models.UserInfo{Username: nil},
	}, nil
}

func splitIPAndPort(val string) (string, *int) {
	if strings.Contains(val, ":") {
		host, portStr, err := net.SplitHostPort(val)
		if err == nil {
			if port, err := strconv.Atoi(portStr); err == nil {
				return host, &port
			}
		}
	}
	return val, nil
}

func parseSyslogTimestamp(raw string) string {
	if raw == "" {
		return time.Now().UTC().Format(time.RFC3339)
	}

	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC().Format(time.RFC3339)
	}

	refYear := time.Now().UTC().Year()
	layout := "2006 Jan 02 15:04:05"
	fullStr := fmt.Sprintf("%d %s", refYear, raw)
	if t, err := time.Parse(layout, fullStr); err == nil {
		return t.UTC().Format(time.RFC3339)
	}

	return time.Now().UTC().Format(time.RFC3339)
}
