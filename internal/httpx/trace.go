package httpx

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
)

var tracePattern = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
var parentPattern = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$`)
var traceStateKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_*/@.-]{0,255}$`)

// TraceID preserves a valid incoming ID or returns a random replacement.
func TraceID(candidate string) string {
	if tracePattern.MatchString(candidate) {
		return candidate
	}
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(value[:])
}

// RequestTraceID prefers a valid W3C traceparent and falls back to the legacy
// X-Cli-Gateway-Trace-Id compatibility header.
func RequestTraceID(header http.Header) string {
	if match := parentPattern.FindStringSubmatch(strings.ToLower(strings.TrimSpace(header.Get("traceparent")))); len(match) == 4 {
		if match[1] != strings.Repeat("0", 32) && match[2] != strings.Repeat("0", 16) {
			return match[1]
		}
	}
	return TraceID(header.Get("X-Cli-Gateway-Trace-Id"))
}

// TraceParent creates a new child span identifier for a known trace.
func TraceParent(traceID string) string {
	traceID = strings.ToLower(TraceID(traceID))
	var span [8]byte
	if _, err := rand.Read(span[:]); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return "00-" + traceID + "-" + hex.EncodeToString(span[:]) + "-01"
}

// TraceState returns a bounded syntactically safe W3C tracestate value or an
// empty string. It never forwards control characters or attacker-sized state.
func TraceState(header http.Header) string {
	value := strings.TrimSpace(header.Get("tracestate"))
	if value == "" || len(value) > 512 {
		return ""
	}
	members := strings.Split(value, ",")
	if len(members) > 32 {
		return ""
	}
	seen := make(map[string]struct{}, len(members))
	for _, member := range members {
		member = strings.TrimSpace(member)
		key, item, found := strings.Cut(member, "=")
		if !found || !traceStateKeyPattern.MatchString(key) || item == "" || len(item) > 256 {
			return ""
		}
		if _, duplicate := seen[key]; duplicate {
			return ""
		}
		seen[key] = struct{}{}
		for _, character := range item {
			if character < 0x20 || character > 0x7e || character == ',' || character == '=' {
				return ""
			}
		}
	}
	return value
}
