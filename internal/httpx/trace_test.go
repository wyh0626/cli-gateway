package httpx

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

func TestRequestTraceIDPrefersValidTraceparent(t *testing.T) {
	t.Parallel()
	const traceID = "0123456789abcdef0123456789abcdef"
	header := http.Header{
		"Traceparent":            {"00-" + traceID + "-0123456789abcdef-01"},
		"X-Cli-Gateway-Trace-Id": {"ffffffffffffffffffffffffffffffff"},
	}
	if got := RequestTraceID(header); got != traceID {
		t.Fatalf("RequestTraceID() = %q", got)
	}
	parent := TraceParent(traceID)
	if !regexp.MustCompile(`^00-` + traceID + `-[0-9a-f]{16}-01$`).MatchString(parent) {
		t.Fatalf("TraceParent() = %q", parent)
	}
}

func TestRequestTraceIDRejectsInvalidAndAllZeroParents(t *testing.T) {
	t.Parallel()
	for _, parent := range []string{
		"ff-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
		"00-" + strings.Repeat("0", 32) + "-0123456789abcdef-01",
		"00-0123456789abcdef0123456789abcdef-" + strings.Repeat("0", 16) + "-01",
		"malformed",
	} {
		got := RequestTraceID(http.Header{"Traceparent": {parent}})
		if !tracePattern.MatchString(got) || got == strings.Repeat("0", 32) {
			t.Fatalf("RequestTraceID(%q) = %q", parent, got)
		}
	}
}

func TestTraceStateValidation(t *testing.T) {
	t.Parallel()
	if got := TraceState(http.Header{"Tracestate": {"vendor=value,other=opaque"}}); got != "vendor=value,other=opaque" {
		t.Fatalf("TraceState() = %q", got)
	}
	for _, value := range []string{"UPPER=value", "vendor=", "vendor=a=b", "vendor=value,vendor=again", "vendor=line\nbreak"} {
		if got := TraceState(http.Header{"Tracestate": {value}}); got != "" {
			t.Fatalf("TraceState(%q) = %q", value, got)
		}
	}
}
