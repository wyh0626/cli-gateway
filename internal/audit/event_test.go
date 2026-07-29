package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEventSerializesArgumentKeysOnly(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(Event{
		Event:    "completed",
		TraceID:  "0123456789abcdef0123456789abcdef",
		Invoker:  "ai",
		Decision: "allow",
		ArgKeys:  []string{"cpu", "type"},
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	text := string(encoded)
	if !strings.Contains(text, `"arg_keys":["cpu","type"]`) {
		t.Fatalf("encoded event = %s", text)
	}
	if strings.Contains(text, "arg_values") {
		t.Fatalf("encoded event unexpectedly contains argument values: %s", text)
	}
}
