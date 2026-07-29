package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestDispatcherDrains(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	dispatcher, err := NewDispatcher([]Sink{&writerSink{writer: &output}}, 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Record(Event{Event: "completed", TraceID: "trace", Decision: "allow"})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := dispatcher.Close(ctx); err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if event.Event != "completed" || event.Timestamp.IsZero() {
		t.Fatalf("event = %#v", event)
	}
}
