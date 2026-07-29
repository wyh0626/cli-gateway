// Package audit defines asynchronous audit contracts.
package audit

import "time"

// Event is deliberately metadata-only; argument values are never audited.
type Event struct {
	Timestamp  time.Time `json:"ts"`
	Event      string    `json:"event"`
	TraceID    string    `json:"trace_id"`
	Subject    string    `json:"sub,omitempty"`
	Invoker    string    `json:"invoker"`
	Command    string    `json:"cmd,omitempty"`
	Risk       string    `json:"risk,omitempty"`
	Decision   string    `json:"decision"`
	DenyReason string    `json:"deny_reason,omitempty"`
	Outcome    string    `json:"outcome,omitempty"`
	Status     int       `json:"status,omitempty"`
	LatencyMS  int64     `json:"latency_ms,omitempty"`
	Client     string    `json:"client,omitempty"`
	ArgKeys    []string  `json:"arg_keys,omitempty"`
	Generation uint64    `json:"runtime_generation,omitempty"`
	AuthMethod string    `json:"auth_method,omitempty"`
	Credential string    `json:"downstream_credential,omitempty"`
	Cache      string    `json:"credential_cache,omitempty"`
}
