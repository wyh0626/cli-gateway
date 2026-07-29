// Package httpx contains shared HTTP-facing contracts.
package httpx

import (
	"fmt"
	"time"
)

// APIError is safe to serialize to a client.
type APIError struct {
	Status         int           `json:"-"`
	Code           string        `json:"error"`
	Message        string        `json:"message"`
	Hint           string        `json:"hint,omitempty"`
	TraceID        string        `json:"trace_id,omitempty"`
	UpstreamStatus int           `json:"status,omitempty"`
	RetryAfter     time.Duration `json:"-"`
	Cause          error         `json:"-"`
}

// Error implements error without exposing the internal cause.
func (e *APIError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap makes the internal cause available to trusted logs and tests.
func (e *APIError) Unwrap() error {
	return e.Cause
}
