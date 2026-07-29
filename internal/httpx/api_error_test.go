package httpx

import (
	"errors"
	"testing"
)

func TestAPIErrorKeepsCauseOutOfPublicMessage(t *testing.T) {
	t.Parallel()

	cause := errors.New("dial tcp 10.0.0.1: secret backend detail")
	err := &APIError{
		Status:  502,
		Code:    "E_UPSTREAM",
		Message: "upstream request failed",
		Cause:   cause,
	}
	if got, want := err.Error(), "E_UPSTREAM: upstream request failed"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, cause) {
		t.Fatal("APIError does not unwrap its internal cause")
	}
}
