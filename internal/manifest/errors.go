package manifest

import (
	"fmt"
	"strings"
)

// Position points at a manifest value.
type Position struct {
	Line   int
	Column int
}

// ValidationError is one semantic manifest failure.
type ValidationError struct {
	Path    string
	Line    int
	Column  int
	Message string
}

func (e ValidationError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s at line %d, column %d: %s", e.Path, e.Line, e.Column, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Path, e.Message)
}

// ValidationErrors preserves all failures from one manifest load.
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	parts := make([]string, 0, len(e))
	for _, item := range e {
		parts = append(parts, item.Error())
	}
	return strings.Join(parts, "; ")
}
