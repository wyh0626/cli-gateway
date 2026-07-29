// Package catalog exposes the compiled command catalog without leaking raw
// manifest configuration into protocol adapters.
package catalog

import (
	"sort"

	"github.com/wyh0626/cli-gateway/internal/manifest"
	"github.com/wyh0626/cli-gateway/internal/model"
	"github.com/wyh0626/cli-gateway/internal/policy"
)

// Service is an immutable view over one manifest snapshot.
type Service struct {
	snapshot *manifest.Snapshot
}

// New constructs a command catalog for one runtime generation.
func New(snapshot *manifest.Snapshot) *Service {
	return &Service{snapshot: snapshot}
}

// Resolve implements model.CommandCatalog.
func (s *Service) Resolve(key string) (*model.CompiledCommand, bool) {
	if s == nil || s.snapshot == nil {
		return nil, false
	}
	command, ok := s.snapshot.Commands[key]
	return command, ok
}

// ResolveTool resolves the stable MCP tool name for this generation.
func (s *Service) ResolveTool(name string) (*model.CompiledCommand, bool) {
	if s == nil || s.snapshot == nil {
		return nil, false
	}
	command, ok := s.snapshot.ToolCommands[name]
	return command, ok
}

// List implements model.CommandCatalog using deterministic command-key order.
func (s *Service) List() []*model.CompiledCommand {
	if s == nil || s.snapshot == nil {
		return nil
	}
	result := make([]*model.CompiledCommand, 0, len(s.snapshot.CommandKeys))
	for _, key := range s.snapshot.CommandKeys {
		result = append(result, s.snapshot.Commands[key])
	}
	return result
}

// Visible returns the commands the caller may discover. Execution must still
// call policy.Authorize because visibility is not an authorization grant.
func (s *Service) Visible(principal model.Principal, invoker model.Invoker) []*model.CompiledCommand {
	if s == nil || s.snapshot == nil {
		return nil
	}
	result := make([]*model.CompiledCommand, 0, len(s.snapshot.CommandKeys))
	for _, key := range s.snapshot.CommandKeys {
		command := s.snapshot.Commands[key]
		if policy.Visible(principal, invoker, command, s.snapshot.AIMaxRisk) {
			result = append(result, command)
		}
	}
	sort.SliceStable(result, func(left, right int) bool {
		return result[left].Key < result[right].Key
	})
	return result
}
