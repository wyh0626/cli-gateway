package catalog

import (
	"testing"

	"github.com/wyh0626/cli-gateway/internal/manifest"
	"github.com/wyh0626/cli-gateway/internal/model"
)

func TestVisibleUsesSharedPolicy(t *testing.T) {
	t.Parallel()
	read := &model.CompiledCommand{Key: "demo.get", Risk: model.RiskRead}
	write := &model.CompiledCommand{Key: "demo.put", Risk: model.RiskWrite}
	snapshot := &manifest.Snapshot{
		AIMaxRisk:   model.RiskRead,
		CommandKeys: []string{"demo.get", "demo.put"},
		Commands: map[string]*model.CompiledCommand{
			read.Key: read, write.Key: write,
		},
		ToolCommands: map[string]*model.CompiledCommand{},
	}
	service := New(snapshot)
	principal := model.Principal{Scopes: map[string]struct{}{"demo:read": {}, "demo:write": {}}}

	visible := service.Visible(principal, model.InvokerAI)
	if len(visible) != 1 || visible[0].Key != read.Key {
		t.Fatalf("Visible() = %#v", visible)
	}
	if resolved, ok := service.Resolve(write.Key); !ok || resolved != write {
		t.Fatalf("Resolve() = %#v, %t", resolved, ok)
	}
}
