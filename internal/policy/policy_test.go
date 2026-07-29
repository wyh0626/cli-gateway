package policy

import (
	"testing"

	"github.com/wyh0626/cli-gateway/internal/model"
)

func TestAuthorize(t *testing.T) {
	t.Parallel()
	command := &model.CompiledCommand{Risk: model.RiskWrite}
	tests := []struct {
		name      string
		principal model.Principal
		invoker   model.Invoker
		maximum   model.Risk
		wantCode  string
	}{
		{name: "authenticated human needs no command scope", principal: model.Principal{}, invoker: model.InvokerHuman, maximum: model.RiskRead},
		{name: "ai risk denied", principal: model.Principal{}, invoker: model.InvokerAI, maximum: model.RiskRead, wantCode: "E_AI_RISK_FORBIDDEN"},
		{name: "unknown risk denied", principal: model.Principal{}, invoker: model.InvokerUnknown, maximum: model.RiskRead, wantCode: "E_AI_RISK_FORBIDDEN"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := Authorize(test.principal, test.invoker, command, test.maximum, false)
			if test.wantCode == "" {
				if err != nil {
					t.Fatalf("Authorize() error = %v", err)
				}
				return
			}
			if err == nil || err.Code != test.wantCode {
				t.Fatalf("Authorize() error = %#v, want %s", err, test.wantCode)
			}
		})
	}
}

func TestConfiguredCommandRequiresConfirmation(t *testing.T) {
	t.Parallel()
	command := &model.CompiledCommand{Risk: model.RiskDestroy, Confirm: true}
	if err := Authorize(model.Principal{}, model.InvokerHuman, command, model.RiskWrite, false); err == nil || err.Code != "E_CONFIRM_REQUIRED" {
		t.Fatalf("Authorize() error = %#v", err)
	}
	if err := Authorize(model.Principal{}, model.InvokerHuman, command, model.RiskWrite, true); err != nil {
		t.Fatalf("confirmed Authorize() error = %v", err)
	}
}

func TestWriteCommandCanRequireConfirmation(t *testing.T) {
	t.Parallel()
	command := &model.CompiledCommand{Risk: model.RiskWrite, Confirm: true}
	if err := Authorize(model.Principal{}, model.InvokerHuman, command, model.RiskWrite, false); err == nil || err.Code != "E_CONFIRM_REQUIRED" {
		t.Fatalf("Authorize() error = %#v", err)
	}
}

func TestVisibleDoesNotUseOAuthScopes(t *testing.T) {
	t.Parallel()
	command := &model.CompiledCommand{Risk: model.RiskRead}
	if !Visible(model.Principal{Scopes: map[string]struct{}{}}, model.InvokerHuman, command, model.RiskRead) {
		t.Fatal("authenticated command was hidden because the access token has no command scope")
	}
}
