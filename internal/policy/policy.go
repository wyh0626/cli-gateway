// Package policy implements the fixed cli-gateway invoker-risk and confirmation policy.
package policy

import (
	"net/http"

	"github.com/wyh0626/cli-gateway/internal/httpx"
	"github.com/wyh0626/cli-gateway/internal/model"
)

// Authorize checks invoker risk and destructive confirmation. Business
// authorization belongs to the downstream service, which receives a verified
// user identity bound to the selected command.
func Authorize(_ model.Principal, invoker model.Invoker, command *model.CompiledCommand, aiMaximum model.Risk, confirmed bool) *httpx.APIError {
	if (invoker == model.InvokerAI || invoker == model.InvokerUnknown) && command.Risk.Exceeds(aiMaximum) {
		return &httpx.APIError{Status: http.StatusForbidden, Code: "E_AI_RISK_FORBIDDEN", Message: "command risk exceeds the invoker limit"}
	}
	if command.Confirm && !confirmed {
		return &httpx.APIError{Status: http.StatusPreconditionRequired, Code: "E_CONFIRM_REQUIRED", Message: "command requires confirmation", Hint: "set X-Cli-Gateway-Confirm: true"}
	}
	return nil
}

// Visible applies list-time invoker-risk filtering. Execution always calls
// Authorize again.
func Visible(_ model.Principal, invoker model.Invoker, command *model.CompiledCommand, aiMaximum model.Risk) bool {
	return !((invoker == model.InvokerAI || invoker == model.InvokerUnknown) && command.Risk.Exceeds(aiMaximum))
}
