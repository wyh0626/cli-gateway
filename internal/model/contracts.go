package model

import (
	"context"
	"net/http"
)

// InvocationService is the single execution boundary used by HTTP and MCP adapters.
type InvocationService interface {
	Invoke(context.Context, Invocation) (*Execution, error)
}

// CommandCatalog resolves compiled commands without exposing manifest details.
type CommandCatalog interface {
	Resolve(key string) (*CompiledCommand, bool)
	List() []*CompiledCommand
}

// OutboundAuthorizer constructs downstream credentials from trusted invocation
// state. It must not make routing or policy decisions.
type OutboundAuthorizer interface {
	Authorize(context.Context, *http.Request, Invocation) error
}

// CredentialInvalidator is optionally implemented by cached downstream
// authorizers. Invocation services call it after a downstream 401 and never
// automatically replay the business request.
type CredentialInvalidator interface {
	Invalidate(Invocation)
}
