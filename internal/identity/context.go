package identity

import (
	"context"
	"net/http"
)

func withPrincipal(r *http.Request, p Principal) context.Context {
	return context.WithValue(r.Context(), ctxKey{}, p)
}

// From returns the principal stored by Require (Anonymous if absent).
func From(ctx context.Context) Principal {
	if p, ok := ctx.Value(ctxKey{}).(Principal); ok {
		return p
	}
	return Anonymous
}
