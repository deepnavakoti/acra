// Package identity authenticates API callers and maps them to roles. Auth is
// opt-in: with no tokens configured every request is treated as an anonymous
// admin (the local demo); once any token is configured, unauthenticated requests
// are rejected and each route requires a role.
package identity

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Roles.
const (
	RoleReader = "reader" // read incidents, evaluations, evidence
	RoleIngest = "ingest" // submit telemetry
	RoleAdmin  = "admin"  // everything, including contracts and investigations
)

// Principal is an authenticated caller.
type Principal struct {
	ID    string
	Roles []string
}

// Has reports whether the principal holds role (admin holds all).
func (p Principal) Has(role string) bool {
	for _, r := range p.Roles {
		if r == role || r == RoleAdmin {
			return true
		}
	}
	return false
}

type entry struct {
	hash [32]byte
	p    Principal
}

// Authenticator checks bearer tokens. Tokens are stored only as SHA-256 hashes
// and compared in constant time across all entries, so neither timing nor
// early exit reveals which token matched.
type Authenticator struct {
	entries []entry
}

// New builds an Authenticator from token -> principal.
func New(tokens map[string]Principal) *Authenticator {
	a := &Authenticator{}
	for t, p := range tokens {
		a.entries = append(a.entries, entry{hash: sha256.Sum256([]byte(t)), p: p})
	}
	return a
}

// Enabled reports whether any token is configured.
func (a *Authenticator) Enabled() bool { return a != nil && len(a.entries) > 0 }

// ParseTokens parses "token:principal:role|role,token2:principal2:role". A
// bare token (no colons) becomes an admin principal named "token-admin". Tokens
// shorter than 16 characters are rejected: they are guessable.
func ParseTokens(spec string) (map[string]Principal, error) {
	out := map[string]Principal{}
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.Split(item, ":")
		tok := parts[0]
		if len(tok) < 16 {
			return nil, errors.New("identity: tokens must be at least 16 characters")
		}
		p := Principal{ID: "token-admin", Roles: []string{RoleAdmin}}
		if len(parts) >= 2 && parts[1] != "" {
			p.ID = parts[1]
		}
		if len(parts) >= 3 {
			p.Roles = nil
			for _, r := range strings.Split(parts[2], "|") {
				switch r {
				case RoleReader, RoleIngest, RoleAdmin:
					p.Roles = append(p.Roles, r)
				default:
					return nil, fmt.Errorf("identity: unknown role %q", r)
				}
			}
		}
		if _, dup := out[tok]; dup {
			return nil, errors.New("identity: duplicate token")
		}
		out[tok] = p
	}
	return out, nil
}

// Authenticate returns the principal for the request's bearer token.
func (a *Authenticator) Authenticate(r *http.Request) (Principal, bool) {
	h := r.Header.Get("Authorization")
	const pfx = "Bearer "
	if len(h) <= len(pfx) || !strings.EqualFold(h[:len(pfx)], pfx) {
		return Principal{}, false
	}
	sum := sha256.Sum256([]byte(h[len(pfx):]))
	var found Principal
	ok := 0
	for _, e := range a.entries {
		m := subtle.ConstantTimeCompare(sum[:], e.hash[:])
		if m == 1 {
			found = e.p
		}
		ok |= m
	}
	return found, ok == 1
}

type ctxKey struct{}

// Anonymous is the principal used when auth is disabled.
var Anonymous = Principal{ID: "anonymous", Roles: []string{RoleAdmin}}

// Require wraps h so that the caller must hold role. When auth is disabled the
// handler runs as Anonymous. The principal is available through From.
func (a *Authenticator) Require(role string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := Anonymous
		if a.Enabled() {
			var ok bool
			p, ok = a.Authenticate(r)
			if !ok {
				w.Header().Set("WWW-Authenticate", `Bearer realm="acra"`)
				deny(w, http.StatusUnauthorized, "authentication required")
				return
			}
			if !p.Has(role) {
				deny(w, http.StatusForbidden, "insufficient role")
				return
			}
		}
		h(w, r.WithContext(withPrincipal(r, p)))
	}
}

func deny(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":{"code":%q,"message":%q}}`, http.StatusText(code), msg)
}
