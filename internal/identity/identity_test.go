package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	tokAdmin  = "admin-token-0123456789"
	tokReader = "reader-token-0123456789"
)

func newAuth(t *testing.T) *Authenticator {
	t.Helper()
	m, err := ParseTokens(tokAdmin + ":ops:admin," + tokReader + ":viewer:reader")
	if err != nil {
		t.Fatal(err)
	}
	return New(m)
}

func do(h http.HandlerFunc, token string) int {
	r := httptest.NewRequest("GET", "/", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w.Code
}

func TestParseTokensRejectsWeakAndUnknown(t *testing.T) {
	if _, err := ParseTokens("short"); err == nil {
		t.Error("short token must be rejected")
	}
	if _, err := ParseTokens("0123456789abcdefXYZ:p:superuser"); err == nil {
		t.Error("unknown role must be rejected")
	}
	if _, err := ParseTokens("0123456789abcdefXYZ,0123456789abcdefXYZ"); err == nil {
		t.Error("duplicate token must be rejected")
	}
}

func TestRequire(t *testing.T) {
	a := newAuth(t)
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	read := a.Require(RoleReader, ok)
	admin := a.Require(RoleAdmin, ok)

	if c := do(read, ""); c != http.StatusUnauthorized {
		t.Errorf("no token: %d", c)
	}
	if c := do(read, "wrong-token-0123456789"); c != http.StatusUnauthorized {
		t.Errorf("bad token: %d", c)
	}
	if c := do(read, tokReader); c != http.StatusOK {
		t.Errorf("reader on reader route: %d", c)
	}
	if c := do(admin, tokReader); c != http.StatusForbidden {
		t.Errorf("reader on admin route: %d", c)
	}
	if c := do(read, tokAdmin); c != http.StatusOK {
		t.Errorf("admin implies reader: %d", c)
	}
}

func TestDisabledAuthIsOpen(t *testing.T) {
	a := New(nil)
	if a.Enabled() {
		t.Fatal("no tokens must mean disabled")
	}
	h := a.Require(RoleAdmin, func(w http.ResponseWriter, r *http.Request) {
		if From(r.Context()).ID != "anonymous" {
			t.Error("expected anonymous principal")
		}
	})
	if c := do(h, ""); c != http.StatusOK {
		t.Errorf("disabled auth must pass: %d", c)
	}
	var nilAuth *Authenticator
	if nilAuth.Enabled() {
		t.Error("nil authenticator must be disabled")
	}
}
