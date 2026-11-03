package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/deepnavakoti/acra/internal/contract"
	"github.com/deepnavakoti/acra/internal/gateway"
	"github.com/deepnavakoti/acra/internal/identity"
)

const readerTok = "reader-token-0123456789"

func newServer(t *testing.T, origins ...string) http.Handler {
	t.Helper()
	gw := gateway.New(gateway.Config{CallsPerMinute: 1000}, nil)
	no, one := false, 1
	if err := gw.Register(gateway.Tool{
		Name: "echo", Description: "echo back", Role: identity.RoleReader,
		Args: &contract.Schema{Type: "object", Required: []string{"id"}, AdditionalProperties: &no,
			Properties: map[string]*contract.Schema{"id": {Type: "string", MinLength: &one}}},
		Handler: func(_ context.Context, a json.RawMessage) (any, error) {
			return map[string]any{"echo": json.RawMessage(a), "note": "token=sk-abcdefghijklmnopqrstuvwxyz0123456789"}, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := gw.Register(gateway.Tool{Name: "admin_only", Description: "x", Role: identity.RoleAdmin,
		Handler: func(context.Context, json.RawMessage) (any, error) { return "ok", nil }}); err != nil {
		t.Fatal(err)
	}
	auth := identity.New(map[string]identity.Principal{readerTok: {ID: "r", Roles: []string{identity.RoleReader}}})
	s := &Server{Backend: gw, Version: "test", AllowedOrigins: origins}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mcp", auth.Require(identity.RoleReader, s.Handler()))
	mux.HandleFunc("GET /mcp", GetHandler)
	return mux
}

func rpc(h http.Handler, body, token string, hdr ...string) (int, map[string]any) {
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestRequiresAuth(t *testing.T) {
	h := newServer(t)
	if code, _ := rpc(h, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, ""); code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", code)
	}
}

func TestInitializeNegotiatesVersion(t *testing.T) {
	h := newServer(t)
	_, out := rpc(h, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`, readerTok)
	res := out["result"].(map[string]any)
	if res["protocolVersion"] != "2025-03-26" {
		t.Fatalf("version: %v", res["protocolVersion"])
	}
	_, out = rpc(h, `{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`, readerTok)
	if out["result"].(map[string]any)["protocolVersion"] != supported[0] {
		t.Fatal("unknown version must fall back to the newest supported")
	}
}

func TestToolsListHidesToolsAboveRole(t *testing.T) {
	h := newServer(t)
	_, out := rpc(h, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, readerTok)
	tools := out["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "echo" {
		t.Fatalf("reader must see only echo: %v", tools)
	}
	if tools[0].(map[string]any)["inputSchema"] == nil {
		t.Fatal("inputSchema missing")
	}
}

func TestToolsCallRedactsAndMarksUntrusted(t *testing.T) {
	h := newServer(t)
	_, out := rpc(h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"id":"a"}}}`, readerTok)
	res := out["result"].(map[string]any)
	if res["isError"] != false {
		t.Fatalf("unexpected error: %v", res)
	}
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if strings.Contains(text, "sk-abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("secret leaked through MCP: %s", text)
	}
	if res["_meta"].(map[string]any)["acra/untrusted"] != true {
		t.Fatal("result must be marked untrusted")
	}
}

func TestToolsCallErrors(t *testing.T) {
	h := newServer(t)
	// Invalid args and denied tools are tool errors the model can see.
	_, out := rpc(h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"id":""}}}`, readerTok)
	if out["result"].(map[string]any)["isError"] != true {
		t.Fatalf("invalid args must be isError: %v", out)
	}
	_, out = rpc(h, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"admin_only"}}`, readerTok)
	if out["result"].(map[string]any)["isError"] != true {
		t.Fatalf("denied tool must be isError: %v", out)
	}
	// Unknown tool and bad params are protocol errors.
	_, out = rpc(h, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nope"}}`, readerTok)
	if out["error"] == nil {
		t.Fatalf("unknown tool must be a JSON-RPC error: %v", out)
	}
	_, out = rpc(h, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":"x"}`, readerTok)
	if out["error"] == nil {
		t.Fatal("bad params must be a JSON-RPC error")
	}
}

func TestProtocolEdgeCases(t *testing.T) {
	h := newServer(t)
	if code, _ := rpc(h, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, readerTok); code != http.StatusAccepted {
		t.Fatalf("notification must be 202, got %d", code)
	}
	for body, want := range map[string]float64{
		`{bad`: codeParse,
		`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`: codeInvalidRequest,
		`{"jsonrpc":"1.0","id":1,"method":"ping"}`:   codeInvalidRequest,
		`{"jsonrpc":"2.0","id":1,"method":"nope"}`:   codeMethodNotFound,
	} {
		_, out := rpc(h, body, readerTok)
		e, _ := out["error"].(map[string]any)
		if e == nil || e["code"].(float64) != want {
			t.Errorf("%s: want code %v, got %v", body, want, out)
		}
	}
}

func TestOriginCheck(t *testing.T) {
	h := newServer(t, "https://console.example")
	body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	if code, _ := rpc(h, body, readerTok, "Origin", "https://evil.example"); code != http.StatusForbidden {
		t.Fatalf("foreign origin must be refused, got %d", code)
	}
	if code, _ := rpc(h, body, readerTok, "Origin", "https://console.example"); code != http.StatusOK {
		t.Fatalf("allowed origin must pass, got %d", code)
	}
	if code, _ := rpc(h, body, readerTok); code != http.StatusOK {
		t.Fatalf("no Origin must pass, got %d", code)
	}
}

func TestGetIsNotSupported(t *testing.T) {
	h := newServer(t)
	r := httptest.NewRequest("GET", "/mcp", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d", w.Code)
	}
}

func TestOversizeBodyRejected(t *testing.T) {
	h := newServer(t)
	big := `{"jsonrpc":"2.0","id":1,"method":"ping","params":"` + strings.Repeat("a", maxBody) + `"}`
	if code, _ := rpc(h, big, readerTok); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d", code)
	}
}
