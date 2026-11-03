package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepnavakoti/acra/internal/a2a"
	"github.com/deepnavakoti/acra/internal/contract"
	"github.com/deepnavakoti/acra/internal/evidence"
	"github.com/deepnavakoti/acra/internal/gateway"
	"github.com/deepnavakoti/acra/internal/identity"
	"github.com/deepnavakoti/acra/internal/incident"
	"github.com/deepnavakoti/acra/internal/mcp"
	"github.com/deepnavakoti/acra/internal/pipeline"
)

const (
	adminTok  = "admin-token-0123456789"
	readerTok = "reader-token-012345678"
	ingestTok = "ingest-token-012345678"
)

func newAPI(t *testing.T, withAuth bool) http.Handler {
	t.Helper()
	dir := t.TempDir()
	priv, err := evidence.LoadOrCreateKey("")
	if err != nil {
		t.Fatal(err)
	}
	store, err := evidence.Open(filepath.Join(dir, "e.db"), priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	incs, err := incident.Open(filepath.Join(dir, "i.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { incs.Close() })

	svc := pipeline.New(pipeline.Config{}, contract.NewRegistry(), incs)
	svc.Evidence = store
	gw := gateway.New(gateway.Config{}, &gateway.EvidenceAuditor{Store: store})
	if err := RegisterReadTools(gw, svc, nil); err != nil {
		t.Fatal(err)
	}
	s := New(store, "console/index.html")
	s.Pipeline, s.Gateway = svc, gw
	s.MCP = &mcp.Server{Backend: gw, Version: "test"}
	s.A2A = &a2a.Server{Backend: a2a.PipelineBackend{S: svc}, Version: "test", PublicURL: "https://acra.test"}
	if withAuth {
		s.Auth = identity.New(map[string]identity.Principal{
			adminTok:  {ID: "admin", Roles: []string{identity.RoleAdmin}},
			readerTok: {ID: "reader", Roles: []string{identity.RoleReader}},
			ingestTok: {ID: "ingest", Roles: []string{identity.RoleIngest}},
		})
	}
	return s.Routes()
}

func do(h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

const contractJSON = `{"id":"c1","agentId":"support","version":"1","outputSchema":{"type":"object","required":["answer"]}}`

func event(kind, span, out string) string {
	s := `{"traceId":"` + "tr-" + span + `","spanId":"` + span + `","agentId":"support","contractVersion":"1","kind":"` + kind + `"`
	if out != "" {
		s += `,"output":` + out
	}
	return s + `}`
}

func TestEndToEndContractViolationOpensIncident(t *testing.T) {
	h := newAPI(t, false)
	if w := do(h, "PUT", "/v1/contracts", contractJSON, ""); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	body := `{"events":[` + event("agent.request", "a1", "") + `,` + event("agent.response", "a2", `{"nope":1}`) + `]}`
	// request and response are different traces here, so ingest a same-trace pair:
	body = strings.NewReplacer("tr-a1", "T1", "tr-a2", "T1").Replace(body)
	if w := do(h, "POST", "/v1/ingest/events", body, ""); w.Code != http.StatusAccepted {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w := do(h, "GET", "/v1/incidents?status=open", "", "")
	var out struct{ Data []incident.Incident }
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out.Data) != 1 {
		t.Fatalf("expected one open incident: %s", w.Body)
	}
	id := out.Data[0].ID
	if w := do(h, "POST", "/v1/incidents/"+id+"/resolve", "", ""); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := do(h, "GET", "/v1/incidents/does-not-exist", "", ""); w.Code != http.StatusNotFound {
		t.Fatalf("%d", w.Code)
	}
	if w := do(h, "GET", "/v1/incidents?status=bogus", "", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("%d", w.Code)
	}
}

func TestRoleEnforcement(t *testing.T) {
	h := newAPI(t, true)
	cases := []struct {
		method, path, body, tok string
		want                    int
	}{
		{"GET", "/v1/incidents", "", "", 401},
		{"GET", "/v1/incidents", "", readerTok, 200},
		{"PUT", "/v1/contracts", contractJSON, readerTok, 403},
		{"PUT", "/v1/contracts", contractJSON, ingestTok, 403},
		{"PUT", "/v1/contracts", contractJSON, adminTok, 200},
		{"POST", "/v1/ingest/events", `{"events":[]}`, readerTok, 403},
		{"POST", "/v1/ingest/events", `{"events":[]}`, ingestTok, 400}, // authorized, but empty batch
		{"POST", "/v1/incidents/x/investigate", "", readerTok, 403},
		{"POST", "/v1/demo/inject?kind=combinative", "", readerTok, 403},
		{"GET", "/healthz", "", "", 200},
	}
	for _, c := range cases {
		if w := do(h, c.method, c.path, c.body, c.tok); w.Code != c.want {
			t.Errorf("%s %s tok=%.6s: got %d want %d (%s)", c.method, c.path, c.tok, w.Code, c.want, w.Body)
		}
	}
}

func TestBodyLimitsAndStrictDecoding(t *testing.T) {
	h := newAPI(t, false)
	huge := `{"id":"c","agentId":"a","version":"1","description":"` + strings.Repeat("x", maxContractBody) + `"}`
	if w := do(h, "PUT", "/v1/contracts", huge, ""); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body: %d", w.Code)
	}
	typo := `{"id":"c","agentId":"a","version":"1","limits":{"maxLatency":5}}`
	if w := do(h, "PUT", "/v1/contracts", typo, ""); w.Code == 200 {
		t.Fatal("a misspelt limit must not silently load")
	}
	if w := do(h, "POST", "/v1/ingest/events", `{"events":[{"traceId":"t"}]}`, ""); w.Code == http.StatusAccepted && !strings.Contains(w.Body.String(), `"rejected":1`) {
		t.Fatalf("event without agentId must be rejected: %s", w.Body)
	}
	if w := do(h, "POST", "/v1/ingest/otlp", `{}`, ""); w.Code != http.StatusOK && w.Code != http.StatusAccepted {
		t.Fatalf("%d", w.Code)
	}
}

func TestToolGateway(t *testing.T) {
	h := newAPI(t, true)
	if w := do(h, "POST", "/v1/tools/incidents.list/call", `{}`, ""); w.Code != 401 {
		t.Fatalf("%d", w.Code)
	}
	if w := do(h, "POST", "/v1/tools/incidents.list/call", `{}`, readerTok); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := do(h, "POST", "/v1/tools/incidents.list/call", `{"status":"x'; drop"}`, readerTok); w.Code != 400 {
		t.Fatalf("bad arg must be rejected: %d", w.Code)
	}
	if w := do(h, "POST", "/v1/tools/delete.everything/call", `{}`, adminTok); w.Code != 404 {
		t.Fatalf("there is no write tool: %d", w.Code)
	}
	if w := do(h, "POST", "/v1/tools/incidents.get/call", `{"id":"../../etc/passwd"}`, readerTok); w.Code != 400 {
		t.Fatalf("path-like id must be rejected: %d", w.Code)
	}
}

func TestMCPAndA2AEndpoints(t *testing.T) {
	h := newAPI(t, true)

	// MCP: authenticated, lists the same read-only tools as REST, can call one.
	list := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	if w := do(h, "POST", "/mcp", list, ""); w.Code != 401 {
		t.Fatalf("mcp without a token: %d", w.Code)
	}
	w := do(h, "POST", "/mcp", list, readerTok)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "incidents.list") {
		t.Fatalf("mcp tools/list: %d %s", w.Code, w.Body)
	}
	call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"incidents.list","arguments":{}}}`
	if w := do(h, "POST", "/mcp", call, readerTok); w.Code != 200 || !strings.Contains(w.Body.String(), `"isError":false`) {
		t.Fatalf("mcp tools/call: %d %s", w.Code, w.Body)
	}

	// A2A: the card is public, the endpoint is not, and investigate needs admin.
	if w := do(h, "GET", "/.well-known/agent-card.json", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "https://acra.test/a2a") {
		t.Fatalf("agent card: %d %s", w.Code, w.Body)
	}
	if w := do(h, "GET", "/.well-known/agent.json", "", ""); w.Code != 200 {
		t.Fatalf("legacy card path: %d", w.Code)
	}
	send := func(text, tok string) *httptest.ResponseRecorder {
		return do(h, "POST", "/a2a", `{"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{"parts":[{"kind":"text","text":"`+text+`"}]}}}`, tok)
	}
	if w := send("list-incidents", ""); w.Code != 401 {
		t.Fatalf("a2a without a token: %d", w.Code)
	}
	if w := send("list-incidents", readerTok); w.Code != 200 || strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("a2a list: %d %s", w.Code, w.Body)
	}
	if w := send("investigate-incident x", readerTok); !strings.Contains(w.Body.String(), "not permitted") {
		t.Fatalf("a reader must not investigate over A2A: %s", w.Body)
	}
}
