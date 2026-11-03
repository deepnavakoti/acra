package a2a

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/deepnavakoti/acra/internal/identity"
	"github.com/deepnavakoti/acra/internal/incident"
	"github.com/deepnavakoti/acra/internal/pipeline"
)

type fake struct{ investigated []string }

func (f *fake) ListIncidents(st incident.Status) ([]incident.Incident, error) {
	return []incident.Incident{{ID: "inc-1", AgentID: "a", Status: incident.StatusOpen, Summary: "key sk-abcdefghijklmnopqrstuvwxyz0123456789"}}, nil
}
func (f *fake) GetIncident(id string) (incident.Incident, error) {
	switch id {
	case "inc-1":
		return incident.Incident{ID: "inc-1"}, nil
	case "gone":
		return incident.Incident{}, pipeline.ErrNoRun
	}
	return incident.Incident{}, incident.ErrNotFound
}
func (f *fake) Investigate(_ context.Context, id string) (any, error) {
	if id == "stale" {
		return nil, pipeline.ErrNoRun
	}
	f.investigated = append(f.investigated, id)
	return map[string]string{"incident": id, "verdict": "likely OOM"}, nil
}

const (
	readerTok = "reader-token-0123456789"
	adminTok  = "admin-token-0123456789a"
)

func setup(t *testing.T) (http.Handler, *fake) {
	t.Helper()
	f := &fake{}
	auth := identity.New(map[string]identity.Principal{
		readerTok: {ID: "r", Roles: []string{identity.RoleReader}},
		adminTok:  {ID: "a", Roles: []string{identity.RoleAdmin}},
	})
	s := &Server{Backend: f, Version: "test", PublicURL: "https://acra.example.com/"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent-card.json", s.CardHandler())
	mux.HandleFunc("POST /a2a", auth.Require(identity.RoleReader, s.Handler()))
	return mux, f
}

func send(h http.Handler, params, token string) (int, map[string]any) {
	body := `{"jsonrpc":"2.0","id":"1","method":"message/send","params":` + params + `}`
	return call(h, body, token)
}

func call(h http.Handler, body, token string) (int, map[string]any) {
	r := httptest.NewRequest("POST", "/a2a", strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func text(out map[string]any) string {
	return out["result"].(map[string]any)["parts"].([]any)[0].(map[string]any)["text"].(string)
}

func TestAgentCardIsPublicAndWellFormed(t *testing.T) {
	h, _ := setup(t)
	r := httptest.NewRequest("GET", "/.well-known/agent-card.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("card must be public, got %d", w.Code)
	}
	var c map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if c["url"] != "https://acra.example.com/a2a" {
		t.Fatalf("url: %v", c["url"])
	}
	if len(c["skills"].([]any)) != 3 || c["capabilities"].(map[string]any)["streaming"] != false {
		t.Fatalf("card: %v", c)
	}
	if c["securitySchemes"] == nil {
		t.Fatal("card must declare the bearer scheme")
	}
}

func TestEndpointRequiresAuth(t *testing.T) {
	h, _ := setup(t)
	if code, _ := send(h, `{"message":{"parts":[{"kind":"text","text":"list-incidents"}]}}`, ""); code != http.StatusUnauthorized {
		t.Fatalf("got %d", code)
	}
}

func TestListIncidentsByTextAndRedacts(t *testing.T) {
	h, _ := setup(t)
	_, out := send(h, `{"message":{"parts":[{"kind":"text","text":"list-incidents open"}]}}`, readerTok)
	if out["error"] != nil {
		t.Fatalf("%v", out)
	}
	txt := text(out)
	if !strings.Contains(txt, "inc-1") || strings.Contains(txt, "sk-abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("expected incident with secret redacted: %s", txt)
	}
	if out["result"].(map[string]any)["metadata"].(map[string]any)["acra/untrusted"] != true {
		t.Fatal("must be marked untrusted")
	}
}

func TestGetIncidentByDataPart(t *testing.T) {
	h, _ := setup(t)
	_, out := send(h, `{"message":{"parts":[{"kind":"data","data":{"skill":"get-incident","incidentId":"inc-1"}}]}}`, readerTok)
	if out["error"] != nil || !strings.Contains(text(out), "inc-1") {
		t.Fatalf("%v", out)
	}
	_, out = send(h, `{"message":{"parts":[{"kind":"text","text":"get-incident missing"}]}}`, readerTok)
	if out["error"] == nil {
		t.Fatal("unknown incident must be an error")
	}
}

func TestInvestigateNeedsAdmin(t *testing.T) {
	h, f := setup(t)
	p := `{"message":{"parts":[{"kind":"text","text":"investigate-incident inc-1"}]}}`
	if _, out := send(h, p, readerTok); out["error"] == nil || len(f.investigated) != 0 {
		t.Fatalf("a reader must not investigate: %v", out)
	}
	_, out := send(h, p, adminTok)
	if out["error"] != nil || len(f.investigated) != 1 || !strings.Contains(text(out), "likely OOM") {
		t.Fatalf("admin investigate: %v", out)
	}
	_, out = send(h, `{"message":{"parts":[{"kind":"text","text":"investigate-incident stale"}]}}`, adminTok)
	if e, _ := out["error"].(map[string]any); e == nil || !strings.Contains(e["message"].(string), "no longer cached") {
		t.Fatalf("stale run: %v", out)
	}
}

func TestBadInputsAreErrors(t *testing.T) {
	h, _ := setup(t)
	for name, p := range map[string]string{
		"no parts":       `{"message":{"parts":[]}}`,
		"unknown skill":  `{"message":{"parts":[{"kind":"text","text":"drop-tables x"}]}}`,
		"too many words": `{"message":{"parts":[{"kind":"text","text":"get-incident a b"}]}}`,
		"bad status":     `{"message":{"parts":[{"kind":"text","text":"list-incidents bogus"}]}}`,
		"id with slash":  `{"message":{"parts":[{"kind":"text","text":"get-incident a/b"}]}}`,
		"missing id":     `{"message":{"parts":[{"kind":"text","text":"get-incident"}]}}`,
	} {
		if _, out := send(h, p, adminTok); out["error"] == nil {
			t.Errorf("%s: expected an error, got %v", name, out)
		}
	}
}

func TestUnsupportedAndUnknownMethods(t *testing.T) {
	h, _ := setup(t)
	for method, want := range map[string]float64{
		"message/stream": codeUnsupportedOp, "tasks/get": codeTaskNotFound,
		"tasks/cancel": codeTaskNotFound, "nope": codeMethodNotFound,
	} {
		_, out := call(h, `{"jsonrpc":"2.0","id":1,"method":"`+method+`","params":{}}`, readerTok)
		e, _ := out["error"].(map[string]any)
		if e == nil || e["code"].(float64) != want {
			t.Errorf("%s: want %v, got %v", method, want, out)
		}
	}
	if _, out := call(h, `{bad`, readerTok); out["error"] == nil {
		t.Error("parse error expected")
	}
	if _, out := call(h, `{"jsonrpc":"2.0","method":"tasks/get"}`, readerTok); out["error"] == nil {
		t.Error("request without id must be rejected")
	}
}

func TestOversizeRejected(t *testing.T) {
	h, _ := setup(t)
	big := `{"jsonrpc":"2.0","id":1,"method":"x","params":"` + strings.Repeat("a", maxBody) + `"}`
	if code, _ := call(h, big, readerTok); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d", code)
	}
}
