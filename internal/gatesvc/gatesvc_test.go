package gatesvc

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepnavakoti/acra/internal/detectors"
	"github.com/deepnavakoti/acra/internal/gate"
	"github.com/deepnavakoti/acra/internal/identity"
	"github.com/deepnavakoti/acra/internal/model"
)

func svc(auth *identity.Authenticator) *Service {
	pol := gate.Policy{
		ApprovedTuples:      []model.Tuple{{Prompt: "p-30", Manifest: "1.8.3", Ruleset: "e8d3", Formula: "f-6"}},
		MinIndependentRoots: 2,
	}
	return New(pol, detectors.Default(), auth, nil)
}

func post(s *Service, path, method, body, token string) (int, string) {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

const approved = `"tuple":{"prompt":"p-30","manifest":"1.8.3","ruleset":"e8d3","formula":"f-6"}`

func TestEvaluateAdmitsApprovedWrite(t *testing.T) {
	code, body := post(svc(nil), "/v1/gate/evaluate", "POST", `{"task":"t1",`+approved+`}`, "")
	if code != 200 || !strings.Contains(body, `"verdict":"ADMIT"`) && !strings.Contains(strings.ToUpper(body), "ADMIT") {
		t.Fatalf("want ADMIT, got %d %s", code, body)
	}
}

func TestEvaluateHoldsUnapprovedTuple(t *testing.T) {
	body := `{"task":"t1","tuple":{"prompt":"p-99","manifest":"1.8.3","ruleset":"e8d3","formula":"f-6"}}`
	code, out := post(svc(nil), "/v1/gate/evaluate", "POST", body, "")
	if code != 200 || !strings.Contains(strings.ToUpper(out), "HOLD") {
		t.Fatalf("want HOLD, got %d %s", code, out)
	}
}

func TestCallerCannotSupplyPolicy(t *testing.T) {
	body := `{"task":"t1",` + approved + `,"policy":{"approvedTuples":[]}}`
	if code, _ := post(svc(nil), "/v1/gate/evaluate", "POST", body, ""); code != http.StatusBadRequest {
		t.Fatalf("unknown field 'policy' must be rejected, got %d", code)
	}
}

func TestEpochFenceIsServerSideAndMonotonic(t *testing.T) {
	s := svc(nil)
	if code, _ := post(s, "/v1/gate/epochs/t1", "PUT", `{"epoch":8}`, ""); code != 200 {
		t.Fatalf("set epoch: %d", code)
	}
	if code, _ := post(s, "/v1/gate/epochs/t1", "PUT", `{"epoch":3}`, ""); code != http.StatusConflict {
		t.Fatalf("epoch must not decrease, got %d", code)
	}
	_, out := post(s, "/v1/gate/evaluate", "POST", `{"task":"t1","epoch":5,`+approved+`}`, "")
	if !strings.Contains(strings.ToUpper(out), "HOLD") {
		t.Fatalf("stale epoch must HOLD: %s", out)
	}
}

func TestBadRequestsAreNotDecisions(t *testing.T) {
	s := svc(nil)
	for _, b := range []string{`not json`, `{}`, `{"task":"t","lineage":{"nodes":[{"id":"a","kind":"weird"}]}}`} {
		if code, _ := post(s, "/v1/gate/evaluate", "POST", b, ""); code != http.StatusBadRequest {
			t.Errorf("body %q: want 400, got %d", b, code)
		}
	}
}

func TestAuthRequired(t *testing.T) {
	m, _ := identity.ParseTokens("ingest-token-0123456789:svc:ingest")
	s := svc(identity.New(m))
	if code, _ := post(s, "/v1/gate/evaluate", "POST", `{"task":"t",`+approved+`}`, ""); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	if code, _ := post(s, "/v1/gate/evaluate", "POST", `{"task":"t",`+approved+`}`, "ingest-token-0123456789"); code != 200 {
		t.Errorf("ingest role may evaluate: %d", code)
	}
	if code, _ := post(s, "/v1/gate/epochs/t", "PUT", `{"epoch":1}`, "ingest-token-0123456789"); code != http.StatusForbidden {
		t.Errorf("only admin may move the fence: %d", code)
	}
}

func TestLoadPolicy(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "p.json")
	os.WriteFile(good, []byte(`{"approvedTuples":[{"prompt":"a","manifest":"b","ruleset":"c","formula":"d"}]}`), 0o600)
	p, err := LoadPolicy(good)
	if err != nil || p.MinIndependentRoots != 2 {
		t.Fatalf("good policy: %v %+v", err, p)
	}
	empty := filepath.Join(dir, "e.json")
	os.WriteFile(empty, []byte(`{"approvedTuples":[]}`), 0o600)
	if _, err := LoadPolicy(empty); err == nil {
		t.Error("empty approved set must be refused")
	}
	if _, err := LoadPolicy(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing file must be refused")
	}
}
