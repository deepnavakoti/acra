package adapters

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var (
	t0 = time.Date(2025, 1, 2, 10, 0, 0, 0, time.UTC)
	q0 = Query{TraceID: "trace-123", AgentID: "billing-agent", Service: "billing", Namespace: "prod",
		Start: t0, End: t0.Add(10 * time.Minute)}
)

// The AWS "get-vanilla" SigV4 test-suite vector.
func TestSignV4_GetVanilla(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	req.Host = "example.amazonaws.com"
	creds := AWSCredentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	if err := SignV4(req, nil, creds, "us-east-1", "service", now); err != nil {
		t.Fatal(err)
	}
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("signature mismatch\n got %s\nwant %s", got, want)
	}
}

func TestQueryValidate_RejectsInjection(t *testing.T) {
	bad := []string{`x" or 1==1 //`, "a b", "a;b", "a\nb", `a"`, "", "a'b", "../etc"}
	for _, b := range bad {
		q := q0
		q.TraceID = b
		if b == "" {
			q.TraceID, q.AgentID, q.Service = "", "", ""
		}
		if _, err := q.Validate(); err == nil {
			t.Errorf("expected rejection for %q", b)
		}
	}
	q := q0
	q.End = q.Start.Add(48 * time.Hour)
	if _, err := q.Validate(); err == nil {
		t.Error("expected window rejection")
	}
	q = q0
	q.End = q.Start
	if _, err := q.Validate(); err == nil {
		t.Error("expected empty window rejection")
	}
}

func TestAzure_Fetch(t *testing.T) {
	var gotAuth, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		gotQuery = b["query"]
		if !strings.HasSuffix(r.URL.Path, "/v1/workspaces/ws-1/query") {
			t.Errorf("bad path %s", r.URL.Path)
		}
		io.WriteString(w, `{"tables":[{"name":"PrimaryResult","columns":[{"name":"TimeGenerated"},{"name":"Type"},{"name":"Msg"},{"name":"SeverityLevel"},{"name":"AppRoleName"},{"name":"OperationId"},{"name":"ItemId"}],
		"rows":[["2025-01-02T10:01:00Z","AppExceptions","boom password=hunter2x",3,"billing","trace-123","i1"],
		        ["2025-01-02T10:02:00Z","AppTraces","ok",1,"billing","trace-123","i2"]]}]}`)
	}))
	defer srv.Close()
	a := &Azure{Endpoint: srv.URL, WorkspaceID: "ws-1", Tokens: StaticToken("tok")}
	res, err := a.Fetch(context.Background(), q0)
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok" || !strings.Contains(gotQuery, `OperationId == "trace-123"`) {
		t.Fatalf("auth=%q query=%q", gotAuth, gotQuery)
	}
	if len(res.Signals) != 2 || res.Signals[0].Severity != "error" || res.Signals[1].Severity != "info" {
		t.Fatalf("signals: %+v", res.Signals)
	}
	if strings.Contains(res.Signals[0].Message, "hunter2x") {
		t.Fatal("secret was not redacted")
	}
}

func TestAWS_Fetch_SignsAndParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKID/") {
			t.Errorf("request not signed: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Amz-Target") != "Logs_20140328.FilterLogEvents" {
			t.Errorf("bad target")
		}
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["logGroupName"] != "/aws/lambda/billing" {
			t.Errorf("bad group %v", b["logGroupName"])
		}
		io.WriteString(w, `{"events":[{"eventId":"e1","logStreamName":"s1","message":"ERROR timeout","timestamp":1735812060000}],"nextToken":"more"}`)
	}))
	defer srv.Close()
	a := &AWS{Region: "us-east-1", Endpoint: srv.URL + "/", LogGroups: []string{"/aws/lambda/billing"},
		Creds: StaticAWSCreds{AccessKeyID: "AKID", SecretAccessKey: "secret"}}
	res, err := a.Fetch(context.Background(), q0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Signals) != 1 || res.Signals[0].Severity != "error" || !res.Partial {
		t.Fatalf("%+v", res)
	}
}

func TestAWS_AllGroupsFail_IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer srv.Close()
	a := &AWS{Region: "us-east-1", Endpoint: srv.URL + "/", LogGroups: []string{"g1"},
		Creds: StaticAWSCreds{AccessKeyID: "AKID", SecretAccessKey: "s"}}
	if _, err := a.Fetch(context.Background(), q0); err == nil {
		t.Fatal("expected error when every group fails")
	}
}

func TestGCP_Fetch(t *testing.T) {
	var filter string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		filter, _ = b["filter"].(string)
		io.WriteString(w, `{"entries":[{"insertId":"x1","timestamp":"2025-01-02T10:03:00Z","severity":"ERROR","jsonPayload":{"message":"quota exceeded"},"resource":{"type":"cloud_run_revision","labels":{"service_name":"billing"}}}]}`)
	}))
	defer srv.Close()
	g := &GCP{Endpoint: srv.URL, ProjectID: "proj-1", Tokens: StaticToken("t")}
	res, err := g.Fetch(context.Background(), q0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filter, `jsonPayload.trace_id="trace-123"`) {
		t.Fatalf("filter: %s", filter)
	}
	if len(res.Signals) != 1 || res.Signals[0].Message != "quota exceeded" || res.Signals[0].Severity != "error" {
		t.Fatalf("%+v", res.Signals)
	}
}

type fakeKube struct{ logsErr error }

func (f fakeKube) ListPods(context.Context, string, string) ([]PodStatus, error) {
	return []PodStatus{
		{Name: "billing-1", Phase: "Running", Ready: false, Restarts: 5, Reason: "CrashLoopBackOff", UID: "u1"},
		{Name: "billing-2", Phase: "Running", Ready: true, UID: "u2"},
	}, nil
}
func (f fakeKube) ListEvents(context.Context, string, time.Time) ([]KubeEvent, error) {
	return []KubeEvent{{Time: t0.Add(time.Minute), Type: "Warning", Reason: "OOMKilling", Object: "Pod/billing-1", Message: "killed"}}, nil
}
func (f fakeKube) PodLogs(context.Context, string, string, int64, time.Time) (string, error) {
	return "starting\nFATAL: out of memory\n", f.logsErr
}

func TestKubernetes_Fetch(t *testing.T) {
	k := &Kubernetes{Reader: fakeKube{}, Namespaces: []string{"prod"}}
	res, err := k.Fetch(context.Background(), q0)
	if err != nil {
		t.Fatal(err)
	}
	var sawCrash, sawOOM, sawFatal bool
	for _, s := range res.Signals {
		sawCrash = sawCrash || (s.Resource == "billing-1" && s.Severity == "error" && s.Kind == "state")
		sawOOM = sawOOM || (s.Kind == "event" && s.Severity == "error")
		sawFatal = sawFatal || (s.Kind == "log" && s.Severity == "critical")
	}
	if !sawCrash || !sawOOM || !sawFatal {
		t.Fatalf("crash=%v oom=%v fatal=%v signals=%+v", sawCrash, sawOOM, sawFatal, res.Signals)
	}
}

func TestKubernetes_NamespaceAllowlist(t *testing.T) {
	k := &Kubernetes{Reader: fakeKube{}, Namespaces: []string{"other"}}
	if _, err := k.Fetch(context.Background(), q0); err == nil {
		t.Fatal("namespace outside allowlist must be refused")
	}
	k = &Kubernetes{Reader: fakeKube{}}
	if _, err := k.Fetch(context.Background(), q0); err == nil {
		t.Fatal("empty allowlist must deny")
	}
}

func TestKAgent_Ask(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["method"] != "message/send" {
			t.Errorf("method %v", b["method"])
		}
		io.WriteString(w, `{"jsonrpc":"2.0","id":"1","result":{"kind":"task","artifacts":[{"parts":[{"kind":"text","text":"likely OOM"}]}]}}`)
	}))
	defer srv.Close()
	k := &KAgent{Endpoint: srv.URL}
	res, err := k.Fetch(context.Background(), q0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Signals[0].Kind != "reasoning" || res.Signals[0].Attrs["trust"] != "advisory" || res.Signals[0].Message != "likely OOM" {
		t.Fatalf("%+v", res.Signals)
	}
}

func TestKAgent_RPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"jsonrpc":"2.0","id":"1","error":{"code":-32601,"message":"no such method"}}`)
	}))
	defer srv.Close()
	if _, err := (&KAgent{Endpoint: srv.URL}).Ask(context.Background(), "hi"); err == nil {
		t.Fatal("expected rpc error")
	}
}

func TestRefusesPlainHTTPNonLoopback(t *testing.T) {
	a := &Azure{Endpoint: "http://example.com", WorkspaceID: "w", Tokens: StaticToken("t")}
	if _, err := a.Fetch(context.Background(), q0); err == nil {
		t.Fatal("plaintext remote endpoint must be refused")
	}
}

type slowAdapter struct{}

func (slowAdapter) Name() string { return "slow" }
func (slowAdapter) Fetch(ctx context.Context, q Query) (Result, error) {
	<-ctx.Done()
	return Result{}, ctx.Err()
}

type okAdapter struct{}

func (okAdapter) Name() string { return "ok" }
func (okAdapter) Fetch(context.Context, Query) (Result, error) {
	return Result{Source: "ok", Signals: []Signal{{Source: "ok", Time: t0, Message: "m"}}}, nil
}

type panicAdapter struct{}

func (panicAdapter) Name() string                                 { return "panic" }
func (panicAdapter) Fetch(context.Context, Query) (Result, error) { panic("x") }

type errAdapter struct{}

func (errAdapter) Name() string { return "bad" }
func (errAdapter) Fetch(context.Context, Query) (Result, error) {
	return Result{}, errors.New("token=abcdefgh1234 failed")
}

func TestFetchAll_IsolatesFailures(t *testing.T) {
	q, _ := q0.Validate()
	res, failed := FetchAll(context.Background(), q, 50*time.Millisecond, okAdapter{}, slowAdapter{}, panicAdapter{}, errAdapter{})
	if len(res) != 1 || res[0].Source != "ok" {
		t.Fatalf("results: %+v", res)
	}
	for _, n := range []string{"slow", "panic", "bad"} {
		if failed[n] == "" {
			t.Errorf("%s failure not reported", n)
		}
	}
	if strings.Contains(failed["bad"], "abcdefgh1234") {
		t.Error("failure message leaked a secret")
	}
}
