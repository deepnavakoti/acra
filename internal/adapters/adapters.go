// Package adapters reads operational evidence (logs, traces, platform state)
// from Azure, AWS, GCP, Kubernetes and KAgent. Every adapter is READ-ONLY and
// returns normalized Signals plus an explicit Partial flag, so a missing source
// is reported as missing rather than silently treated as "no problems found".
package adapters

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/deepnavakoti/acra/internal/redact"
)

// Signal is one normalized piece of evidence from a source system.
type Signal struct {
	Source   string            `json:"source"` // azure|aws|gcp|k8s|kagent
	Kind     string            `json:"kind"`   // log|trace|event|state|reasoning
	Time     time.Time         `json:"time"`
	Severity string            `json:"severity"` // debug|info|warning|error|critical
	Resource string            `json:"resource,omitempty"`
	Message  string            `json:"message"`
	Attrs    map[string]string `json:"attrs,omitempty"`
	Ref      string            `json:"ref,omitempty"` // stable id of the source record
}

// Query scopes a fetch. All identifiers are validated before use because they
// are interpolated into provider query languages (KQL, CloudWatch filter
// patterns, Cloud Logging filters): an unvalidated id is a query-injection hole.
type Query struct {
	TraceID   string
	AgentID   string
	Service   string
	Namespace string
	Start     time.Time
	End       time.Time
	Limit     int
}

const (
	maxWindow     = 24 * time.Hour
	defaultLimit  = 200
	maxLimit      = 1000
	maxHTTPBody   = 4 << 20
	defaultSource = 15 * time.Second
)

var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/\-]{0,199}$`)

// SafeID reports whether s is safe to interpolate into a provider query.
func SafeID(s string) bool { return safeID.MatchString(s) }

// Validate checks the query and applies defaults (returning the normalized copy).
func (q Query) Validate() (Query, error) {
	for name, v := range map[string]string{"traceId": q.TraceID, "agentId": q.AgentID, "service": q.Service, "namespace": q.Namespace} {
		if v != "" && !SafeID(v) {
			return q, fmt.Errorf("adapters: %s contains characters that are not allowed", name)
		}
	}
	if q.TraceID == "" && q.AgentID == "" && q.Service == "" {
		return q, errors.New("adapters: query needs a traceId, agentId or service")
	}
	if q.End.IsZero() || q.Start.IsZero() || !q.End.After(q.Start) {
		return q, errors.New("adapters: query needs a valid time window")
	}
	if q.End.Sub(q.Start) > maxWindow {
		return q, fmt.Errorf("adapters: window longer than %s", maxWindow)
	}
	if q.Limit <= 0 {
		q.Limit = defaultLimit
	}
	if q.Limit > maxLimit {
		q.Limit = maxLimit
	}
	q.Start, q.End = q.Start.UTC(), q.End.UTC()
	return q, nil
}

// Result is one adapter's output.
type Result struct {
	Source   string   `json:"source"`
	Signals  []Signal `json:"signals"`
	Partial  bool     `json:"partial"` // results were truncated or incomplete
	Warnings []string `json:"warnings,omitempty"`
}

// Adapter is a read-only evidence source.
type Adapter interface {
	Name() string
	Fetch(ctx context.Context, q Query) (Result, error)
}

// FetchAll queries all adapters concurrently, each under its own timeout. An
// adapter failure becomes a Failed entry, never a silent omission, so the caller
// can say "AWS logs unavailable" instead of "AWS logs clean".
func FetchAll(ctx context.Context, q Query, timeout time.Duration, as ...Adapter) ([]Result, map[string]string) {
	if timeout <= 0 {
		timeout = defaultSource
	}
	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		out    []Result
		failed = map[string]string{}
	)
	for _, a := range as {
		wg.Add(1)
		go func(a Adapter) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					mu.Lock()
					failed[a.Name()] = "adapter panic"
					mu.Unlock()
				}
			}()
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			res, err := a.Fetch(cctx, q)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed[a.Name()] = redact.String(err.Error())
				return
			}
			out = append(out, res)
		}(a)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out, failed
}

// Merge flattens results into one time-ordered signal list.
func Merge(rs []Result) []Signal {
	var all []Signal
	for _, r := range rs {
		all = append(all, r.Signals...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.Before(all[j].Time) })
	return all
}

// checkBaseURL refuses plaintext endpoints except loopback (tests, sidecars).
func checkBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("adapters: invalid endpoint URL")
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); u.Scheme == "http" && (host == "localhost" || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return errors.New("adapters: endpoint must be https (http allowed for loopback only)")
}

// httpDo executes req with a bounded body read and returns the body. Non-2xx
// responses become errors carrying the status and a short redacted excerpt.
func httpDo(hc *http.Client, req *http.Request) ([]byte, error) {
	if hc == nil {
		hc = &http.Client{Timeout: defaultSource}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ex := redact.String(strings.TrimSpace(string(data)))
		if len(ex) > 200 {
			ex = ex[:200]
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, ex)
	}
	return data, nil
}

// TokenSource yields a bearer token for a cloud API.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken is a fixed bearer token (for tests or externally refreshed tokens).
type StaticToken string

// Token implements TokenSource.
func (s StaticToken) Token(context.Context) (string, error) {
	if s == "" {
		return "", errors.New("adapters: empty token")
	}
	return string(s), nil
}

func clip(s string, n int) string {
	s = redact.String(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
