package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// AWSCredentialSource yields signing credentials.
type AWSCredentialSource interface {
	Credentials(ctx context.Context) (AWSCredentials, error)
}

// StaticAWSCreds is a fixed credential set.
type StaticAWSCreds AWSCredentials

// Credentials implements AWSCredentialSource.
func (s StaticAWSCreds) Credentials(context.Context) (AWSCredentials, error) {
	return AWSCredentials(s), nil
}

// EnvAWSCreds reads AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN.
type EnvAWSCreds struct{}

// Credentials implements AWSCredentialSource.
func (EnvAWSCreds) Credentials(context.Context) (AWSCredentials, error) {
	c := AWSCredentials{
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return c, errors.New("aws: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY not set")
	}
	return c, nil
}

// WebIdentityCreds exchanges a projected service-account token for temporary
// credentials (EKS IRSA). The token file is re-read on every refresh because
// the kubelet rotates it.
type WebIdentityCreds struct {
	RoleARN   string
	TokenFile string
	Region    string
	STSURL    string // default https://sts.<region>.amazonaws.com/
	HTTP      *http.Client

	mu     sync.Mutex
	cached AWSCredentials
	expiry time.Time
}

// Credentials implements AWSCredentialSource.
func (w *WebIdentityCreds) Credentials(ctx context.Context) (AWSCredentials, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cached.AccessKeyID != "" && time.Until(w.expiry) > 2*time.Minute {
		return w.cached, nil
	}
	if w.RoleARN == "" || w.TokenFile == "" {
		return AWSCredentials{}, errors.New("aws: role ARN and web identity token file are required")
	}
	tok, err := os.ReadFile(w.TokenFile)
	if err != nil {
		return AWSCredentials{}, fmt.Errorf("aws: reading web identity token: %w", err)
	}
	endpoint := w.STSURL
	if endpoint == "" {
		endpoint = "https://sts." + w.Region + ".amazonaws.com/"
	}
	if err := checkBaseURL(endpoint); err != nil {
		return AWSCredentials{}, err
	}
	form := url.Values{
		"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"},
		"RoleArn": {w.RoleARN}, "RoleSessionName": {"acra"},
		"WebIdentityToken": {strings.TrimSpace(string(tok))}, "DurationSeconds": {"3600"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return AWSCredentials{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	data, err := httpDo(w.HTTP, req)
	if err != nil {
		return AWSCredentials{}, fmt.Errorf("aws sts: %w", err)
	}
	var x struct {
		AccessKeyID  string `xml:"AssumeRoleWithWebIdentityResult>Credentials>AccessKeyId"`
		SecretKey    string `xml:"AssumeRoleWithWebIdentityResult>Credentials>SecretAccessKey"`
		SessionToken string `xml:"AssumeRoleWithWebIdentityResult>Credentials>SessionToken"`
		Expiration   string `xml:"AssumeRoleWithWebIdentityResult>Credentials>Expiration"`
	}
	if err := xml.Unmarshal(data, &x); err != nil || x.AccessKeyID == "" {
		return AWSCredentials{}, errors.New("aws sts: unexpected response")
	}
	exp, err := time.Parse(time.RFC3339, x.Expiration)
	if err != nil {
		exp = time.Now().Add(30 * time.Minute)
	}
	w.cached = AWSCredentials{AccessKeyID: x.AccessKeyID, SecretAccessKey: x.SecretKey, SessionToken: x.SessionToken}
	w.expiry = exp
	return w.cached, nil
}

// safeLogGroup matches CloudWatch log group names (they may start with "/").
var safeLogGroup = regexp.MustCompile(`^[A-Za-z0-9_.\-/#]{1,512}$`)

// AWS reads CloudWatch Logs with FilterLogEvents. Read-only; signed with SigV4.
type AWS struct {
	Region    string
	Endpoint  string // default https://logs.<region>.amazonaws.com/
	LogGroups []string
	Creds     AWSCredentialSource
	HTTP      *http.Client
	Now       func() time.Time // for tests
}

// Name implements Adapter.
func (a *AWS) Name() string { return "aws" }

func (a *AWS) endpoint() string {
	if a.Endpoint != "" {
		return a.Endpoint
	}
	return "https://logs." + a.Region + ".amazonaws.com/"
}

// filterPattern builds a CloudWatch filter pattern matching any of the given
// (already validated) terms. Terms are quoted, so they match as exact strings.
func filterPattern(terms []string) string {
	if len(terms) == 1 {
		return `"` + terms[0] + `"`
	}
	parts := make([]string, len(terms))
	for i, t := range terms {
		parts[i] = `?"` + t + `"`
	}
	return strings.Join(parts, " ")
}

// Fetch implements Adapter.
func (a *AWS) Fetch(ctx context.Context, q Query) (Result, error) {
	q, err := q.Validate()
	if err != nil {
		return Result{}, err
	}
	if a.Region == "" || !SafeID(a.Region) || len(a.LogGroups) == 0 {
		return Result{}, errors.New("aws: region and at least one log group are required")
	}
	if err := checkBaseURL(a.endpoint()); err != nil {
		return Result{}, err
	}
	var terms []string
	for _, t := range []string{q.TraceID, q.AgentID} {
		if t != "" {
			terms = append(terms, t)
		}
	}
	if len(terms) == 0 {
		terms = append(terms, q.Service)
	}
	creds, err := a.Creds.Credentials(ctx)
	if err != nil {
		return Result{}, err
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	res := Result{Source: "aws", Signals: []Signal{}}
	var failures []string
	for _, g := range a.LogGroups {
		if !safeLogGroup.MatchString(g) {
			failures = append(failures, "invalid log group name")
			continue
		}
		body, _ := json.Marshal(map[string]any{
			"logGroupName": g, "startTime": q.Start.UnixMilli(), "endTime": q.End.UnixMilli(),
			"filterPattern": filterPattern(terms), "limit": q.Limit,
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint(), bytes.NewReader(body))
		if err != nil {
			return Result{}, err
		}
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", "Logs_20140328.FilterLogEvents")
		if err := SignV4(req, body, creds, a.Region, "logs", now()); err != nil {
			return Result{}, err
		}
		data, err := httpDo(a.HTTP, req)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", g, err))
			continue
		}
		var out struct {
			Events []struct {
				EventID       string `json:"eventId"`
				LogStreamName string `json:"logStreamName"`
				Message       string `json:"message"`
				Timestamp     int64  `json:"timestamp"`
			} `json:"events"`
			NextToken string `json:"nextToken"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			failures = append(failures, g+": bad response")
			continue
		}
		for _, e := range out.Events {
			res.Signals = append(res.Signals, Signal{
				Source: "aws", Kind: "log", Time: time.UnixMilli(e.Timestamp).UTC(),
				Severity: guessSeverity(e.Message), Resource: g + "/" + e.LogStreamName,
				Message: clip(e.Message, 1000), Ref: e.EventID,
			})
		}
		if out.NextToken != "" {
			res.Partial = true
			res.Warnings = append(res.Warnings, g+": more events exist than the limit returned")
		}
	}
	if len(failures) > 0 {
		res.Partial = true
		for _, f := range failures {
			res.Warnings = append(res.Warnings, "log group failed: "+clip(f, 200))
		}
		if len(failures) == len(a.LogGroups) {
			return Result{}, errors.New("aws: every log group query failed: " + clip(failures[0], 200))
		}
	}
	return res, nil
}

// guessSeverity classifies unstructured log text. It is a heuristic, and is
// only used where the source carries no severity field of its own.
func guessSeverity(msg string) string {
	u := strings.ToUpper(msg)
	switch {
	case strings.Contains(u, "FATAL"), strings.Contains(u, "PANIC"), strings.Contains(u, "CRITICAL"):
		return "critical"
	case strings.Contains(u, "ERROR"), strings.Contains(u, "EXCEPTION"), strings.Contains(u, "TRACEBACK"):
		return "error"
	case strings.Contains(u, "WARN"):
		return "warning"
	}
	return "info"
}
