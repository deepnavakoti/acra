package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// GCP reads Cloud Logging through entries.list. Read-only.
type GCP struct {
	Endpoint  string // default https://logging.googleapis.com
	ProjectID string
	Tokens    TokenSource
	HTTP      *http.Client
}

// Name implements Adapter.
func (g *GCP) Name() string { return "gcp" }

func (g *GCP) endpoint() string {
	if g.Endpoint != "" {
		return strings.TrimRight(g.Endpoint, "/")
	}
	return "https://logging.googleapis.com"
}

// buildFilter composes the Logging query. Values were validated by SafeID so
// they cannot contain a quote or newline that would alter the filter.
func buildFilter(q Query) string {
	var terms []string
	if q.TraceID != "" {
		terms = append(terms, fmt.Sprintf(`trace:"%s"`, q.TraceID))
		terms = append(terms, fmt.Sprintf(`jsonPayload.trace_id="%s"`, q.TraceID))
	}
	if q.AgentID != "" {
		terms = append(terms, fmt.Sprintf(`jsonPayload.agent_id="%s"`, q.AgentID))
	}
	if q.Service != "" {
		terms = append(terms, fmt.Sprintf(`resource.labels.service_name="%s"`, q.Service))
	}
	return fmt.Sprintf(`(%s) AND timestamp>="%s" AND timestamp<="%s"`,
		strings.Join(terms, " OR "), q.Start.Format(time.RFC3339), q.End.Format(time.RFC3339))
}

// Fetch implements Adapter.
func (g *GCP) Fetch(ctx context.Context, q Query) (Result, error) {
	q, err := q.Validate()
	if err != nil {
		return Result{}, err
	}
	if !SafeID(g.ProjectID) {
		return Result{}, errors.New("gcp: invalid project id")
	}
	if err := checkBaseURL(g.endpoint()); err != nil {
		return Result{}, err
	}
	tok, err := g.Tokens.Token(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("gcp: token: %w", err)
	}
	body, _ := json.Marshal(map[string]any{
		"resourceNames": []string{"projects/" + g.ProjectID},
		"filter":        buildFilter(q), "orderBy": "timestamp asc", "pageSize": q.Limit,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.endpoint()+"/v2/entries:list", bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	data, err := httpDo(g.HTTP, req)
	if err != nil {
		return Result{}, fmt.Errorf("gcp: %w", err)
	}
	var out struct {
		Entries []struct {
			InsertID    string          `json:"insertId"`
			Timestamp   string          `json:"timestamp"`
			Severity    string          `json:"severity"`
			TextPayload string          `json:"textPayload"`
			JSONPayload json.RawMessage `json:"jsonPayload"`
			Resource    struct {
				Type   string            `json:"type"`
				Labels map[string]string `json:"labels"`
			} `json:"resource"`
		} `json:"entries"`
		NextPageToken string `json:"nextPageToken"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return Result{}, fmt.Errorf("gcp: bad response: %w", err)
	}
	res := Result{Source: "gcp", Signals: []Signal{}}
	for _, e := range out.Entries {
		ts, _ := time.Parse(time.RFC3339Nano, e.Timestamp)
		msg := e.TextPayload
		if msg == "" && len(e.JSONPayload) > 0 {
			var jp map[string]any
			if json.Unmarshal(e.JSONPayload, &jp) == nil {
				for _, k := range []string{"message", "msg", "error"} {
					if s, ok := jp[k].(string); ok && s != "" {
						msg = s
						break
					}
				}
			}
			if msg == "" {
				msg = string(e.JSONPayload)
			}
		}
		name := e.Resource.Labels["service_name"]
		if name == "" {
			name = e.Resource.Type
		}
		res.Signals = append(res.Signals, Signal{
			Source: "gcp", Kind: "log", Time: ts, Severity: gcpSeverity(e.Severity),
			Resource: name, Message: clip(msg, 1000), Ref: e.InsertID,
		})
	}
	if out.NextPageToken != "" {
		res.Partial = true
		res.Warnings = append(res.Warnings, "more log entries exist than the limit returned")
	}
	return res, nil
}

func gcpSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "DEBUG", "DEFAULT":
		return "debug"
	case "WARNING":
		return "warning"
	case "ERROR":
		return "error"
	case "CRITICAL", "ALERT", "EMERGENCY":
		return "critical"
	}
	return "info"
}
