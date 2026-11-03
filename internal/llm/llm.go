// Package llm is a minimal OpenAI-compatible chat-completions client. It is the
// only place ACRA talks to a language model, and it is optional: every caller
// has a deterministic path that works with no model configured.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Completer is the seam used by the judge and the RCA reasoner, so tests and
// air-gapped deployments can substitute a fake or disable the model entirely.
type Completer interface {
	Complete(ctx context.Context, system, user string) (string, error)
}

// Client talks to any OpenAI-compatible /chat/completions endpoint.
type Client struct {
	BaseURL     string // e.g. https://api.openai.com/v1
	APIKey      string
	Model       string
	MaxTokens   int
	Temperature float64
	HTTP        *http.Client
}

const maxResponse = 1 << 20

// Validate refuses plaintext non-loopback endpoints so an API key is never sent
// in the clear.
func (c *Client) Validate() error {
	if c.Model == "" {
		return errors.New("llm: model is required")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" {
		return errors.New("llm: invalid base URL")
	}
	if u.Scheme != "https" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if u.Scheme != "http" || !(host == "localhost" || (ip != nil && ip.IsLoopback())) {
			return errors.New("llm: base URL must be https (http is allowed for loopback only)")
		}
	}
	return nil
}

// Complete sends one system+user exchange and returns the assistant text.
func (c *Client) Complete(ctx context.Context, system, user string) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	body := map[string]any{
		"model": c.Model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"temperature": c.Temperature,
	}
	if c.MaxTokens > 0 {
		body["max_tokens"] = c.MaxTokens
	}
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(c.BaseURL, "/")+"/chat/completions", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("llm: request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("llm: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("llm: bad response: %w", err)
	}
	if len(out.Choices) == 0 {
		return "", errors.New("llm: no choices returned")
	}
	return out.Choices[0].Message.Content, nil
}

// ExtractJSON pulls the first top-level JSON object out of model text that may
// be wrapped in prose or code fences.
func ExtractJSON(s string) (json.RawMessage, bool) {
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return nil, false
	}
	depth, inStr, esc := 0, false, false
	for i := start; i < len(s); i++ {
		ch := s[i]
		switch {
		case esc:
			esc = false
		case inStr && ch == '\\':
			esc = true
		case ch == '"':
			inStr = !inStr
		case !inStr && ch == '{':
			depth++
		case !inStr && ch == '}':
			depth--
			if depth == 0 {
				raw := json.RawMessage(s[start : i+1])
				if json.Valid(raw) {
					return raw, true
				}
				return nil, false
			}
		}
	}
	return nil, false
}
