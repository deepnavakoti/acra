package adapters

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// KAgent is a client for a KAgent-hosted agent exposed over the A2A (agent to
// agent) JSON-RPC protocol. It is used in two ways:
//
//  1. As a Responder, to ask a diagnostic agent for an independent opinion
//     during an investigation (advisory only: its answer is stored as
//     evidence labelled "reasoning" and never decides a verdict).
//  2. As an Adapter, returning that opinion as a Signal of Kind "reasoning".
//
// The JSON-RPC method name and endpoint layout are configurable because they
// differ between KAgent releases; verify them against your deployed version.
type KAgent struct {
	Endpoint string // full A2A endpoint URL of the agent
	Method   string // default "message/send"
	Token    TokenSource
	HTTP     *http.Client
}

// Name implements Adapter.
func (k *KAgent) Name() string { return "kagent" }

// Ask sends one message and returns the agent's text reply.
func (k *KAgent) Ask(ctx context.Context, prompt string) (string, error) {
	if err := checkBaseURL(k.Endpoint); err != nil {
		return "", err
	}
	method := k.Method
	if method == "" {
		method = "message/send"
	}
	var idb [8]byte
	_, _ = rand.Read(idb[:])
	msgID := hex.EncodeToString(idb[:])
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": msgID, "method": method,
		"params": map[string]any{
			"message": map[string]any{
				"role": "user", "messageId": msgID,
				"parts": []map[string]string{{"kind": "text", "text": prompt}},
			},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if k.Token != nil {
		tok, err := k.Token.Token(ctx)
		if err != nil {
			return "", fmt.Errorf("kagent: token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	data, err := httpDo(k.HTTP, req)
	if err != nil {
		return "", fmt.Errorf("kagent: %w", err)
	}
	var rpc struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &rpc); err != nil {
		return "", fmt.Errorf("kagent: bad response: %w", err)
	}
	if rpc.Error != nil {
		return "", fmt.Errorf("kagent: rpc error %d: %s", rpc.Error.Code, clip(rpc.Error.Message, 200))
	}
	text := collectText(rpc.Result, 0)
	if strings.TrimSpace(text) == "" {
		return "", errors.New("kagent: reply contained no text")
	}
	return text, nil
}

// collectText walks an A2A result (a Message, or a Task with artifacts/history)
// and concatenates text parts, bounded in depth.
func collectText(raw json.RawMessage, depth int) string {
	if depth > 6 || len(raw) == 0 {
		return ""
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	var parts []string
	var walk func(x any, d int)
	walk = func(x any, d int) {
		if d > 8 {
			return
		}
		switch t := x.(type) {
		case map[string]any:
			if k, _ := t["kind"].(string); k == "text" {
				if s, ok := t["text"].(string); ok {
					parts = append(parts, s)
					return
				}
			}
			for _, key := range []string{"parts", "artifacts", "message", "status", "history"} {
				if c, ok := t[key]; ok {
					walk(c, d+1)
				}
			}
		case []any:
			for _, c := range t {
				walk(c, d+1)
			}
		}
	}
	walk(v, 0)
	return strings.Join(parts, "\n")
}

// Fetch implements Adapter by asking the agent to summarize the incident
// window. The reply is untrusted text: it is redacted, length-capped and
// labelled as reasoning, never as observed fact.
func (k *KAgent) Fetch(ctx context.Context, q Query) (Result, error) {
	q, err := q.Validate()
	if err != nil {
		return Result{}, err
	}
	prompt := fmt.Sprintf("Diagnose agent %q (trace %q, service %q, namespace %q) between %s and %s. "+
		"Reply with likely causes and the evidence you would check. Do not take any action.",
		q.AgentID, q.TraceID, q.Service, q.Namespace, q.Start.Format(time.RFC3339), q.End.Format(time.RFC3339))
	text, err := k.Ask(ctx, prompt)
	if err != nil {
		return Result{}, err
	}
	return Result{Source: "kagent", Signals: []Signal{{
		Source: "kagent", Kind: "reasoning", Time: q.End, Severity: "info",
		Resource: k.Endpoint, Message: clip(text, 2000),
		Attrs: map[string]string{"trust": "advisory"},
	}}}, nil
}
