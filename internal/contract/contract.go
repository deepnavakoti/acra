// Package contract defines the Agent Contract: the versioned, machine-checkable
// statement of what an agent is supposed to do, and the evaluator that checks
// a finished agent Run against it. Deterministic checks always run first;
// rubric (LLM-judge) checks are optional and never override a deterministic
// failure.
package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
)

// Contract is the per-agent policy. JSON is the only supported format.
type Contract struct {
	ID          string `json:"id"`
	AgentID     string `json:"agentId"`
	Version     string `json:"version"`
	Environment string `json:"environment,omitempty"`
	Owner       string `json:"owner,omitempty"`
	Description string `json:"description,omitempty"`

	// OutputSchema pins the final response shape (deterministic).
	OutputSchema *Schema `json:"outputSchema,omitempty"`
	// ForbiddenPatterns are regexes that must not appear in the final output
	// (secrets, PII markers, banned content).
	ForbiddenPatterns []string `json:"forbiddenPatterns,omitempty"`

	Tools   ToolRules   `json:"tools,omitempty"`
	Memory  MemoryRules `json:"memory,omitempty"`
	Limits  Limits      `json:"limits,omitempty"`
	Rubrics []Rubric    `json:"rubrics,omitempty"`
}

// ToolRules constrain which tools the agent may or must call.
type ToolRules struct {
	Allowed         []string `json:"allowed,omitempty"`  // empty = no allowlist check
	Required        []string `json:"required,omitempty"` // must be called at least once
	MaxCalls        int      `json:"maxCalls,omitempty"`
	MaxCallsPerTool int      `json:"maxCallsPerTool,omitempty"`
	MaxRetries      int      `json:"maxRetries,omitempty"` // attempts beyond the first, per tool call
}

// Limits are operational budgets. Zero means "unchecked".
type Limits struct {
	MaxLatencyMs      int64   `json:"maxLatencyMs,omitempty"`
	MaxTotalTokens    int64   `json:"maxTotalTokens,omitempty"`
	MaxInputTokens    int64   `json:"maxInputTokens,omitempty"`
	MaxContextUtil    float64 `json:"maxContextUtilization,omitempty"` // 0..1 of the model window
	MaxToolDurationMs int64   `json:"maxToolDurationMs,omitempty"`
}

// Rubric is a semantic check scored by a Judge (0..1). It never replaces a
// deterministic check and is skipped, not failed, when no judge is configured.
type Rubric struct {
	ID          string  `json:"id"`
	Criterion   string  `json:"criterion"`
	MinScore    float64 `json:"minScore"`
	Description string  `json:"description,omitempty"`
}

// Validate rejects contracts that could silently never fail.
func (c *Contract) Validate() error {
	if c.ID == "" || c.AgentID == "" || c.Version == "" {
		return errors.New("contract: id, agentId and version are required")
	}
	if err := c.OutputSchema.Validate(); err != nil {
		return fmt.Errorf("contract %s: outputSchema: %w", c.ID, err)
	}
	for _, p := range c.ForbiddenPatterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("contract %s: forbiddenPatterns %q: %w", c.ID, p, err)
		}
	}
	if c.Limits.MaxContextUtil < 0 || c.Limits.MaxContextUtil > 1 {
		return fmt.Errorf("contract %s: maxContextUtilization must be within 0..1", c.ID)
	}
	if c.Limits.MaxLatencyMs < 0 || c.Limits.MaxTotalTokens < 0 || c.Limits.MaxInputTokens < 0 ||
		c.Limits.MaxToolDurationMs < 0 || c.Tools.MaxCalls < 0 || c.Tools.MaxCallsPerTool < 0 || c.Tools.MaxRetries < 0 {
		return fmt.Errorf("contract %s: limits must not be negative", c.ID)
	}
	if err := c.Memory.validate(c.ID); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, r := range c.Rubrics {
		if r.ID == "" || r.Criterion == "" {
			return fmt.Errorf("contract %s: rubric needs id and criterion", c.ID)
		}
		if seen[r.ID] {
			return fmt.Errorf("contract %s: duplicate rubric id %q", c.ID, r.ID)
		}
		seen[r.ID] = true
		if r.MinScore < 0 || r.MinScore > 1 {
			return fmt.Errorf("contract %s: rubric %s minScore must be within 0..1", c.ID, r.ID)
		}
	}
	return nil
}

// Parse decodes and validates one contract. Unknown fields are rejected so a
// typo in a limit name cannot silently disable the check.
func Parse(data []byte) (*Contract, error) {
	var c Contract
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("contract: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Registry holds versioned contracts per agent.
type Registry struct {
	mu   sync.RWMutex
	byID map[string]map[string]*Contract // agentId -> version -> contract
	cur  map[string]string               // agentId -> active version
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byID: map[string]map[string]*Contract{}, cur: map[string]string{}}
}

// Put stores a contract version and makes it the active one for its agent.
// Re-putting an existing version with different content is refused: a version
// is immutable so past evaluations stay explainable.
func (r *Registry) Put(c *Contract) error {
	if err := c.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	vs := r.byID[c.AgentID]
	if vs == nil {
		vs = map[string]*Contract{}
		r.byID[c.AgentID] = vs
	}
	if old, ok := vs[c.Version]; ok {
		a, _ := json.Marshal(old)
		b, _ := json.Marshal(c)
		if string(a) != string(b) {
			return fmt.Errorf("contract: %s version %s already exists with different content", c.AgentID, c.Version)
		}
		return nil
	}
	vs[c.Version] = c
	r.cur[c.AgentID] = c.Version
	return nil
}

// Get returns a specific version, or the active one when version is empty.
func (r *Registry) Get(agentID, version string) (*Contract, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if version == "" {
		version = r.cur[agentID]
	}
	c, ok := r.byID[agentID][version]
	return c, ok
}

// Versions lists the stored versions of an agent (sorted).
func (r *Registry) Versions(agentID string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []string
	for v := range r.byID[agentID] {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// All returns the active contract of every agent.
func (r *Registry) All() []*Contract {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Contract
	for a, v := range r.cur {
		out = append(out, r.byID[a][v])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgentID < out[j].AgentID })
	return out
}
