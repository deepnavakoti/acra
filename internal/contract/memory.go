package contract

import (
	"fmt"
	"regexp"

	"github.com/deepnavakoti/acra/internal/agentrun"
)

// MemoryRules constrain how an agent uses long-term memory tools. ACRA does not
// see inside the memory store: it checks the tool calls an agent made to it, so
// tools must be named explicitly (a name that is not listed is not treated as
// memory). All checks are deterministic.
type MemoryRules struct {
	WriteTools             []string `json:"writeTools,omitempty"`
	ReadTools              []string `json:"readTools,omitempty"`
	MaxWrites              int      `json:"maxWrites,omitempty"`
	MaxReads               int      `json:"maxReads,omitempty"`
	MaxWriteBytes          int      `json:"maxWriteBytes,omitempty"`          // size of one write call's input
	ForbiddenWritePatterns []string `json:"forbiddenWritePatterns,omitempty"` // regexes the written content must not match
}

func (m MemoryRules) empty() bool {
	return len(m.WriteTools) == 0 && len(m.ReadTools) == 0 && m.MaxWrites == 0 && m.MaxReads == 0 &&
		m.MaxWriteBytes == 0 && len(m.ForbiddenWritePatterns) == 0
}

// validate rejects rules that could silently never fire.
func (m MemoryRules) validate(id string) error {
	if m.MaxWrites < 0 || m.MaxReads < 0 || m.MaxWriteBytes < 0 {
		return fmt.Errorf("contract %s: memory limits must not be negative", id)
	}
	if len(m.WriteTools) == 0 && (m.MaxWrites > 0 || m.MaxWriteBytes > 0 || len(m.ForbiddenWritePatterns) > 0) {
		return fmt.Errorf("contract %s: memory write rules need memory.writeTools", id)
	}
	if len(m.ReadTools) == 0 && m.MaxReads > 0 {
		return fmt.Errorf("contract %s: memory.maxReads needs memory.readTools", id)
	}
	writes := map[string]bool{}
	for _, n := range m.WriteTools {
		if n == "" {
			return fmt.Errorf("contract %s: memory tool names must not be empty", id)
		}
		writes[n] = true
	}
	for _, n := range m.ReadTools {
		if n == "" {
			return fmt.Errorf("contract %s: memory tool names must not be empty", id)
		}
		if writes[n] {
			return fmt.Errorf("contract %s: memory tool %q is listed as both read and write", id, n)
		}
	}
	for _, p := range m.ForbiddenWritePatterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("contract %s: memory.forbiddenWritePatterns %q: %w", id, p, err)
		}
	}
	return nil
}

func checkMemory(c *Contract, run agentrun.Run, add func(Violation)) {
	m := c.Memory
	if m.empty() {
		return
	}
	writeSet := map[string]bool{}
	for _, n := range m.WriteTools {
		writeSet[n] = true
	}
	readSet := map[string]bool{}
	for _, n := range m.ReadTools {
		readSet[n] = true
	}
	var writes, reads int
	var unseen []string // write calls whose input was not captured
	for _, t := range run.Of(agentrun.KindTool) {
		switch {
		case readSet[t.Name]:
			reads++
		case writeSet[t.Name]:
			writes++
			if m.MaxWriteBytes == 0 && len(m.ForbiddenWritePatterns) == 0 {
				continue
			}
			if len(t.Input) == 0 {
				unseen = append(unseen, refs(t)...)
				continue
			}
			if m.MaxWriteBytes > 0 && len(t.Input) > m.MaxWriteBytes {
				add(Violation{
					Rule: "memory.writeBytes", Category: "tool", Status: "violated", Severity: "medium", Deterministic: true,
					Message:   fmt.Sprintf("memory write %q carried %d bytes (limit %d)", t.Name, len(t.Input), m.MaxWriteBytes),
					EventRefs: refs(t),
				})
			}
			text := string(t.Input)
			for i, p := range m.ForbiddenWritePatterns {
				if re, err := regexp.Compile(p); err == nil && re.MatchString(text) {
					// The matched text is not echoed: it may be the secret being detected.
					add(Violation{
						Rule: fmt.Sprintf("memory.forbiddenWrite[%d]", i), Category: "safety", Status: "violated",
						Severity: "high", Deterministic: true, EventRefs: refs(t),
						Message: fmt.Sprintf("memory write %q matches a forbidden pattern", t.Name),
					})
				}
			}
		}
	}
	if m.MaxWrites > 0 && writes > m.MaxWrites {
		add(Violation{
			Rule: "memory.maxWrites", Category: "tool", Status: "violated", Severity: "medium", Deterministic: true,
			Message: fmt.Sprintf("%d memory writes (limit %d)", writes, m.MaxWrites),
		})
	}
	if m.MaxReads > 0 && reads > m.MaxReads {
		add(Violation{
			Rule: "memory.maxReads", Category: "tool", Status: "violated", Severity: "low", Deterministic: true,
			Message: fmt.Sprintf("%d memory reads (limit %d)", reads, m.MaxReads),
		})
	}
	if len(unseen) > 0 {
		// Absent input is not evidence the write was clean.
		add(Violation{
			Rule: "memory.inputCaptured", Category: "tool", Status: "unknown", Severity: "medium", Deterministic: true,
			Message:   "memory write input was not captured, so write content rules cannot be checked",
			EventRefs: unseen,
		})
	}
}
