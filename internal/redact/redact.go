// Package redact masks credentials and common PII before text is stored,
// logged, shown to an operator, or sent to a language model.
package redact

import "regexp"

const mask = "[REDACTED]"

var rules = []*regexp.Regexp{
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),                                            // AWS access key id
	regexp.MustCompile(`\bASIA[0-9A-Z]{16}\b`),                                            // AWS temp key id
	regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),                                      // Google API key
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`),                                  // GitHub token
	regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`), // JWT
	regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-+/=]{12,}`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{20,}\b`), // OpenAI-style key
	regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token|client[_-]?secret|authorization)\b("?\s*[:=]\s*"?)[^\s",;&]{4,}`),
	regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`), // email
	regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),                                // US SSN shape
	regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`),                              // card-number shape
}

// kvRule is the key=value rule, which keeps the key and masks only the value.
var kvRule = rules[8]

// String masks sensitive substrings. It is deliberately conservative: it may
// over-redact, never under-redact the patterns it knows about.
func String(s string) string {
	for _, r := range rules {
		if r == kvRule {
			s = r.ReplaceAllString(s, "${1}${2}"+mask)
			continue
		}
		s = r.ReplaceAllString(s, mask)
	}
	return s
}

// Map returns a redacted copy of a string map.
func Map(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = String(v)
	}
	return out
}
