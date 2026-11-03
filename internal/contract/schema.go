package contract

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"unicode/utf8"
)

// Schema is a deliberately small JSON-Schema subset, enough to pin an agent's
// output shape deterministically without a third-party dependency.
type Schema struct {
	Type       string             `json:"type,omitempty"` // object|array|string|number|integer|boolean|null
	Required   []string           `json:"required,omitempty"`
	Properties map[string]*Schema `json:"properties,omitempty"`
	Items      *Schema            `json:"items,omitempty"`
	Enum       []json.RawMessage  `json:"enum,omitempty"`
	MinLength  *int               `json:"minLength,omitempty"`
	MaxLength  *int               `json:"maxLength,omitempty"`
	Minimum    *float64           `json:"minimum,omitempty"`
	Maximum    *float64           `json:"maximum,omitempty"`
	MinItems   *int               `json:"minItems,omitempty"`
	MaxItems   *int               `json:"maxItems,omitempty"`
	Pattern    string             `json:"pattern,omitempty"`
	// AdditionalProperties=false rejects keys not in Properties.
	AdditionalProperties *bool `json:"additionalProperties,omitempty"`
}

const maxSchemaDepth = 32

// Validate checks the schema itself (types, regexes), so a bad contract is
// rejected at load time rather than silently never failing.
func (s *Schema) Validate() error { return s.validateSelf(0) }

func (s *Schema) validateSelf(depth int) error {
	if s == nil {
		return nil
	}
	if depth > maxSchemaDepth {
		return fmt.Errorf("schema nested deeper than %d", maxSchemaDepth)
	}
	switch s.Type {
	case "", "object", "array", "string", "number", "integer", "boolean", "null":
	default:
		return fmt.Errorf("unknown schema type %q", s.Type)
	}
	if s.Pattern != "" {
		if _, err := regexp.Compile(s.Pattern); err != nil {
			return fmt.Errorf("bad pattern %q: %w", s.Pattern, err)
		}
	}
	for k, p := range s.Properties {
		if err := p.validateSelf(depth + 1); err != nil {
			return fmt.Errorf("properties.%s: %w", k, err)
		}
	}
	return s.Items.validateSelf(depth + 1)
}

// Check validates raw JSON against the schema and returns every problem found
// (sorted, so results are deterministic). Invalid JSON is itself a problem.
func (s *Schema) Check(raw json.RawMessage) []string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return []string{"output is not valid JSON"}
	}
	var probs []string
	s.check("$", v, &probs, 0)
	sort.Strings(probs)
	return probs
}

func typeOf(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		if x == float64(int64(x)) {
			return "integer"
		}
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

func (s *Schema) check(path string, v any, probs *[]string, depth int) {
	if s == nil || depth > maxSchemaDepth {
		return
	}
	got := typeOf(v)
	if s.Type != "" {
		ok := got == s.Type || (s.Type == "number" && got == "integer")
		if !ok {
			*probs = append(*probs, fmt.Sprintf("%s: expected %s, got %s", path, s.Type, got))
			return
		}
	}
	if len(s.Enum) > 0 {
		match := false
		b, _ := json.Marshal(v)
		for _, e := range s.Enum {
			var ev any
			if json.Unmarshal(e, &ev) == nil {
				eb, _ := json.Marshal(ev)
				if string(eb) == string(b) {
					match = true
					break
				}
			}
		}
		if !match {
			*probs = append(*probs, fmt.Sprintf("%s: value not in enum", path))
		}
	}
	switch x := v.(type) {
	case string:
		n := utf8.RuneCountInString(x)
		if s.MinLength != nil && n < *s.MinLength {
			*probs = append(*probs, fmt.Sprintf("%s: shorter than minLength %d", path, *s.MinLength))
		}
		if s.MaxLength != nil && n > *s.MaxLength {
			*probs = append(*probs, fmt.Sprintf("%s: longer than maxLength %d", path, *s.MaxLength))
		}
		if s.Pattern != "" {
			if re, err := regexp.Compile(s.Pattern); err == nil && !re.MatchString(x) {
				*probs = append(*probs, fmt.Sprintf("%s: does not match pattern", path))
			}
		}
	case float64:
		if s.Minimum != nil && x < *s.Minimum {
			*probs = append(*probs, fmt.Sprintf("%s: below minimum %v", path, *s.Minimum))
		}
		if s.Maximum != nil && x > *s.Maximum {
			*probs = append(*probs, fmt.Sprintf("%s: above maximum %v", path, *s.Maximum))
		}
	case []any:
		if s.MinItems != nil && len(x) < *s.MinItems {
			*probs = append(*probs, fmt.Sprintf("%s: fewer than minItems %d", path, *s.MinItems))
		}
		if s.MaxItems != nil && len(x) > *s.MaxItems {
			*probs = append(*probs, fmt.Sprintf("%s: more than maxItems %d", path, *s.MaxItems))
		}
		for i, it := range x {
			s.Items.check(fmt.Sprintf("%s[%d]", path, i), it, probs, depth+1)
		}
	case map[string]any:
		for _, r := range s.Required {
			if _, ok := x[r]; !ok {
				*probs = append(*probs, fmt.Sprintf("%s: missing required %q", path, r))
			}
		}
		for k, val := range x {
			if p, ok := s.Properties[k]; ok {
				p.check(path+"."+k, val, probs, depth+1)
			} else if s.AdditionalProperties != nil && !*s.AdditionalProperties {
				*probs = append(*probs, fmt.Sprintf("%s: unexpected property %q", path, k))
			}
		}
	}
}
