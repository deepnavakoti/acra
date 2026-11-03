package redact

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	secrets := []string{
		"AKIAABCDEFGHIJKLMNOP", "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
		"Bearer abcdef1234567890xyz", "hunter2secret", "alice@example.com", "123-45-6789",
		"sk-abcdefghijklmnopqrstuvwx", "4111 1111 1111 1111",
	}
	in := "k=AKIAABCDEFGHIJKLMNOP gh=ghp_abcdefghijklmnopqrstuvwxyz0123456789 " +
		"jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop " +
		"Authorization: Bearer abcdef1234567890xyz password=hunter2secret mail alice@example.com " +
		"ssn 123-45-6789 key sk-abcdefghijklmnopqrstuvwx card 4111 1111 1111 1111"
	out := String(in)
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("not redacted: %q in %q", s, out)
		}
	}
	if !strings.Contains(out, "password=") {
		t.Error("key name should be preserved for readability")
	}
}

func TestString_KeepsOrdinaryText(t *testing.T) {
	in := "tool lookup took 120ms and returned 5 rows"
	if got := String(in); got != in {
		t.Fatalf("over-redacted: %q", got)
	}
}

func TestPrivateKeyBlock(t *testing.T) {
	in := "x -----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY----- y"
	if strings.Contains(String(in), "MIIabc") {
		t.Fatal("private key leaked")
	}
}
