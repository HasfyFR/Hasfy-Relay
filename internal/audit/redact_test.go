package audit

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"aws-access", "key=AKIAIOSFODNN7EXAMPLE rest"},
		{"github", "token=ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
		{"jwt", "auth=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJoZWxsbyJ9.deadbeefcafebabe"},
		{"vault", "VAULT_TOKEN=hvs.AAAAAAAAAAAAAAAAAAAAAAAA"},
		{"password", "DB_PASSWORD=hunter2hunter2"},
		{"pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := Redact(tc.in)
			if !strings.Contains(out, "[REDACTED]") {
				t.Fatalf("expected redaction, got %q", out)
			}
			// Idempotency.
			if Redact(out) != out {
				t.Fatalf("redact not idempotent")
			}
		})
	}
}

func TestRedactKeepsBenignText(t *testing.T) {
	in := "Hello world, today is sunny. file=/var/log/syslog count=42"
	if out := Redact(in); out != in {
		t.Fatalf("benign text mutated: %q", out)
	}
}
