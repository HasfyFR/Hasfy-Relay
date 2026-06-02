package audit

import "regexp"

// redactors masks high-confidence secret patterns in command output before
// it is shipped to ES or shown to operators in audit replays.
//
// We err on the side of false positives. Patterns must be anchored on
// recognizable prefixes (sk-, ghp_, AKIA, etc.) to avoid mauling legitimate
// strings.
var redactors = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                            // AWS access key
	regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*\S+`),         // AWS secret
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),                  // GitHub PAT/OAuth/refresh
	regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`),                // Slack
	regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),                         // OpenAI / Anthropic-style
	regexp.MustCompile(`hvs\.[A-Za-z0-9_-]{20,}`),                     // Vault token
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), // JWT
	regexp.MustCompile(`-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*["']?[^\s"']{6,}`),
}

// Redact replaces each match with a fixed marker that retains length hints
// only via the marker string itself (no length leak). Idempotent.
func Redact(s string) string {
	for _, re := range redactors {
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}
