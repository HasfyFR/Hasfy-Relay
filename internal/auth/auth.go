// Package auth verifies the two distinct credential types this relay accepts:
//
//	1. Agent bearer tokens — issued by Hasfy-App when a device enrolls.
//	   HMAC-SHA256 signed with the shared secret in Vault hasfy/relay/svc-hmac.
//	   Claims: device_id, org_id, exp.
//
//	2. Operator session tokens — minted by THIS relay's /api/console endpoint
//	   after Hasfy-App proves identity via the service HMAC. They authorize a
//	   single browser to attach to a single device for a short window.
//	   Claims: org_id, device_id, session_id, sub (operator_user_id),
//	          ip_hash, ua_hash, exp.
//
// Phase 1.4 will add mTLS for agents (cert-manager + Vault PKI). For now,
// bearer-only is acceptable because the WS endpoint is reachable only via
// the public ingress AND every connection is rate-limited and audited.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrUnauthorized is returned for any verification failure. Callers MUST
// NOT leak the underlying reason to clients (only to logs).
var ErrUnauthorized = errors.New("unauthorized")

// AgentClaims are the validated claims of an agent bearer token.
type AgentClaims struct {
	DeviceID string `json:"device_id"`
	OrgID    string `json:"org_id"`
	jwt.RegisteredClaims
}

// SessionClaims are the validated claims of an operator session token.
type SessionClaims struct {
	OrgID     string `json:"org_id"`
	DeviceID  string `json:"device_id"`
	SessionID string `json:"sid"`
	IPHash    string `json:"iph"`
	UAHash    string `json:"uah"`
	jwt.RegisteredClaims
}

// Verifier holds the symmetric keys used to verify tokens. Keys are loaded
// from Vault at startup; rotation requires a relay restart (acceptable —
// the relay is stateless from the operator's perspective).
type Verifier struct {
	agentSecret   []byte // HMAC-SHA256 — verifies tokens minted by Hasfy-App
	sessionSecret []byte // HMAC-SHA256 — verifies tokens minted by this relay
}

func NewVerifier(agentSecret, sessionSecret []byte) (*Verifier, error) {
	if len(agentSecret) < 32 || len(sessionSecret) < 32 {
		return nil, errors.New("auth secrets must be at least 32 bytes")
	}
	return &Verifier{agentSecret: agentSecret, sessionSecret: sessionSecret}, nil
}

// VerifyAgent parses and validates a bearer token presented by an agent.
func (v *Verifier) VerifyAgent(token string) (*AgentClaims, error) {
	c := &AgentClaims{}
	t, err := jwt.ParseWithClaims(token, c, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("alg %q not allowed", t.Method.Alg())
		}
		return v.agentSecret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !t.Valid {
		return nil, ErrUnauthorized
	}
	if c.DeviceID == "" || c.OrgID == "" {
		return nil, ErrUnauthorized
	}
	return c, nil
}

// VerifySession validates a session token AND binds it to the connecting
// browser's IP and User-Agent. Mismatch ⇒ unauthorized (replay defense).
func (v *Verifier) VerifySession(token, ip, ua string) (*SessionClaims, error) {
	c := &SessionClaims{}
	t, err := jwt.ParseWithClaims(token, c, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("alg %q not allowed", t.Method.Alg())
		}
		return v.sessionSecret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !t.Valid {
		return nil, ErrUnauthorized
	}
	if c.SessionID == "" || c.DeviceID == "" || c.OrgID == "" {
		return nil, ErrUnauthorized
	}
	if !hashEq(c.IPHash, ip) || !hashEq(c.UAHash, ua) {
		return nil, ErrUnauthorized
	}
	return c, nil
}

// IssueSession mints a single-use session token bound to the operator's IP
// and UA. TTL is hardcoded to 5 minutes — the browser must connect quickly.
func (v *Verifier) IssueSession(orgID, deviceID, sessionID, sub, ip, ua string) (string, error) {
	now := time.Now()
	c := SessionClaims{
		OrgID:     orgID,
		DeviceID:  deviceID,
		SessionID: sessionID,
		IPHash:    hashHex(ip),
		UAHash:    hashHex(ua),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			ID:        sessionID,
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return t.SignedString(v.sessionSecret)
}

func hashHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func hashEq(expectedHex, raw string) bool {
	got := hashHex(raw)
	return subtle.ConstantTimeCompare([]byte(expectedHex), []byte(got)) == 1
}
