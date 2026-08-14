package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestLoadOrCreateIdentityGeneratesThenReuses(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "device.key")

	first, created, err := loadOrCreateIdentity(keyPath, "dev-1")
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if !created {
		t.Fatal("expected the first call to generate a key")
	}

	second, created, err := loadOrCreateIdentity(keyPath, "dev-1")
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if created {
		t.Fatal("expected the second call to reuse the key on disk")
	}
	// Regenerating instead of reusing would desync the private key from the
	// public key registered with Hasfy-App, and the device would silently stop
	// being able to obtain a token.
	if !first.key.Equal(second.key) {
		t.Fatal("key changed across loads")
	}
}

func TestGeneratedKeyIsOwnerOnly(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "device.key")
	if _, _, err := loadOrCreateIdentity(keyPath, "dev-1"); err != nil {
		t.Fatalf("load: %v", err)
	}
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// This file is the device's whole identity.
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode is %v, want 0600", perm)
	}
}

func TestLoadOrCreateIdentityRejectsMalformedKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "device.key")
	if err := os.WriteFile(keyPath, []byte("too short"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Silently regenerating would orphan the registered public key; refusing
	// makes the problem visible instead.
	if _, _, err := loadOrCreateIdentity(keyPath, "dev-1"); err == nil {
		t.Fatal("expected a malformed key to be rejected")
	}
}

func TestSignAssertionVerifiesAgainstPublicKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "device.key")
	id, _, err := loadOrCreateIdentity(keyPath, "equipment-42")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	assertion, err := id.signAssertion()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(id.publicKeyBase64URL())
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		t.Fatalf("public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}

	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(assertion, claims, func(*jwt.Token) (any, error) {
		return ed25519.PublicKey(raw), nil
	}, jwt.WithValidMethods([]string{"EdDSA"}))
	if err != nil || !tok.Valid {
		t.Fatalf("assertion did not verify: %v", err)
	}

	if claims["sub"] != "equipment-42" {
		t.Errorf("sub = %v", claims["sub"])
	}
	// The audience binds the assertion to the token endpoint, so a signature
	// captured elsewhere cannot be replayed to obtain a relay token.
	if claims["aud"] != assertionAudience {
		t.Errorf("aud = %v, want %q", claims["aud"], assertionAudience)
	}
	if jti, ok := claims["jti"].(string); !ok || jti == "" {
		t.Error("assertion carries no jti — the server could not make it single-use")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatal("assertion carries no exp")
	}
	if life := time.Until(time.Unix(int64(exp), 0)); life > 5*time.Minute {
		t.Errorf("assertion lifetime %v is too long", life)
	}
}

func TestSignAssertionProducesFreshJTIs(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "device.key")
	id, _, _ := loadOrCreateIdentity(keyPath, "dev-1")

	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		a, err := id.signAssertion()
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		claims := jwt.MapClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(a, claims); err != nil {
			t.Fatalf("parse: %v", err)
		}
		jti, _ := claims["jti"].(string)
		// A repeated jti would be rejected by the server's replay check and
		// the device would lock itself out.
		if seen[jti] {
			t.Fatalf("duplicate jti %q", jti)
		}
		seen[jti] = true
	}
}

func TestRemoveEnvKeyWipesOnlyThatLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "agent.env")
	body := strings.Join([]string{
		"HASFY_RELAY_URL=wss://relay.hasfy.fr/agent/ws",
		"HASFY_API_URL=https://app.hasfy.fr",
		"HASFY_DEVICE_ID=dev-1",
		"HASFY_ORG_ID=org-1",
		envDeviceEnrollmentToken + "=one-shot-secret",
		"",
	}, "\n")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := removeEnvKey(p, envDeviceEnrollmentToken); err != nil {
		t.Fatalf("removeEnvKey: %v", err)
	}

	got, _ := os.ReadFile(p)
	out := string(got)
	if strings.Contains(out, "one-shot-secret") {
		t.Errorf("spent enrollment secret still on disk:\n%s", out)
	}
	for _, want := range []string{
		"HASFY_RELAY_URL=wss://relay.hasfy.fr/agent/ws",
		"HASFY_API_URL=https://app.hasfy.fr",
		"HASFY_DEVICE_ID=dev-1",
		"HASFY_ORG_ID=org-1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lost line %q:\n%s", want, out)
		}
	}
}

func TestRemoveEnvKeyKeepsPermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.env")
	if err := os.WriteFile(p, []byte(envDeviceEnrollmentToken+"=s\nHASFY_ORG_ID=o\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := removeEnvKey(p, envDeviceEnrollmentToken); err != nil {
		t.Fatalf("removeEnvKey: %v", err)
	}
	fi, _ := os.Stat(p)
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("permissions widened to %v via the rename", perm)
	}
}

func TestRemoveEnvKeyIsIdempotent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.env")
	if err := os.WriteFile(p, []byte("HASFY_ORG_ID=o\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A daemon restarting after a successful registration must not error out
	// just because the secret is already gone.
	if err := removeEnvKey(p, envDeviceEnrollmentToken); err != nil {
		t.Fatalf("removing an absent key should be a no-op, got %v", err)
	}
}
