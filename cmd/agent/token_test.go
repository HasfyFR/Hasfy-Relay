package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testIdentity(t *testing.T) *deviceIdentity {
	t.Helper()
	id, _, err := loadOrCreateIdentity(filepath.Join(t.TempDir(), "device.key"), "dev-1")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return id
}

// withFastTokenStart removes the boot delay so scheduler tests run instantly.
func withFastTokenStart(t *testing.T) {
	t.Helper()
	prev := tokenInitialDelay
	tokenInitialDelay = 0
	t.Cleanup(func() { tokenInitialDelay = prev })
}

func tokenServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestAcquireTokenSendsSignedAssertion(t *testing.T) {
	var gotAuth string
	srv := tokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != deviceTokenPath {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data":    map[string]any{"agentToken": "relay.jwt", "ttlSeconds": 3600},
		})
	})

	tok, ttl, err := acquireToken(context.Background(), srv.URL, testIdentity(t))
	if err != nil {
		t.Fatalf("acquireToken: %v", err)
	}
	if tok != "relay.jwt" {
		t.Errorf("token = %q", tok)
	}
	if ttl != time.Hour {
		t.Errorf("ttl = %v", ttl)
	}
	// The assertion is the credential — a bearer secret is never sent.
	if !strings.HasPrefix(gotAuth, "Bearer ey") {
		t.Errorf("expected a signed assertion in Authorization, got %q", gotAuth)
	}
}

func TestAcquireTokenTrimsTrailingSlash(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != deviceTokenPath {
			t.Errorf("double slash leaked into path: %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data":    map[string]any{"agentToken": "t", "ttlSeconds": 3600},
		})
	})
	if _, _, err := acquireToken(context.Background(), srv.URL+"/", testIdentity(t)); err != nil {
		t.Fatalf("acquireToken: %v", err)
	}
}

func TestAcquireTokenMapsUnauthorizedToRefusal(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	_, _, err := acquireToken(context.Background(), srv.URL, testIdentity(t))
	if !errors.Is(err, errDeviceRefused) {
		t.Fatalf("expected errDeviceRefused, got %v", err)
	}
}

func TestAcquireTokenTreatsServerErrorAsTransient(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	_, _, err := acquireToken(context.Background(), srv.URL, testIdentity(t))
	if err == nil {
		t.Fatal("expected an error")
	}
	// A 502 is an upstream blip: the daemon must keep retrying, not give up.
	if errors.Is(err, errDeviceRefused) {
		t.Fatal("a 502 must not be treated as refusal")
	}
}

func TestAcquireTokenRejectsEmptyToken(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data":    map[string]any{"agentToken": ""},
		})
	})
	if _, _, err := acquireToken(context.Background(), srv.URL, testIdentity(t)); err == nil {
		t.Fatal("an empty token must be rejected, not stored")
	}
}

func TestRegisterPublicKeySpendsEnrollmentSecret(t *testing.T) {
	var gotSecret, gotKey string
	srv := tokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != deviceKeyPath {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		gotSecret = r.Header.Get("X-Hasfy-Device-Enrollment")
		var body struct {
			PublicKey string `json:"publicKey"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotKey = body.PublicKey
		w.WriteHeader(http.StatusOK)
	})

	id := testIdentity(t)
	if err := registerPublicKey(context.Background(), srv.URL, "one-shot", id.publicKeyBase64URL()); err != nil {
		t.Fatalf("registerPublicKey: %v", err)
	}
	if gotSecret != "one-shot" {
		t.Errorf("enrollment secret = %q", gotSecret)
	}
	if gotKey != id.publicKeyBase64URL() || gotKey == "" {
		t.Errorf("public key = %q", gotKey)
	}
}

func TestRegisterPublicKeyRefusalIsPermanent(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	err := registerPublicKey(context.Background(), srv.URL, "spent", "k")
	if !errors.Is(err, errDeviceRefused) {
		t.Fatalf("expected errDeviceRefused, got %v", err)
	}
}

func TestRenewDelayIsHalfTheTTLWithinBounds(t *testing.T) {
	// Half a lifetime leaves a full second attempt before expiry.
	if got := renewDelay(time.Hour); got != 30*time.Minute {
		t.Errorf("renewDelay(1h) = %v, want 30m", got)
	}
	// A pathologically short TTL must not turn into a request storm.
	if got := renewDelay(10 * time.Second); got != tokenRenewMin {
		t.Errorf("renewDelay(10s) = %v, want the %v floor", got, tokenRenewMin)
	}
	// Nor a long one into an unbounded gap.
	if got := renewDelay(48 * time.Hour); got != tokenRenewMax {
		t.Errorf("renewDelay(48h) = %v, want the %v ceiling", got, tokenRenewMax)
	}
}

func TestTokenStoreWaitUnblocksOnFirstToken(t *testing.T) {
	store := newTokenStore()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- store.wait(ctx) }()

	select {
	case <-done:
		t.Fatal("wait returned before any token was stored")
	case <-time.After(50 * time.Millisecond):
	}

	store.set("relay.jwt")
	if err := <-done; err != nil {
		t.Fatalf("wait: %v", err)
	}
	if store.get() != "relay.jwt" {
		t.Errorf("get() = %q", store.get())
	}
}

func TestTokenStoreWaitHonoursContext(t *testing.T) {
	store := newTokenStore()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := store.wait(ctx); err == nil {
		t.Fatal("wait must return when the context is cancelled")
	}
}

func TestRunTokenManagerRegistersThenWipesTheSecret(t *testing.T) {
	withFastTokenStart(t)

	envPath := filepath.Join(t.TempDir(), "agent.env")
	if err := os.WriteFile(envPath,
		[]byte("HASFY_ORG_ID=org-1\n"+envDeviceEnrollmentToken+"=one-shot\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	registered := false
	srv := tokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case deviceKeyPath:
			registered = true
			w.WriteHeader(http.StatusOK)
		case deviceTokenPath:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"data":    map[string]any{"agentToken": "relay.jwt", "ttlSeconds": 3600},
			})
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := newTokenStore()
	go runTokenManager(ctx, testLogger(), srv.URL, testIdentity(t),
		enrollmentState{needed: true, secret: "one-shot", envPath: envPath}, store)

	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	if err := store.wait(waitCtx); err != nil {
		t.Fatalf("no token obtained: %v", err)
	}

	if !registered {
		t.Error("expected the public key to be registered on first boot")
	}
	body, _ := os.ReadFile(envPath)
	// Spend-once: leaving it behind would keep a credential on disk that can
	// register a key for this device.
	if strings.Contains(string(body), "one-shot") {
		t.Errorf("spent enrollment secret survived in agent.env:\n%s", body)
	}
}

func TestRunTokenManagerStopsWhenDeviceIsRefused(t *testing.T) {
	withFastTokenStart(t)

	calls := 0
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnauthorized)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		runTokenManager(ctx, testLogger(), srv.URL, testIdentity(t),
			enrollmentState{}, newTokenStore())
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("runTokenManager kept retrying after a refusal")
	}
	if calls != 1 {
		t.Errorf("expected exactly one attempt after refusal, got %d", calls)
	}
}

func TestRunTokenManagerStopsWhenEnrollmentSecretIsMissing(t *testing.T) {
	withFastTokenStart(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		// A freshly generated key with no secret to register it cannot ever
		// succeed; the daemon must say so rather than spin.
		runTokenManager(ctx, testLogger(), "http://127.0.0.1:1", testIdentity(t),
			enrollmentState{needed: true, secret: ""}, newTokenStore())
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("runTokenManager should have returned immediately")
	}
}
