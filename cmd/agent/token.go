package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// Relay token acquisition
// =============================================================================
//
// The daemon mints a relay token on demand by signing an assertion with its
// device key, rather than reading a long-lived one off disk. Tokens live ~1 h
// and are re-acquired at roughly half that, so:
//
//   - no durable credential exists on disk to steal;
//   - revoking the device key stops the *next* acquisition, which bounds
//     revocation to one token lifetime instead of the 30 days it used to take.

const (
	// Fraction of a token's lifetime after which we go get a new one. Half
	// gives a full second attempt before the current token lapses.
	tokenRenewFraction = 2

	// Floor and ceiling on the renewal delay, in case the server ever returns
	// an unexpected TTL.
	tokenRenewMin = 5 * time.Minute
	tokenRenewMax = 3 * time.Hour

	// Retry cadence after a transient failure (network down, 5xx).
	tokenRetryInterval = 2 * time.Minute

	tokenHTTPTimeout = 30 * time.Second

	deviceTokenPath = "/api/v1/device/token"
	deviceKeyPath   = "/api/v1/device/key"
)

// errDeviceRefused means Hasfy-App positively rejected us: the device key is
// revoked, or the equipment is gone. Retrying cannot help.
var errDeviceRefused = errors.New("device refused by Hasfy-App")

// tokenInitialDelay is how long runTokenManager waits before its first
// acquisition. A var so tests need not wait. Zero in practice — the daemon
// cannot connect at all until it holds a token.
var tokenInitialDelay = time.Duration(0)

// tokenStore holds the relay token currently in use. The reconnect loop reads
// it on every attempt; the token manager writes it.
type tokenStore struct {
	mu    sync.RWMutex
	token string
	ready chan struct{}
	once  sync.Once
}

func newTokenStore() *tokenStore {
	return &tokenStore{ready: make(chan struct{})}
}

func (s *tokenStore) get() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token
}

func (s *tokenStore) set(token string) {
	s.mu.Lock()
	s.token = token
	s.mu.Unlock()
	s.once.Do(func() { close(s.ready) })
}

// wait blocks until a token has been obtained at least once.
//
// Without this the reconnect loop would dial the relay with an empty
// Authorization header, get rejected, and burn through its backoff before the
// first token even arrived.
func (s *tokenStore) wait(ctx context.Context) error {
	select {
	case <-s.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type deviceTokenResponse struct {
	Success bool `json:"success"`
	Data    struct {
		AgentToken          string `json:"agentToken"`
		AgentTokenExpiresAt string `json:"agentTokenExpiresAt"`
		TTLSeconds          int    `json:"ttlSeconds"`
	} `json:"data"`
}

func postJSON(ctx context.Context, url, bearer string, headers map[string]string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hasfy-agent/"+Version)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: tokenHTTPTimeout}
	return client.Do(req)
}

// registerPublicKey performs the one-time enrollment: it spends the single-use
// secret the installer left in agent.env to register the public half of the
// keypair generated on first boot.
func registerPublicKey(ctx context.Context, apiBase, enrollmentSecret, publicKey string) error {
	body, err := json.Marshal(map[string]string{"publicKey": publicKey})
	if err != nil {
		return err
	}

	resp, err := postJSON(ctx,
		strings.TrimRight(apiBase, "/")+deviceKeyPath,
		"",
		map[string]string{"X-Hasfy-Device-Enrollment": enrollmentSecret},
		body,
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: enrollment secret rejected (expired or already used)", errDeviceRefused)
	default:
		return fmt.Errorf("key registration HTTP %d", resp.StatusCode)
	}
}

// acquireToken exchanges a freshly signed assertion for a relay token.
func acquireToken(ctx context.Context, apiBase string, identity *deviceIdentity) (string, time.Duration, error) {
	assertion, err := identity.signAssertion()
	if err != nil {
		return "", 0, fmt.Errorf("sign assertion: %w", err)
	}

	resp, err := postJSON(ctx,
		strings.TrimRight(apiBase, "/")+deviceTokenPath,
		assertion,
		nil,
		[]byte("{}"),
	)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return "", 0, errDeviceRefused
	case resp.StatusCode != http.StatusOK:
		return "", 0, fmt.Errorf("token request HTTP %d", resp.StatusCode)
	}

	var out deviceTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, fmt.Errorf("decode token response: %w", err)
	}
	if !out.Success || out.Data.AgentToken == "" {
		return "", 0, errors.New("token response carried no token")
	}

	ttl := time.Duration(out.Data.TTLSeconds) * time.Second
	return out.Data.AgentToken, ttl, nil
}

// renewDelay converts a token TTL into how long to wait before renewing.
func renewDelay(ttl time.Duration) time.Duration {
	d := ttl / tokenRenewFraction
	if d < tokenRenewMin {
		return tokenRenewMin
	}
	if d > tokenRenewMax {
		return tokenRenewMax
	}
	return d
}

// runTokenManager registers the device key when needed, then keeps a valid
// relay token in the store until ctx is cancelled.
//
// It stops permanently on errDeviceRefused: the server has said this device is
// no longer authorised, so continuing to ask would be pointless noise. The
// current connection is left alone — it dies when its token expires, which is
// the revocation taking effect.
func runTokenManager(
	ctx context.Context,
	log *slog.Logger,
	apiBase string,
	identity *deviceIdentity,
	enroll enrollmentState,
	store *tokenStore,
) {
	if enroll.needed {
		if enroll.secret == "" {
			log.Error("device key was generated but agent.env carries no enrollment secret — " +
				"cannot register with Hasfy-App; re-run the installer")
			return
		}
		if err := registerPublicKey(ctx, apiBase, enroll.secret, identity.publicKeyBase64URL()); err != nil {
			log.Error("device key registration failed", "err", err)
			if errors.Is(err, errDeviceRefused) {
				return
			}
			// Transient: fall through and let the acquisition loop retry.
			// Registration is attempted again on the next daemon start.
		} else {
			log.Info("device key registered", "device", identity.deviceID)
			// Spend-once: the secret must not survive on disk.
			if err := removeEnvKey(enroll.envPath, envDeviceEnrollmentToken); err != nil {
				log.Warn("could not wipe the spent enrollment secret from agent.env", "err", err)
			}
		}
	}

	timer := time.NewTimer(tokenInitialDelay)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		token, ttl, err := acquireToken(ctx, apiBase, identity)
		var next time.Duration
		switch {
		case errors.Is(err, errDeviceRefused):
			log.Error("this device is no longer authorised by Hasfy-App — " +
				"it will drop off the relay when its current token expires")
			return
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			log.Warn("relay token request failed", "err", err, "retry_in", tokenRetryInterval.String())
			next = tokenRetryInterval
		default:
			store.set(token)
			next = renewDelay(ttl)
			log.Info("relay token acquired", "ttl", ttl.String(), "renew_in", next.String())
		}

		timer.Reset(next)
	}
}
