package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadEnvFileParsesAndIgnoresNoise(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.env")
	body := strings.Join([]string{
		"# a comment",
		"",
		"HASFY_API_URL=https://app.hasfy.fr",
		"export HASFY_DEVICE_ID=dev-1",
		`HASFY_ORG_ID="org-1"`,
		"'HASFY_QUOTED'=x",
		"NOEQUALS",
		"",
	}, "\n")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	env, err := loadEnvFile(p)
	if err != nil {
		t.Fatalf("loadEnvFile: %v", err)
	}
	if env["HASFY_API_URL"] != "https://app.hasfy.fr" {
		t.Errorf("api url = %q", env["HASFY_API_URL"])
	}
	// `export ` prefixes appear when someone has sourced the file by hand.
	if env["HASFY_DEVICE_ID"] != "dev-1" {
		t.Errorf("device id = %q", env["HASFY_DEVICE_ID"])
	}
	// Quotes are presentation, not part of the value — leaving them in would
	// produce an org id that matches nothing.
	if env["HASFY_ORG_ID"] != "org-1" {
		t.Errorf("org id = %q", env["HASFY_ORG_ID"])
	}
	if _, ok := env["NOEQUALS"]; ok {
		t.Error("a line with no '=' must be skipped")
	}
}

func TestLoadEnvFileTreatsMissingFileAsEmpty(t *testing.T) {
	// A fresh install has no agent.env at all; that is the normal first-boot
	// path, not an error.
	env, err := loadEnvFile(filepath.Join(t.TempDir(), "absent.env"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(env) != 0 {
		t.Errorf("expected an empty map, got %v", env)
	}
}

func TestWriteEnvFileRoundTripsAndIsOwnerOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.env")
	values := map[string]string{
		"HASFY_API_URL":          "https://app.hasfy.fr",
		"HASFY_RELAY_URL":        "wss://relay.hasfy.fr/agent/ws",
		"HASFY_DEVICE_ID":        "dev-1",
		"HASFY_ORG_ID":           "org-1",
		envDeviceEnrollmentToken: "one-shot",
	}
	if err := writeEnvFile(p, values); err != nil {
		t.Fatalf("writeEnvFile: %v", err)
	}

	back, err := loadEnvFile(p)
	if err != nil {
		t.Fatalf("loadEnvFile: %v", err)
	}
	for k, v := range values {
		if back[k] != v {
			t.Errorf("%s round-tripped as %q, want %q", k, back[k], v)
		}
	}

	fi, _ := os.Stat(p)
	// The file still carries the one-shot enrolment secret until the key is
	// registered.
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode is %v, want 0600", perm)
	}
}

func TestWriteEnvFileSkipsEmptyValues(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.env")
	if err := writeEnvFile(p, map[string]string{
		"HASFY_DEVICE_ID":        "dev-1",
		envDeviceEnrollmentToken: "",
	}); err != nil {
		t.Fatalf("writeEnvFile: %v", err)
	}
	body, _ := os.ReadFile(p)
	// An empty assignment would read back as a present-but-blank secret and
	// send the daemon down the registration path with nothing to present.
	if strings.Contains(string(body), envDeviceEnrollmentToken) {
		t.Errorf("empty value should not be written:\n%s", body)
	}
}

func TestIsEnrolled(t *testing.T) {
	full := map[string]string{
		"HASFY_DEVICE_ID": "d", "HASFY_ORG_ID": "o", "HASFY_RELAY_URL": "wss://r",
	}
	if !isEnrolled(full) {
		t.Error("a complete env should read as enrolled")
	}
	for _, missing := range []string{"HASFY_DEVICE_ID", "HASFY_ORG_ID", "HASFY_RELAY_URL"} {
		partial := map[string]string{}
		for k, v := range full {
			partial[k] = v
		}
		delete(partial, missing)
		// A half-written env must send the daemon back through enrolment
		// rather than into a connect loop it cannot satisfy.
		if isEnrolled(partial) {
			t.Errorf("missing %s should not read as enrolled", missing)
		}
	}
	if isEnrolled(map[string]string{}) {
		t.Error("an empty env is not enrolled")
	}
}

func TestWriteEnrollmentStatusIsAdminReadableOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "enrollment-status.json")
	if err := writeEnrollmentStatus(p, EnrollmentStatus{
		State:           "awaiting_approval",
		UserCode:        "BCDF-GHJK",
		VerificationURI: "https://app.hasfy.fr/device?user_code=BCDF-GHJK",
	}); err != nil {
		t.Fatalf("writeEnrollmentStatus: %v", err)
	}

	fi, _ := os.Stat(p)
	// Anyone who can read the code *and* holds Hasfy rights in another tenant
	// could approve this machine into that tenant, so it is not world-readable.
	if perm := fi.Mode().Perm(); perm != 0o640 {
		t.Errorf("mode is %v, want 0640", perm)
	}

	var got EnrollmentStatus
	body, _ := os.ReadFile(p)
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("status file is not valid JSON: %v", err)
	}
	if got.UserCode != "BCDF-GHJK" || got.State != "awaiting_approval" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if got.UpdatedAt.IsZero() {
		t.Error("updatedAt should be stamped so a stale file is recognisable")
	}
}

// The status file is what the unprivileged GUI reads; a device code leaking
// into it would hand a local user the ability to claim the enrolment.
func TestEnrollmentStatusNeverCarriesTheDeviceCode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "enrollment-status.json")
	_ = writeEnrollmentStatus(p, EnrollmentStatus{
		State:           "awaiting_approval",
		UserCode:        "BCDF-GHJK",
		VerificationURI: "https://app.hasfy.fr/device?user_code=BCDF-GHJK",
	})
	body, _ := os.ReadFile(p)
	if strings.Contains(strings.ToLower(string(body)), "device_code") {
		t.Errorf("status file must not carry the device code:\n%s", body)
	}
}

func enrollServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestRequestDeviceCode(t *testing.T) {
	var gotBody map[string]string
	srv := enrollServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != deviceCodePath {
			t.Errorf("path = %q", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":               "dc",
			"user_code":                 "BCDF-GHJK",
			"verification_uri":          "https://app.hasfy.fr/device",
			"verification_uri_complete": "https://app.hasfy.fr/device?user_code=BCDF-GHJK",
			"expires_in":                600,
			"interval":                  5,
		})
	})

	code, err := requestDeviceCode(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("requestDeviceCode: %v", err)
	}
	if code.DeviceCode != "dc" || code.UserCode != "BCDF-GHJK" {
		t.Errorf("got %+v", code)
	}
	if code.approvalURL() != "https://app.hasfy.fr/device?user_code=BCDF-GHJK" {
		t.Errorf("approvalURL = %q", code.approvalURL())
	}
	// The hints are what let the approver recognise the machine.
	if gotBody["os"] == "" || gotBody["arch"] == "" {
		t.Errorf("device hints were not sent: %v", gotBody)
	}
}

func TestRequestDeviceCodeRejectsIncompleteResponse(t *testing.T) {
	srv := enrollServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"user_code": "BCDF-GHJK"})
	})
	if _, err := requestDeviceCode(context.Background(), srv.URL); err == nil {
		t.Fatal("a response with no device_code must be rejected")
	}
}

func TestDeviceCodeFallbacks(t *testing.T) {
	c := &deviceCodeResponse{VerificationURI: "https://app.hasfy.fr/device"}
	if c.approvalURL() != "https://app.hasfy.fr/device" {
		t.Errorf("approvalURL = %q", c.approvalURL())
	}
	if c.pollInterval() != defaultPollInterval {
		t.Errorf("pollInterval = %v", c.pollInterval())
	}
	if c.lifetime() != defaultCodeLifetime {
		t.Errorf("lifetime = %v", c.lifetime())
	}
}

func TestPollForInstallTokenWaitsThenSucceeds(t *testing.T) {
	calls := 0
	srv := enrollServer(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls < 2 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"install_token": "install-token",
			"equipment_id":  "eq-1",
		})
	})

	code := &deviceCodeResponse{DeviceCode: "dc", ExpiresIn: 30, Interval: 0}
	// Keep the test quick without touching production defaults.
	code.Interval = 1

	got, err := pollForInstallToken(context.Background(), testLogger(), srv.URL, code)
	if err != nil {
		t.Fatalf("pollForInstallToken: %v", err)
	}
	if got.InstallToken != "install-token" {
		t.Errorf("token = %q", got.InstallToken)
	}
	if calls != 2 {
		t.Errorf("expected to keep polling through the pending answer, got %d calls", calls)
	}
}

func TestPollForInstallTokenStopsOnDenial(t *testing.T) {
	srv := enrollServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "access_denied"})
	})

	code := &deviceCodeResponse{DeviceCode: "dc", ExpiresIn: 30, Interval: 1}
	_, err := pollForInstallToken(context.Background(), testLogger(), srv.URL, code)
	if err != errEnrollmentRefused {
		t.Fatalf("expected errEnrollmentRefused, got %v", err)
	}
}

func TestPollForInstallTokenGivesUpAtExpiry(t *testing.T) {
	srv := enrollServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
	})

	// A negative ExpiresIn falls back to the 10-minute default (it reads as
	// "the server omitted it"), so use a real, very short lifetime instead:
	// one poll happens, then the deadline passes.
	code := &deviceCodeResponse{DeviceCode: "dc", ExpiresIn: 1, Interval: 1}
	_, err := pollForInstallToken(context.Background(), testLogger(), srv.URL, code)
	if err != errEnrollmentRefused {
		t.Fatalf("expected errEnrollmentRefused, got %v", err)
	}
}

func TestFetchRelayEnrollment(t *testing.T) {
	srv := enrollServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != relayEnrollmentPath {
			t.Errorf("path = %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"relayUrl":              "wss://relay.hasfy.fr/agent/ws",
				"deviceId":              "eq-1",
				"orgId":                 "org-1",
				"apiBaseUrl":            "https://app.hasfy.fr",
				"deviceEnrollmentToken": "one-shot",
			},
		})
	})

	got, err := fetchRelayEnrollment(context.Background(), srv.URL, "install-token")
	if err != nil {
		t.Fatalf("fetchRelayEnrollment: %v", err)
	}
	if got.Data.DeviceID != "eq-1" || got.Data.DeviceEnrollmentToken != "one-shot" {
		t.Errorf("got %+v", got.Data)
	}
}

func TestFetchRelayEnrollmentRejectsIncompleteData(t *testing.T) {
	srv := enrollServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data":    map[string]any{"orgId": "org-1"},
		})
	})
	// Persisting this would leave the daemon looping on a config it can never
	// connect with.
	if _, err := fetchRelayEnrollment(context.Background(), srv.URL, "t"); err == nil {
		t.Fatal("incomplete enrollment data must be rejected")
	}
}

func TestRunSelfEnrollmentWritesTheEnvFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "agent.env")
	statusPath := filepath.Join(dir, "enrollment-status.json")

	srv := enrollServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case deviceCodePath:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code": "dc", "user_code": "BCDF-GHJK",
				"verification_uri": "https://app.hasfy.fr/device",
				"expires_in":       30, "interval": 1,
			})
		case deviceFlowTokenPath:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"install_token": "install-token", "equipment_id": "eq-1",
			})
		case relayEnrollmentPath:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"data": map[string]any{
					"relayUrl": "wss://relay.hasfy.fr/agent/ws",
					"deviceId": "eq-1", "orgId": "org-1",
					"apiBaseUrl":            "https://app.hasfy.fr",
					"deviceEnrollmentToken": "one-shot",
				},
			})
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	values, err := runSelfEnrollment(ctx, testLogger(), srv.URL, envPath, statusPath)
	if err != nil {
		t.Fatalf("runSelfEnrollment: %v", err)
	}
	if values["HASFY_DEVICE_ID"] != "eq-1" {
		t.Errorf("device id = %q", values["HASFY_DEVICE_ID"])
	}

	// The env file is the durable result — a restart must not re-enrol.
	back, err := loadEnvFile(envPath)
	if err != nil {
		t.Fatalf("loadEnvFile: %v", err)
	}
	if !isEnrolled(back) {
		t.Errorf("env file does not read back as enrolled: %v", back)
	}

	var status EnrollmentStatus
	body, _ := os.ReadFile(statusPath)
	_ = json.Unmarshal(body, &status)
	if status.State != "enrolled" {
		t.Errorf("final status = %q, want enrolled", status.State)
	}
}

// A machine installed before anyone was ready to approve it must keep offering
// a fresh code rather than needing a reinstall.
func TestRunSelfEnrollmentRetriesAfterRefusal(t *testing.T) {
	dir := t.TempDir()
	codeRequests := 0

	srv := enrollServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case deviceCodePath:
			codeRequests++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code": "dc", "user_code": "BCDF-GHJK",
				"verification_uri": "https://app.hasfy.fr/device",
				"expires_in":       30, "interval": 1,
			})
		case deviceFlowTokenPath:
			if codeRequests == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "expired_token"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"install_token": "install-token", "equipment_id": "eq-1",
			})
		case relayEnrollmentPath:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"data": map[string]any{
					"relayUrl": "wss://relay.hasfy.fr/agent/ws",
					"deviceId": "eq-1", "orgId": "org-1",
				},
			})
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if _, err := runSelfEnrollment(ctx, testLogger(), srv.URL,
		filepath.Join(dir, "agent.env"), filepath.Join(dir, "status.json")); err != nil {
		t.Fatalf("runSelfEnrollment: %v", err)
	}
	if codeRequests < 2 {
		t.Errorf("expected a fresh code after expiry, got %d code requests", codeRequests)
	}
}
