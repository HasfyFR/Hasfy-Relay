package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// =============================================================================
// Self-enrollment
// =============================================================================
//
// The daemon enrols itself. It runs the device authorization flow (RFC 8628),
// exchanges the resulting install token for its relay configuration, and
// writes /etc/hasfy/agent.env — all as root, because it already *is* root.
//
// Why this moved out of the installer
// -----------------------------------
// Every privileged step used to open its own elevation session: one for the
// Elastic Agent install, one for registering the relay service, one more each
// time the daemon updated itself. On macOS that meant a password prompt per
// operation, including one appearing out of nowhere every six hours while the
// GUI was open — which trains people to type their password at unexpected
// prompts, the exact habit an attacker wants.
//
// With the daemon owning enrolment, the OS package installer is the *only*
// thing that ever needs privileges: it places the binary and registers the
// service in a single authenticated session, and nothing afterwards prompts.
//
// The GUI is reduced to a viewer. It reads the status file this module writes
// — which holds the user code and the approval URL, never a credential — and
// opens a browser. It has no privileged channel to the daemon to attack.

const (
	// Where the daemon publishes what the user has to act on. Deliberately
	// not world-readable: see writeEnrollmentStatus.
	defaultStatusFileName = "enrollment-status.json"

	deviceCodePath      = "/api/v1/auth/device/code"
	deviceFlowTokenPath = "/api/v1/auth/device/token"
	relayEnrollmentPath = "/api/v1/installer/relay-enrollment"

	enrollHTTPTimeout = 30 * time.Second

	// Fallbacks when the server omits them.
	defaultPollInterval = 5 * time.Second
	defaultCodeLifetime = 10 * time.Minute

	// Added to the interval each time the server answers `slow_down`.
	slowDownIncrement = 5 * time.Second
)

// errEnrollmentRefused means the user denied the request, or the code lapsed.
// Retrying the same code is pointless; the daemon starts a fresh one.
var errEnrollmentRefused = errors.New("device authorization refused or expired")

// EnrollmentStatus is what the GUI/CLI reads to show the user what to do.
// It carries no secret: the device code stays in memory.
type EnrollmentStatus struct {
	State           string    `json:"state"` // "awaiting_approval" | "enrolled" | "error"
	UserCode        string    `json:"userCode,omitempty"`
	VerificationURI string    `json:"verificationUri,omitempty"`
	Message         string    `json:"message,omitempty"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

func defaultStatusFilePath() string {
	return filepath.Join(filepath.Dir(defaultEnvFilePath()), defaultStatusFileName)
}

// writeEnrollmentStatus publishes the current state for the UI.
//
// Mode 0640, not 0644. The user code is not a credential on its own, but
// anyone who can read it *and* holds Hasfy rights in some other tenant could
// approve this machine into that tenant and obtain remote root on it. Keeping
// the file to the admin group matches the fact that installing management
// software is already an administrative act.
func writeEnrollmentStatus(path string, status EnrollmentStatus) error {
	if path == "" {
		return nil
	}
	status.UpdatedAt = time.Now().UTC()

	body, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create status directory: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".enrollment-status.")
	if err != nil {
		return fmt.Errorf("create temp status file: %w", err)
	}
	tmpName := tmp.Name()
	// Nettoyage au mieux : le fichier a soit été renommé, soit disparu.
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp status file: %w", err)
	}
	if _, err := tmp.Write(append(body, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp status file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp status file: %w", err)
	}
	return os.Rename(tmpName, path)
}

// =============================================================================
// agent.env
// =============================================================================

// loadEnvFile parses `KEY=VALUE` lines into a map. Blank lines and `#`
// comments are skipped; surrounding quotes are stripped.
//
// The daemon reads the file itself rather than relying on the service manager
// to inject it, because it *rewrites* the file during enrolment and must see
// its own writes without a restart.
func loadEnvFile(path string) (map[string]string, error) {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:eq])
		v := strings.TrimSpace(line[eq+1:])
		if len(v) >= 2 &&
			((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out, sc.Err()
}

// writeEnvFile replaces agent.env atomically at mode 0600.
//
// Atomic because a crash mid-write would leave the daemon unable to boot; 0600
// because the file still carries the one-shot device-enrollment secret until
// the key is registered.
func writeEnvFile(path string, values map[string]string) error {
	// Stable order so the file diffs cleanly and is readable by a human
	// debugging an enrolment.
	order := []string{
		"HASFY_API_URL",
		"HASFY_RELAY_URL",
		"HASFY_DEVICE_ID",
		"HASFY_ORG_ID",
		envDeviceEnrollmentToken,
	}

	var buf bytes.Buffer
	written := map[string]bool{}
	for _, k := range order {
		if v, ok := values[k]; ok && v != "" {
			fmt.Fprintf(&buf, "%s=%s\n", k, v)
			written[k] = true
		}
	}
	for k, v := range values {
		if !written[k] && v != "" {
			fmt.Fprintf(&buf, "%s=%s\n", k, v)
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".agent.env.")
	if err != nil {
		return fmt.Errorf("create temp env file: %w", err)
	}
	tmpName := tmp.Name()
	// Nettoyage au mieux : le fichier a soit été renommé, soit disparu.
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp env file: %w", err)
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp env file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp env file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp env file: %w", err)
	}
	return os.Rename(tmpName, path)
}

// isEnrolled reports whether agent.env already describes a device.
func isEnrolled(env map[string]string) bool {
	return env["HASFY_DEVICE_ID"] != "" &&
		env["HASFY_ORG_ID"] != "" &&
		env["HASFY_RELAY_URL"] != ""
}

// =============================================================================
// Device authorization flow
// =============================================================================

type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type deviceFlowTokenResponse struct {
	InstallToken string `json:"install_token"`
	EquipmentID  string `json:"equipment_id"`
}

type oauthError struct {
	Error string `json:"error"`
}

type relayEnrollmentResponse struct {
	Success bool `json:"success"`
	Data    struct {
		RelayURL              string `json:"relayUrl"`
		DeviceID              string `json:"deviceId"`
		OrgID                 string `json:"orgId"`
		APIBaseURL            string `json:"apiBaseUrl"`
		DeviceEnrollmentToken string `json:"deviceEnrollmentToken"`
	} `json:"data"`
}

func (r *deviceCodeResponse) approvalURL() string {
	if r.VerificationURIComplete != "" {
		return r.VerificationURIComplete
	}
	return r.VerificationURI
}

func (r *deviceCodeResponse) pollInterval() time.Duration {
	if r.Interval > 0 {
		return time.Duration(r.Interval) * time.Second
	}
	return defaultPollInterval
}

func (r *deviceCodeResponse) lifetime() time.Duration {
	if r.ExpiresIn > 0 {
		return time.Duration(r.ExpiresIn) * time.Second
	}
	return defaultCodeLifetime
}

func postEnrollJSON(ctx context.Context, url string, body any) (*http.Response, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hasfy-agent/"+Version)
	return (&http.Client{Timeout: enrollHTTPTimeout}).Do(req)
}

// requestDeviceCode opens a device authorization request, sending the hints
// the approval screen shows so the user can tell which machine is asking.
func requestDeviceCode(ctx context.Context, apiBase string) (*deviceCodeResponse, error) {
	hostname, _ := os.Hostname()
	resp, err := postEnrollJSON(ctx, strings.TrimRight(apiBase, "/")+deviceCodePath, map[string]string{
		"hostname":         hostname,
		"os":               daemonOS(),
		"arch":             daemonArch(),
		"installerVersion": Version,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device code request HTTP %d", resp.StatusCode)
	}
	var out deviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode device code response: %w", err)
	}
	if out.DeviceCode == "" || out.UserCode == "" {
		return nil, errors.New("device code response was incomplete")
	}
	return &out, nil
}

// pollForInstallToken waits for a user to approve, honouring the RFC's
// back-off signals.
func pollForInstallToken(
	ctx context.Context,
	log *slog.Logger,
	apiBase string,
	code *deviceCodeResponse,
) (*deviceFlowTokenResponse, error) {
	url := strings.TrimRight(apiBase, "/") + deviceFlowTokenPath
	deadline := time.Now().Add(code.lifetime())
	interval := code.pollInterval()

	for {
		if time.Now().After(deadline) {
			return nil, errEnrollmentRefused
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}

		resp, err := postEnrollJSON(ctx, url, map[string]string{"device_code": code.DeviceCode})
		if err != nil {
			// A network blip must not abandon an enrolment the user is about
			// to approve; keep going until the code itself lapses.
			log.Warn("enrollment poll failed", "err", err)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			var out deviceFlowTokenResponse
			decodeErr := json.NewDecoder(resp.Body).Decode(&out)
			resp.Body.Close()
			if decodeErr != nil {
				return nil, fmt.Errorf("decode token response: %w", decodeErr)
			}
			if out.InstallToken == "" {
				return nil, errors.New("token response carried no install token")
			}
			return &out, nil
		}

		var oe oauthError
		_ = json.NewDecoder(resp.Body).Decode(&oe)
		resp.Body.Close()

		switch oe.Error {
		case "authorization_pending":
		case "slow_down":
			interval += slowDownIncrement
			log.Info("enrollment: slowing down", "interval", interval.String())
		case "access_denied", "expired_token":
			return nil, errEnrollmentRefused
		default:
			return nil, fmt.Errorf("enrollment failed: %s", oe.Error)
		}
	}
}

// fetchRelayEnrollment exchanges the install token for this device's relay
// configuration and its one-shot key-registration secret.
func fetchRelayEnrollment(
	ctx context.Context,
	apiBase, installToken string,
) (*relayEnrollmentResponse, error) {
	resp, err := postEnrollJSON(ctx,
		strings.TrimRight(apiBase, "/")+relayEnrollmentPath,
		map[string]string{"token": installToken},
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("relay enrollment HTTP %d", resp.StatusCode)
	}
	var out relayEnrollmentResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode relay enrollment response: %w", err)
	}
	if !out.Success || out.Data.DeviceID == "" || out.Data.RelayURL == "" {
		return nil, errors.New("relay enrollment response was incomplete")
	}
	return &out, nil
}

// runSelfEnrollment drives the whole flow and persists the result.
//
// Retries indefinitely on refusal/expiry with a fresh code: a machine that was
// installed before anyone was ready to approve it must simply keep offering a
// code rather than needing a reinstall.
func runSelfEnrollment(
	ctx context.Context,
	log *slog.Logger,
	apiBase, envPath, statusPath string,
) (map[string]string, error) {
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		code, err := requestDeviceCode(ctx, apiBase)
		if err != nil {
			log.Warn("could not start enrollment", "err", err, "retry_in", "60s")
			_ = writeEnrollmentStatus(statusPath, EnrollmentStatus{
				State:   "error",
				Message: "Could not reach Hasfy to start enrolment; retrying.",
			})
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Minute):
			}
			continue
		}

		log.Info("awaiting approval", "user_code", code.UserCode, "url", code.approvalURL())
		if err := writeEnrollmentStatus(statusPath, EnrollmentStatus{
			State:           "awaiting_approval",
			UserCode:        code.UserCode,
			VerificationURI: code.approvalURL(),
		}); err != nil {
			// Only the UI loses out; the daemon can still be approved by
			// someone reading the code from the logs.
			log.Warn("could not publish enrollment status", "err", err)
		}

		token, err := pollForInstallToken(ctx, log, apiBase, code)
		if err != nil {
			if errors.Is(err, errEnrollmentRefused) {
				log.Warn("enrollment request refused or expired; issuing a new code")
				continue
			}
			return nil, err
		}

		enrollment, err := fetchRelayEnrollment(ctx, apiBase, token.InstallToken)
		if err != nil {
			return nil, fmt.Errorf("relay enrollment: %w", err)
		}

		values := map[string]string{
			"HASFY_API_URL":          firstNonEmpty(enrollment.Data.APIBaseURL, apiBase),
			"HASFY_RELAY_URL":        enrollment.Data.RelayURL,
			"HASFY_DEVICE_ID":        enrollment.Data.DeviceID,
			"HASFY_ORG_ID":           enrollment.Data.OrgID,
			envDeviceEnrollmentToken: enrollment.Data.DeviceEnrollmentToken,
		}
		if err := writeEnvFile(envPath, values); err != nil {
			return nil, fmt.Errorf("persist enrollment: %w", err)
		}

		_ = writeEnrollmentStatus(statusPath, EnrollmentStatus{State: "enrolled"})
		log.Info("device enrolled", "device", enrollment.Data.DeviceID)
		return values, nil
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// defaultAPIBaseURL is where a freshly installed daemon looks for Hasfy-App
// when the package did not configure anything else. It is the only piece of
// bootstrap configuration self-enrolment needs — everything else (relay URL,
// device id, org) is discovered during the flow.
const defaultAPIBaseURL = "https://app.hasfy.fr"

// daemonOS / daemonArch report the platform in the vocabulary Hasfy-App's
// approval screen expects.
func daemonOS() string   { return runtime.GOOS }
func daemonArch() string { return runtime.GOARCH }
