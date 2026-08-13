// Command agent is the cross-platform Hasfy-Relay agent.
//
// It connects to the relay over WebSocket, registers itself, and executes
// non-interactive commands on demand. All commands are passed as argv
// arrays; the agent never invokes a shell to interpret a string.
//
// # Identity
//
// The daemon holds an Ed25519 private key (device.key, generated on first
// boot) and mints short-lived relay tokens by signing assertions — see
// deviceid.go and token.go. It does NOT store a relay credential: the earlier
// design wrote a 30-day JWT into agent.env, which made the config file itself
// a root-PTY credential and left no way to revoke access before it expired.
//
// # Enrolment
//
// The daemon enrols *itself* (see enroll.go): on first boot it finds no
// device in /etc/hasfy/agent.env, runs the device authorization flow, and
// writes the file. Since it is already root, nothing prompts — which is what
// lets the OS package installer be the only privileged step in the whole
// lifecycle.
//
// Configuration is read from /etc/hasfy/agent.env, overridable by the process
// environment. A fresh install needs none of it: HASFY_API_URL defaults to the
// production origin and everything else is discovered during enrolment.
//
//	HASFY_API_URL                  Hasfy-App origin (default app.hasfy.fr)
//	HASFY_RELAY_URL                e.g. wss://relay.hasfy.fr/agent/ws
//	HASFY_DEVICE_ID                stable identifier issued by Hasfy-App
//	HASFY_ORG_ID                   org the device belongs to
//	HASFY_DEVICE_ENROLLMENT_TOKEN  one-shot, wiped once the key is registered
//	HASFY_ENV_FILE                 override for the env file path (optional)
//	HASFY_DEVICE_KEY_FILE          override for the key path (optional)
//	HASFY_STATUS_FILE              override for the enrolment status file
//	HASFY_AGENT_VERSION            baked at build time via -ldflags
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/HasfyFR/Hasfy-Relay/internal/proto"
)

// Version is overridden at build time: -ldflags "-X main.Version=v1.2.3".
var Version = "dev"

// Env var carrying the single-use device-enrollment secret.
const envDeviceEnrollmentToken = "HASFY_DEVICE_ENROLLMENT_TOKEN"

// enrollmentState describes whether the device still has to register its
// public key, and what it needs to do so.
type enrollmentState struct {
	needed  bool
	secret  string
	envPath string
}

func main() {
	// `hasfy-agent --version` / `-v` prints the baked version and
	// exits. Used by the installer's daemon-updater to compare the
	// running binary against the latest release, and by humans for
	// support diagnostics.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-v", "version":
			os.Stdout.WriteString(Version + "\n")
			return
		case "ticket":
			// Runs as whoever typed it, not as the daemon: this is the user at
			// the keyboard reporting a problem with their own machine.
			ctx, cancel := signal.NotifyContext(
				context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			os.Exit(cmdTicket(ctx, os.Args[2:]))
		}
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	envPath := os.Getenv("HASFY_ENV_FILE")
	if envPath == "" {
		envPath = defaultEnvFilePath()
	}
	keyPath := os.Getenv("HASFY_DEVICE_KEY_FILE")
	if keyPath == "" {
		keyPath = defaultKeyPath()
	}
	statusPath := os.Getenv("HASFY_STATUS_FILE")
	if statusPath == "" {
		statusPath = defaultStatusFilePath()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Read agent.env ourselves rather than trusting the service manager to
	// have injected it: enrolment *rewrites* this file, and we have to see our
	// own writes without a restart.
	env, err := loadEnvFile(envPath)
	if err != nil {
		os.Stderr.WriteString("read " + envPath + ": " + err.Error() + "\n")
		os.Exit(2)
	}
	// The process environment still wins, so an operator can override any of
	// it for a one-off run.
	for _, k := range []string{
		"HASFY_API_URL", "HASFY_RELAY_URL", "HASFY_DEVICE_ID", "HASFY_ORG_ID",
		envDeviceEnrollmentToken,
	} {
		if v := os.Getenv(k); v != "" {
			env[k] = v
		}
	}

	apiURL := firstNonEmpty(env["HASFY_API_URL"], defaultAPIBaseURL)

	// Not enrolled yet: run the device flow ourselves. This is what lets the
	// OS package installer be the only thing that ever needs privileges — we
	// are already root here, so writing agent.env prompts nobody.
	if !isEnrolled(env) {
		log.Info("no enrollment on disk; starting device authorization", "api", apiURL)
		enrolled, enrollErr := runSelfEnrollment(ctx, log, apiURL, envPath, statusPath)
		if enrollErr != nil {
			if ctx.Err() != nil {
				return
			}
			os.Stderr.WriteString("enrollment failed: " + enrollErr.Error() + "\n")
			os.Exit(2)
		}
		env = enrolled
		apiURL = firstNonEmpty(env["HASFY_API_URL"], apiURL)
	}

	relayURL := env["HASFY_RELAY_URL"]
	deviceID := env["HASFY_DEVICE_ID"]
	orgID := env["HASFY_ORG_ID"]

	identity, created, err := loadOrCreateIdentity(keyPath, deviceID)
	if err != nil {
		os.Stderr.WriteString("device identity: " + err.Error() + "\n")
		os.Exit(2)
	}
	if created {
		log.Info("generated device keypair", "path", keyPath)
	}

	hostname, _ := os.Hostname()

	hello := proto.Register{
		DeviceID: deviceID,
		OrgID:    orgID,
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Version:  Version,
	}

	store := newTokenStore()
	go runTokenManager(ctx, log, apiURL, identity, enrollmentState{
		needed:  created,
		secret:  env[envDeviceEnrollmentToken],
		envPath: envPath,
	}, store)

	// Inventory runs independently of the relay connection: a device behind a
	// firewall that blocks the WebSocket must still populate the CMDB.
	go runInventoryReporter(ctx, log, apiURL, identity)

	// Metrics go straight to Elasticsearch with a per-org, create_doc-only key
	// the daemon holds in memory. Independent of the relay for the same reason
	// as inventory: a blocked WebSocket must not blind the monitoring.
	go runMetricsReporter(ctx, log, apiURL, deviceID, orgID, identity)

	// Nothing can be attempted before the first token arrives; dialling the
	// relay without one would just burn through the backoff.
	if err := store.wait(ctx); err != nil {
		return
	}

	// Reconnect loop with exponential backoff capped at 60 s.
	backoff := time.Second
	for {
		// Read the token per attempt, not once at startup: the token manager
		// renews on its own schedule, and reconnecting with a stale token is
		// exactly how a device used to fall off for good.
		err := runOnce(ctx, log, relayURL, store.get(), hello)
		if ctx.Err() != nil {
			return
		}
		log.Warn("relay disconnected", "err", err, "backoff", backoff.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

// defaultEnvFilePath is where the installer writes agent.env on each platform
// (kept in sync with Hasfy-Agent/src-tauri/src/installer/relay.rs).
func defaultEnvFilePath() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\Hasfy\agent.env`
	}
	return "/etc/hasfy/agent.env"
}
