// Command agent is the cross-platform Hasfy-Relay agent.
//
// It connects to the relay over WebSocket, registers itself, and executes
// non-interactive commands on demand. All commands are passed as argv
// arrays; the agent never invokes a shell to interpret a string.
//
// Configuration (env, populated by /etc/hasfy/agent.env which is written
// by the installer):
//
//	HASFY_RELAY_URL    e.g. wss://relay.hasfy.fr/agent/ws
//	HASFY_RELAY_TOKEN  agent JWT issued by Hasfy-App at enrolment
//	HASFY_DEVICE_ID    stable identifier issued by Hasfy-App
//	HASFY_ORG_ID       org the device belongs to
//	HASFY_AGENT_VERSION  baked at build time via -ldflags
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
		}
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	relayURL := mustEnv("HASFY_RELAY_URL")
	token := mustEnv("HASFY_RELAY_TOKEN")
	deviceID := mustEnv("HASFY_DEVICE_ID")
	orgID := mustEnv("HASFY_ORG_ID")

	hostname, _ := os.Hostname()

	hello := proto.Register{
		DeviceID: deviceID,
		OrgID:    orgID,
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Version:  Version,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Reconnect loop with exponential backoff capped at 60 s.
	backoff := time.Second
	for {
		err := runOnce(ctx, log, relayURL, token, hello)
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

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		// Use stderr/exit, no log noise: the agent runs as a service and a
		// missing env var is a deployment bug.
		os.Stderr.WriteString("missing required env: " + k + "\n")
		os.Exit(2)
	}
	return v
}
