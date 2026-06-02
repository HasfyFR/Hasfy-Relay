// Command relay starts the Hasfy-Relay server.
//
// Configuration is read from env (12-factor; populated by Vault Agent
// Injector in K8s):
//
//	RELAY_LISTEN_ADDR        default :8443
//	RELAY_AGENT_SECRET       HS256 key (≥ 32 B), hex or base64
//	RELAY_SESSION_SECRET     HS256 key (≥ 32 B)
//	RELAY_SVC_SECRET         HMAC key (≥ 32 B) shared with Hasfy-App
//	RELAY_OPERATOR_ORIGINS   comma-separated Origin allow-list (default app.hasfy.fr)
//	RELAY_TLS_CERT, RELAY_TLS_KEY  if set, the server terminates TLS itself
//	                                (otherwise plain HTTP — TLS done at ingress)
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/HasfyFR/Hasfy-Relay/internal/server"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	// Load env from Vault Agent Injector template (if present) before
	// reading config. Allows the relay container to run on distroless
	// (no shell) without a wrapper script.
	if p := os.Getenv("RELAY_ENV_FILE"); p != "" {
		loadEnvFile(p)
	} else {
		loadEnvFile("/vault/secrets/env")
	}

	cfg, err := buildConfig()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}

	srv, err := server.New(cfg, log)
	if err != nil {
		log.Error("server init", "err", err)
		os.Exit(2)
	}

	addr := envDefault("RELAY_LISTEN_ADDR", ":8443")
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       70 * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go func() {
		log.Info("relay listening", "addr", addr)
		var err error
		if cert, key := os.Getenv("RELAY_TLS_CERT"), os.Getenv("RELAY_TLS_KEY"); cert != "" && key != "" {
			err = httpSrv.ListenAndServeTLS(cert, key)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen", "err", err)
			cancel()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}

func buildConfig() (server.Config, error) {
	agent, err := readSecret("RELAY_AGENT_SECRET")
	if err != nil {
		return server.Config{}, err
	}
	sess, err := readSecret("RELAY_SESSION_SECRET")
	if err != nil {
		return server.Config{}, err
	}
	svc, err := readSecret("RELAY_SVC_SECRET")
	if err != nil {
		return server.Config{}, err
	}
	origins := strings.Split(envDefault("RELAY_OPERATOR_ORIGINS", "app.hasfy.fr"), ",")
	for i := range origins {
		origins[i] = strings.TrimSpace(origins[i])
	}
	return server.Config{
		AgentSecret:     agent,
		SessionSecret:   sess,
		SvcSecret:       svc,
		OperatorOrigins: origins,
	}, nil
}
