// Package server wires HTTP routes for the relay.
//
// Endpoints:
//
//	GET  /healthz          — liveness/readiness for K8s
//	GET  /metrics          — prometheus
//	GET  /agent/ws         — agent WS, requires Authorization: Bearer <agent-jwt>
//	POST /api/devices      — list online devices for an org (svc HMAC)
//	POST /api/console      — mint session token for an operator (svc HMAC)
//	GET  /console/ws       — operator WS, ?token=<session-jwt>
//
// All svc-HMAC endpoints expect headers:
//
//	X-Hasfy-Ts: <unix seconds>
//	X-Hasfy-Sig: hex(HMAC-SHA256(svc_secret, ts + "\n" + method + "\n" + path + "\n" + sha256(body)))
//
// ts must be within ±60 s of now to prevent replay.
package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/HasfyFR/Hasfy-Relay/internal/audit"
	"github.com/HasfyFR/Hasfy-Relay/internal/auth"
	"github.com/HasfyFR/Hasfy-Relay/internal/registry"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config holds runtime parameters loaded from env / Vault.
type Config struct {
	AgentSecret     []byte   // HS256 — verifies agent tokens minted by Hasfy-App
	SessionSecret   []byte   // HS256 — verifies session tokens we issue
	SvcSecret       []byte   // HMAC — Hasfy-App service-to-service auth
	OperatorOrigins []string // accepted Origin: headers on /console/ws (e.g. "app.hasfy.fr")
	MaxFrameBytes   int64    // WS frame size cap
	WriteBufSize    int      // outbound channel size per agent
}

type Server struct {
	cfg      Config
	verifier *auth.Verifier
	reg      *registry.Registry
	audit    *audit.Logger
	router   *router
	log      *slog.Logger
}

func New(cfg Config, log *slog.Logger) (*Server, error) {
	v, err := auth.NewVerifier(cfg.AgentSecret, cfg.SessionSecret)
	if err != nil {
		return nil, err
	}
	if len(cfg.SvcSecret) < 32 {
		return nil, errors.New("svc secret too short")
	}
	if cfg.MaxFrameBytes == 0 {
		cfg.MaxFrameBytes = 1 << 20
	}
	if cfg.WriteBufSize == 0 {
		cfg.WriteBufSize = 32
	}
	srv := &Server{
		cfg:      cfg,
		verifier: v,
		reg:      registry.New(),
		audit:    audit.NewStdout(),
		log:      log,
	}
	srv.initRouter()
	return srv, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.Handle("GET /metrics", promhttp.Handler())
	mux.HandleFunc("GET /agent/ws", s.handleAgentWS)
	mux.HandleFunc("POST /api/devices", s.handleListDevices)
	mux.HandleFunc("POST /api/console", s.handleIssueSession)
	mux.HandleFunc("GET /console/ws", s.handleOperatorWS)
	return mux
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

// verifySvcHMAC authenticates a request from Hasfy-App. Returns true on
// success; on failure it has already written the response.
func (s *Server) verifySvcHMAC(w http.ResponseWriter, r *http.Request, body []byte) bool {
	tsStr := r.Header.Get("X-Hasfy-Ts")
	sig := r.Header.Get("X-Hasfy-Sig")
	if tsStr == "" || sig == "" {
		http.Error(w, "missing svc auth", http.StatusUnauthorized)
		return false
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		http.Error(w, "bad ts", http.StatusUnauthorized)
		return false
	}
	if abs(time.Now().Unix()-ts) > 60 {
		http.Error(w, "stale ts", http.StatusUnauthorized)
		return false
	}

	bodyHash := sha256.Sum256(body)
	mac := hmac.New(sha256.New, s.cfg.SvcSecret)
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(r.Method))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(r.URL.Path))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(hex.EncodeToString(bodyHash[:])))
	want := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(want), []byte(sig)) {
		s.audit.Emit(audit.Event{Kind: "auth.fail", IP: clientIP(r), Reason: "svc hmac mismatch"})
		http.Error(w, "bad sig", http.StatusUnauthorized)
		return false
	}
	return true
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		// Trust only the first hop. Ingress NGINX prepends.
		if i := strings.IndexByte(v, ','); i > 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	if i := strings.LastIndexByte(r.RemoteAddr, ':'); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}

func bearerToken(r *http.Request) string {
	a := r.Header.Get("Authorization")
	const p = "Bearer "
	if !strings.HasPrefix(a, p) {
		return ""
	}
	return a[len(p):]
}

// readBody reads up to maxFrameBytes; bigger requests are rejected.
func (s *Server) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxFrameBytes)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	return b, true
}

// writeJSON serializes v as JSON. Only call once per response.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
