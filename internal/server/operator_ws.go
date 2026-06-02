package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"github.com/HasfyFR/Hasfy-Relay/internal/audit"
	"github.com/HasfyFR/Hasfy-Relay/internal/auth"
	"github.com/HasfyFR/Hasfy-Relay/internal/proto"
	"github.com/coder/websocket"
)

const (
	sessionMaxDuration = 4 * time.Hour
	sessionIdleTimeout = 15 * time.Minute
)

// activeSession is the live state of one operator's console session.
//
// We keep an in-memory router map sessionID → channel so that frames
// returned by the agent can find their way back to the right operator
// websocket. There is exactly ONE operator per session — second WS
// connections with the same token are rejected (one-time use).
type activeSession struct {
	claims    *auth.SessionClaims
	toBrowser chan proto.Frame
	closed    chan struct{}
	closeOnce sync.Once
}

func (s *activeSession) close() {
	s.closeOnce.Do(func() { close(s.closed) })
}

// router holds session state, keyed by deviceID + sessionID.
type router struct {
	mu       sync.Mutex
	sessions map[string]*activeSession // key = sid
}

func newRouter() *router { return &router{sessions: make(map[string]*activeSession)} }

func (r *router) attach(sid string, sess *activeSession) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.sessions[sid]; exists {
		return false
	}
	r.sessions[sid] = sess
	return true
}

func (r *router) detach(sid string) {
	r.mu.Lock()
	if sess, ok := r.sessions[sid]; ok {
		delete(r.sessions, sid)
		sess.close()
	}
	r.mu.Unlock()
}

func (r *router) get(sid string) *activeSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[sid]
}

// (added to Server in server.go via routeAgentResponse + initRouter)

// initRouter is called once from New() — declared here so server.go stays
// focused on routing.
func (s *Server) initRouter() { s.router = newRouter() }

// routeAgentResponse forwards a frame from an agent to the operator that
// owns the session. Drops silently if the session is gone (operator
// disconnected mid-exec) — the agent is already cancelled or will be on
// next exec.
func (s *Server) routeAgentResponse(_ /*a*/ any, f proto.Frame) {
	if f.SessionID == "" {
		return
	}
	sess := s.router.get(f.SessionID)
	if sess == nil {
		return
	}
	select {
	case sess.toBrowser <- f:
	default:
		// Operator backed up — close the session. Better than ballooning memory.
		sess.close()
	}
}

// handleOperatorWS upgrades the browser side. Requires `?token=<jwt>` and
// matching IP/UA hash from the issued claims.
func (s *Server) handleOperatorWS(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if tok == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	claims, err := s.verifier.VerifySession(tok, clientIP(r), r.UserAgent())
	if err != nil {
		s.audit.Emit(audit.Event{Kind: "auth.fail", IP: clientIP(r), Reason: "bad session token"})
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	a, err := s.reg.Get(claims.DeviceID)
	if err != nil {
		http.Error(w, "device offline", http.StatusConflict)
		return
	}
	if a.OrgID != claims.OrgID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Hasfy-App is the only legitimate origin for the operator console.
		// In dev/test we allow localhost via env override (see config).
		OriginPatterns:  s.cfg.OperatorOrigins,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	c.SetReadLimit(wsReadLimit)

	sess := &activeSession{
		claims:    claims,
		toBrowser: make(chan proto.Frame, 64),
		closed:    make(chan struct{}),
	}
	if !s.router.attach(claims.SessionID, sess) {
		// Token replayed — already in use.
		_ = c.Close(websocket.StatusPolicyViolation, "session already active")
		return
	}
	defer s.router.detach(claims.SessionID)

	// Hard cap.
	ctx, cancel := context.WithTimeout(r.Context(), sessionMaxDuration)
	defer cancel()

	// Idle timeout — reset on each operator frame.
	idle := time.NewTimer(sessionIdleTimeout)
	defer idle.Stop()

	// Operator → agent pump.
	opErr := make(chan error, 1)
	go func() {
		for {
			f, err := readFrame(ctx, c)
			if err != nil {
				opErr <- err
				return
			}
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(sessionIdleTimeout)

			// Lock down what an operator may send. Only Exec/Cancel/Ping.
			switch f.Type {
			case proto.TypePing:
				_ = writeFrame(ctx, c, proto.Frame{Type: proto.TypePong})
				continue
			case proto.TypeExec, proto.TypeCancel:
				// continue below
			default:
				// Drop everything else.
				continue
			}
			f.SessionID = claims.SessionID

			if f.Type == proto.TypeExec && f.Exec != nil {
				// Server-side guards.
				if f.Exec.TimeoutMs <= 0 || f.Exec.TimeoutMs > 600_000 {
					f.Exec.TimeoutMs = 60_000
				}
				if f.Exec.OutputCap <= 0 || f.Exec.OutputCap > 8<<20 {
					f.Exec.OutputCap = 1 << 20
				}
				if len(f.Exec.Argv) == 0 {
					continue
				}
				s.audit.Emit(audit.Event{
					Kind: "exec.start", OrgID: claims.OrgID, DeviceID: claims.DeviceID,
					SessionID: claims.SessionID, ExecID: f.ExecID,
					Operator: claims.Subject, Argv: f.Exec.Argv,
				})
			}

			if !a.Send(f) {
				// Agent buffer full — kill session, agent is unresponsive.
				_ = c.Close(websocket.StatusInternalError, "agent backpressure")
				opErr <- nil
				return
			}
		}
	}()

	// Forward agent responses to browser, with re-redaction for defense in depth.
	for {
		select {
		case <-ctx.Done():
			_ = c.Close(websocket.StatusNormalClosure, "session ended")
			s.audit.Emit(audit.Event{
				Kind: "session.close", SessionID: claims.SessionID,
				OrgID: claims.OrgID, DeviceID: claims.DeviceID,
				Reason: "max duration",
			})
			return
		case <-idle.C:
			_ = c.Close(websocket.StatusGoingAway, "idle")
			s.audit.Emit(audit.Event{
				Kind: "session.close", SessionID: claims.SessionID,
				OrgID: claims.OrgID, DeviceID: claims.DeviceID,
				Reason: "idle timeout",
			})
			return
		case <-sess.closed:
			_ = c.Close(websocket.StatusGoingAway, "session closed")
			return
		case err := <-opErr:
			_ = c.Close(websocket.StatusNormalClosure, "")
			if err != nil {
				s.audit.Emit(audit.Event{
					Kind: "session.close", SessionID: claims.SessionID,
					OrgID: claims.OrgID, DeviceID: claims.DeviceID,
					Reason: "operator disconnect",
				})
			}
			return
		case f := <-sess.toBrowser:
			// Re-redact base64 payloads on the way out. Defense in depth:
			// if a future agent forgets to redact, we still scrub.
			if f.Output != nil && f.Output.Data != "" {
				if raw, err := base64.StdEncoding.DecodeString(f.Output.Data); err == nil {
					redacted := audit.Redact(string(raw))
					f.Output.Data = base64.StdEncoding.EncodeToString([]byte(redacted))
				}
			}
			if f.Type == proto.TypeExit && f.Exit != nil {
				ec := f.Exit.ExitCode
				s.audit.Emit(audit.Event{
					Kind: "exec.exit", OrgID: claims.OrgID, DeviceID: claims.DeviceID,
					SessionID: claims.SessionID, ExecID: f.ExecID, ExitCode: &ec,
				})
			}
			if err := writeFrame(ctx, c, f); err != nil {
				return
			}
		}
	}
}
