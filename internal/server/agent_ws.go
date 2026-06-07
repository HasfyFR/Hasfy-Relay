package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/HasfyFR/Hasfy-Relay/internal/audit"
	"github.com/HasfyFR/Hasfy-Relay/internal/proto"
	"github.com/HasfyFR/Hasfy-Relay/internal/registry"
	"github.com/coder/websocket"
)

const (
	wsReadLimit       = 1 << 20 // 1 MiB max frame
	wsPingInterval    = 25 * time.Second
	wsRegisterTimeout = 10 * time.Second
)

// handleAgentWS is the WS endpoint agents connect to.
//
// Lifecycle:
//   1. Authorization: Bearer <agent-jwt>  → claims (device_id, org_id)
//   2. Upgrade WS, set 1 MiB read limit
//   3. Expect first frame: register (must match claims)
//   4. Pump reads/writes until either side closes or the parent ctx ends
func (s *Server) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	tok := bearerToken(r)
	if tok == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	claims, err := s.verifier.VerifyAgent(tok)
	if err != nil {
		s.audit.Emit(audit.Event{Kind: "auth.fail", IP: clientIP(r), Reason: "bad agent token"})
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Same-origin: only the relay's own host. Agents come from anywhere
		// so we DO NOT enforce a list — the bearer token is the auth.
		InsecureSkipVerify: true,
		// We never compress untrusted input; protects against zip-bomb DoS.
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	c.SetReadLimit(wsReadLimit)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// 3. Register handshake.
	regCtx, regCancel := context.WithTimeout(ctx, wsRegisterTimeout)
	defer regCancel()
	first, err := readFrame(regCtx, c)
	if err != nil || first.Type != proto.TypeRegister || first.Register == nil {
		_ = c.Close(websocket.StatusPolicyViolation, "register frame required")
		return
	}
	reg := first.Register
	if reg.DeviceID != claims.DeviceID || reg.OrgID != claims.OrgID {
		s.audit.Emit(audit.Event{
			Kind: "auth.fail", IP: clientIP(r), DeviceID: reg.DeviceID,
			OrgID: reg.OrgID, Reason: "register mismatch with token claims",
		})
		_ = c.Close(websocket.StatusPolicyViolation, "claims mismatch")
		return
	}

	a := &registry.Agent{
		DeviceID: reg.DeviceID,
		OrgID:    reg.OrgID,
		Hostname: reg.Hostname,
		OS:       reg.OS,
		Arch:     reg.Arch,
		Version:  reg.Version,
	}
	agentCtx := s.reg.Register(ctx, a, s.cfg.WriteBufSize)
	s.audit.Emit(audit.Event{
		Kind: "agent.connect", OrgID: a.OrgID, DeviceID: a.DeviceID,
		IP: clientIP(r), Meta: map[string]string{"hostname": a.Hostname, "os": a.OS},
	})
	defer func() {
		s.reg.Unregister(a)
		s.audit.Emit(audit.Event{Kind: "agent.disconnect", OrgID: a.OrgID, DeviceID: a.DeviceID})
	}()

	// 4. Two pumps. We use a small errgroup-like pattern by hand so we can
	// stay on stdlib + coder/websocket.
	errCh := make(chan error, 2)
	go func() { errCh <- agentReadPump(agentCtx, c, s, a) }()
	go func() { errCh <- agentWritePump(agentCtx, c, a) }()
	<-errCh
	_ = c.Close(websocket.StatusNormalClosure, "")
}

func agentReadPump(ctx context.Context, c *websocket.Conn, s *Server, a *registry.Agent) error {
	for {
		f, err := readFrame(ctx, c)
		if err != nil {
			return err
		}
		// Currently we only consume agent → relay frames that are responses
		// to an in-flight exec (ack/output/exit/error/pong). They are
		// forwarded to the operator session via a side channel set up in
		// operator_ws.go. For now, ignore unsolicited frames.
		switch f.Type {
		case proto.TypePong, proto.TypePing:
			// keep-alive, no-op
		case proto.TypeExecAck, proto.TypeExit, proto.TypeError,
			proto.TypeStdout, proto.TypeStderr,
			proto.TypePtyData, proto.TypePtyExit:
			s.routeAgentResponse(a, f)
		default:
			// Unknown — drop on the floor, log once.
			s.log.Warn("agent unexpected frame", "type", f.Type, "device", a.DeviceID)
		}
	}
}

func agentWritePump(ctx context.Context, c *websocket.Conn, a *registry.Agent) error {
	ping := time.NewTicker(wsPingInterval)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case f, ok := <-a.Outbound():
			if !ok {
				return errors.New("outbound closed")
			}
			if err := writeFrame(ctx, c, f); err != nil {
				return err
			}
		case <-ping.C:
			if err := writeFrame(ctx, c, proto.Frame{Type: proto.TypePing}); err != nil {
				return err
			}
		}
	}
}

func readFrame(ctx context.Context, c *websocket.Conn) (proto.Frame, error) {
	_, data, err := c.Read(ctx)
	if err != nil {
		return proto.Frame{}, err
	}
	var f proto.Frame
	if err := json.Unmarshal(data, &f); err != nil {
		return proto.Frame{}, err
	}
	return f, nil
}

func writeFrame(ctx context.Context, c *websocket.Conn, f proto.Frame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.Write(wctx, websocket.MessageText, b)
}
