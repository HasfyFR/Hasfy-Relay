package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/HasfyFR/Hasfy-Relay/internal/audit"
	"github.com/HasfyFR/Hasfy-Relay/internal/proto"
	"github.com/google/uuid"
)

// =============================================================================
// Server-initiated execution
// =============================================================================
//
// Hasfy-App runs a script-library entry on a device by calling this endpoint,
// which pushes an Exec frame down the agent's existing WebSocket and waits for
// the result.
//
// Why this replaces the HTTP-polling channel
// ------------------------------------------
// There used to be a second execution path: the device polled
// `/api/v1/installer/script-executions/...` over HTTP. It had no runner —
// nothing scheduled the poll on an unattended machine — so a command pushed
// from the console was simply never executed. Worse, the two paths had
// opposite security models: the polling one ran `bash -c "<content>"` with no
// timeout, while this one is argv-only with a timeout, a cancel, and an audit
// trail.
//
// One channel, with the stricter model, is the whole point of this endpoint.

const (
	// Hard ceiling on a single server-initiated command. The operator's
	// requested timeout is clamped to it: this handler holds an HTTP request
	// open for the duration, and an unbounded one would pin a connection.
	maxExecTimeoutMs = 600_000

	// Bytes per stream returned to the caller.
	defaultExecOutputCap = 1 << 20
)

type execReq struct {
	OrgID    string `json:"org_id"`
	DeviceID string `json:"device_id"`

	// Either an argv or a script body.
	Argv   []string `json:"argv,omitempty"`
	Script *struct {
		Interpreter string `json:"interpreter"`
		Content     string `json:"content"`
	} `json:"script,omitempty"`

	Cwd       string `json:"cwd,omitempty"`
	TimeoutMs int    `json:"timeout_ms,omitempty"`
	OutputCap int    `json:"output_cap,omitempty"`

	// Who asked, and which execution row this belongs to. Recorded in the
	// audit trail — an execution with no attributable operator is worthless
	// after the fact.
	OperatorUserID string `json:"operator_user_id"`
	ExecutionID    string `json:"execution_id,omitempty"`
}

type execRes struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	Truncated  bool   `json:"truncated"`
	TimedOut   bool   `json:"timed_out"`
	DurationMs int64  `json:"duration_ms"`
}

// handleExec runs one command on one device and returns its result.
//
// Synchronous by design: script executions are operator-initiated, bounded by
// a timeout, and the caller wants the outcome to store. An async job queue
// would add a second source of truth for something that already has one
// (`script_executions` in Postgres).
func (s *Server) handleExec(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	if !s.verifySvcHMAC(w, r, body) {
		return
	}

	var req execReq
	if err := json.Unmarshal(body, &req); err != nil ||
		req.OrgID == "" || req.DeviceID == "" || req.OperatorUserID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(req.Argv) == 0 && req.Script == nil {
		http.Error(w, "argv or script is required", http.StatusBadRequest)
		return
	}

	a, err := s.reg.Get(req.DeviceID)
	if err != nil {
		http.Error(w, "device offline", http.StatusConflict)
		return
	}
	if a.OrgID != req.OrgID {
		// The app should not have asked. Audit it: a mismatch here is either a
		// bug or an attempt to reach across tenants.
		s.audit.Emit(audit.Event{
			Kind: "auth.fail", OrgID: req.OrgID, DeviceID: req.DeviceID,
			Operator: req.OperatorUserID, Reason: "org mismatch",
		})
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	timeout := req.TimeoutMs
	if timeout <= 0 || timeout > maxExecTimeoutMs {
		timeout = maxExecTimeoutMs
	}
	outputCap := req.OutputCap
	if outputCap <= 0 || outputCap > 8<<20 {
		outputCap = defaultExecOutputCap
	}

	// A synthetic session so agent responses route back here through the same
	// machinery browser sessions use.
	sessionID := "svc-" + uuid.NewString()
	execID := uuid.NewString()

	sess := &activeSession{
		toBrowser: make(chan proto.Frame, 64),
		closed:    make(chan struct{}),
	}
	if !s.router.attach(sessionID, sess) {
		http.Error(w, "session collision", http.StatusInternalServerError)
		return
	}
	defer s.router.detach(sessionID)

	execFrame := proto.Frame{
		Type: proto.TypeExec, SessionID: sessionID, ExecID: execID,
		Exec: &proto.Exec{
			Argv:      req.Argv,
			Cwd:       req.Cwd,
			TimeoutMs: timeout,
			OutputCap: outputCap,
		},
	}
	if req.Script != nil {
		execFrame.Exec.Script = &proto.Script{
			Interpreter: req.Script.Interpreter,
			Content:     req.Script.Content,
		}
	}

	s.audit.Emit(audit.Event{
		Kind: "exec.start", OrgID: req.OrgID, DeviceID: req.DeviceID,
		SessionID: sessionID, ExecID: execID, Operator: req.OperatorUserID,
		Argv: auditArgv(req),
		Meta: map[string]string{"execution_id": req.ExecutionID, "source": "app"},
	})

	started := time.Now()
	if !a.Send(execFrame) {
		http.Error(w, "agent backpressure", http.StatusServiceUnavailable)
		return
	}

	// Give the agent its full timeout plus a margin for the round trip. Tying
	// this to the request context means a caller hanging up also stops us
	// waiting.
	ctx, cancel := context.WithTimeout(r.Context(),
		time.Duration(timeout)*time.Millisecond+15*time.Second)
	defer cancel()

	res, timedOut := collectExecResult(ctx, sess)
	res.DurationMs = time.Since(started).Milliseconds()
	res.TimedOut = timedOut

	if timedOut {
		// Tell the agent to stop; otherwise the process keeps running on the
		// device with nobody reading its output.
		a.Send(proto.Frame{Type: proto.TypeCancel, SessionID: sessionID, ExecID: execID})
	}

	exitCode := res.ExitCode
	s.audit.Emit(audit.Event{
		Kind: "exec.exit", OrgID: req.OrgID, DeviceID: req.DeviceID,
		SessionID: sessionID, ExecID: execID, Operator: req.OperatorUserID,
		ExitCode: &exitCode,
		Meta: map[string]string{
			"execution_id": req.ExecutionID,
			"source":       "app",
			"duration":     durationLabel(res.DurationMs),
		},
	})

	writeJSON(w, http.StatusOK, res)
}

// auditArgv is what gets recorded for the command.
//
// For a script we record the interpreter and a marker rather than the body:
// script contents routinely carry credentials, and the audit log is read by
// more people than the script library is.
func auditArgv(req execReq) []string {
	if req.Script != nil {
		return []string{req.Script.Interpreter, "<script>"}
	}
	return req.Argv
}

// collectExecResult drains the session until the agent reports an exit.
func collectExecResult(ctx context.Context, sess *activeSession) (execRes, bool) {
	var res execRes
	var stdout, stderr []byte

	for {
		select {
		case <-ctx.Done():
			res.Stdout = string(stdout)
			res.Stderr = string(stderr)
			res.ExitCode = -1
			return res, true

		case <-sess.closed:
			res.Stdout = string(stdout)
			res.Stderr = string(stderr)
			res.ExitCode = -1
			return res, false

		case f := <-sess.toBrowser:
			switch f.Type {
			case proto.TypeStdout:
				stdout = append(stdout, decodeOutput(f)...)
			case proto.TypeStderr:
				stderr = append(stderr, decodeOutput(f)...)
			case proto.TypeExit:
				if f.Exit != nil {
					res.ExitCode = f.Exit.ExitCode
					res.Truncated = f.Exit.Truncated
				} else {
					res.ExitCode = -1
				}
				res.Stdout = string(stdout)
				res.Stderr = string(stderr)
				return res, false
			}
		}
	}
}

func decodeOutput(f proto.Frame) []byte {
	if f.Output == nil || f.Output.Data == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(f.Output.Data)
	if err != nil {
		return nil
	}
	return raw
}

// durationLabel renders a millisecond count as "1.5s" for the audit metadata,
// which is read by humans far more often than it is parsed.
func durationLabel(ms int64) string {
	return (time.Duration(ms) * time.Millisecond).String()
}
