package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os/exec"
	"sync"
	"time"

	"github.com/HasfyFR/Hasfy-Relay/internal/audit"
	"github.com/HasfyFR/Hasfy-Relay/internal/proto"
	"github.com/coder/websocket"
)

const (
	wsReadLimit       = 1 << 20
	defaultTimeoutMs  = 60_000
	maxParallelExec   = 8 // bound resource usage on the device
	registerTimeout   = 10 * time.Second
)

// runOnce performs one full session: connect, register, pump frames until
// the connection drops. Returns the disconnect cause.
func runOnce(parent context.Context, log *slog.Logger, url, token string, reg proto.Register) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}},
		// Plain WS only — TLS is handled by the URL scheme (wss://).
	})
	if err != nil {
		return err
	}
	c.SetReadLimit(wsReadLimit)
	defer c.Close(websocket.StatusNormalClosure, "")

	// Register.
	rctx, rcancel := context.WithTimeout(ctx, registerTimeout)
	defer rcancel()
	if err := writeFrame(rctx, c, proto.Frame{Type: proto.TypeRegister, Register: &reg}); err != nil {
		return err
	}

	log.Info("agent registered", "device", reg.DeviceID, "os", reg.OS)

	out := make(chan proto.Frame, 32)
	defer close(out)

	// Bound concurrent execs.
	sem := make(chan struct{}, maxParallelExec)

	// Writer goroutine.
	writeErr := make(chan error, 1)
	go func() {
		ping := time.NewTicker(20 * time.Second)
		defer ping.Stop()
		for {
			select {
			case <-ctx.Done():
				writeErr <- ctx.Err()
				return
			case f, ok := <-out:
				if !ok {
					writeErr <- nil
					return
				}
				if err := writeFrame(ctx, c, f); err != nil {
					writeErr <- err
					return
				}
			case <-ping.C:
				if err := writeFrame(ctx, c, proto.Frame{Type: proto.TypePing}); err != nil {
					writeErr <- err
					return
				}
			}
		}
	}()

	// Tracks running execs so we can cancel them.
	var mu sync.Mutex
	cancels := map[string]context.CancelFunc{}

	// Tracks interactive PTY sessions.
	ptys := newPtyRegistry()
	defer ptys.closeAll()

	// Reader loop.
	for {
		select {
		case err := <-writeErr:
			return err
		default:
		}
		f, err := readFrame(ctx, c)
		if err != nil {
			return err
		}
		switch f.Type {
		case proto.TypePing:
			out <- proto.Frame{Type: proto.TypePong}
		case proto.TypePong:
			// no-op
		case proto.TypeExec:
			if f.Exec == nil || f.SessionID == "" || f.ExecID == "" || len(f.Exec.Argv) == 0 {
				continue
			}
			ectx, ecancel := context.WithCancel(ctx)
			mu.Lock()
			cancels[f.ExecID] = ecancel
			mu.Unlock()

			select {
			case sem <- struct{}{}:
			default:
				// At cap. Refuse politely.
				out <- proto.Frame{
					Type: proto.TypeExit, SessionID: f.SessionID, ExecID: f.ExecID,
					Exit: &proto.Exit{ExitCode: -1, EndedAt: time.Now()},
					Error: &proto.ErrorMsg{Code: "busy", Message: "agent at exec capacity"},
				}
				ecancel()
				continue
			}

			go func(cmd proto.Frame, ectx context.Context, ecancel context.CancelFunc) {
				defer func() {
					ecancel()
					<-sem
					mu.Lock()
					delete(cancels, cmd.ExecID)
					mu.Unlock()
				}()
				runExec(ectx, log, cmd, out)
			}(f, ectx, ecancel)

		case proto.TypeCancel:
			if f.ExecID == "" {
				// Empty ExecID means "kill the PTY for this session".
				if f.SessionID != "" {
					if p := ptys.delete(f.SessionID); p != nil {
						p.close()
					}
				}
				continue
			}
			mu.Lock()
			if c, ok := cancels[f.ExecID]; ok {
				c()
			}
			mu.Unlock()

		case proto.TypePtyStart:
			if f.SessionID == "" || f.PtyStart == nil {
				continue
			}
			if err := ptys.startPty(ctx, log, f.SessionID, *f.PtyStart, out); err != nil {
				out <- proto.Frame{
					Type: proto.TypeError, SessionID: f.SessionID,
					Error: &proto.ErrorMsg{Code: "pty_start_failed", Message: err.Error()},
				}
			}

		case proto.TypePtyData:
			if f.SessionID == "" || f.PtyData == nil {
				continue
			}
			p := ptys.get(f.SessionID)
			if p == nil {
				continue
			}
			raw, derr := base64.StdEncoding.DecodeString(f.PtyData.Data)
			if derr != nil {
				continue
			}
			if werr := p.writeStdin(raw); werr != nil {
				// Shell is gone — clean up.
				if removed := ptys.delete(f.SessionID); removed != nil {
					removed.close()
				}
			}

		case proto.TypePtyResize:
			if f.SessionID == "" || f.PtyResize == nil {
				continue
			}
			p := ptys.get(f.SessionID)
			if p == nil {
				continue
			}
			_ = p.resize(f.PtyResize.Cols, f.PtyResize.Rows)

		default:
			// ignore
		}
	}
}

// runExec runs the requested command with timeout and output cap, then
// emits ack + chunked output + exit frames.
func runExec(ctx context.Context, log *slog.Logger, f proto.Frame, out chan<- proto.Frame) {
	tm := f.Exec.TimeoutMs
	if tm <= 0 {
		tm = defaultTimeoutMs
	}
	cap := f.Exec.OutputCap
	if cap <= 0 {
		cap = 1 << 20
	}

	ectx, cancel := context.WithTimeout(ctx, time.Duration(tm)*time.Millisecond)
	defer cancel()

	// IMPORTANT: argv-only. Never pass to a shell. CommandContext does not
	// invoke a shell.
	cmd := exec.CommandContext(ectx, f.Exec.Argv[0], f.Exec.Argv[1:]...)
	if f.Exec.Cwd != "" {
		cmd.Dir = f.Exec.Cwd
	}
	if len(f.Exec.Env) > 0 {
		// Whitelist additive env. Refuse to pass through HASFY_* and
		// known-sensitive prefixes.
		extra := make([]string, 0, len(f.Exec.Env))
		for k, v := range f.Exec.Env {
			if isSensitiveEnvName(k) {
				continue
			}
			extra = append(extra, k+"="+v)
		}
		cmd.Env = append(cmd.Environ(), extra...)
	}
	if f.Exec.Stdin != "" {
		if b, err := base64.StdEncoding.DecodeString(f.Exec.Stdin); err == nil {
			cmd.Stdin = bytesReader(b)
		}
	}

	stdout := newCapBuffer(cap)
	stderr := newCapBuffer(cap)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		out <- proto.Frame{
			Type: proto.TypeExit, SessionID: f.SessionID, ExecID: f.ExecID,
			Exit: &proto.Exit{ExitCode: -1, EndedAt: time.Now()},
			Error: &proto.ErrorMsg{Code: "exec_start_failed", Message: err.Error()},
		}
		return
	}

	out <- proto.Frame{
		Type: proto.TypeExecAck, SessionID: f.SessionID, ExecID: f.ExecID,
		ExecAck: &proto.ExecAck{StartedAt: time.Now(), PID: cmd.Process.Pid},
	}

	err := cmd.Wait()
	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
		}
	}

	// Flush stdout/stderr in two final chunks. Phase 1 is line-buffered
	// final; phase 2 will stream incremental chunks for long-running cmds.
	if b := stdout.Bytes(); len(b) > 0 {
		emitOutput(out, f.SessionID, f.ExecID, proto.TypeStdout, b)
	}
	if b := stderr.Bytes(); len(b) > 0 {
		emitOutput(out, f.SessionID, f.ExecID, proto.TypeStderr, b)
	}

	truncated := stdout.Truncated() || stderr.Truncated()
	out <- proto.Frame{
		Type: proto.TypeExit, SessionID: f.SessionID, ExecID: f.ExecID,
		Exit: &proto.Exit{
			ExitCode:  exitCode,
			EndedAt:   time.Now(),
			Truncated: truncated,
		},
	}
}

func emitOutput(out chan<- proto.Frame, sid, eid string, t proto.FrameType, b []byte) {
	// First-line redaction at the source — reduces what's on the wire.
	scrubbed := audit.Redact(string(b))
	out <- proto.Frame{
		Type: t, SessionID: sid, ExecID: eid,
		Output: &proto.Output{Data: base64.StdEncoding.EncodeToString([]byte(scrubbed))},
	}
}

func isSensitiveEnvName(k string) bool {
	switch k {
	case "HASFY_RELAY_TOKEN", "HASFY_DEVICE_ID", "HASFY_ORG_ID", "HASFY_RELAY_URL":
		return true
	}
	switch {
	case len(k) > 5 && (k[:5] == "AWS_S" || k[:5] == "AWS_A"):
		return true
	}
	return false
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
