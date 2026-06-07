package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"os"
	"runtime"
	"sync"

	"github.com/HasfyFR/Hasfy-Relay/internal/proto"
)

// Cap on how many concurrent PTY shells one agent may host. Each session
// holds a full process tree, so this bounds resource use.
const maxParallelPtys = 8

// Output streaming knobs.
const (
	ptyReadBuf = 32 * 1024 // bytes
)

// ptyMaster is the OS-specific shell + pseudo-terminal pair. Closing the
// master tears down the underlying process tree. Implemented by
// `pty_unix.go` (creack/pty) on Unix-like systems and `pty_windows.go`
// (ConPTY) on Windows 10 1809+.
type ptyMaster interface {
	io.ReadWriter
	// Resize informs the kernel of a new terminal size in cells.
	Resize(cols, rows uint16) error
	// Wait blocks until the shell exits and returns its exit code. Safe
	// to call after Close() — the OS-specific impl must be idempotent.
	Wait() (int, error)
	// Close tears down the shell process and releases the PTY. Idempotent.
	Close() error
	// PID returns the OS PID of the shell process. Useful for logs.
	PID() int
}

// ptySession is one live shell under a PTY, keyed by the operator session ID.
type ptySession struct {
	sid    string
	master ptyMaster
	cancel context.CancelFunc
	mu     sync.Mutex // serializes stdin writes to the PTY master
}

func (p *ptySession) writeStdin(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, err := p.master.Write(b)
	return err
}

func (p *ptySession) resize(cols, rows uint16) error {
	if cols == 0 || rows == 0 {
		return nil
	}
	return p.master.Resize(cols, rows)
}

func (p *ptySession) close() {
	p.cancel()
	_ = p.master.Close()
}

// ptyRegistry holds active PTY sessions for this agent connection. The
// registry lifetime is tied to one runOnce call (one WS connection): on
// disconnect, closeAll() tears everything down.
type ptyRegistry struct {
	mu       sync.Mutex
	sessions map[string]*ptySession
}

func newPtyRegistry() *ptyRegistry {
	return &ptyRegistry{sessions: make(map[string]*ptySession)}
}

func (r *ptyRegistry) get(sid string) *ptySession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[sid]
}

func (r *ptyRegistry) put(sid string, p *ptySession) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sessions[sid]; ok {
		return false
	}
	if len(r.sessions) >= maxParallelPtys {
		return false
	}
	r.sessions[sid] = p
	return true
}

func (r *ptyRegistry) delete(sid string) *ptySession {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.sessions[sid]
	delete(r.sessions, sid)
	return p
}

func (r *ptyRegistry) closeAll() {
	r.mu.Lock()
	all := r.sessions
	r.sessions = make(map[string]*ptySession)
	r.mu.Unlock()
	for _, p := range all {
		p.close()
	}
}

// startPty spawns a shell under a fresh PTY for the given session ID and
// streams its output back via `out`. It returns immediately; the shell
// runs in background goroutines until the parent context is cancelled,
// the shell exits, or the session is explicitly closed.
//
// The OS-specific shell spawn is delegated to `spawnShell` which is
// implemented separately for Unix (creack/pty) and Windows (ConPTY).
func (r *ptyRegistry) startPty(
	parent context.Context,
	log *slog.Logger,
	sid string,
	params proto.PtyStart,
	out chan<- proto.Frame,
) error {
	if sid == "" {
		return errors.New("empty session id")
	}

	shell := params.Shell
	if shell == "" {
		shell = defaultShell()
	}
	term := params.Term
	if term == "" {
		term = "xterm-256color"
	}
	cols := params.Cols
	if cols == 0 {
		cols = 80
	}
	rows := params.Rows
	if rows == 0 {
		rows = 24
	}

	ctx, cancel := context.WithCancel(parent)

	master, err := spawnShell(shell, term, cols, rows)
	if err != nil {
		cancel()
		return err
	}

	sess := &ptySession{
		sid:    sid,
		master: master,
		cancel: cancel,
	}
	if !r.put(sid, sess) {
		sess.close()
		return errors.New("pty already exists for session or capacity reached")
	}

	log.Info("pty started", "sid", sid, "shell", shell, "pid", master.PID())

	// Reader goroutine: drains PTY → emits pty.data frames.
	go func() {
		defer func() {
			// Ensure session removed from registry on any exit.
			if removed := r.delete(sid); removed != nil {
				removed.close()
			}
		}()
		buf := make([]byte, ptyReadBuf)
		for {
			n, rerr := master.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				select {
				case out <- proto.Frame{
					Type:      proto.TypePtyData,
					SessionID: sid,
					PtyData:   &proto.PtyData{Data: base64.StdEncoding.EncodeToString(chunk)},
				}:
				case <-ctx.Done():
					return
				}
			}
			if rerr != nil {
				// Shell exited or PTY closed. Wait() returns the exit
				// code (or -1 if the process was killed by signal).
				exitCode, _ := master.Wait()
				if rerr != io.EOF {
					log.Info("pty closed", "sid", sid, "err", rerr.Error())
				}
				select {
				case out <- proto.Frame{
					Type:      proto.TypePtyExit,
					SessionID: sid,
					PtyExit:   &proto.PtyExit{ExitCode: exitCode},
				}:
				case <-ctx.Done():
				}
				return
			}
		}
	}()

	return nil
}

// defaultShell returns the most reasonable interactive shell available on
// the current OS. Falls back to a minimal shell if nothing else exists.
func defaultShell() string {
	switch runtime.GOOS {
	case "windows":
		// PowerShell if present, else cmd.exe via ComSpec.
		if cs := os.Getenv("ComSpec"); cs != "" {
			return cs
		}
		return "cmd.exe"
	case "darwin":
		for _, p := range []string{"/bin/zsh", "/bin/bash", "/bin/sh"} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		return "/bin/sh"
	default: // linux + other unix
		for _, p := range []string{"/bin/bash", "/bin/zsh", "/bin/sh"} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		return "/bin/sh"
	}
}
