package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/HasfyFR/Hasfy-Relay/internal/proto"
	"github.com/creack/pty"
)

// Cap on how many concurrent PTY shells one agent may host. Each session
// holds a full process tree, so this bounds resource use.
const maxParallelPtys = 8

// Output streaming knobs.
const (
	ptyReadBuf    = 32 * 1024 // bytes
	ptyMaxFrameMs = 30        // flush every 30ms even if buffer not full
)

// ptySession is one live shell under a PTY, keyed by the operator session ID.
type ptySession struct {
	sid    string
	pty    *os.File
	cmd    *exec.Cmd
	cancel context.CancelFunc
	mu     sync.Mutex // serializes stdin writes to the PTY master
}

func (p *ptySession) writeStdin(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, err := p.pty.Write(b)
	return err
}

func (p *ptySession) resize(cols, rows uint16) error {
	if cols == 0 || rows == 0 {
		return nil
	}
	return pty.Setsize(p.pty, &pty.Winsize{Cols: cols, Rows: rows})
}

func (p *ptySession) close() {
	// Cancel context first so the reader goroutine sees EOF cleanly.
	p.cancel()
	_ = p.pty.Close()
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Signal(syscall.SIGHUP)
		// Give it 200ms to exit gracefully, then kill.
		done := make(chan struct{})
		go func() { _, _ = p.cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(200 * time.Millisecond):
			_ = p.cmd.Process.Kill()
		}
	}
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

	// Login shell so PATH and user env are populated as if the operator
	// SSH'd in. This matches the "SSH-like" UX expected by the operator.
	cmd := exec.CommandContext(ctx, shell, "-l")
	cmd.Env = ptyEnv(term, shell)

	// Start under PTY.
	ptyFile, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: cols, Rows: rows})
	if err != nil {
		cancel()
		return err
	}

	sess := &ptySession{
		sid:    sid,
		pty:    ptyFile,
		cmd:    cmd,
		cancel: cancel,
	}
	if !r.put(sid, sess) {
		sess.close()
		return errors.New("pty already exists for session or capacity reached")
	}

	log.Info("pty started", "sid", sid, "shell", shell, "pid", cmd.Process.Pid)

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
			n, rerr := ptyFile.Read(buf)
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
				// Shell exited or PTY closed.
				exitCode := 0
				if cmd.ProcessState != nil {
					exitCode = cmd.ProcessState.ExitCode()
				} else if werr := cmd.Wait(); werr != nil {
					var ee *exec.ExitError
					if errors.As(werr, &ee) {
						exitCode = ee.ExitCode()
					} else {
						exitCode = -1
					}
				}
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
// the current OS. Falls back to /bin/sh if nothing else exists.
func defaultShell() string {
	candidates := []string{}
	if runtime.GOOS == "darwin" {
		candidates = append(candidates, "/bin/zsh", "/bin/bash")
	} else {
		candidates = append(candidates, "/bin/bash", "/bin/zsh")
	}
	candidates = append(candidates, "/bin/sh")
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/bin/sh"
}

// ptyEnv builds a minimal, deterministic environment for the shell. We
// deliberately do NOT inherit the agent's env (which is launchd-cleansed
// and contains the relay token) to avoid leaking secrets into the shell.
func ptyEnv(term, shell string) []string {
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/"
	}
	pathSuffix := ""
	if runtime.GOOS == "darwin" {
		pathSuffix = ":/opt/homebrew/bin:/opt/homebrew/sbin"
	}
	return []string{
		"TERM=" + term,
		"HOME=" + home,
		"SHELL=" + shell,
		"LANG=en_US.UTF-8",
		"LC_ALL=en_US.UTF-8",
		"PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin" + pathSuffix,
	}
}
