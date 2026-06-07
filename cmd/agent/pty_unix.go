//go:build !windows
// +build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

// unixPtyMaster wraps a creack/pty master file plus the shell process.
// It is used on darwin, linux, and other Unix-like systems where
// `creack/pty` provides a native PTY implementation.
type unixPtyMaster struct {
	pty *os.File
	cmd *exec.Cmd

	// waitOnce guarantees Wait() and the ProcessState read are
	// serialized — exec.Cmd.Wait must be called at most once.
	waitOnce sync.Once
	exitCode int
	waitErr  error
}

func (m *unixPtyMaster) Read(p []byte) (int, error)  { return m.pty.Read(p) }
func (m *unixPtyMaster) Write(p []byte) (int, error) { return m.pty.Write(p) }

func (m *unixPtyMaster) Resize(cols, rows uint16) error {
	return pty.Setsize(m.pty, &pty.Winsize{Cols: cols, Rows: rows})
}

func (m *unixPtyMaster) PID() int {
	if m.cmd.Process == nil {
		return 0
	}
	return m.cmd.Process.Pid
}

func (m *unixPtyMaster) Wait() (int, error) {
	m.waitOnce.Do(func() {
		if m.cmd.ProcessState != nil {
			m.exitCode = m.cmd.ProcessState.ExitCode()
			return
		}
		err := m.cmd.Wait()
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				m.exitCode = ee.ExitCode()
				return
			}
			m.exitCode = -1
			m.waitErr = err
			return
		}
		m.exitCode = 0
	})
	return m.exitCode, m.waitErr
}

func (m *unixPtyMaster) Close() error {
	closeErr := m.pty.Close()
	if m.cmd.Process != nil {
		// Try to bring the shell down gracefully via SIGHUP (the standard
		// "controlling terminal closed" signal). If it doesn't exit
		// within 200ms, force-kill.
		_ = m.cmd.Process.Signal(syscall.SIGHUP)
		done := make(chan struct{})
		go func() {
			_, _ = m.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(200 * time.Millisecond):
			_ = m.cmd.Process.Kill()
		}
	}
	return closeErr
}

// spawnShell starts a login shell under a fresh PTY of the given size on
// Unix-like systems.
func spawnShell(shell, term string, cols, rows uint16) (ptyMaster, error) {
	// Login shell so PATH and user env are populated as if the operator
	// SSH'd in. This matches the "SSH-like" UX expected by the operator.
	cmd := exec.Command(shell, "-l")
	cmd.Env = ptyEnv(term, shell)

	f, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: cols, Rows: rows})
	if err != nil {
		return nil, err
	}
	return &unixPtyMaster{pty: f, cmd: cmd}, nil
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
