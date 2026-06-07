//go:build windows
// +build windows

package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"

	"github.com/UserExistsError/conpty"
)

// windowsPtyMaster wraps a ConPTY (Windows 10 1809+) attached to a shell
// process. ConPTY natively manages the process lifecycle: closing the
// pseudo-console terminates the attached process tree.
type windowsPtyMaster struct {
	cpty *conpty.ConPty

	waitOnce sync.Once
	exitCode int
	waitErr  error
}

func (m *windowsPtyMaster) Read(p []byte) (int, error)  { return m.cpty.Read(p) }
func (m *windowsPtyMaster) Write(p []byte) (int, error) { return m.cpty.Write(p) }

func (m *windowsPtyMaster) Resize(cols, rows uint16) error {
	return m.cpty.Resize(int(cols), int(rows))
}

func (m *windowsPtyMaster) PID() int { return m.cpty.Pid() }

func (m *windowsPtyMaster) Wait() (int, error) {
	m.waitOnce.Do(func() {
		// Background context — we always wait for the shell to actually
		// exit. Cancellation/timeout is enforced upstream by Close().
		code, err := m.cpty.Wait(context.Background())
		if err != nil {
			m.exitCode = -1
			m.waitErr = err
			return
		}
		m.exitCode = int(code)
	})
	return m.exitCode, m.waitErr
}

func (m *windowsPtyMaster) Close() error {
	// Closing the ConPTY signals the attached process to exit. After
	// Close, Read returns EOF and the upstream goroutine collects the
	// exit code via Wait().
	return m.cpty.Close()
}

// spawnShell starts a Windows shell under a ConPTY of the given size.
//
// Requires Windows 10 build 1809 (October 2018) or later. On older
// Windows versions ConPty is not available and this returns an error.
func spawnShell(shell, term string, cols, rows uint16) (ptyMaster, error) {
	if !conpty.IsConPtyAvailable() {
		return nil, errors.New("ConPTY not available; Hasfy agent requires Windows 10 1809+ or Windows Server 2019+")
	}

	opts := []conpty.ConPtyOption{
		conpty.ConPtyDimensions(int(cols), int(rows)),
		conpty.ConPtyEnv(winPtyEnv(term)),
	}

	cpty, err := conpty.Start(shell, opts...)
	if err != nil {
		return nil, err
	}
	return &windowsPtyMaster{cpty: cpty}, nil
}

// winPtyEnv builds the env block for the Windows shell. Inherits the
// agent's env minus HASFY_* (which contain the relay token and other
// secrets we must not leak into an interactive shell).
func winPtyEnv(term string) []string {
	out := make([]string, 0, len(os.Environ())+1)
	hasTerm := false
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "HASFY_") {
			continue
		}
		if strings.HasPrefix(kv, "TERM=") {
			hasTerm = true
		}
		out = append(out, kv)
	}
	if !hasTerm {
		out = append(out, "TERM="+term)
	}
	return out
}
