package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/HasfyFR/Hasfy-Relay/internal/proto"
)

// =============================================================================
// Running a script without a shell
// =============================================================================
//
// The agent's central rule is argv-only: a command is a list of arguments, and
// nothing the operator sends is ever handed to a shell to parse. That rule is
// what makes remote execution auditable — `argv` in the audit log *is* what
// ran.
//
// Script bodies would normally break it. The old HTTP-polling path did
// `bash -c "<content>"`, which places the whole program text where the shell
// performs word splitting, expansion and substitution: the audit line and the
// executed program are then different things.
//
// Instead the body is written to a private temp file and executed as
// `argv = [interpreter, path]`. The content is only ever file data, the argv
// stays short and truthful, and the invariant survives.

// interpreterCommand maps the small fixed set of interpreters we accept onto
// the executable to run.
//
// A closed set on purpose: taking a path from the wire would let whoever can
// reach the relay name any binary on the device and call it an "interpreter".
func interpreterCommand(name string) (cmd string, extension string, err error) {
	switch name {
	case "bash":
		return "bash", ".sh", nil
	case "sh":
		return "sh", ".sh", nil
	case "python", "python3":
		return "python3", ".py", nil
	case "powershell", "pwsh":
		if runtime.GOOS == "windows" {
			return "powershell.exe", ".ps1", nil
		}
		// PowerShell Core, when the operator installed it.
		return "pwsh", ".ps1", nil
	default:
		return "", "", fmt.Errorf("unsupported interpreter %q", name)
	}
}

// materialiseScript writes the body to a private file and returns the argv to
// run plus a cleanup function.
//
// The file is created with O_EXCL at mode 0600 inside a fresh 0700 directory:
// the daemon runs as root, so a predictable path in a world-writable directory
// would let any local user swap the body between write and exec and have root
// run it — the same class of flaw the audit found in the macOS installer.
func materialiseScript(script *proto.Script) (argv []string, cleanup func(), err error) {
	cmd, ext, err := interpreterCommand(script.Interpreter)
	if err != nil {
		return nil, nil, err
	}
	if script.Content == "" {
		return nil, nil, fmt.Errorf("script body is empty")
	}

	dir, err := os.MkdirTemp("", "hasfy-script-")
	if err != nil {
		return nil, nil, fmt.Errorf("create script directory: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(dir) }

	if err := os.Chmod(dir, 0o700); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("chmod script directory: %w", err)
	}

	path := filepath.Join(dir, "script"+ext)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("create script file: %w", err)
	}
	if _, err := f.WriteString(script.Content); err != nil {
		f.Close()
		cleanup()
		return nil, nil, fmt.Errorf("write script: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		cleanup()
		return nil, nil, fmt.Errorf("sync script: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("close script: %w", err)
	}

	// The interpreter is invoked on the file; the body never appears in argv,
	// so it cannot be re-parsed and the audit line stays readable.
	switch script.Interpreter {
	case "powershell", "pwsh":
		// -File runs the script; without it PowerShell would treat the path as
		// a command *string* and we would be back to shell parsing.
		argv = []string{cmd, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path}
	default:
		argv = []string{cmd, path}
	}
	return argv, cleanup, nil
}
