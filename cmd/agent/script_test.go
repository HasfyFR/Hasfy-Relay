package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gitlab.hasfy.fr/hasfy/applications/hasfy-relay/internal/proto"
)

// The argv-only rule is what makes remote execution auditable: `argv` in the
// audit log *is* what ran. A script must not undo it by ending up back on a
// command line where a shell would re-parse it.
func TestMaterialiseScriptKeepsTheBodyOutOfArgv(t *testing.T) {
	body := "echo hello; rm -rf /tmp/nothing $(whoami) `id`"
	argv, cleanup, err := materialiseScript(&proto.Script{
		Interpreter: "bash",
		Content:     body,
	})
	if err != nil {
		t.Fatalf("materialiseScript: %v", err)
	}
	defer cleanup()

	joined := strings.Join(argv, " ")
	if strings.Contains(joined, "echo hello") || strings.Contains(joined, "whoami") {
		t.Errorf("script body leaked into argv: %v", argv)
	}
	if len(argv) != 2 || argv[0] != "bash" {
		t.Errorf("expected [bash <path>], got %v", argv)
	}

	written, err := os.ReadFile(argv[1])
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(written) != body {
		t.Errorf("body was altered on the way to disk")
	}
}

func TestMaterialiseScriptWritesAPrivateFile(t *testing.T) {
	argv, cleanup, err := materialiseScript(&proto.Script{
		Interpreter: "bash", Content: "true",
	})
	if err != nil {
		t.Fatalf("materialiseScript: %v", err)
	}
	defer cleanup()

	fi, err := os.Stat(argv[1])
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// The daemon runs as root. A group- or world-writable script in a shared
	// directory would let a local user swap the body between write and exec
	// and have root run it — the flaw the audit found in the macOS installer.
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("script mode is %v, want 0600", perm)
	}

	dirInfo, err := os.Stat(filepath.Dir(argv[1]))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("script directory mode is %v, want 0700", perm)
	}
}

func TestMaterialiseScriptCleansUp(t *testing.T) {
	argv, cleanup, err := materialiseScript(&proto.Script{
		Interpreter: "sh", Content: "true",
	})
	if err != nil {
		t.Fatalf("materialiseScript: %v", err)
	}
	path := argv[1]
	cleanup()

	// A script body left on disk after the run is a credential left on disk.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("script survived cleanup: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Error("script directory survived cleanup")
	}
}

// A path from the wire would let whoever reaches the relay name any binary on
// the device and call it an interpreter.
func TestMaterialiseScriptRejectsUnknownInterpreters(t *testing.T) {
	for _, name := range []string{"", "ruby", "/bin/sh", "../../bin/sh", "bash;id"} {
		if _, _, err := materialiseScript(&proto.Script{
			Interpreter: name, Content: "true",
		}); err == nil {
			t.Errorf("interpreter %q should have been rejected", name)
		}
	}
}

func TestMaterialiseScriptRejectsAnEmptyBody(t *testing.T) {
	if _, _, err := materialiseScript(&proto.Script{
		Interpreter: "bash", Content: "",
	}); err == nil {
		t.Fatal("an empty script should be rejected rather than run")
	}
}

func TestInterpreterExtensions(t *testing.T) {
	// PowerShell refuses to run a file without a .ps1 extension, and python
	// wants .py for tracebacks to be readable.
	cases := map[string]string{
		"bash": ".sh", "sh": ".sh",
		"python": ".py", "python3": ".py",
		"powershell": ".ps1", "pwsh": ".ps1",
	}
	for name, wantExt := range cases {
		_, ext, err := interpreterCommand(name)
		if err != nil {
			t.Errorf("interpreterCommand(%q): %v", name, err)
			continue
		}
		if ext != wantExt {
			t.Errorf("interpreterCommand(%q) extension = %q, want %q", name, ext, wantExt)
		}
	}
}

func TestPowerShellUsesFileNotCommand(t *testing.T) {
	argv, cleanup, err := materialiseScript(&proto.Script{
		Interpreter: "powershell", Content: "Get-Date",
	})
	if err != nil {
		t.Fatalf("materialiseScript: %v", err)
	}
	defer cleanup()

	joined := strings.Join(argv, " ")
	// Without -File, PowerShell treats the path as a *command string* and we
	// are back to shell parsing.
	if !strings.Contains(joined, "-File") {
		t.Errorf("expected -File, got %v", argv)
	}
	if strings.Contains(joined, "-Command") {
		t.Errorf("-Command re-introduces shell parsing: %v", argv)
	}
	if !strings.HasSuffix(argv[len(argv)-1], ".ps1") {
		t.Errorf("expected a .ps1 path last, got %v", argv)
	}
	if runtime.GOOS == "windows" && argv[0] != "powershell.exe" {
		t.Errorf("argv[0] = %q on Windows", argv[0])
	}
}
