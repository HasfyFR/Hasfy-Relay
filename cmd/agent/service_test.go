package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The daemon registers itself with the SCM under this name, and the MSI
// installs the service under the name in the .wxs. If the two drift, the
// service starts and is immediately killed: the SCM waits for a process
// claiming *its* name, gets nothing, and gives up after ~30 s. Nothing else
// in the build would notice, so it is asserted here.
func TestServiceNameMatchesTheInstaller(t *testing.T) {
	wxs, err := os.ReadFile(filepath.Join("..", "..", "packaging", "windows", "hasfy-agent.wxs"))
	if err != nil {
		t.Fatalf("cannot read the MSI definition: %v", err)
	}

	const name = "HasfyAgent"
	if !strings.Contains(string(wxs), `Name="`+name+`"`) {
		t.Errorf("the MSI does not install a service named %q", name)
	}
	if !strings.Contains(string(wxs), `ServiceName="`+name+`"`) {
		t.Errorf("the MSI failure policy does not target %q", name)
	}
}

// The MSI lays the binary down under CommonAppDataFolder\Hasfy. The installer
// UI, the uninstall commands in Hasfy-App and `check_relay_installed` in the
// Rust installer all hard-code C:\ProgramData\Hasfy — a move here would leave
// every one of them looking in the wrong place.
func TestInstallLocationIsProgramDataHasfy(t *testing.T) {
	wxs, err := os.ReadFile(filepath.Join("..", "..", "packaging", "windows", "hasfy-agent.wxs"))
	if err != nil {
		t.Fatalf("cannot read the MSI definition: %v", err)
	}
	s := string(wxs)

	if !strings.Contains(s, `Directory Id="CommonAppDataFolder"`) {
		t.Error("the install root is no longer CommonAppDataFolder (C:\\ProgramData)")
	}
	if !strings.Contains(s, `Id="INSTALLFOLDER" Name="Hasfy"`) {
		t.Error("the install folder is no longer named Hasfy")
	}
	if !strings.Contains(s, `Name="hasfy-agent.exe"`) {
		t.Error("the daemon is not installed as hasfy-agent.exe")
	}
}

// The directory holds device.key and, briefly, the one-shot enrolment secret.
// Under ProgramData the inherited ACL lets any authenticated user read it, so
// the package has to narrow it explicitly.
func TestAgentDataDirectoryIsLockedDown(t *testing.T) {
	wxs, err := os.ReadFile(filepath.Join("..", "..", "packaging", "windows", "hasfy-agent.wxs"))
	if err != nil {
		t.Fatalf("cannot read the MSI definition: %v", err)
	}
	s := string(wxs)

	if !strings.Contains(s, "util:PermissionEx") {
		t.Fatal("no explicit ACL on the agent data directory")
	}
	for _, principal := range []string{`User="SYSTEM"`, `User="Administrators"`} {
		if !strings.Contains(s, principal) {
			t.Errorf("expected %s to be granted access", principal)
		}
	}
	for _, forbidden := range []string{`User="Everyone"`, `User="Users"`, `User="Authenticated Users"`} {
		if strings.Contains(s, forbidden) {
			t.Errorf("%s must not have access to the device key", forbidden)
		}
	}
}

// The daemon enrols itself on first start because the service runs as SYSTEM.
// An MSI that wrote a credential would reintroduce the very thing the device
// flow removed: a secret sitting on disk before anyone approved the device.
func TestTheInstallerWritesNoCredential(t *testing.T) {
	wxs, err := os.ReadFile(filepath.Join("..", "..", "packaging", "windows", "hasfy-agent.wxs"))
	if err != nil {
		t.Fatalf("cannot read the MSI definition: %v", err)
	}
	// Comments stripped first: the .wxs explains *why* the data directory is
	// locked down, and naming device.key in that prose is not shipping it.
	s := stripXMLComments(string(wxs))

	for _, forbidden := range []string{
		"HASFY_DEVICE_ENROLLMENT_TOKEN", "agent.env", "enrollment_token", "device.key",
	} {
		if strings.Contains(s, forbidden) {
			t.Errorf("the MSI must not ship %s — the daemon writes it during enrolment", forbidden)
		}
	}
}

func stripXMLComments(s string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "<!--")
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		j := strings.Index(s[i:], "-->")
		if j < 0 {
			return b.String()
		}
		s = s[i+j+3:]
	}
}
