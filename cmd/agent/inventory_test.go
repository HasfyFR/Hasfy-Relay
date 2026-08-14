package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInventoryQueriesCoverTheCMDBTables(t *testing.T) {
	// These names are the contract with Hasfy-App's core/osquery/sync.ts
	// (`ALL_TABLES`). A table missing here silently degrades the CMDB — the
	// transformation just sees no rows and writes nothing.
	required := []string{
		"system_info", "os_version", "interface_addresses", "mounts",
		"smart_drive_info", "battery",
		"apps", "homebrew_packages", "programs", "deb_packages", "rpm_packages",
	}
	have := map[string]bool{}
	for _, q := range inventoryQueries {
		have[q.table] = true
	}
	for _, table := range required {
		if !have[table] {
			t.Errorf("no query collects %q", table)
		}
	}
}

func TestInventoryQueriesSelectFromTheirOwnTable(t *testing.T) {
	// Guards a copy-paste slip: a query labelled `battery` that actually reads
	// `apps` would post rows under the wrong key and corrupt the CMDB.
	for _, q := range inventoryQueries {
		if !strings.Contains(strings.ToLower(q.sql), "from "+q.table) {
			t.Errorf("query %q does not select FROM %s:\n%s", q.table, q.table, q.sql)
		}
	}
}

func TestInventoryQueriesAreBounded(t *testing.T) {
	// Every query must cap its result set. An unbounded software inventory on
	// a loaded workstation would be posted in full and rejected by the
	// server's row cap — losing the whole collection, not just that table.
	for _, q := range inventoryQueries {
		if !strings.Contains(strings.ToUpper(q.sql), "LIMIT") {
			t.Errorf("query %q has no LIMIT:\n%s", q.table, q.sql)
		}
	}
}

func TestAppliesHere(t *testing.T) {
	all := osqueryQuery{table: "system_info"}
	if !all.appliesHere() {
		t.Error("a query with no platform list applies everywhere")
	}

	here := osqueryQuery{table: "x", platforms: []string{runtime.GOOS}}
	if !here.appliesHere() {
		t.Errorf("a query listing %s should apply here", runtime.GOOS)
	}

	elsewhere := osqueryQuery{table: "x", platforms: []string{"plan9"}}
	if elsewhere.appliesHere() {
		t.Error("a query for another platform must not run here")
	}
}

func TestCollapseSQL(t *testing.T) {
	got := collapseSQL("SELECT a,\n\t\tb\n\t\tFROM t LIMIT 1")
	want := "SELECT a, b FROM t LIMIT 1"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestOsqueryBinaryHonoursTheExplicitOverride(t *testing.T) {
	fake := filepath.Join(t.TempDir(), "osqueryi")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("HASFY_OSQUERY_PATH", fake)

	got, err := osqueryBinary()
	if err != nil {
		t.Fatalf("osqueryBinary: %v", err)
	}
	if got != fake {
		t.Errorf("got %q, want the override %q", got, fake)
	}
}

func TestOsqueryBinaryIgnoresAnOverrideThatDoesNotExist(t *testing.T) {
	t.Setenv("HASFY_OSQUERY_PATH", filepath.Join(t.TempDir(), "nope"))
	// Falls through to the normal candidates; on a machine without osquery
	// that is errNoOsquery, which is the case we care about.
	if _, err := osqueryBinary(); err != nil && !errors.Is(err, errNoOsquery) {
		t.Errorf("unexpected error: %v", err)
	}
}

// A stub osqueryi lets the collection path be exercised without installing
// osquery: it answers every query with one row.
func stubOsquery(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stub is not portable to Windows")
	}
	p := filepath.Join(t.TempDir(), "osqueryi")
	script := "#!/bin/sh\necho '[{\"hostname\":\"stub-host\",\"uuid\":\"stub-uuid\"}]'\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	return p
}

func TestRunOsqueryTableDecodesRows(t *testing.T) {
	rows, err := runOsqueryTable(context.Background(), stubOsquery(t),
		osqueryQuery{table: "system_info", sql: "SELECT 1 LIMIT 1"})
	if err != nil {
		t.Fatalf("runOsqueryTable: %v", err)
	}
	if len(rows) != 1 || rows[0]["hostname"] != "stub-host" {
		t.Errorf("got %v", rows)
	}
}

func TestRunOsqueryTableRejectsNonJSON(t *testing.T) {
	p := filepath.Join(t.TempDir(), "osqueryi")
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho 'not json'\n"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Posting garbage would be worse than posting nothing: the server would
	// reject the whole report.
	if _, err := runOsqueryTable(context.Background(), p,
		osqueryQuery{table: "t", sql: "SELECT 1"}); err == nil {
		t.Fatal("expected a decode error")
	}
}

func TestCollectInventoryStampsAndKeysEachTable(t *testing.T) {
	t.Setenv("HASFY_OSQUERY_PATH", stubOsquery(t))

	snapshots, err := collectInventory(context.Background(), testLogger())
	if err != nil {
		t.Fatalf("collectInventory: %v", err)
	}
	if len(snapshots) == 0 {
		t.Fatal("expected at least one table")
	}
	for table, snap := range snapshots {
		if len(snap.Rows) == 0 {
			t.Errorf("table %q has no rows", table)
		}
		if snap.LatestTimestamp == "" {
			t.Errorf("table %q has no timestamp — the CMDB uses it for freshness", table)
		}
	}
	// Platform-specific tables must not be collected off-platform.
	if runtime.GOOS != "windows" {
		if _, ok := snapshots["programs"]; ok {
			t.Error("the Windows-only `programs` table was collected here")
		}
	}
}

func TestCollectInventoryReportsMissingOsquery(t *testing.T) {
	t.Setenv("HASFY_OSQUERY_PATH", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("PATH", t.TempDir()) // nothing on PATH either

	_, err := collectInventory(context.Background(), testLogger())
	// The caller distinguishes this from a transient failure and stops
	// retrying, rather than logging the same line every ten minutes forever.
	if !errors.Is(err, errNoOsquery) {
		t.Fatalf("expected errNoOsquery, got %v", err)
	}
}

func TestPostInventorySendsASignedAssertion(t *testing.T) {
	var gotAuth string
	var gotBody inventoryRequest

	srv := tokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != inventoryPath {
			t.Errorf("path = %q", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	})

	snapshots := map[string]tableSnapshot{
		"system_info": {Rows: []map[string]any{{"hostname": "h"}}, LatestTimestamp: "2026-08-12T00:00:00Z"},
	}
	if err := postInventory(context.Background(), srv.URL, testIdentity(t), snapshots); err != nil {
		t.Fatalf("postInventory: %v", err)
	}

	// Proof of possession, not a bearer credential — same model as the relay
	// token request.
	if !strings.HasPrefix(gotAuth, "Bearer ey") {
		t.Errorf("expected a signed assertion, got %q", gotAuth)
	}
	if len(gotBody.Snapshots["system_info"].Rows) != 1 {
		t.Errorf("payload lost its rows: %+v", gotBody)
	}
	if gotBody.AgentVersion == "" {
		t.Error("agent version should travel with the report")
	}
}

func TestPostInventoryMapsUnauthorizedToRefusal(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	err := postInventory(context.Background(), srv.URL, testIdentity(t),
		map[string]tableSnapshot{"system_info": {}})
	if !errors.Is(err, errDeviceRefused) {
		t.Fatalf("expected errDeviceRefused, got %v", err)
	}
}

func TestPostInventoryTreatsServerErrorAsTransient(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	err := postInventory(context.Background(), srv.URL, testIdentity(t),
		map[string]tableSnapshot{"system_info": {}})
	if err == nil {
		t.Fatal("expected an error")
	}
	// A 502 must not stop the reporter for good.
	if errors.Is(err, errDeviceRefused) {
		t.Fatal("a 502 must not read as refusal")
	}
}

// A machine without osquery installs cleanly and reports an empty CMDB. The
// reporter used to give up for good on the first miss, so osquery arriving
// later — installed by hand, or by the package manager moments after us —
// left the machine with no inventory until somebody restarted the agent.
func TestMissingOsqueryPausesInventoryWithoutDisablingIt(t *testing.T) {
	src, err := os.ReadFile("inventory.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)

	i := strings.Index(s, "case errors.Is(err, errNoOsquery):")
	if i < 0 {
		t.Fatal("the missing-osquery branch is gone")
	}
	// Look at that branch only, up to the next case.
	branch := s[i:]
	if j := strings.Index(branch[1:], "\n\t\tcase "); j > 0 {
		branch = branch[:j]
	}

	if strings.Contains(branch, "return") {
		t.Error("a missing osquery must not disable inventory for the process lifetime")
	}
	if !strings.Contains(branch, "noOsqueryRetryInterval") {
		t.Error("the branch must schedule a re-check")
	}
}

// osquery has to come from somewhere. On Linux the package metadata is what
// makes the single privileged step install it too.
func TestLinuxPackagesDependOnOsquery(t *testing.T) {
	cfg, err := os.ReadFile(filepath.Join("..", "..", ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(cfg)

	depends := strings.Index(s, "depends:")
	if depends < 0 {
		t.Fatal("the .deb/.rpm declare no dependencies")
	}
	if !strings.Contains(s[depends:depends+200], "osquery") {
		t.Error("osquery is not declared as a package dependency")
	}
}
