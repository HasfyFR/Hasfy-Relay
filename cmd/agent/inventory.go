package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// =============================================================================
// Inventory collection
// =============================================================================
//
// The daemon runs osquery locally and posts the results to Hasfy-App, which
// feeds them through the same CMDB transformation that used to consume
// Elastic Agent's output.
//
//	before:  elastic-agent → osquery_manager → Fleet → Elasticsearch
//	                       → hourly cron reads ES → Supabase
//	after:   hasfy-agent   → POST /api/v1/device/inventory → Supabase
//
// What that removes: a ~500 MB Elastic Agent download per install, Fleet
// Server, and an Elasticsearch round-trip that inventory never needed — it
// always ended up in Postgres. osquery on its own is ~20 MB and ships as a
// signed .pkg / .msi / .deb / .rpm from osquery.io, so the "one elevation"
// property of phase 4 survives.
//
// Elastic Agent is *not* uninstalled by this code. Removing it is a separate,
// deliberate step once a real machine has been observed reporting through this
// path — losing inventory silently would be worse than carrying it a while
// longer.

const (
	inventoryPath = "/api/v1/device/inventory"

	// Inventory changes slowly; hourly matches what the Fleet scheduled packs
	// were configured for and keeps the volume negligible.
	inventoryInterval = time.Hour

	// First collection shortly after boot so a freshly enrolled machine shows
	// up in the CMDB straight away rather than in up to an hour.
	inventoryInitialDelay = 2 * time.Minute

	inventoryRetryInterval = 10 * time.Minute

	// osquery occasionally wedges on a slow filesystem; bound it so a stuck
	// query cannot stall the whole collection cycle.
	osqueryTimeout = 60 * time.Second

	// How often to re-check for osquery when it is missing. Slow on purpose:
	// this is a state an operator has to fix, so polling it hard buys nothing.
	noOsqueryRetryInterval = 15 * time.Minute

	inventoryHTTPTimeout = 60 * time.Second
)

// errNoOsquery means osqueryi is not installed. Not an error to retry
// aggressively — it needs a human or a package to fix.
var errNoOsquery = errors.New("osqueryi not found")

// osqueryQuery is one table we collect, and where it is meaningful.
type osqueryQuery struct {
	table string
	sql   string
	// goos values this query applies to; empty means all.
	platforms []string
}

// inventoryQueries mirrors `ALL_TABLES` in Hasfy-App's core/osquery/sync.ts.
// Keep the two in step: a table collected here but unknown there is wasted
// bandwidth, and one expected there but missing here silently degrades the
// CMDB.
var inventoryQueries = []osqueryQuery{
	{table: "system_info", sql: `SELECT hostname, uuid, cpu_brand, cpu_physical_cores,
		cpu_logical_cores, physical_memory, hardware_vendor, hardware_model,
		hardware_serial, computer_name, local_hostname, board_vendor, board_model
		FROM system_info LIMIT 1`},
	{table: "os_version", sql: `SELECT name, version, major, minor, patch, build,
		platform, platform_like, codename, arch FROM os_version LIMIT 1`},
	{table: "interface_addresses", sql: `SELECT interface, address, mask, broadcast, type
		FROM interface_addresses
		WHERE address NOT LIKE '127.%' AND address != '::1' LIMIT 20`},
	{table: "mounts", sql: `SELECT device, path, type, blocks, blocks_free, blocks_size
		FROM mounts LIMIT 20`},

	// Health tables — absent on some hardware, which osquery reports as an
	// empty result rather than an error.
	{table: "smart_drive_info", sql: `SELECT device_name, model_family, device_model,
		serial_number, disk_id FROM smart_drive_info LIMIT 10`,
		platforms: []string{"darwin", "linux"}},
	{table: "battery", sql: `SELECT percent_remaining, health, cycle_count, condition
		FROM battery LIMIT 1`, platforms: []string{"darwin"}},

	// Software inventory, one table per platform.
	{table: "apps", sql: `SELECT name, bundle_short_version AS version, bundle_identifier
		FROM apps LIMIT 2000`, platforms: []string{"darwin"}},
	{table: "homebrew_packages", sql: `SELECT name, version FROM homebrew_packages LIMIT 2000`,
		platforms: []string{"darwin"}},
	{table: "programs", sql: `SELECT name, version, publisher FROM programs LIMIT 2000`,
		platforms: []string{"windows"}},
	{table: "deb_packages", sql: `SELECT name, version, source FROM deb_packages LIMIT 2000`,
		platforms: []string{"linux"}},
	{table: "rpm_packages", sql: `SELECT name, version, source FROM rpm_packages LIMIT 2000`,
		platforms: []string{"linux"}},
}

func (q osqueryQuery) appliesHere() bool {
	if len(q.platforms) == 0 {
		return true
	}
	for _, p := range q.platforms {
		if p == runtime.GOOS {
			return true
		}
	}
	return false
}

// osqueryBinary locates osqueryi.
//
// The vendor packages install to fixed, unprivileged-writable-free locations;
// we look there first and fall back to PATH so a custom deployment still
// works. An absolute path is preferred on purpose: this runs as root, and
// resolving a bare name through PATH would let anyone who can influence the
// service environment choose the binary.
func osqueryBinary() (string, error) {
	if custom := os.Getenv("HASFY_OSQUERY_PATH"); custom != "" {
		if _, err := os.Stat(custom); err == nil {
			return custom, nil
		}
	}

	var candidates []string
	switch runtime.GOOS {
	case "darwin":
		candidates = []string{"/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryi", "/usr/local/bin/osqueryi"}
	case "windows":
		candidates = []string{`C:\Program Files\osquery\osqueryi.exe`}
	default:
		candidates = []string{"/usr/bin/osqueryi", "/usr/local/bin/osqueryi"}
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}

	if p, err := exec.LookPath("osqueryi"); err == nil {
		return p, nil
	}
	return "", errNoOsquery
}

// tableSnapshot is one table's worth of rows, in the shape Hasfy-App's CMDB
// transformation consumes.
type tableSnapshot struct {
	Rows            []map[string]any `json:"rows"`
	LatestTimestamp string           `json:"latestTimestamp"`
}

// runOsqueryTable executes one query and decodes its JSON result.
//
// A failing table is not a failing collection: hardware-specific tables
// (battery on a desktop, smart_drive_info on an NVMe-less VM) legitimately
// error out, and one of them must not cost us the whole inventory.
func runOsqueryTable(ctx context.Context, binary string, q osqueryQuery) ([]map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, osqueryTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, "--json", collapseSQL(q.sql))
	// osquery reads ~/.osqueryi and can be steered by the environment; a root
	// daemon should not inherit whatever the service manager happened to set.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("osquery %s: %w", q.table, err)
	}

	var rows []map[string]any
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("decode %s: %w", q.table, err)
	}
	return rows, nil
}

// collapseSQL flattens the multi-line literals above into one line. osqueryi
// takes the query as a single argv element; embedded newlines and runs of
// indentation are harmless but make the process listing unreadable.
func collapseSQL(sql string) string {
	return strings.Join(strings.Fields(sql), " ")
}

// collectInventory runs every query that applies to this platform.
//
// Returns whatever succeeded. An empty result is reported as an error so the
// caller does not post a payload that would blank the CMDB.
func collectInventory(ctx context.Context, log *slog.Logger) (map[string]tableSnapshot, error) {
	binary, err := osqueryBinary()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	snapshots := map[string]tableSnapshot{}

	for _, q := range inventoryQueries {
		if !q.appliesHere() {
			continue
		}
		rows, err := runOsqueryTable(ctx, binary, q)
		if err != nil {
			// Expected for hardware-specific tables; debug rather than warn so
			// a desktop without a battery does not log noise every hour.
			log.Debug("inventory table unavailable", "table", q.table, "err", err)
			continue
		}
		snapshots[q.table] = tableSnapshot{Rows: rows, LatestTimestamp: now}
	}

	if len(snapshots) == 0 {
		return nil, errors.New("no osquery table could be collected")
	}
	return snapshots, nil
}

type inventoryRequest struct {
	Snapshots    map[string]tableSnapshot `json:"snapshots"`
	AgentVersion string                   `json:"agentVersion"`
}

// postInventory ships a collection, authenticated by a freshly signed device
// assertion — the same proof-of-possession used for relay tokens, so no
// credential is involved.
func postInventory(
	ctx context.Context,
	apiBase string,
	identity *deviceIdentity,
	snapshots map[string]tableSnapshot,
) error {
	assertion, err := identity.signAssertion()
	if err != nil {
		return fmt.Errorf("sign assertion: %w", err)
	}

	body, err := json.Marshal(inventoryRequest{Snapshots: snapshots, AgentVersion: Version})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, inventoryHTTPTimeout)
	defer cancel()

	resp, err := postJSON(ctx, strings.TrimRight(apiBase, "/")+inventoryPath, assertion, nil, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return errDeviceRefused
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("inventory HTTP %d", resp.StatusCode)
	}
	return nil
}

// runInventoryReporter collects and posts on a schedule until ctx is done.
//
// Stops permanently on errDeviceRefused — the device is no longer authorised,
// and the token manager will already have said so. Stops on a missing osquery
// too: retrying every ten minutes forever would just fill the log with the
// same line.
func runInventoryReporter(
	ctx context.Context,
	log *slog.Logger,
	apiBase string,
	identity *deviceIdentity,
) {
	timer := time.NewTimer(inventoryInitialDelay)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		next := inventoryInterval
		snapshots, err := collectInventory(ctx, log)
		switch {
		case errors.Is(err, errNoOsquery):
			// Keep looking rather than giving up for good. Returning here
			// disabled inventory for the lifetime of the process: a machine
			// where osquery arrived later — installed by hand, or by the
			// package manager a moment after us — kept an empty CMDB until
			// somebody thought to restart the agent, with one line in a
			// service log as the only trace.
			log.Warn("osquery not found — inventory paused",
				"retry_in", noOsqueryRetryInterval.String())
			next = noOsqueryRetryInterval
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			log.Warn("inventory collection failed", "err", err, "retry_in", inventoryRetryInterval.String())
			next = inventoryRetryInterval
		default:
			if postErr := postInventory(ctx, apiBase, identity, snapshots); postErr != nil {
				if errors.Is(postErr, errDeviceRefused) {
					log.Error("inventory refused: this device is no longer authorised")
					return
				}
				if ctx.Err() != nil {
					return
				}
				log.Warn("inventory upload failed", "err", postErr,
					"retry_in", inventoryRetryInterval.String())
				next = inventoryRetryInterval
			} else {
				log.Info("inventory reported", "tables", len(snapshots))
			}
		}

		timer.Reset(next)
	}
}
