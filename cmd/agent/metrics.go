package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
)

// =============================================================================
// System metrics
// =============================================================================
//
// Collected natively rather than by Fluent Bit or Metricbeat, for one reason
// that outweighs the others: an external collector needs its Elasticsearch
// credential in a config file on disk. Collecting in-process lets the daemon
// hold the key in memory only, so a stolen disk yields nothing.
//
// # Field names
//
// The documents deliberately use Elastic's `system.*` metricbeat field names.
// Hasfy-App's query builders (core/elk/queries.ts) already speak that schema;
// inventing our own would have meant rewriting every builder and its tests for
// no gain. Only the index moved — `hasfy-metrics-<org>-YYYY.MM.DD` instead of
// `metrics-system.*` — which makes this a like-for-like migration whose graphs
// can be compared before and after.

// rfc3339Millis is RFC 3339 with millisecond precision. Go has no such
// constant (RFC3339Nano trims trailing zeros, which produces ragged
// timestamps), and Elasticsearch's default date mapping parses this exactly.
const rfc3339Millis = "2006-01-02T15:04:05.000Z07:00"

const (
	// One sample a minute. Matches what the Elastic Agent system module was
	// configured for, and keeps a 150-device org well under a document a
	// second.
	metricsInterval = time.Minute

	metricsInitialDelay = 30 * time.Second
	metricsRetryDelay   = 5 * time.Minute

	// Credentials are re-fetched daily; the server rotates well before the
	// key's own 90-day expiry.
	ingestCredentialsTTL = 24 * time.Hour

	// CPU sampling window. Long enough to be meaningful, short enough not to
	// hold the collection loop.
	cpuSampleWindow = 2 * time.Second

	ingestCredentialsPath = "/api/v1/device/ingest-credentials"

	metricsHTTPTimeout = 30 * time.Second

	// Bounded buffer for samples taken while Elasticsearch is unreachable.
	// 60 samples ≈ one hour at a sample a minute: enough to ride out a
	// restart or a short outage, small enough that an agent cut off for a
	// week cannot grow without limit. Oldest are dropped first — recent
	// metrics matter more than complete history.
	maxBufferedSamples = 60
)

// ingestCredentials is what /api/v1/device/ingest-credentials returns.
// Held in memory only; never written to disk.
type ingestCredentials struct {
	ElasticsearchURL string `json:"elasticsearchUrl"`
	APIKey           string `json:"apiKey"`
	IndexPrefix      string `json:"indexPrefix"`
	ExpiresAt        string `json:"expiresAt"`
}

type ingestCredentialsResponse struct {
	Success bool              `json:"success"`
	Data    ingestCredentials `json:"data"`
}

// fetchIngestCredentials authenticates with a device assertion — the same
// proof of possession used everywhere else — and returns an ES key scoped to
// this organisation with `create_doc` and nothing more.
func fetchIngestCredentials(
	ctx context.Context,
	apiBase string,
	identity *deviceIdentity,
) (*ingestCredentials, error) {
	assertion, err := identity.signAssertion()
	if err != nil {
		return nil, fmt.Errorf("sign assertion: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, metricsHTTPTimeout)
	defer cancel()

	resp, err := postJSON(ctx, trimSlash(apiBase)+ingestCredentialsPath, assertion, nil, []byte("{}"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, errDeviceRefused
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ingest credentials HTTP %d", resp.StatusCode)
	}

	var out ingestCredentialsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode ingest credentials: %w", err)
	}
	if !out.Success || out.Data.APIKey == "" || out.Data.ElasticsearchURL == "" {
		return nil, fmt.Errorf("ingest credentials response was incomplete")
	}
	return &out.Data, nil
}

// collectMetrics takes one sample, shaped like a metricbeat `system.*` document.
//
// Individual subsystems are allowed to fail: a container without a battery, a
// VM with no disk counters, a host where `load` is meaningless on Windows. A
// partial sample is far more useful than none.
func collectMetrics(ctx context.Context, deviceID, orgID string) (map[string]any, error) {
	doc := map[string]any{
		"@timestamp": time.Now().UTC().Format(rfc3339Millis),
		// Mirrors the Elastic Agent document shape so `buildAgentFilter` and
		// the org filter keep working untouched.
		"agent":        map[string]any{"id": deviceID, "version": Version},
		"organization": map[string]any{"id": orgID},
	}

	system := map[string]any{}

	if pcts, err := cpu.PercentWithContext(ctx, cpuSampleWindow, false); err == nil && len(pcts) > 0 {
		// gopsutil reports 0-100; the Elastic schema is a 0-1 fraction.
		total := pcts[0] / 100
		cpuDoc := map[string]any{
			"total": map[string]any{"norm": map[string]any{"pct": total}},
			"idle":  map[string]any{"norm": map[string]any{"pct": 1 - total}},
		}
		if counts, err := cpu.CountsWithContext(ctx, true); err == nil {
			cpuDoc["cores"] = counts
		}
		system["cpu"] = cpuDoc
	}

	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		system["memory"] = map[string]any{
			"total": vm.Total,
			"free":  vm.Free,
			"used":  map[string]any{"bytes": vm.Used, "pct": vm.UsedPercent / 100},
			"actual": map[string]any{
				"free": vm.Available,
				"used": map[string]any{
					"bytes": vm.Total - vm.Available,
					"pct":   float64(vm.Total-vm.Available) / float64(max64(vm.Total, 1)),
				},
			},
		}
	}

	if avg, err := load.AvgWithContext(ctx); err == nil {
		if counts, err := cpu.CountsWithContext(ctx, true); err == nil && counts > 0 {
			system["load"] = map[string]any{
				"1": avg.Load1, "5": avg.Load5, "15": avg.Load15,
				"cores": counts,
			}
		}
	}

	if info, err := host.InfoWithContext(ctx); err == nil {
		doc["host"] = map[string]any{
			"hostname": info.Hostname,
			"os": map[string]any{
				"platform": normalisePlatform(info.OS),
				"version":  info.PlatformVersion,
				"name":     info.Platform,
			},
		}
		system["uptime"] = map[string]any{"duration": map[string]any{"ms": info.Uptime * 1000}}
	}

	if len(system) == 0 {
		return nil, fmt.Errorf("no metric subsystem could be read")
	}
	doc["system"] = system
	return doc, nil
}

// collectFilesystemMetrics emits one document per real mount point.
//
// Split from the main sample because the schema is per-filesystem: the query
// builders aggregate on `system.filesystem.mount_point`, so folding them into
// one document would make the disk graphs unusable.
func collectFilesystemMetrics(ctx context.Context, deviceID, orgID string) []map[string]any {
	partitions, err := disk.PartitionsWithContext(ctx, false)
	if err != nil {
		return nil
	}

	now := time.Now().UTC().Format(rfc3339Millis)
	out := make([]map[string]any, 0, len(partitions))
	for _, p := range partitions {
		usage, err := disk.UsageWithContext(ctx, p.Mountpoint)
		if err != nil || usage.Total == 0 {
			// Pseudo-filesystems and unreadable mounts; skipping them keeps
			// the disk graphs about real storage.
			continue
		}
		out = append(out, map[string]any{
			"@timestamp":   now,
			"agent":        map[string]any{"id": deviceID, "version": Version},
			"organization": map[string]any{"id": orgID},
			"system": map[string]any{
				"filesystem": map[string]any{
					"mount_point": p.Mountpoint,
					"device_name": p.Device,
					"type":        p.Fstype,
					"total":       usage.Total,
					"free":        usage.Free,
					"used": map[string]any{
						"bytes": usage.Used,
						"pct":   usage.UsedPercent / 100,
					},
				},
			},
		})
	}
	return out
}

// collectNetworkMetrics emits one document per interface with traffic.
func collectNetworkMetrics(ctx context.Context, deviceID, orgID string) []map[string]any {
	counters, err := net.IOCountersWithContext(ctx, true)
	if err != nil {
		return nil
	}

	now := time.Now().UTC().Format(rfc3339Millis)
	out := make([]map[string]any, 0, len(counters))
	for _, c := range counters {
		if c.BytesRecv == 0 && c.BytesSent == 0 {
			continue // idle or virtual interface; nothing to plot
		}
		out = append(out, map[string]any{
			"@timestamp":   now,
			"agent":        map[string]any{"id": deviceID, "version": Version},
			"organization": map[string]any{"id": orgID},
			"system": map[string]any{
				"network": map[string]any{
					"name": c.Name,
					"in":   map[string]any{"bytes": c.BytesRecv, "packets": c.PacketsRecv},
					"out":  map[string]any{"bytes": c.BytesSent, "packets": c.PacketsSent},
				},
			},
		})
	}
	return out
}

// normalisePlatform maps gopsutil's OS string onto what the query builders
// expect (`buildPlatformFilter` compares against darwin/linux/windows).
func normalisePlatform(osName string) string {
	switch osName {
	case "darwin":
		return "darwin"
	case "windows":
		return "windows"
	default:
		return "linux"
	}
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
