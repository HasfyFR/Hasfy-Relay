package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// dig walks a nested map by dotted path, the way an Elasticsearch field name
// addresses a document. Returns nil when any hop is missing.
func dig(doc map[string]any, path string) any {
	var cur any = doc
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[part]
		if !ok {
			return nil
		}
	}
	return cur
}

// The field names below are the contract with Hasfy-App's query builders
// (core/elk/queries.ts). A document that omits one renders an empty graph with
// no error anywhere — exactly the kind of silent breakage this test exists to
// prevent.
func TestCollectMetricsMatchesTheQueriedFieldNames(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	doc, err := collectMetrics(ctx, "dev-1", "org-1")
	if err != nil {
		t.Fatalf("collectMetrics: %v", err)
	}

	// Required everywhere: the org filter and the per-agent filter.
	if dig(doc, "agent.id") != "dev-1" {
		t.Errorf("agent.id = %v", dig(doc, "agent.id"))
	}
	if dig(doc, "organization.id") != "org-1" {
		t.Errorf("organization.id = %v", dig(doc, "organization.id"))
	}
	if ts, ok := doc["@timestamp"].(string); !ok || ts == "" {
		t.Error("@timestamp is missing")
	} else if _, err := time.Parse(rfc3339Millis, ts); err != nil {
		t.Errorf("@timestamp %q is not parseable: %v", ts, err)
	}

	for _, field := range []string{
		"system.cpu.total.norm.pct",
		"system.cpu.idle.norm.pct",
		"system.memory.total",
		"system.memory.free",
		"system.memory.actual.free",
		"system.memory.actual.used.bytes",
		"system.memory.actual.used.pct",
		"host.os.platform",
	} {
		if dig(doc, field) == nil {
			t.Errorf("missing %s — the graph that reads it would render empty", field)
		}
	}
}

func TestCpuAndMemoryPercentagesAreFractions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	doc, err := collectMetrics(ctx, "dev-1", "org-1")
	if err != nil {
		t.Fatalf("collectMetrics: %v", err)
	}

	// The Elastic schema these field names come from expresses `.pct` as a
	// 0-1 fraction, while gopsutil reports 0-100. Getting this wrong would
	// render every CPU graph at 100x scale.
	for _, field := range []string{
		"system.cpu.total.norm.pct",
		"system.cpu.idle.norm.pct",
		"system.memory.actual.used.pct",
	} {
		v, ok := dig(doc, field).(float64)
		if !ok {
			t.Errorf("%s is not a number", field)
			continue
		}
		if v < 0 || v > 1 {
			t.Errorf("%s = %v, expected a 0-1 fraction", field, v)
		}
	}
}

func TestCpuIdleAndTotalAreComplementary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	doc, err := collectMetrics(ctx, "dev-1", "org-1")
	if err != nil {
		t.Fatalf("collectMetrics: %v", err)
	}
	total, _ := dig(doc, "system.cpu.total.norm.pct").(float64)
	idle, _ := dig(doc, "system.cpu.idle.norm.pct").(float64)
	if sum := total + idle; sum < 0.99 || sum > 1.01 {
		t.Errorf("total+idle = %v, expected ~1", sum)
	}
}

func TestFilesystemMetricsAreOneDocumentPerMount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	docs := collectFilesystemMetrics(ctx, "dev-1", "org-1")
	if len(docs) == 0 {
		t.Skip("no readable filesystem on this host")
	}

	seen := map[string]bool{}
	for _, doc := range docs {
		mount, _ := dig(doc, "system.filesystem.mount_point").(string)
		if mount == "" {
			t.Error("a filesystem document has no mount_point — the disk graph groups on it")
		}
		// One document per mount: folding them together would make the
		// per-filesystem aggregation meaningless.
		if seen[mount] {
			t.Errorf("duplicate document for mount %q", mount)
		}
		seen[mount] = true

		for _, field := range []string{
			"system.filesystem.total",
			"system.filesystem.free",
			"system.filesystem.used.bytes",
			"system.filesystem.used.pct",
		} {
			if dig(doc, field) == nil {
				t.Errorf("mount %q is missing %s", mount, field)
			}
		}
		if pct, ok := dig(doc, "system.filesystem.used.pct").(float64); ok && (pct < 0 || pct > 1) {
			t.Errorf("mount %q used.pct = %v, expected a 0-1 fraction", mount, pct)
		}
	}
}

func TestNetworkMetricsCarryTheirInterfaceName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	docs := collectNetworkMetrics(ctx, "dev-1", "org-1")
	if len(docs) == 0 {
		t.Skip("no active interface on this host")
	}
	for _, doc := range docs {
		if name, _ := dig(doc, "system.network.name").(string); name == "" {
			t.Error("a network document has no name — the graph groups on it")
		}
		for _, field := range []string{
			"system.network.in.bytes", "system.network.out.bytes",
			"system.network.in.packets", "system.network.out.packets",
		} {
			if dig(doc, field) == nil {
				t.Errorf("missing %s", field)
			}
		}
	}
}

func TestNormalisePlatformMatchesTheQueryFilter(t *testing.T) {
	// buildPlatformFilter compares against exactly these three values.
	cases := map[string]string{
		"darwin": "darwin", "windows": "windows",
		"ubuntu": "linux", "debian": "linux", "": "linux",
	}
	for in, want := range cases {
		if got := normalisePlatform(in); got != want {
			t.Errorf("normalisePlatform(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDailyIndexIsPerOrgPerDay(t *testing.T) {
	at := time.Date(2026, 8, 12, 13, 0, 0, 0, time.UTC)
	got := dailyIndex("hasfy-metrics-org-1", at)
	if got != "hasfy-metrics-org-1-2026.08.12" {
		t.Errorf("got %q", got)
	}
	// The key's index pattern is `hasfy-metrics-<org>-*`; an index outside it
	// would be refused by Elasticsearch on every write.
	if !strings.HasPrefix(got, "hasfy-metrics-org-1-") {
		t.Errorf("%q falls outside the key's permitted pattern", got)
	}
}

func TestAppendBoundedDropsOldestFirst(t *testing.T) {
	buf := []map[string]any{{"n": 1}, {"n": 2}}
	buf = appendBounded(buf, []map[string]any{{"n": 3}, {"n": 4}}, 3)

	if len(buf) != 3 {
		t.Fatalf("len = %d, want 3", len(buf))
	}
	// Recent metrics matter more than complete history, so the oldest go.
	if buf[0]["n"] != 2 || buf[2]["n"] != 4 {
		t.Errorf("expected the oldest to be dropped, got %v", buf)
	}
}

func TestShipMetricsUsesCreateAndTheApiKey(t *testing.T) {
	var gotAuth, gotBody, gotContentType string

	srv := tokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_bulk" {
			t.Errorf("path = %q", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": false, "items": []any{}})
	})

	creds := &ingestCredentials{
		ElasticsearchURL: srv.URL,
		APIKey:           "es-key",
		IndexPrefix:      "hasfy-metrics-org-1",
	}
	docs := []map[string]any{{"@timestamp": "2026-08-12T00:00:00.000Z"}}

	if err := shipMetrics(context.Background(), testLogger(), creds, docs); err != nil {
		t.Fatalf("shipMetrics: %v", err)
	}

	if gotAuth != "ApiKey es-key" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotContentType != "application/x-ndjson" {
		t.Errorf("Content-Type = %q", gotContentType)
	}
	// `create`, not `index`: the key only carries create_doc, and append-only
	// means a device cannot overwrite an existing document.
	if !strings.Contains(gotBody, `"create"`) {
		t.Errorf("bulk body does not use create:\n%s", gotBody)
	}
	if strings.Contains(gotBody, `"index":{"_index"`) {
		t.Errorf("bulk body uses index instead of create:\n%s", gotBody)
	}
	if !strings.HasSuffix(gotBody, "\n") {
		t.Error("ndjson body must end with a newline")
	}
}

func TestShipMetricsIsANoOpForAnEmptyBatch(t *testing.T) {
	called := false
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	creds := &ingestCredentials{ElasticsearchURL: srv.URL, APIKey: "k", IndexPrefix: "p"}

	if err := shipMetrics(context.Background(), testLogger(), creds, nil); err != nil {
		t.Fatalf("shipMetrics: %v", err)
	}
	if called {
		t.Error("an empty batch should not reach Elasticsearch")
	}
}

func TestShipMetricsSignalsAStaleKey(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		})
		creds := &ingestCredentials{ElasticsearchURL: srv.URL, APIKey: "stale", IndexPrefix: "p"}
		err := shipMetrics(context.Background(), testLogger(), creds,
			[]map[string]any{{"a": 1}})
		// Recoverable by re-fetching, unlike a 5xx which is just transient.
		if !errors.Is(err, errIngestUnauthorized) {
			t.Errorf("status %d gave %v, want errIngestUnauthorized", status, err)
		}
	}
}

func TestShipMetricsTreatsServerErrorAsTransient(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	creds := &ingestCredentials{ElasticsearchURL: srv.URL, APIKey: "k", IndexPrefix: "p"}

	err := shipMetrics(context.Background(), testLogger(), creds, []map[string]any{{"a": 1}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, errIngestUnauthorized) {
		t.Error("a 502 must not be mistaken for a stale key")
	}
}

// A rejected document is rejected forever (a mapping conflict, say). Retrying
// the batch would block every later sample behind it.
func TestShipMetricsDoesNotFailOnPartialRejection(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"errors": true,
			"items": []any{
				map[string]any{"create": map[string]any{"status": 400, "error": map[string]any{"type": "mapper_parsing_exception"}}},
			},
		})
	})
	creds := &ingestCredentials{ElasticsearchURL: srv.URL, APIKey: "k", IndexPrefix: "p"}

	if err := shipMetrics(context.Background(), testLogger(), creds,
		[]map[string]any{{"a": 1}}); err != nil {
		t.Fatalf("a partial rejection must not fail the batch, got %v", err)
	}
}

func TestFetchIngestCredentialsSendsAnAssertion(t *testing.T) {
	var gotAuth string
	srv := tokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ingestCredentialsPath {
			t.Errorf("path = %q", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"elasticsearchUrl": "https://es.hasfy.fr",
				"apiKey":           "es-key",
				"indexPrefix":      "hasfy-metrics-org-1",
			},
		})
	})

	creds, err := fetchIngestCredentials(context.Background(), srv.URL, testIdentity(t))
	if err != nil {
		t.Fatalf("fetchIngestCredentials: %v", err)
	}
	if creds.APIKey != "es-key" || creds.IndexPrefix != "hasfy-metrics-org-1" {
		t.Errorf("got %+v", creds)
	}
	if !strings.HasPrefix(gotAuth, "Bearer ey") {
		t.Errorf("expected a signed assertion, got %q", gotAuth)
	}
}

func TestFetchIngestCredentialsRejectsIncompleteResponse(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data":    map[string]any{"elasticsearchUrl": "https://es.hasfy.fr"},
		})
	})
	// Shipping with an empty key would fail on every write; better to treat
	// the response as unusable and retry.
	if _, err := fetchIngestCredentials(context.Background(), srv.URL, testIdentity(t)); err == nil {
		t.Fatal("a response with no apiKey must be rejected")
	}
}

func TestFetchIngestCredentialsMapsUnauthorizedToRefusal(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	_, err := fetchIngestCredentials(context.Background(), srv.URL, testIdentity(t))
	if !errors.Is(err, errDeviceRefused) {
		t.Fatalf("expected errDeviceRefused, got %v", err)
	}
}
