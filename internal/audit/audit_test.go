package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func testForwarder(t *testing.T) *Forwarder {
	t.Helper()
	f := NewForwarder("https://app.example", []byte(strings.Repeat("k", 32)))
	if f == nil {
		t.Fatal("NewForwarder returned nil for a valid config")
	}
	return f
}

// Every event reaches stdout — that stream is the cluster-wide record and must
// not lose anything, whatever the forwarding rules are.
func TestEmitAlwaysWritesToTheLocalSink(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf).WithForwarder(testForwarder(t))

	l.Emit(Event{Kind: "auth.fail", Reason: "bad agent token"})
	l.Emit(Event{Kind: "session.open", OrgID: "org-1", DeviceID: "dev-1"})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 NDJSON lines, got %d: %q", len(lines), buf.String())
	}
	for _, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line is not valid JSON: %v (%q)", err, line)
		}
		if e.Ts.IsZero() {
			t.Error("Emit did not stamp a timestamp")
		}
	}
}

// Hasfy-App stores the trail per organisation, so an event with no org has
// nowhere to land. Forwarding it anyway used to cost the whole batch it
// travelled with, because the app rejected the request and the forwarder
// swallows delivery errors by design.
func TestEmitDoesNotForwardEventsWithoutAnOrg(t *testing.T) {
	f := testForwarder(t)
	l := New(&bytes.Buffer{}).WithForwarder(f)

	l.Emit(Event{Kind: "auth.fail", IP: "203.0.113.7", Reason: "bad session token"})

	if got := len(f.queue); got != 0 {
		t.Fatalf("org-less event was queued for forwarding (queue len %d)", got)
	}
}

func TestEmitForwardsOrgScopedEvents(t *testing.T) {
	f := testForwarder(t)
	l := New(&bytes.Buffer{}).WithForwarder(f)

	l.Emit(Event{Kind: "session.open", OrgID: "org-1", DeviceID: "dev-1", Operator: "user-1"})

	if len(f.queue) != 1 {
		t.Fatalf("expected 1 queued event, got %d", len(f.queue))
	}
	got := <-f.queue
	if got.Kind != "session.open" || got.OrgID != "org-1" {
		t.Fatalf("wrong event queued: %+v", got)
	}
}

// A relay deployed without an app URL is a supported configuration, not an
// error: it keeps working and simply does not populate the console's trail.
func TestEmitWithoutAForwarderIsSafe(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)

	l.Emit(Event{Kind: "session.open", OrgID: "org-1"})

	if !strings.Contains(buf.String(), "session.open") {
		t.Fatal("event did not reach the local sink")
	}
}

func TestNewForwarderRefusesAnUnusableConfig(t *testing.T) {
	if NewForwarder("", []byte(strings.Repeat("k", 32))) != nil {
		t.Error("forwarder built with no app URL")
	}
	// A short secret cannot produce a signature the app will accept, so
	// building one would only queue events destined to be rejected.
	if NewForwarder("https://app.example", []byte("short")) != nil {
		t.Error("forwarder built with a too-short secret")
	}
}

// The queue drops rather than blocks: back-pressuring the caller would let an
// unreachable Hasfy-App stall every exec on the relay, turning an
// observability problem into an availability one.
func TestEnqueueDropsRatherThanBlockingOnAFullQueue(t *testing.T) {
	f := testForwarder(t)
	l := New(&bytes.Buffer{}).WithForwarder(f)

	for i := 0; i < forwardQueueSize+10; i++ {
		l.Emit(Event{Kind: "exec.start", OrgID: "org-1"})
	}

	if len(f.queue) != forwardQueueSize {
		t.Fatalf("queue length %d, want the cap %d", len(f.queue), forwardQueueSize)
	}
}
