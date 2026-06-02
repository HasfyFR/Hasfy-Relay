// Package audit emits append-only NDJSON events to stdout, where Filebeat
// picks them up and ships to Elasticsearch (index hasfy-console-audit-*).
//
// We deliberately do NOT write to a file: stateless pod, K8s log driver
// handles rotation, and Filebeat already runs cluster-wide.
//
// Every event includes ISO-8601 ts, event type, actor, and structured
// metadata. Free-form payloads (command output) go through Redact first.
package audit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Event is the NDJSON shape Filebeat will ship.
type Event struct {
	Ts        time.Time         `json:"@timestamp"`
	Kind      string            `json:"kind"`        // "session.open", "exec.start", "exec.output", "exec.exit", "session.close", "auth.fail"
	OrgID     string            `json:"org_id,omitempty"`
	DeviceID  string            `json:"device_id,omitempty"`
	SessionID string            `json:"session_id,omitempty"`
	ExecID    string            `json:"exec_id,omitempty"`
	Operator  string            `json:"operator,omitempty"`
	IP        string            `json:"ip,omitempty"`
	Argv      []string          `json:"argv,omitempty"`
	ExitCode  *int              `json:"exit_code,omitempty"`
	OutputRef string            `json:"output_ref,omitempty"` // pointer to chunk store, never raw output
	Bytes     int               `json:"bytes,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
}

// Logger serializes Events to a single io.Writer with a mutex. The writer
// MUST itself be safe (os.Stdout is line-buffered when attached to a pipe;
// fine for our k8s log driver use case).
type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

func NewStdout() *Logger { return &Logger{w: os.Stdout} }

func New(w io.Writer) *Logger { return &Logger{w: w} }

// Emit writes one NDJSON line. Errors are swallowed: audit is best-effort,
// it must never crash the data path. (We surface them via /metrics counter
// in the server package.)
func (l *Logger) Emit(e Event) {
	if e.Ts.IsZero() {
		e.Ts = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	l.mu.Lock()
	_, _ = l.w.Write(b)
	l.mu.Unlock()
}
