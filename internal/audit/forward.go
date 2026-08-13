package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// =============================================================================
// Forwarding the audit trail to Hasfy-App
// =============================================================================
//
// Events go to stdout for the cluster log pipeline, and now also to Hasfy-App
// so the console can answer "who opened a root shell on this device, when, and
// what did they run" without anyone going to Kibana.
//
// Delivery is best-effort and asynchronous: an audit sink must never be able
// to stall or fail the data path it observes. The trade is explicit — a batch
// lost to a network blip is a gap in the trail, whereas blocking an exec on
// the audit endpoint would be an outage.

const (
	// Flush whenever the batch reaches this size, or the interval elapses,
	// whichever comes first. Sessions are bursty (open, several execs, close),
	// so a short interval keeps the console close to live without one request
	// per event.
	forwardBatchSize   = 50
	forwardInterval    = 5 * time.Second
	forwardHTTPTimeout = 10 * time.Second
	forwardQueueSize   = 500
	forwardPath        = "/api/v1/relay/audit"
)

// Forwarder ships events to Hasfy-App, signed with the shared service HMAC.
type Forwarder struct {
	appURL string
	secret []byte
	queue  chan Event
	client *http.Client
}

// NewForwarder returns nil when forwarding is not configured, which callers
// treat as "stdout only" rather than an error — a relay deployed without the
// app URL still works, it just does not populate the console's trail.
func NewForwarder(appURL string, secret []byte) *Forwarder {
	if appURL == "" || len(secret) < 32 {
		return nil
	}
	return &Forwarder{
		appURL: strings.TrimRight(appURL, "/"),
		secret: secret,
		queue:  make(chan Event, forwardQueueSize),
		client: &http.Client{Timeout: forwardHTTPTimeout},
	}
}

// Enqueue hands an event to the forwarder without blocking.
//
// Drops on a full queue. That is the correct failure: back-pressuring the
// caller would let an unreachable Hasfy-App stall every exec on the relay,
// turning an observability problem into an availability one.
func (f *Forwarder) Enqueue(e Event) {
	if f == nil {
		return
	}
	select {
	case f.queue <- e:
	default:
	}
}

// Run drains the queue until ctx is cancelled, flushing what remains on the
// way out so a graceful shutdown does not discard the last session's events.
func (f *Forwarder) Run(ctx context.Context) {
	if f == nil {
		return
	}
	ticker := time.NewTicker(forwardInterval)
	defer ticker.Stop()

	batch := make([]Event, 0, forwardBatchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		f.post(ctx, batch)
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			// Best-effort final flush on a context that is already cancelled;
			// post() uses its own timeout so this still gets a chance.
			f.post(context.Background(), batch)
			return
		case e := <-f.queue:
			batch = append(batch, e)
			if len(batch) >= forwardBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

type auditBatch struct {
	Events []Event `json:"events"`
}

// post signs and sends one batch. Errors are swallowed on purpose: there is
// nobody to report them to that would not itself be an audit sink.
func (f *Forwarder) post(ctx context.Context, batch []Event) {
	if len(batch) == 0 {
		return
	}

	body, err := json.Marshal(auditBatch{Events: batch})
	if err != nil {
		return
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	bodyHash := sha256.Sum256(body)
	mac := hmac.New(sha256.New, f.secret)
	// Same message shape Hasfy-App uses when calling us, in the other
	// direction: ts \n method \n path \n sha256(body). The timestamp is signed
	// and bounded, so a captured request cannot be replayed later to inject
	// fabricated audit history.
	fmt.Fprintf(mac, "%s\nPOST\n%s\n%s", ts, forwardPath, hex.EncodeToString(bodyHash[:]))
	sig := hex.EncodeToString(mac.Sum(nil))

	ctx, cancel := context.WithTimeout(ctx, forwardHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		f.appURL+forwardPath, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hasfy-Ts", ts)
	req.Header.Set("X-Hasfy-Sig", sig)

	resp, err := f.client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}
