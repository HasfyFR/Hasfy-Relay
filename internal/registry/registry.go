// Package registry maintains the set of currently-connected agents.
//
// The map is keyed by deviceID (a stable identifier issued by Hasfy-App at
// install time). At most one connection per deviceID is allowed: a new
// register evicts the previous one with close code 4409 (conflict).
//
// Each registered agent runs a goroutine pump that sends frames written to
// its outbound channel; the registry never writes to a websocket directly.
package registry

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/HasfyFR/Hasfy-Relay/internal/proto"
)

// ErrNotFound is returned when a device is not currently online.
var ErrNotFound = errors.New("device not registered")

// Agent is the live record of a connected agent.
type Agent struct {
	DeviceID  string
	OrgID     string
	Hostname  string
	OS        string
	Arch      string
	Version   string
	JoinedAt  time.Time

	// outbound delivers frames to the WS write pump. Closed on disconnect.
	outbound chan proto.Frame

	// cancel detaches the previous registration when evicted.
	cancel context.CancelFunc
}

// Send queues a frame for delivery. Returns false if the agent is gone or
// the buffer is full (caller decides how to react — disconnects on overflow
// are appropriate to bound memory).
func (a *Agent) Send(f proto.Frame) bool {
	select {
	case a.outbound <- f:
		return true
	default:
		return false
	}
}

// Outbound exposes the channel for the WS write pump.
func (a *Agent) Outbound() <-chan proto.Frame { return a.outbound }

// Registry is safe for concurrent use.
type Registry struct {
	mu    sync.RWMutex
	byDev map[string]*Agent
}

func New() *Registry {
	return &Registry{byDev: make(map[string]*Agent)}
}

// Register installs the agent. Any previous registration for the same
// deviceID is evicted via its cancel func. The returned ctx is cancelled
// when the agent is evicted or unregistered.
func (r *Registry) Register(parent context.Context, a *Agent, bufSize int) context.Context {
	ctx, cancel := context.WithCancel(parent)
	a.cancel = cancel
	a.outbound = make(chan proto.Frame, bufSize)
	a.JoinedAt = time.Now()

	r.mu.Lock()
	if prev, ok := r.byDev[a.DeviceID]; ok {
		prev.cancel()
		close(prev.outbound)
	}
	r.byDev[a.DeviceID] = a
	r.mu.Unlock()
	return ctx
}

// Unregister removes the agent if it is still the active one for its
// deviceID. Calling twice is safe.
func (r *Registry) Unregister(a *Agent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.byDev[a.DeviceID]; ok && cur == a {
		delete(r.byDev, a.DeviceID)
		a.cancel()
		// Close after delete so concurrent Send fails fast.
		close(a.outbound)
	}
}

// Get looks up an online agent.
func (r *Registry) Get(deviceID string) (*Agent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.byDev[deviceID]
	if !ok {
		return nil, ErrNotFound
	}
	return a, nil
}

// ListByOrg returns a snapshot for an org. Cheap; for large orgs add an
// org-keyed secondary index.
func (r *Registry) ListByOrg(orgID string) []*Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Agent, 0)
	for _, a := range r.byDev {
		if a.OrgID == orgID {
			out = append(out, a)
		}
	}
	return out
}

// Count returns the total number of online agents (for /metrics).
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byDev)
}
