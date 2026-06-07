// Package proto defines the wire protocol shared between Hasfy-Relay agents
// and the relay server, and between the relay server and operator browsers.
//
// All frames are JSON over WebSocket. Frame size is capped at 1 MiB.
//
// Three logical channels:
//
//	agent  ↔ relay   : control + per-session multiplexed exec frames
//	app    → relay   : REST (out of scope, see internal/server/api.go)
//	browser ↔ relay  : single-session console frames
//
// Versioning: the first frame on any WS is HelloFrame with Version. The
// server rejects unknown versions with code 4400 and a CloseFrame.
package proto

import "time"

// Version is the wire-protocol version. Bump on breaking changes.
const Version = 1

// FrameType discriminates JSON envelopes.
type FrameType string

const (
	// Control frames (both directions).
	TypeHello   FrameType = "hello"
	TypePing    FrameType = "ping"
	TypePong    FrameType = "pong"
	TypeError   FrameType = "error"
	TypeBye     FrameType = "bye"

	// Agent → relay.
	TypeRegister FrameType = "register" // agent announces itself
	TypeExecAck  FrameType = "exec.ack" // agent accepted an exec
	TypeStdout   FrameType = "stdout"
	TypeStderr   FrameType = "stderr"
	TypeExit     FrameType = "exit"

	// Relay → agent / browser → relay → agent.
	TypeExec   FrameType = "exec"   // run a non-interactive command (legacy, kept for one-shot tooling)
	TypeCancel FrameType = "cancel" // cancel an in-flight exec OR end a PTY session when ExecID is empty

	// Interactive PTY (SSH-like) frames.
	// Lifecycle: operator sends pty.start once → agent spawns shell under
	// a PTY → bytes stream both directions via pty.data → operator may
	// emit pty.resize on terminal resize → shell exit triggers pty.exit
	// from agent. Session ends when either side closes the WS or relay
	// sends TypeCancel with empty ExecID.
	TypePtyStart  FrameType = "pty.start"
	TypePtyData   FrameType = "pty.data"
	TypePtyResize FrameType = "pty.resize"
	TypePtyExit   FrameType = "pty.exit"
)

// Frame is the envelope for every WS message. Exactly one of the typed
// payload fields is set, depending on Type.
type Frame struct {
	Type      FrameType `json:"type"`
	SessionID string    `json:"sid,omitempty"` // only for session-scoped frames
	ExecID    string    `json:"eid,omitempty"` // identifies a command within a session
	Hello     *Hello    `json:"hello,omitempty"`
	Register  *Register `json:"register,omitempty"`
	Exec      *Exec     `json:"exec,omitempty"`
	ExecAck   *ExecAck  `json:"exec_ack,omitempty"`
	Output    *Output   `json:"output,omitempty"`
	Exit      *Exit     `json:"exit,omitempty"`
	Error     *ErrorMsg `json:"error,omitempty"`

	// PTY payloads.
	PtyStart  *PtyStart  `json:"pty_start,omitempty"`
	PtyData   *PtyData   `json:"pty_data,omitempty"`
	PtyResize *PtyResize `json:"pty_resize,omitempty"`
	PtyExit   *PtyExit   `json:"pty_exit,omitempty"`
}

// Hello is the first frame sent by either side, used for capability
// negotiation. No secrets here — auth is in HTTP headers.
type Hello struct {
	Version  int               `json:"version"`
	Role     string            `json:"role"`     // "agent" | "operator"
	Features []string          `json:"features"` // e.g. ["exec.argv", "stdin.line"]
	Meta     map[string]string `json:"meta,omitempty"`
}

// Register is the agent's identity claim. The relay cross-checks DeviceID
// against the org embedded in the bearer token's claims.
type Register struct {
	DeviceID string            `json:"device_id"`
	OrgID    string            `json:"org_id"`
	Hostname string            `json:"hostname"`
	OS       string            `json:"os"`         // "linux" | "darwin" | "windows"
	Arch     string            `json:"arch"`       // "amd64" | "arm64"
	Version  string            `json:"version"`    // agent build version
	Tags     map[string]string `json:"tags,omitempty"`
}

// Exec is sent by the relay (originating from an operator session) to ask
// an agent to run a command. The agent MUST execute Argv as a single argv
// array — never join into a shell string. This blocks shell injection by
// construction.
type Exec struct {
	Argv      []string          `json:"argv"`
	Cwd       string            `json:"cwd,omitempty"`
	Env       map[string]string `json:"env,omitempty"`     // additive, won't override sensitive vars
	Stdin     string            `json:"stdin,omitempty"`   // base64 — full content, not a stream
	TimeoutMs int               `json:"timeout_ms"`        // mandatory, max 600_000
	OutputCap int               `json:"output_cap"`        // bytes per stream, default 1 MiB
}

// ExecAck signals the agent has accepted an Exec and is starting it.
type ExecAck struct {
	StartedAt time.Time `json:"started_at"`
	PID       int       `json:"pid"`
}

// Output carries stdout or stderr chunks. Already redacted by the agent
// before transmission — relay re-redacts for defense in depth.
type Output struct {
	Data string `json:"data"` // base64
}

// Exit terminates an exec. ExitCode == -1 means "killed by signal/timeout".
type Exit struct {
	ExitCode  int       `json:"exit_code"`
	EndedAt   time.Time `json:"ended_at"`
	Truncated bool      `json:"truncated,omitempty"`
}

// ErrorMsg communicates a recoverable protocol error. Fatal errors use a
// WebSocket close frame.
type ErrorMsg struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// PtyStart opens an interactive shell under a PTY for the current
// session. Sent once at session start. If Shell is empty, the agent picks
// a sensible default (zsh on darwin, bash on linux, falling back to sh).
type PtyStart struct {
	Cols  uint16 `json:"cols"`
	Rows  uint16 `json:"rows"`
	Shell string `json:"shell,omitempty"`
	Term  string `json:"term,omitempty"` // TERM env, default "xterm-256color"
}

// PtyData carries raw bytes both ways. Base64-encoded so the JSON envelope
// stays valid for any byte sequence (escape codes, UTF-8, control chars).
type PtyData struct {
	Data string `json:"data"` // base64
}

// PtyResize informs the agent that the operator's terminal has resized.
type PtyResize struct {
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// PtyExit signals the shell process has terminated.
type PtyExit struct {
	ExitCode int `json:"exit_code"`
}
