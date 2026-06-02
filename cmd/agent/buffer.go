package main

import "bytes"

// capBuffer is a bytes.Buffer that stops accepting writes after `cap` bytes.
// Used to bound the memory the agent will spend on a runaway command.
type capBuffer struct {
	buf  bytes.Buffer
	max  int
	full bool
}

func newCapBuffer(max int) *capBuffer { return &capBuffer{max: max} }

func (b *capBuffer) Write(p []byte) (int, error) {
	if b.full {
		return len(p), nil // pretend success; data dropped
	}
	remain := b.max - b.buf.Len()
	if remain <= 0 {
		b.full = true
		return len(p), nil
	}
	if len(p) > remain {
		p = p[:remain]
		b.full = true
	}
	return b.buf.Write(p)
}

func (b *capBuffer) Bytes() []byte    { return b.buf.Bytes() }
func (b *capBuffer) Truncated() bool  { return b.full }

// bytesReader is a thin wrapper to feed []byte as io.Reader for cmd.Stdin
// without pulling in bytes.NewReader's allocation patterns repeatedly.
func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
