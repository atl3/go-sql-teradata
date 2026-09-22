// Copyright 2026 Andrew Lapham
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package teradata

import (
	"errors"
	"io"
)

const (
	defaultBufSize   = 4096
	maxCachedBufSize = 2*1024*1024 + 1
)

type readerFunc func([]byte) (int, error)

// accumulates incoming bytes so a caller can inspect a message header before committing to reading the msg
type readBuffer struct {
	pending []byte // Holds bytes that have been read but not consued yet
	store   []byte
}

func newReadBuffer() readBuffer {
	return readBuffer{store: make([]byte, defaultBufSize)}
}

// reports how many bytes have been read but not yet consumed.
func (b *readBuffer) len() int {
	return len(b.pending)
}

// read from the connection until at least need bytes are pending
func (b *readBuffer) fill(need int, read readerFunc) error {
	if need <= len(b.pending) {
		return nil
	}

	// Grow when we need more bytes (no ceiling on how big we grow only what we keep later)
	dest := b.store
	if need > len(dest) {
		dest = make([]byte, (need/defaultBufSize+1)*defaultBufSize)
		if len(dest) <= maxCachedBufSize {
			b.store = dest
		}
	}

	// Move unconsumed to front and then read in after it
	have := copy(dest, b.pending)
	for {
		n, err := read(dest[have:])
		have += n
		if err != nil {
			b.pending = dest[:have]
			if errors.Is(err, io.EOF) {
				if have < need {
					return io.ErrUnexpectedEOF
				}
				return nil
			}
			return err
		}
		if have >= need {
			b.pending = dest[:have]
			return nil
		}
	}
}

func (b *readBuffer) peek(need int, read readerFunc) ([]byte, error) {
	if err := b.fill(need, read); err != nil {
		return nil, err
	}
	return b.pending[:need:need], nil
}

func (b *readBuffer) next(need int) []byte {
	data := b.pending[:need:need]
	b.pending = b.pending[need:]
	return data
}

// Buffer for framing outgoing messages
type writeBuffer struct {
	store []byte
}

func newWriteBuffer() writeBuffer {
	return writeBuffer{store: make([]byte, defaultBufSize)}
}

// Take a new buffer - rusing the slice if we have enough space or else returning a new one
func (b *writeBuffer) take(length int) []byte {
	if length <= len(b.store) {
		buf := b.store[:length]
		clear(buf)
		return buf
	}

	buf := make([]byte, length)
	if length <= maxCachedBufSize {
		b.store = buf
	}
	return buf
}
