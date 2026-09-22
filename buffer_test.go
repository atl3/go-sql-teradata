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
	"bytes"
	"errors"
	"io"
	"testing"
)

// chunkReader hands back the scripted chunks one call at a time, so a test can
// force fill to loop rather than being satisfied by a single read.
type chunkReader struct {
	chunks [][]byte
	err    error
}

func (r *chunkReader) read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	if n < len(r.chunks[0]) {
		r.chunks[0] = r.chunks[0][n:]
	} else {
		r.chunks = r.chunks[1:]
	}
	return n, nil
}

func seq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// A peek must not consume, so the following next sees the peeked bytes and the
// ones after them as one contiguous slice. Reading a LAN header and then the
// message it sizes depends on exactly this.
func TestReadBufferPeekDoesNotConsume(t *testing.T) {
	msg := seq(200)
	r := &chunkReader{chunks: [][]byte{msg[:20], msg[20:]}}
	b := newReadBuffer()

	head, err := b.peek(16, r.read)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if !bytes.Equal(head, msg[:16]) {
		t.Fatalf("peek returned %v, want %v", head, msg[:16])
	}

	all, err := readNextFrom(&b, len(msg), r.read)
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if !bytes.Equal(all, msg) {
		t.Fatal("bytes after peek are not contiguous with the peeked header")
	}
	if b.len() != 0 {
		t.Fatalf("len = %d after consuming everything, want 0", b.len())
	}
}

// A message larger than the starting array has to grow, and the leftover bytes
// of the previous read have to survive being compacted into the new one.
func TestReadBufferGrowsPreservingPending(t *testing.T) {
	big := seq(defaultBufSize * 3)
	r := &chunkReader{chunks: [][]byte{big[:100], big[100:]}}
	b := newReadBuffer()

	if _, err := b.peek(100, r.read); err != nil {
		t.Fatalf("peek: %v", err)
	}
	got, err := readNextFrom(&b, len(big), r.read)
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if !bytes.Equal(got, big) {
		t.Fatal("grown buffer lost or reordered bytes")
	}
}

// Successive messages come back independently once the window slides forward.
func TestReadBufferSequentialMessages(t *testing.T) {
	first, second := seq(30), bytes.Repeat([]byte{0xAB}, 40)
	r := &chunkReader{chunks: [][]byte{append(append([]byte{}, first...), second...)}}
	b := newReadBuffer()

	got, err := readNextFrom(&b, len(first), r.read)
	if err != nil || !bytes.Equal(got, first) {
		t.Fatalf("first message = %v, %v", got, err)
	}
	got, err = readNextFrom(&b, len(second), r.read)
	if err != nil || !bytes.Equal(got, second) {
		t.Fatalf("second message = %v, %v", got, err)
	}
}

// A server that hangs up mid message is a truncation, not a clean EOF.
func TestReadBufferShortReadAtEOF(t *testing.T) {
	r := &chunkReader{chunks: [][]byte{seq(10)}}
	b := newReadBuffer()

	if err := b.fill(50, r.read); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("fill = %v, want io.ErrUnexpectedEOF", err)
	}
}

// An EOF reported alongside enough bytes is not an error.
func TestReadBufferEOFWithFullMessage(t *testing.T) {
	msg := seq(24)
	b := newReadBuffer()
	done := false
	read := func(p []byte) (int, error) {
		if done {
			return 0, io.EOF
		}
		done = true
		return copy(p, msg), io.EOF
	}

	got, err := readNextFrom(&b, len(msg), read)
	if err != nil {
		t.Fatalf("fill: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %v, want %v", got, msg)
	}
}

func TestReadBufferPropagatesReadError(t *testing.T) {
	want := errors.New("connection reset")
	r := &chunkReader{err: want}
	b := newReadBuffer()

	if err := b.fill(8, r.read); !errors.Is(err, want) {
		t.Fatalf("fill = %v, want %v", err, want)
	}
}

// Reused write space must come back zeroed: parcel writers leave gaps they
// never explicitly write, and stale bytes in those gaps go straight onto the
// wire.
func TestWriteBufferTakeIsZeroed(t *testing.T) {
	b := newWriteBuffer()

	first := b.take(64)
	for i := range first {
		first[i] = 0xFF
	}

	second := b.take(64)
	if !bytes.Equal(second, make([]byte, 64)) {
		t.Fatal("take returned bytes from the previous message")
	}
}

func TestWriteBufferTakeLengths(t *testing.T) {
	b := newWriteBuffer()

	for _, n := range []int{0, 1, defaultBufSize, defaultBufSize * 4, 7} {
		if got := b.take(n); len(got) != n {
			t.Fatalf("take(%d) returned %d bytes", n, len(got))
		}
	}
}

// An oversized request is served but not retained, so one huge message does
// not pin that memory for the life of the connection.
func TestWriteBufferDoesNotCacheOversized(t *testing.T) {
	b := newWriteBuffer()

	if got := b.take(maxCachedBufSize + 1); len(got) != maxCachedBufSize+1 {
		t.Fatalf("take returned %d bytes", len(got))
	}
	if len(b.store) > maxCachedBufSize {
		t.Fatalf("retained a %d byte array, want at most %d", len(b.store), maxCachedBufSize)
	}
}

// readNextFrom is the buffer half of teradataConnection.readNext, without
// needing a connection to drive it.
func readNextFrom(b *readBuffer, n int, read readerFunc) ([]byte, error) {
	if err := b.fill(n, read); err != nil {
		return nil, err
	}
	return b.next(n), nil
}
