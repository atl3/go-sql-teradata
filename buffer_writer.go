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

import "encoding/binary"

type bufferWritable interface {
	getLength() int
	write(writer *bufferWriter) error
}

// Buffer Writer
type bufferWriter struct {
	buff []byte
	indx int
}

func newBufferWriter(buff []byte) *bufferWriter {
	return &bufferWriter{
		buff: buff,
		indx: 0,
	}
}

func (w *bufferWriter) u8(v uint8) *bufferWriter {
	return w.byte(v)
}

func (w *bufferWriter) u16(v uint16) *bufferWriter {
	_ = w.buff[w.indx+1]
	binary.BigEndian.PutUint16(w.buff[w.indx:], v)
	w.indx += 2
	return w
}

func (w *bufferWriter) u32(v uint32) *bufferWriter {
	_ = w.buff[w.indx+3]
	binary.BigEndian.PutUint32(w.buff[w.indx:], v)
	w.indx += 4
	return w
}

func (w *bufferWriter) u64(v uint64) *bufferWriter {
	_ = w.buff[w.indx+7]
	binary.BigEndian.PutUint64(w.buff[w.indx:], v)
	w.indx += 8
	return w
}

func (w *bufferWriter) bytes(v []byte) *bufferWriter {
	_ = w.buff[w.indx+len(v)-1]
	copy(w.buff[w.indx:], v)
	w.indx += len(v)
	return w
}

func (w *bufferWriter) byte(v byte) *bufferWriter {
	_ = w.buff[w.indx]
	w.buff[w.indx] = v
	w.indx += 1
	return w
}

func (w *bufferWriter) tlv16(tag uint16, v []byte) *bufferWriter {
	return w.u16(tag).u16(uint16(len(v))).bytes(v)
}

func (w *bufferWriter) tz16(tag uint16) *bufferWriter {
	return w.u16(tag).u16(0)
}

func (w *bufferWriter) skip(len int) *bufferWriter {
	end := w.indx + len
	for ; w.indx < end; w.indx++ {
		w.buff[w.indx] = 0
	}
	return w
}

func (w *bufferWriter) setPosition(pos int) *bufferWriter {
	w.indx = pos
	return w
}

func (w *bufferWriter) position() int {
	return w.indx
}
