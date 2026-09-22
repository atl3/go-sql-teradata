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
	"encoding/binary"
	"math"
	"math/big"
)

// Buffer Reader
type bufferReader struct {
	buff []byte
	indx int
	len  int
}

func newBufferReader(buff []byte, start int, len int) *bufferReader {
	return &bufferReader{
		buff: buff,
		indx: start,
		len:  len,
	}
}

func (r *bufferReader) isDone() bool {
	return r.indx >= r.len
}

func (r *bufferReader) peekU16() uint16 {
	return binary.BigEndian.Uint16(r.buff[r.indx : r.indx+2])
}

func (r *bufferReader) u16() uint16 {
	d := binary.BigEndian.Uint16(r.buff[r.indx : r.indx+2])
	r.indx += 2
	return d
}

func (r *bufferReader) u32() uint32 {
	d := binary.BigEndian.Uint32(r.buff[r.indx : r.indx+4])
	r.indx += 4
	return d
}

func (r *bufferReader) u64() uint64 {
	d := binary.BigEndian.Uint64(r.buff[r.indx : r.indx+8])
	r.indx += 8
	return d
}

func (r *bufferReader) bytes(len int) []byte {
	d := r.buff[r.indx : r.indx+len]
	r.indx += len
	return d
}

func (r *bufferReader) skip(len int) *bufferReader {
	r.indx += len
	return r
}

func (r *bufferReader) position() int {
	return r.indx
}

func (r *bufferReader) seek(pos int) *bufferReader {
	r.indx = pos
	return r
}

func (r *bufferReader) u8() byte {
	d := r.buff[r.indx]
	r.indx++
	return d
}

func (r *bufferReader) f64() float64 {
	return math.Float64frombits(r.u64())
}

func (r *bufferReader) bigInt16() *big.Int {
	return r.bigIntN(16)
}

func (r *bufferReader) bigIntN(n int) *big.Int {
	b := r.bytes(n)
	v := new(big.Int).SetBytes(b)
	if n > 0 && b[0]&0x80 != 0 {
		full := new(big.Int).Lsh(big.NewInt(1), uint(n*8))
		v.Sub(v, full)
	}
	return v
}

func (r *bufferReader) byteAt(pos int) byte {
	return r.buff[pos]
}

func (r *bufferReader) u16At(pos int) uint16 {
	return binary.BigEndian.Uint16(r.buff[pos : pos+2])
}

func (r *bufferReader) u32At(pos int) uint32 {
	return binary.BigEndian.Uint32(r.buff[pos : pos+4])
}

func (r *bufferReader) u64At(pos int) uint64 {
	return binary.BigEndian.Uint64(r.buff[pos : pos+8])
}

func (r *bufferReader) asciiString(len int) string {
	d := r.bytes(len)
	return string(d)
}

func (r *bufferReader) asciiStringAt(pos int, len int) string {
	return string(r.buff[pos : pos+len])
}

func (c *teradataConnection) readNext(n int) ([]byte, error) {
	if err := c.buffer.fill(n, c.netConn.Read); err != nil {
		return nil, err
	}
	return c.buffer.next(n), nil
}
