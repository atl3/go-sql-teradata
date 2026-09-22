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
	"fmt"
	"math/big"
)

// Port of com.teradata.tdgss.jalgapi.Encoding for minimal  BER/DER TLV parsing

type derTLV struct {
	tag         byte
	constructed bool
	content     []byte
	totalLen    int // identifier + length + content octets consumed
}

// parseDerTLV parses one TLV record starting at data[pos].
func parseDerTLV(data []byte, pos int) (derTLV, error) {
	if pos < 0 || pos >= len(data) {
		return derTLV{}, fmt.Errorf("der: position %d out of range (len %d)", pos, len(data))
	}
	idByte := data[pos]
	if idByte&0x1F == 0x1F {
		return derTLV{}, fmt.Errorf("der: high-tag-number form not supported")
	}
	tag := idByte & 0x1F
	constructed := idByte&0x20 != 0

	lenPos := pos + 1
	if lenPos >= len(data) {
		return derTLV{}, fmt.Errorf("der: truncated length octet")
	}
	lenByte := data[lenPos]

	var contentLen, lenOctets int
	if lenByte&0x80 != 0 {
		n := int(lenByte & 0x7F)
		if lenPos+1+n > len(data) {
			return derTLV{}, fmt.Errorf("der: truncated long-form length")
		}
		for i := 0; i < n; i++ {
			contentLen = (contentLen << 8) | int(data[lenPos+1+i])
		}
		lenOctets = 1 + n
	} else {
		contentLen = int(lenByte & 0x7F)
		lenOctets = 1
	}

	contentStart := lenPos + lenOctets
	contentEnd := contentStart + contentLen
	if contentEnd > len(data) {
		return derTLV{}, fmt.Errorf("der: truncated content octets (want %d, have %d)", contentEnd, len(data))
	}

	return derTLV{
		tag:         tag,
		constructed: constructed,
		content:     data[contentStart:contentEnd],
		totalLen:    1 + lenOctets + contentLen,
	}, nil
}

func parseDerChildren(content []byte) ([]derTLV, error) {
	var out []derTLV
	pos := 0
	for pos < len(content) {
		t, err := parseDerTLV(content, pos)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		pos += t.totalLen
	}
	return out, nil
}

func derInt(content []byte) int {
	v := new(big.Int).SetBytes(content)
	if len(content) > 0 && content[0]&0x80 != 0 {
		full := new(big.Int).Lsh(big.NewInt(1), uint(8*len(content)))
		v.Sub(v, full)
	}
	return int(v.Int64())
}

func derUint64(content []byte) uint64 {
	return new(big.Int).SetBytes(content).Uint64()
}

func findDerChild(children []derTLV, tag byte) (derTLV, bool) {
	for _, c := range children {
		if c.tag == tag {
			return c, true
		}
	}
	return derTLV{}, false
}

/* Writing */
func encodeDerTLV(tagNumber byte, constructed bool, content []byte) []byte {
	if tagNumber > 30 {
		panic("der: high-tag-number form not supported")
	}
	idByte := byte(0xC0) // DERClass.PRIVATE (ordinal 3) << 6
	if constructed {
		idByte |= 0x20
	}
	idByte |= tagNumber

	length := encodeDerLength(len(content))
	out := make([]byte, 0, 1+len(length)+len(content))
	out = append(out, idByte)
	out = append(out, length...)
	out = append(out, content...)
	return out
}

func encodeDerLength(n int) []byte {
	if n <= 127 {
		return []byte{byte(n)}
	}
	var lb []byte
	for v := n; v > 0; v >>= 8 {
		lb = append([]byte{byte(v & 0xFF)}, lb...)
	}
	return append([]byte{0x80 | byte(len(lb))}, lb...)
}

func encodeDerConstructed(tagNumber byte, children ...[]byte) []byte {
	var content []byte
	for _, c := range children {
		content = append(content, c...)
	}
	return encodeDerTLV(tagNumber, true, content)
}

func derMinimalInt(v uint64) []byte {
	b := new(big.Int).SetUint64(v).Bytes()
	if len(b) == 0 {
		return []byte{0}
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b
}
