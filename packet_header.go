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
	"fmt"
)

const (
	lanHeaderLen = 52

	copVersion      = 3
	copClassRequest = 1
	copEncryptFlag  = 0x80

	lanHeaderTypeAssign   = 1
	lanHeaderTypeConnect  = 3
	lanHeaderTypeStart    = 5
	lanHeaderTypeContinue = 6
	lanHeaderTypeLogoff   = 8
	lanHeaderTypeCfg      = 10
	lanHeaderTypeSSOReq   = 12
)

type lanHeader struct {
	kind        byte
	byteVar     byte
	sessionNo   uint32
	authNonce   [8]byte
	requestNo   uint32
	hostCharSet byte
	encrypted   bool

	version           byte
	msgType           byte
	bodyLen           int
	msgLen            int
	wordVar           uint16
	correlationTag    uint32
	authentication    []byte
	unionGTW          byte
	controlDataLength uint32
}

func newLanHeader() *lanHeader {
	return &lanHeader{
		version:     3,
		msgType:     1,
		hostCharSet: 0xFF,
	}
}

func (c *teradataConnection) newLanHeaderLogoff() *lanHeader {
	header := newLanHeader()
	header.kind = lanHeaderTypeLogoff
	header.byteVar = 7
	header.hostCharSet = 0xFF
	header.requestNo = 0
	header.sessionNo = c.sessionNo
	binary.BigEndian.PutUint64(header.authNonce[:], uint64(c.nextAuthNonce()))
	return header
}

func (c *teradataConnection) newLanHeaderConnect() *lanHeader {
	header := newLanHeader()
	header.kind = lanHeaderTypeConnect
	header.byteVar = 7
	header.hostCharSet = 0xFF
	header.requestNo = 0
	header.sessionNo = c.sessionNo
	return header
}

func (c *teradataConnection) newLanHeaderStart() *lanHeader {
	header := newLanHeader()
	header.kind = lanHeaderTypeStart
	header.byteVar = 7
	header.hostCharSet = 0xFF
	header.requestNo = c.nextRequestNumber()
	header.sessionNo = c.sessionNo
	binary.BigEndian.PutUint64(header.authNonce[:], uint64(c.nextAuthNonce()))
	return header
}

func (c *teradataConnection) newLanHeaderContinue() *lanHeader {
	header := newLanHeader()
	header.kind = lanHeaderTypeContinue
	header.byteVar = 7
	header.hostCharSet = 0xFF
	header.requestNo = c.sameRequestNumber()
	header.sessionNo = c.sessionNo
	binary.BigEndian.PutUint64(header.authNonce[:], uint64(c.nextAuthNonce()))
	return header
}

func (c *teradataConnection) newLanHeaderCancel(requestNo uint32) *lanHeader {
	header := newLanHeader()
	header.kind = lanHeaderTypeContinue
	header.byteVar = 0
	header.hostCharSet = 0xFF
	header.requestNo = requestNo
	header.sessionNo = c.sessionNo
	binary.BigEndian.PutUint64(header.authNonce[:], uint64(c.nextAuthNonce()))
	return header
}

func (h *lanHeader) write(w *bufferWriter, offset int, bodyLen int) error {
	w.byte(copVersion)
	if h.encrypted {
		w.byte(copClassRequest | copEncryptFlag)
	} else {
		w.byte(copClassRequest)
	}
	w.byte(h.kind)
	w.u16(uint16(bodyLen >> 16))
	w.byte(h.byteVar)
	w.u16(h.wordVar)
	w.u16(uint16(bodyLen & 0xFFFF))
	w.skip(6)
	w.u32(h.correlationTag)
	w.u32(h.sessionNo)
	w.bytes(h.authNonce[:])
	w.u32(h.requestNo)
	w.byte(h.unionGTW)
	w.byte(h.hostCharSet)
	w.skip(offset + lanHeaderLen - w.position())
	w.setPosition(lanHeaderLen + offset)
	return nil
}

func (h *lanHeader) String() string {
	return fmt.Sprintf("lanHeader{kind = %d, msgLenength = %d, sessionNo=%d}", h.kind, h.msgLen, h.sessionNo)
}

func lanHeaderFromBuffer(data []byte) (*lanHeader, error) {
	if data == nil || len(data) != lanHeaderLen {
		return nil, ErrInternal
	}
	hdr := &lanHeader{
		version:           data[0],
		msgType:           data[1],
		kind:              data[2],
		byteVar:           data[5],
		wordVar:           binary.BigEndian.Uint16(data[6:8]),
		correlationTag:    binary.BigEndian.Uint32(data[16:20]),
		sessionNo:         binary.BigEndian.Uint32(data[20:24]),
		authentication:    data[24:32],
		requestNo:         binary.BigEndian.Uint32(data[32:36]),
		unionGTW:          data[36],
		hostCharSet:       data[37],
		controlDataLength: binary.BigEndian.Uint32(data[40:44]),
		bodyLen:           int(binary.BigEndian.Uint16(data[3:5]))<<16 | int(binary.BigEndian.Uint16(data[8:10])),
	}
	hdr.msgLen = hdr.bodyLen + lanHeaderLen
	return hdr, nil
}
