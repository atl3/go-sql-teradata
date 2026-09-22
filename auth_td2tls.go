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
	"log/slog"
)

// Simplified TD2 GSS Context used when channel is TLS encrypted and server allows CI Bypass
type td2TlsGssContext struct {
	logger *slog.Logger
}

func newTd2TlsGssContext(logger *slog.Logger) *td2TlsGssContext {
	return &td2TlsGssContext{logger: logger}
}

func (c *td2TlsGssContext) wrap(data []byte) ([]byte, error) {
	return data, nil
}

func (c *td2TlsGssContext) unwrap(data []byte) ([]byte, error) {
	return data, nil
}

func (c *td2TlsGssContext) establishSecureChannel(con *teradataConnection) error {
	ssoResp, err := c.handshake(con)
	if err != nil {
		return err
	}

	authDataReader := newBufferReader(ssoResp.authData, 0, len(ssoResp.authData))
	respTokenHdr, err := td2TokenHeaderFromBuffer(authDataReader)
	if err != nil {
		return err
	}
	if respTokenHdr.byteVar == 1 && (respTokenHdr.msgType == 1 || respTokenHdr.msgType == 2) {
		return nil
	}
	return ErrNoSecureChannel
}

func (c *td2TlsGssContext) handshake(con *teradataConnection) (*ssoResponseParcel, error) {
	header := newLanHeader()
	header.kind = lanHeaderTypeAssign
	header.byteVar = 7
	header.hostCharSet = 0xFF
	header.requestNo = 0
	header.sessionNo = con.sessionNo
	binary.BigEndian.PutUint64(header.authNonce[:], uint64(con.nextAuthNonce()))

	// Init Msg
	tokenHeader := &td2TokenHeader{
		version:        1,
		msgType:        1,
		byteVar:        1,
		clientOrServer: 0,
		capabilities:   0x80000000,
		flags:          0x02,
	}
	trailerLen := len(td2Trailer)
	bufferLen := 80 + trailerLen
	messageLen := 64
	initSsoAuthData := make([]byte, bufferLen)
	w := newBufferWriter(initSsoAuthData)
	tokenHeader.encode(w, messageLen)
	w.setPosition(16).bytes(tdGssVersion)
	w.setPosition(80).bytes(td2Trailer)
	err := con.writeLanMessage(
		header,
		newSSORequestParcel(0, 0, initSsoAuthData),
		newAssignParcel(con.config.User),
	)
	if err != nil {
		return nil, err
	}

	// Read response
	parcels, hdr, err := con.readLanMessage()
	if err != nil {
		return nil, err
	}
	con.sessionNo = hdr.sessionNo
	header.sessionNo = hdr.requestNo

	ssoResp, ok := findParcel[*ssoResponseParcel](parcels)
	if !ok {
		return nil, ErrInternal
	}
	return ssoResp, nil
}
