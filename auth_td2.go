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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/big"
)

const td2TokenHeaderLen = 16

type td2TokenHeader struct {
	version        uint8
	msgType        uint8
	byteVar        uint8
	clientOrServer uint8
	capabilities   uint32
	flags          uint8
}

type td2GssContext struct {
	master       *big.Int
	keyLen       int
	qopOptions   []td2AlgQop
	wrapSeqNum   uint64
	targetEndien byte
	logger       *slog.Logger
}

type td2WrapToken struct {
	version   byte
	msgType   byte
	flag      byte
	qopIndex  byte
	msgLength uint32
	seqNum    uint64
}

const (
	qopTagConfAlg    = 16
	qopTagIntegAlg   = 17
	qopTagKeyExchAlg = 18
	qopTagMode       = 19
	qopTagPadding    = 20
	qopTagKeyLength  = 21
	qopTagKeyLengthP = 22
)

var (
	td2AlgNames = []string{"NONE", "Blowfish", "AES", "MD5", "SHA1", "DH", "SHA-256", "SHA-512"}
	td2Modes    = []string{"NONE", "CBC", "CFB", "ECB", "OFB", "GCM", "CCM", "CTR", "AEADGCM", "GCM96"}
	td2Paddings = []string{"NoPadding", "OAEPWithDIGESTAndMGFPadding", "", "PKCS1Padding", "PKCS5Padding", "SSL3Padding"}
	td2Trailer  = []byte{
		0x06, 0x0D, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0x3F, 0x01, 0x87, 0x74, 0x01, 0x01, 0x09,
		0x46, 0x08, 0x00, 0x02, 0x81, 0x00, 0x04, 0x04, 0x04, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x1F, 0x01,
	}
	td2CipherSuite = []byte{
		0xE1, 0x5B, 0xE2, 0x15, 0xD0, 0x01, 0x02, 0xD3, 0x01, 0x01, 0xD4, 0x01, 0x04, 0xD5, 0x02, 0x00,
		0x80, 0xD5, 0x02, 0x00, 0xC0, 0xD5, 0x02, 0x01, 0x00,
		0xE2, 0x03, 0xD1, 0x01, 0x04, 0xE2, 0x03, 0xD1, 0x01, 0x06, 0xE2, 0x03, 0xD1, 0x01, 0x07,
		0xE2, 0x07, 0xD2, 0x01, 0x05, 0xD6, 0x02, 0x08, 0x00,
		0xE2, 0x09, 0xD0, 0x01, 0x02, 0xD3, 0x01, 0x07, 0xD4, 0x01, 0x04,
		0xE2, 0x09, 0xD0, 0x01, 0x02, 0xD3, 0x01, 0x05, 0xD4, 0x01, 0x04,
		0xE2, 0x09, 0xD0, 0x01, 0x02, 0xD3, 0x01, 0x08, 0xD4, 0x01, 0x04,
		0xE2, 0x09, 0xD0, 0x01, 0x02, 0xD3, 0x01, 0x09, 0xD4, 0x01, 0x04,
	}
)

type td2AlgQop struct {
	confAlg    string
	mode       string
	padding    string
	keyLength  int
	integAlg   string
	keyExchAlg string
	keyLengthP int
}

func newTd2GssContext(logger *slog.Logger) *td2GssContext {
	return &td2GssContext{wrapSeqNum: 1, logger: logger}
}

func (q td2AlgQop) String() string {
	return fmt.Sprintf("AlgQop{conf=%s/%s/%s keyLen=%d integ=%s keyExch=%s keyLenP=%d}",
		q.confAlg, q.mode, q.padding, q.keyLength, q.integAlg, q.keyExchAlg, q.keyLengthP)
}

func (t td2TokenHeader) String() string {
	return fmt.Sprintf(
		"td2TokenHeader{version: %d, msgType: %d, byteVar: %d, clientOrServer: %d, capabilities: 0x%X, flags: 0x%02X}",
		t.version,
		t.msgType,
		t.byteVar,
		t.clientOrServer,
		t.capabilities,
		t.flags,
	)
}

func (t *td2TokenHeader) encode(w *bufferWriter, msgLength int) {
	w.byte(t.version)
	w.byte(t.msgType)
	w.byte(t.byteVar)
	w.byte(t.clientOrServer)
	w.u32(uint32(msgLength))
	w.u32(t.capabilities)
	w.byte(t.flags | 0x02)
}

func td2TokenHeaderFromBuffer(reader *bufferReader) (*td2TokenHeader, error) {
	if reader.len < 16 {
		return nil, ErrInternal
	}
	token := &td2TokenHeader{}
	token.version = reader.u8()
	token.msgType = reader.u8()
	msgLen := reader.u32At(4)
	if msgLen != 7 && msgLen != 8 {
		reader.seek(2)
		token.byteVar = reader.u8()
		token.clientOrServer = reader.u8()
		if (token.msgType == 1 || token.msgType == 2) && token.byteVar == 1 {
			token.capabilities = reader.u32At(8)
		}
		token.flags = reader.byteAt(12)
		// resForExp?
	} else {
		token.flags = reader.byteAt(2)
		//v3fQOP
		//seqNum
	}
	return token, nil
}

func (t td2WrapToken) bytes() []byte {
	b := make([]byte, td2TokenHeaderLen)
	b[0] = t.version
	b[1] = t.msgType
	b[2] = t.flag
	b[3] = t.qopIndex
	binary.BigEndian.PutUint32(b[4:8], t.msgLength)
	binary.BigEndian.PutUint64(b[8:16], t.seqNum)
	return b
}

// encrypts everything after the first 24 bytes
func (c *td2GssContext) wrap(data []byte) ([]byte, error) {
	if len(c.qopOptions) == 0 {
		return nil, fmt.Errorf("td2 wrap: no negotiated QOP options")
	}

	var alg td2AlgQop
	qopIndex := -1
	for i, q := range c.qopOptions {
		c.logger.Log(context.Background(), logLevelTrace, "td2 wrap", "qopOption", q)
		if q.confAlg == "AES" && q.mode == "GCM96" {
			alg = q
			qopIndex = i
			break
		}
	}
	if qopIndex == -1 {
		return nil, ErrTd2InvalidAlg
	}

	key, err := c.qopKey(qopIndex)
	if err != nil {
		return nil, fmt.Errorf("td2 wrap: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block) // 12-byte nonce, 16-byte tag -- matches GCMParameterSpec.getInstance(128, 12-byte nonce)
	if err != nil {
		return nil, err
	}

	hmacLen, err := td2HmacLen(alg.integAlg)
	if err != nil {
		return nil, err
	}

	n := len(data)
	padded := make([]byte, n+16)
	copy(padded, data)

	msgLength := uint32(n + 16 + 16 + hmacLen + 16)
	token := td2WrapToken{
		version:   3,
		msgType:   7, // wrap
		flag:      0x04,
		qopIndex:  byte(qopIndex),
		msgLength: msgLength,
		seqNum:    c.wrapSeqNum,
	}
	tokenBytes := token.bytes()
	nonce := tokenBytes[4:16] // GCM96: token[4:16], NOT the full 16-byte token
	copy(padded[n:n+12], nonce)

	sealed := gcm.Seal(nil, nonce, padded, nil) // ciphertext(n+16), 16-byte tag
	if len(sealed) != n+16+16 {
		return nil, fmt.Errorf("td2 wrap: unexpected GCM output size %d", len(sealed))
	}
	inputMsg := sealed[:n+16]
	authTag := sealed[n+16:]

	fQOP := make([]byte, 4)
	binary.BigEndian.PutUint32(fQOP, uint32(qopIndex))
	tokenHdr := encodeDerConstructed(1,
		encodeDerTLV(0, false, []byte{token.version}),
		encodeDerTLV(1, false, []byte{token.msgType}),
		encodeDerTLV(2, false, []byte{token.flag}),
		encodeDerTLV(3, false, fQOP),
		encodeDerTLV(4, false, derMinimalInt(uint64(token.msgLength))),
		encodeDerTLV(5, false, derMinimalInt(token.seqNum)),
	)

	envelope := encodeDerConstructed(0,
		encodeDerTLV(0, false, inputMsg),
		tokenHdr,
		encodeDerTLV(3, false, authTag),
	)

	c.wrapSeqNum++
	return envelope, nil
}

func (c *td2GssContext) qopKey(qopIndex int) ([]byte, error) {
	if qopIndex < 0 || qopIndex >= len(c.qopOptions) {
		return nil, fmt.Errorf("invalid QOP index %d", qopIndex)
	}
	alg := c.qopOptions[qopIndex]
	masterBytes := normalizeDHSecretLen(c.master, c.keyLen)
	keyLenBytes := alg.keyLength / 8
	keyOffset := 0
	for i := 0; i < qopIndex; i++ {
		keyOffset += c.qopOptions[i].keyLength / 8
	}
	if keyOffset+keyLenBytes > len(masterBytes) {
		return nil, fmt.Errorf("master secret too short to slice QOP key")
	}
	return masterBytes[keyOffset : keyOffset+keyLenBytes], nil
}

func (c *td2GssContext) unwrap(data []byte) ([]byte, error) {
	top, err := parseDerTLV(data, 0)
	if err != nil {
		return nil, fmt.Errorf("td2 unwrap: %w", err)
	}
	children, err := parseDerChildren(top.content)
	if err != nil {
		return nil, fmt.Errorf("td2 unwrap: %w", err)
	}

	inputMsg, ok := findDerChild(children, 0)
	if !ok {
		return nil, fmt.Errorf("td2 unwrap: missing inputMsg")
	}
	tokenHdr, ok := findDerChild(children, 1)
	if !ok {
		return nil, fmt.Errorf("td2 unwrap: missing tokenHdr")
	}
	authTag, ok := findDerChild(children, 3)
	if !ok {
		return nil, fmt.Errorf("td2 unwrap: missing authTag (only GCM96/AEADGCM are implemented)")
	}

	hdrFields, err := parseDerChildren(tokenHdr.content)
	if err != nil {
		return nil, fmt.Errorf("td2 unwrap: %w", err)
	}

	var token td2WrapToken
	var qopIndex int
	for _, f := range hdrFields {
		switch f.tag {
		case 0:
			if len(f.content) > 0 {
				token.version = f.content[0]
			}
		case 1:
			if len(f.content) > 0 {
				token.msgType = f.content[0]
			}
		case 2:
			if len(f.content) > 0 {
				token.flag = f.content[0]
			}
		case 3: // fQOP -- encoded as a 4-byte int in the DER, unlike the
			// raw token's single qopIndex byte at offset 3.
			qopIndex = derInt(f.content)
		case 4:
			token.msgLength = uint32(derInt(f.content))
		case 5:
			token.seqNum = derUint64(f.content)
		}
	}
	token.qopIndex = byte(qopIndex)

	if qopIndex < 0 || qopIndex >= len(c.qopOptions) {
		return nil, fmt.Errorf("td2 unwrap: QOP index %d out of range (%d negotiated options)", qopIndex, len(c.qopOptions))
	}

	alg := c.qopOptions[qopIndex]
	if alg.confAlg != "AES" || alg.mode != "GCM96" {
		return nil, fmt.Errorf("td2 unwrap: %w, negotiated %q/%q", ErrTd2InvalidAlg, alg.confAlg, alg.mode)
	}

	key, err := c.qopKey(qopIndex)
	if err != nil {
		return nil, fmt.Errorf("td2 unwrap: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	tokenBytes := token.bytes()
	nonce := tokenBytes[4:16] // GCM96: token[4:16], same as wrap()

	sealed := make([]byte, 0, len(inputMsg.content)+len(authTag.content))
	sealed = append(sealed, inputMsg.content...)
	sealed = append(sealed, authTag.content...)

	padded, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("td2 unwrap: gcm open failed: %w", err)
	}

	const unwrapTrailerLen = 16
	if len(padded) < unwrapTrailerLen {
		return nil, fmt.Errorf("td2 unwrap: decrypted message too short")
	}
	return padded[:len(padded)-unwrapTrailerLen], nil
}

func (c *td2GssContext) establishSecureChannel(con *teradataConnection) error {
	ssoResp, err := c.handshake(con)
	if err != nil {
		return err
	}

	authDataReader := newBufferReader(ssoResp.authData, 0, len(ssoResp.authData))
	respTokenHdr, err := td2TokenHeaderFromBuffer(authDataReader)
	if err != nil {
		return err
	}
	if len(ssoResp.authData) < 36 {
		return ErrNoSecureChannel
	}
	verifyDhKey := authDataReader.u32At(32)
	capabilities := respTokenHdr.capabilities

	// TODO: Implement flip in wrap/unwrap if needed
	if respTokenHdr.flags&2 == 2 {
		c.targetEndien = 1
	} else {
		c.targetEndien = 0
	}

	var attmpt = 0
	if capabilities&1 == 1 {
		for {
			primeLength := authDataReader.u32At(20)
			genLength := authDataReader.u32At(24)
			pubKeyLength := authDataReader.u32At(28)
			//fmt.Printf("primeLength=%d genLength=%d pubKeyLength=%d\n", primeLength, genLength, pubKeyLength)

			serverPrimeBytes := authDataReader.seek(80).bytes(int(primeLength))
			serverGenBytes := authDataReader.bytes(int(genLength))
			serverPkBytes := authDataReader.bytes(int(pubKeyLength))

			if capabilities&4 == 4 {
				qopLen := authDataReader.u32At(36)
				qopData := authDataReader.bytes(int(qopLen))
				qop, err := decodeTd2QOPOptions(qopData)
				if err != nil {
					return err
				}
				c.qopOptions = qop
			}

			prime := new(big.Int).SetBytes(serverPrimeBytes)
			gen := new(big.Int).SetBytes(serverGenBytes)
			serverPk := new(big.Int).SetBytes(serverPkBytes)

			var x *big.Int
			for {
				x, _ = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 512))
				if x.Sign() > 0 && x.Cmp(new(big.Int).Sub(prime, big.NewInt(1))) < 0 {
					break
				}
			}
			//fmt.Printf("x=%x\n", x.Bytes())

			clientPkRaw := new(big.Int).Exp(gen, x, prime)
			clientPkNormal := normalizeToLen(clientPkRaw, int(primeLength))

			masterRaw := new(big.Int).Exp(serverPk, x, prime)
			//masterNormal := normalizeToLen(masterRaw, int(primeLength))

			c.master = masterRaw
			c.keyLen = int(primeLength)

			// TODO: if verifyDhKey != 0, the server requires the wrap/proof step

			ssoResp, err = c.sendClientKey(con, clientPkNormal, verifyDhKey)
			if err != nil {
				return err
			}
			if ssoResp.code == 1 {
				break
			}

			if attmpt > 5 {
				return ErrNoSecureChannel
			}
		}
		return nil
	}
	return ErrNoSecureChannel
}

func (c *td2GssContext) handshake(con *teradataConnection) (*ssoResponseParcel, error) {
	header := newLanHeader()
	header.kind = lanHeaderTypeAssign
	header.byteVar = 7
	header.hostCharSet = 0xFF
	header.requestNo = 0
	header.sessionNo = con.sessionNo
	binary.BigEndian.PutUint64(header.authNonce[:], uint64(con.nextAuthNonce()))

	// Init Msg with ciphersuite
	tokenHeader := &td2TokenHeader{
		version:        1,
		msgType:        1,
		byteVar:        1,
		clientOrServer: 0,
		capabilities:   0x15,
		flags:          0x02,
	}
	trailerLen := len(td2Trailer)
	cipherSuiteLen := len(td2CipherSuite)
	bufferLen := 80 + cipherSuiteLen + trailerLen
	messageLen := 64 + cipherSuiteLen //33 + cipherSuiteLen + trailerLen
	initSsoAuthData := make([]byte, bufferLen)
	w := newBufferWriter(initSsoAuthData)
	tokenHeader.encode(w, messageLen)
	w.setPosition(16).bytes(tdGssVersion)
	w.setPosition(36).u32(uint32(cipherSuiteLen))
	w.setPosition(80).bytes(td2CipherSuite).bytes(td2Trailer)
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

func (c *td2GssContext) sendClientKey(con *teradataConnection, clientPk []byte, verifyDhKey uint32) (*ssoResponseParcel, error) {
	header := newLanHeader()
	header.kind = lanHeaderTypeSSOReq
	header.byteVar = 7
	header.hostCharSet = 0xFF
	header.requestNo = 0
	header.sessionNo = con.sessionNo
	binary.BigEndian.PutUint64(header.authNonce[:], uint64(con.nextAuthNonce()))

	tokenHeader := &td2TokenHeader{
		version:        3,
		msgType:        1,
		byteVar:        2,
		clientOrServer: 0,
		capabilities:   0,
		flags:          0x02,
	}
	msgLen := len(clientPk)

	authData := make([]byte, msgLen+td2TokenHeaderLen)
	w := newBufferWriter(authData)
	tokenHeader.encode(w, msgLen)
	w.setPosition(16).bytes(clientPk)

	err := con.writeLanMessage(
		header,
		newSSORequestParcel(2, 0, authData),
	)
	if err != nil {
		return nil, err
	}

	// Read response
	parcels, _, err := con.readLanMessage()
	if err != nil {
		return nil, err
	}

	ssoResp, ok := findParcel[*ssoResponseParcel](parcels)
	if !ok {
		return nil, ErrInternal
	}
	return ssoResp, nil
}

func normalizeToLen(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) == size {
		return b
	}
	if len(b) > size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func normalizeDHSecretLen(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) > size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out, b)
	return out
}

func td2HmacLen(integAlg string) (int, error) {
	switch integAlg {
	case "SHA1":
		return 20, nil
	case "SHA-256":
		return 32, nil
	case "SHA-512":
		return 64, nil
	case "MD5":
		return 16, nil
	default:
		return 0, fmt.Errorf("td2 wrap: unsupported integrity algorithm %q", integAlg)
	}
}

func decodeTd2QOPOptions(data []byte) ([]td2AlgQop, error) {
	top, err := parseDerTLV(data, 0)
	if err != nil {
		return nil, fmt.Errorf("td2 qop: %w", err)
	}
	if !top.constructed {
		return nil, fmt.Errorf("td2 qop: top-level TLV is not constructed")
	}

	groups, err := parseDerChildren(top.content)
	if err != nil {
		return nil, fmt.Errorf("td2 qop: %w", err)
	}

	options := make([]td2AlgQop, 0)
	for _, group := range groups {
		if !group.constructed {
			return nil, fmt.Errorf("td2 qop: suite group TLV is not constructed")
		}
		fields, err := parseDerChildren(group.content)
		if err != nil {
			return nil, fmt.Errorf("td2 qop: %w", err)
		}

		var alg td2AlgQop
		for _, f := range fields {
			val := derInt(f.content)
			switch f.tag {
			case qopTagConfAlg:
				alg.confAlg = td2LookupName(td2AlgNames, val)
			case qopTagIntegAlg:
				alg.integAlg = td2LookupName(td2AlgNames, val)
			case qopTagKeyExchAlg:
				alg.keyExchAlg = td2LookupName(td2AlgNames, val)
			case qopTagMode:
				alg.mode = td2LookupName(td2Modes, val)
			case qopTagPadding:
				alg.padding = td2LookupName(td2Paddings, val)
			case qopTagKeyLength:
				alg.keyLength = val
			case qopTagKeyLengthP:
				alg.keyLengthP = val
			default:
				return nil, fmt.Errorf("td2 qop: invalid QOP tag %d", f.tag)
			}
		}
		options = append(options, alg)
	}

	return options, nil
}

func td2LookupName(table []string, idx int) string {
	if idx < 0 || idx >= len(table) {
		return fmt.Sprintf("UNKNOWN(%d)", idx)
	}
	return table[idx]
}
