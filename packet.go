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
	"encoding/binary"
	"fmt"
	"io"
)

func (c *teradataConnection) writeLanMessage(header *lanHeader, bodyParts ...parcel) error {
	if header == nil {
		return ErrInternal
	}

	// Encyprtion check
	enc := false
	if c.gss != nil && !c.isTlsConn {
		switch {
		case header.kind == 3 || header.kind == 4:
			enc = true
		case header.kind == 1 || header.kind == 2 || header.kind == 10 || header.kind == 11 || header.kind == 12:
			enc = false
		default:
			enc = c.config.EncryptData || c.polSecurityRequired
		}
	}
	header.encrypted = enc

	// Calculate Length
	bodyLen := 0
	for _, p := range bodyParts {
		bodyLen += p.getLength()
	}

	// Create Buffer/Writer
	packetLen := lanHeaderLen + bodyLen
	buff := c.writeBuffer.take(packetLen + c.getWsFrameLength(packetLen))
	writer := newBufferWriter(buff)
	wsOffset, err := c.writeWsFrameHeader(writer, packetLen)
	if err != nil {
		return err
	}

	// Write Lan Header
	err = header.write(writer, wsOffset, 0) // Length set after encrupt
	if err != nil {
		return err
	}

	// Write Parcels
	for _, p := range bodyParts {
		//c.config.Logger.Log(context.Background(), logLevelTrace, "writingLanMessage", "parcelFlavor", p.getFlavor())
		pos := writer.position()
		// TODO: Move Parcel Flavor and Length write up here so we can implement alt headers and more easily allow parcel code embedding
		//writer.u16(uint16(p.getFlavor()))
		//writer.u16(uint16(p.getLength()))
		err = p.write(writer)
		if err != nil {
			return err
		}
		if writer.position() < pos+p.getLength() {
			c.config.Logger.Log(context.Background(), logLevelTrace, fmt.Sprintf("parcel flavor %d wrote fewer bytes than getLength() declared -- zero-padding the gap", p.getFlavor()))
			writer.skip(pos + p.getLength() - writer.position())
		} else if writer.position() > pos+p.getLength() {
			c.config.Logger.Log(context.Background(), logLevelTrace, fmt.Sprintf("parcel flavor %d wrote more bytes than getLength() declared -- stream is now corrupt", p.getFlavor()))
		}
	}

	// Encrypt and transmit
	if enc {
		wrapped, err := c.gss.wrap(buff[24:])
		if err != nil {
			return err
		}
		encLen := len(wrapped) - 28
		binary.BigEndian.PutUint16(buff[wsOffset+3:], uint16(encLen>>16))
		binary.BigEndian.PutUint16(buff[wsOffset+8:], uint16(encLen&0xFFFF))
		err = c.writeLanMessageRaw(append(buff[0:24], wrapped...))
	} else {
		binary.BigEndian.PutUint16(buff[wsOffset+3:], uint16(bodyLen>>16))
		binary.BigEndian.PutUint16(buff[wsOffset+8:], uint16(bodyLen&0xFFFF))
		err = c.writeLanMessageRaw(buff)
	}

	if err != nil {
		return err
	}

	return nil
}

func (c *teradataConnection) writeLanMessageRaw(data []byte) error {
	n, err := c.netConn.Write(data)
	if err != nil {
		// TODO: Cleanup
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func (c *teradataConnection) readLanMessage() ([]responseParcel, *lanHeader, error) {
	parcelData, parcelStart, parcelEnd, header, err := c.readLanMessageRaw()
	if err != nil {
		return nil, header, err
	}

	parcels := make([]responseParcel, 0)
	reader := newBufferReader(parcelData, parcelStart, parcelEnd)
	for {
		parcelStart := reader.position()
		flavor, parcelLen, _ := readParcelHeader(reader)
		parcel, err := responseParcelFactory(flavor)
		if err != nil {
			c.config.Logger.Log(context.Background(), logLevelTrace, "unknown parcel", "error", err.Error())
		} else {
			err = parcel.fromBuffer(reader, int(parcelLen))
			if err != nil {
				c.config.Logger.Log(context.Background(), logLevelTrace, "parcel read error", "err", err)
			}
			c.config.Logger.Log(context.Background(), logLevelTrace, "received parcel", "parcel", parcel)
			parcels = append(parcels, parcel)
		}
		reader.seek(parcelStart + int(parcelLen))
		if reader.isDone() {
			break
		}
	}

	errResp, ok := findParcel[*errorResponseParcel](parcels)
	if ok {
		return nil, nil, errResp.asTeradataError()
	}

	return parcels, header, nil
}

// readLanMessageRaw - return the next msg still in the connections read buffer
func (c *teradataConnection) readLanMessageRaw() ([]byte, int, int, *lanHeader, error) {
	return c.readLanMessageRawInto(false)
}

// readLanMessageRawOwned - return the next message in its own shared buffer (needed for LOB fetching while mid-row read)
func (c *teradataConnection) readLanMessageRawOwned() ([]byte, int, int, *lanHeader, error) {
	return c.readLanMessageRawInto(true)
}

func (c *teradataConnection) readLanMessageRawInto(own bool) ([]byte, int, int, *lanHeader, error) {
	// If TLS Connection we have to unwrap the WebSocket frame
	if c.isTlsConn {
		_, err := c.readWsFrameHeader()
		if err != nil {
			return nil, 0, 0, nil, err
		}
	}

	// Peek the header so we can get the the length
	headerBuff, err := c.buffer.peek(lanHeaderLen, c.netConn.Read)
	if err != nil {
		return nil, 0, 0, nil, err
	}
	header, err := lanHeaderFromBuffer(headerBuff)
	if err != nil {
		return nil, 0, 0, nil, err
	}

	// Read the header and body together now:
	data, err := c.readNext(header.msgLen)
	if err != nil {
		return nil, 0, 0, header, err
	}

	parcelData := data
	parcelStart := lanHeaderLen
	parcelEnd := header.msgLen - int(header.controlDataLength)
	decrypted := false

	c.transactionInProgress = header.byteVar&1 == 1

	// Handle encrypted response:
	if header.msgType&0x80 != 0 {
		if c.gss == nil {
			return nil, 0, 0, header, ErrNoSecureChannel
		}

		// First 24 bytes are clear, unwrap the rest
		plaintext, err := c.gss.unwrap(data[24:])
		if err != nil {
			return nil, 0, 0, header, err
		}
		if len(plaintext) < lanHeaderLen-24 {
			return nil, 0, 0, header, ErrInternal
		}
		controlDataLength := binary.BigEndian.Uint32(plaintext[16:20]) // offset 40 - 24
		parcelData = plaintext
		parcelStart = lanHeaderLen - 24
		parcelEnd = len(plaintext) - int(controlDataLength)
		header.controlDataLength = controlDataLength
		decrypted = true
	}

	// Read Control Data
	if header.controlDataLength > 0 {
		reader := newBufferReader(parcelData, parcelEnd, parcelEnd+int(header.controlDataLength))
		for {
			parcelStart := reader.position()
			flavor, parcelLen, _ := readParcelHeader(reader)
			parcel, err := responseParcelFactory(flavor)
			if err == nil {
				err = parcel.fromBuffer(reader, int(parcelLen))
				if err == nil {
					if secParcel, ok := parcel.(*securityPolicyParcel); ok {
						c.config.Logger.Log(context.Background(), logLevelTrace, "Recevied Security Policy", "Parcel", secParcel)
						c.polSecurityRequired = secParcel.securityRequired
						c.polConfidentialityRequired = secParcel.confidentialityRequired
						c.polSecurityLevel = secParcel.securityLevel
					}
				}
			}
			reader.seek(parcelStart + int(parcelLen))
			if reader.isDone() {
				break
			}
		}

	}
	//printDebug("Receiving Payload: %s", hex.EncodeToString(parcelData[parcelStart:parcelEnd]))

	// If message was decrypted then we already have the decrypted bytes in a fresh slice,
	// otherwise we need to copy to a new slice if called wants to own it
	if own && !decrypted {
		owned := make([]byte, parcelEnd)
		copy(owned, parcelData[:parcelEnd])
		parcelData = owned
	}

	return parcelData, parcelStart, parcelEnd, header, nil
}
