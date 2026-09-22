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
	"database/sql/driver"
	"fmt"
)

const (
	lobRequestLengthSentinel = 2097088000
	lobSelectQuery           = "SELECT ?"
)

func (c *teradataConnection) isLobReceivable() bool {
	return c.capabilities.statementInfoSupport >= 1 && c.capabilities.slobClientToServerSupport >= 1
}

func (c *teradataConnection) getRespondParcel() parcel {
	useKeepResp := c.capabilities.lobSupport && c.config.LOBSupport
	aphSupport := c.capabilities.aphSupport
	if useKeepResp && aphSupport {
		// Big Keep Response
		return newBigKeepRespondParcel(c.capabilities, c.config)
	} else if aphSupport {
		// Big Response
		return newBigRespondParcel(c.capabilities, c.config)
	} else if useKeepResp {
		// Keep Response
		return newKeepRespondParcel(c.capabilities, c.config)
	}
	return newRespondParcel(c.capabilities, c.config)
}

func (c *teradataConnection) isKeepResponses() bool {
	return c.capabilities.lobSupport && c.config.LOBSupport
}

/*
LOB Readers
*/
type teradataLob interface {
	start() error
	complete() error
	append(data []byte) error
	setLength(len uint64)
}

type terataBaseLob struct {
	// Lob Data
	length    uint64
	data      []byte
	started   bool
	done      bool
	dataIndex int

	// Locator
	dataType    uint16
	locatorData []byte
	conn        *teradataConnection
	requestNo   uint32

	nullIndicatorRead bool
	lengthRead        bool
}

type TeradataClob struct {
	*terataBaseLob
}

type TeradataBlob struct {
	*terataBaseLob
}

func newTeradataClob(dataType uint16, len uint64, data []byte, conn *teradataConnection) *TeradataClob {
	return &TeradataClob{
		terataBaseLob: &terataBaseLob{
			dataType:    dataType,
			length:      len,
			locatorData: data,
			done:        false,
			conn:        conn,
		},
	}
}

func newTeradataBlob(dataType uint16, len uint64, data []byte, conn *teradataConnection) *TeradataBlob {
	return &TeradataBlob{
		terataBaseLob: &terataBaseLob{
			dataType:    dataType,
			length:      len,
			locatorData: data,
			done:        false,
			conn:        conn,
		},
	}
}

func (c *terataBaseLob) start() error {
	if c.length <= 0 {
		return ErrInvalidLobSize
	}
	c.data = make([]byte, c.length)
	c.started = true
	return nil
}

func (c *terataBaseLob) complete() error {
	c.done = true
	c.conn = nil
	// TODO: Check length vs Appended?
	return nil
}

func (c *terataBaseLob) append(data []byte) error {
	datalen := len(data)
	if c.dataIndex+datalen > len(c.data) {
		return ErrInvalidLobSize
	}
	copy(c.data[c.dataIndex:], data)
	c.dataIndex += datalen
	return nil
}

func (c *terataBaseLob) setLength(len uint64) {
	c.length = len
}

func (l *terataBaseLob) GetBytes() ([]byte, error) {
	return l.GetBytesContext(context.Background())
}

func (l *terataBaseLob) GetBytesContext(ctx context.Context) ([]byte, error) {
	if l.done && l.data != nil {
		return l.data, nil
	}

	// Fetch with locator
	// For GetString/GetBytes we loop and get all the bytes
	for {
		err := l.fetch(ctx)
		if err != nil {
			return nil, err
		}
		if l.done {
			break
		}
	}

	return l.data, nil
}

func (l *TeradataClob) GetString() (string, error) {
	return l.GetStringContext(context.Background())
}

func (l *TeradataClob) GetStringContext(ctx context.Context) (string, error) {
	data, err := l.GetBytesContext(ctx)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (l *TeradataClob) Scan(src any) error {
	switch v := src.(type) {
	case *TeradataClob:
		*l = *v
		return nil
	default:
		return fmt.Errorf("cannot scan %T into teradatasql.TeradataClob", src)
	}
}

func (l *TeradataBlob) Scan(src any) error {
	switch v := src.(type) {
	case *TeradataBlob:
		*l = *v
		return nil
	default:
		return fmt.Errorf("cannot scan %T into teradatasql.TeradataBlob", src)
	}
}

func (l *terataBaseLob) fetch(ctx context.Context) error {
	if l.conn == nil || l.conn.closed.Load() {
		return driver.ErrBadConn
	}
	var lastRead = false
	return l.conn.runCancelable(ctx, func() error {
		// Request LOB with locator
		var err error
		if !l.started {
			err := l.conn.writeLanMessage(
				l.conn.newLanHeaderStart(),
				newOptionsParcelLobSelect(l.conn),
				newIndicRequestParcel(lobSelectQuery),
				newLobRequestDataInfoParcel(l.dataType),
				newLobRequestIndicDataParcel(l.locatorData),
				newSlobRespondParcel(l.conn.capabilities, l.conn.config),
				l.conn.getRespondParcel(),
			)
			if err != nil {
				return err
			}
			l.requestNo = l.conn.sameRequestNumber()
		} else {
			err := l.conn.writeLanMessage(
				l.conn.newLanHeaderContinue(),
				l.conn.getRespondParcel(),
			)
			if err != nil {
				return err
			}
		}

		parcelData, parcelStart, parcelEnd, _, err := l.conn.readLanMessageRaw()
		if err != nil {
			return err
		}
		reader := newBufferReader(parcelData, parcelStart, parcelEnd)
		err = checkErrorParcel(reader)
		if err != nil {
			return err
		}

		//var dataType uint16
		for {
			parcelStart := reader.position()
			flavor, parcelLen, altHeader := readParcelHeader(reader)
			switch flavor {
			//TODO: Do we need StatementInfo?
			case uint16(flavorRecord), uint16(flavorMultiPartRecord):
				bodyLen := int(parcelLen) - parcelHeaderLen
				if altHeader {
					bodyLen -= 4
				}
				if !l.nullIndicatorRead && bodyLen > 0 {
					bodyLen -= 1
					reader.u8() //TODO: Null Ind
					l.nullIndicatorRead = true
				}
				if !l.lengthRead && bodyLen >= 8 {
					lobLen := reader.u64()
					l.lengthRead = true
					l.setLength(lobLen)
					err = l.start()
					if err != nil {
						return err
					}
				}
				err = l.append(reader.bytes(int(bodyLen - 8)))
				if err != nil {
					return err
				}

			case uint16(flavorEndRequest):
				lastRead = true
			}
			reader.seek(parcelStart + int(parcelLen))
			if reader.isDone() {
				break
			}
		}

		// Close / Release
		if lastRead {
			l.conn.sendCancelAndDrain(l.requestNo)
			err = l.complete()
			if err != nil {
				return err
			}
		}

		return nil
	})
}

/*
LOB Parcels
*/

// startSlobDataParcel - Starts a new stream of LOB data parcels
type startSlobDataParcel struct {
	metaItemNumber int
}

func (p *startSlobDataParcel) getFlavor() parcelFlavor {
	return flavorStartSlobData
}

func (p *startSlobDataParcel) String() string {
	return fmt.Sprintf("startSlobDataParcel{metaItemNumber=%d}", p.metaItemNumber)
}

func (p *startSlobDataParcel) fromBuffer(reader *bufferReader, length int) error {
	p.metaItemNumber = int(reader.u32())
	return nil
}

// slobDataParcel - Holds part of the LOB bytes
type slobDataParcel struct {
	data []byte
}

func (p *slobDataParcel) getFlavor() parcelFlavor {
	return flavorSlobData
}

func (p *slobDataParcel) String() string {
	return fmt.Sprintf("slobDataParcel{size=%d}", len(p.data))
}

func (p *slobDataParcel) fromBuffer(reader *bufferReader, length int) error {
	//p.data = reader.bytes(length - reader.position())
	return nil
}

// endSlobdataParcel - Signifies the end of the LOB parcels
type endSlobdataParcel struct {
}

func (p *endSlobdataParcel) getFlavor() parcelFlavor {
	return flavorEndSlobData
}

func (p *endSlobdataParcel) String() string {
	return "endSlobdataParcel{}"
}

func (p *endSlobdataParcel) fromBuffer(reader *bufferReader, length int) error {
	return nil
}

/*
Lob Request Parcels
*/
type lobRequestDataInfoParcel struct {
	dataType uint16
}

func newLobRequestDataInfoParcel(dataType uint16) *lobRequestDataInfoParcel {
	return &lobRequestDataInfoParcel{dataType: dataType}
}

func (p *lobRequestDataInfoParcel) getFlavor() parcelFlavor {
	return flavorDataInfo
}

func (p *lobRequestDataInfoParcel) getLength() int {
	return parcelHeaderLen + 2 + 4 // fieldCount(2) + one DataInfoField(4)
}

func (p *lobRequestDataInfoParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.u16(1) // fieldCount -- always one param for a locator fetch
	w.u16(p.dataType)
	// Go, unlike Java's (short) cast, refuses to truncate a too-large
	// constant straight to uint16 at compile time -- route it through a
	// runtime uint32 variable to get the same bit-truncating behavior as
	// DataInfoField.putBufferLength's (short) cast.
	sentinel := uint32(lobRequestLengthSentinel)
	w.u16(uint16(sentinel))
	return nil
}

type lobRequestIndicDataParcel struct {
	locator []byte
}

func newLobRequestIndicDataParcel(locator []byte) *lobRequestIndicDataParcel {
	return &lobRequestIndicDataParcel{locator: locator}
}

func (p *lobRequestIndicDataParcel) getFlavor() parcelFlavor {
	return flavorIndicData
}

func (p *lobRequestIndicDataParcel) getLength() int {
	return parcelHeaderLen + 1 + 2 + len(p.locator)
}

func (p *lobRequestIndicDataParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.u8(0) // null bitmap -- single param, one byte, never null here
	w.u16(uint16(len(p.locator)))
	w.bytes(p.locator)
	return nil
}
