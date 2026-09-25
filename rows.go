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
	"io"
	"math"
	"math/big"
	"reflect"
	"strings"
	"time"
)

type tdRowData struct {
	statement   *teradataStatement
	columnMeta  []*statementInfoMetaDataFull
	columns     []string
	columnCount int
	//stmtInfo    *statementInfoResponseParcel
	reader      *bufferReader
	data        []byte
	parcelStart int
	parcelEnd   int
	readDone    bool

	ctx         context.Context
	watcherStop chan struct{}
}

func (r *tdRowData) watcherCtx() context.Context {
	return r.ctx
}

func newTdRowData(statement *teradataStatement, stmtInfo *statementInfoResponseParcel, data []byte, start int, end int) (*tdRowData, error) {
	numCols := len(stmtInfo.resultSetColumnMetaItems())
	columnNames := make([]string, numCols)
	columnMetas := make([]*statementInfoMetaDataFull, numCols)
	for i, metaItem := range stmtInfo.resultSetColumnMetaItems() {
		m, isFull := metaItem.(*statementInfoMetaDataFull)
		if isFull {
			columnNames[i] = m.getColumnName()
			columnMetas[i] = m
		} else {
			return nil, ErrInternal
		}
	}
	reader := newBufferReader(data, start, end)
	err := checkErrorParcel(reader)
	if err != nil {
		return nil, err
	}

	return &tdRowData{
		statement: statement,
		//stmtInfo:    stmtInfo,
		columns:     columnNames,
		columnCount: numCols,
		reader:      reader,
		data:        data,
		parcelStart: start,
		parcelEnd:   end,
		columnMeta:  columnMetas,
		readDone:    false,
	}, nil
}

func (r *tdRowData) Columns() []string {
	return r.columns
}

func (r *tdRowData) ColumnTypeScanType(i int) reflect.Type {
	if i < 0 || i >= len(r.columnMeta) {
		return scanTypeUnknown
	}
	meta := r.columnMeta[i]
	return scanTypeForDataType(meta.getDataType(), meta.isNullable == 'Y')
}

func (r *tdRowData) ColumnTypeDatabaseTypeName(i int) string {
	if i < 0 || i >= len(r.columnMeta) {
		return ""
	}
	return dbNameForDataType(r.columnMeta[i].getDataType())
}

func (r *tdRowData) ColumnTypeNullable(i int) (nullable, ok bool) {
	// The nullable value should be true if it is known the column may be null, or false if the column is known to be not nullable. If the column nullability is unknown, ok should be false.
	if i < 0 || i >= len(r.columnMeta) {
		return false, false
	}
	return r.columnMeta[i].isNullable == 'Y', true
}

func (r *tdRowData) ColumnTypePrecisionScale(i int) (precision, scale int64, ok bool) {
	// It should return the precision and scale for decimal types. If not applicable, ok should be false.
	if i < 0 || i >= len(r.columnMeta) {
		return 0, 0, false
	}
	meta := r.columnMeta[i]
	switch getTdBasicType(meta.getDataType()) {
	case tdDecimal, tdNumber:
		precision := meta.getPercision()
		if precision == 0 {
			return math.MaxInt64, math.MaxInt64, true
		}
		return int64(precision), int64(meta.getScale()), true
	}
	return 0, 0, false
}

func (r *tdRowData) ColumnTypeLength(i int) (length int64, ok bool) {
	//  It should return the length of the column type if the column is a variable length type.
	//  If the column is not a variable length type ok should return false.
	//  If length is not limited other than system limits, it should return math.MaxInt64.
	if i < 0 || i >= len(r.columnMeta) {
		return 0, false
	}
	meta := r.columnMeta[i]
	switch getTdBasicType(meta.getDataType()) {
	case tdVarchar, tdLongVarchar, tdVarGraphic, tdLongVarGraphic,
		tdVarByte, tdLongVarByte,
		tdBlob, tdBlobDeferred, tdBlobLocator,
		tdClob, tdClobDeferred, tdClobLocator,
		tdXmlText, tdXmlTextDeferred, tdXmlTextLocator,
		tdXmlBinary, tdXmlBinaryDeferre, tdXmlBinaryLocator,
		tdJsonInline, tdJsonLocator, tdJsonDeferred:
		return int64(meta.getMaxLength()), true
	}
	return 0, false
}

func (r *tdRowData) startCtxWatcher(ctx context.Context) {
	if ctx.Done() == nil {
		return
	}
	r.ctx = ctx
	r.watcherStop = make(chan struct{})
	go func(stop chan struct{}) {
		select {
		case <-ctx.Done():
			r.statement.conn.netConn.SetReadDeadline(time.Now())
		case <-stop:
		}
	}(r.watcherStop)
}

func (r *tdRowData) stopCtxWatcher() {
	if r.watcherStop != nil {
		close(r.watcherStop)
		r.watcherStop = nil
	}
}

func (r *tdRowData) Close() error {
	r.stopCtxWatcher()
	if r.readDone {
		return nil
	}
	for !r.reader.isDone() {
		parcelStart := r.reader.position()
		flavor, parcelLen, _ := readParcelHeader(r.reader)
		r.reader.seek(parcelStart + int(parcelLen))
		if flavor == uint16(flavorEndRequest) {
			r.readDone = true
			break
		}
	}
	if r.readDone {
		return nil
	}
	r.readDone = true

	r.statement.conn.netConn.SetReadDeadline(time.Time{})

	// We never hit "EndRequest" parcel so cancel the query:
	return r.statement.sendCancelAndDrain()
}

func (r *tdRowData) Next(dest []driver.Value) error {
	if r.readDone {
		return io.EOF
	}

	var indx int = 0
	var err error
	var lobMetaItem = -1
	for {
		if r.reader.isDone() {
			// Buffer is out before hitting flavorEndRequest so we fetch more:
			err := r.fetchMore()
			if err != nil {
				return err
			}
		}
		parcelStart := r.reader.position()
		flavor, parcelLen, altHeader := readParcelHeader(r.reader)

		switch flavor {
		case uint16(flavorRecord), uint16(flavorMultiPartRecord):
			indx, err = r.processRow(dest, indx)
			if err != nil {
				r.log("processRow", "error", err)
				r.reader.seek(parcelStart + int(parcelLen))
				return err //TODO: Teardown
			}
			if flavor == uint16(flavorRecord) {
				// Non multi part record has entire row in one parcel so we can return now
				r.reader.seek(parcelStart + int(parcelLen))
				//return nil
				return r.finalizeRow(dest)
			}
		case uint16(flavorMultiPartEnd):
			r.reader.seek(parcelStart + int(parcelLen))
			//return nil //r.fetchLobData(dest)
			return r.finalizeRow(dest)
		case uint16(flavorEndRequest):
			r.readDone = true
			return io.EOF
		case uint16(flavorStartSlobData):
			parcel := &startSlobDataParcel{}
			parcel.fromBuffer(r.reader, int(parcelLen))
			lobMetaItem = parcel.metaItemNumber - 1
			if lobMetaItem != -1 && lobMetaItem < len(dest) {
				if lob, ok := dest[lobMetaItem].(teradataLob); ok {
					lob.start()
				}
			}
		case uint16(flavorSlobData):
			bodyLen := int(parcelLen) - parcelHeaderLen
			if altHeader {
				bodyLen -= 4
			}
			r.reader.skip(8)
			if lobMetaItem != -1 && lobMetaItem < len(dest) {
				if lob, ok := dest[lobMetaItem].(teradataLob); ok {
					lob.append(r.reader.bytes(int(bodyLen - 8)))
				}
			}
		case uint16(flavorEndSlobData):
			r.log("flavorEndSlobData", "lobMetaItem", lobMetaItem)
			if lobMetaItem != -1 && lobMetaItem < len(dest) {
				if lob, ok := dest[lobMetaItem].(teradataLob); ok {
					lob.complete()
				}
			}
			lobMetaItem = -1
		default:
			parcel, err := responseParcelFactory(flavor)
			if err == nil {
				parcel.fromBuffer(r.reader, int(parcelLen))
			} else {
				r.log("rowData,Next", "UnknownParcel,ParcelFlavor", flavor)
			}
		}
		r.reader.seek(parcelStart + int(parcelLen))
		if r.reader.isDone() {
			break
		}
	}
	// We should never get here if everything goes correctly
	return ErrInvalidRead
}

func (r *tdRowData) finalizeRow(dest []driver.Value) error {
	if !r.statement.conn.config.LOBPrefetch {
		return nil
	}
	// If prefetch lobs then replace lobs with their string/byte values:
	for i, d := range dest {
		if lob, ok := d.(*TeradataClob); ok {
			str, err := lob.GetString()
			if err != nil {
				return err
			}
			dest[i] = str
		} else if lob, ok := d.(*TeradataBlob); ok {
			data, err := lob.GetBytes()
			if err != nil {
				return err
			}
			dest[i] = data
		}
	}
	return nil
}

func (r *tdRowData) processRow(dest []driver.Value, indx int) (int, error) {
	nullIndicators := r.reader.bytes((r.columnCount + 7) / 8)
	for colIndex, meta := range r.columnMeta {
		isNull := r.isNull(nullIndicators, colIndex)
		v, err := produceColumnValue(r.reader, meta, isNull, r.statement.conn)
		if err != nil {
			return -1, err
		}
		dest[indx] = v
		indx++
	}
	return indx, nil
}

func (r *tdRowData) isNull(nullIndicators []byte, col int) bool {
	return nullIndicators[col/8]&(0x80>>uint(col%8)) != 0
}

func (r *tdRowData) fetchMore() error {
	// TODO: RowPositionParcel and FetchRowCountParcel
	err := r.statement.conn.writeLanMessage(
		r.statement.conn.newLanHeaderContinue(),
		r.statement.conn.getRespondParcel(),
	)
	if err != nil {
		return err
	}

	// We need our own slice here again incase of LOB fetch
	parcelData, parcelStart, parcelEnd, _, err := r.statement.conn.readLanMessageRawOwned()
	if err != nil {
		if watchCtx := r.watcherCtx(); watchCtx != nil && watchCtx.Err() != nil && isDeadlineErr(err) {
			return watchCtx.Err()
		}
		return err
	}
	r.reader = newBufferReader(parcelData, parcelStart, parcelEnd)
	r.parcelStart = parcelStart
	r.parcelEnd = parcelEnd
	return nil
}

func produceColumnValue(r *bufferReader, meta *statementInfoMetaDataFull, isNull bool, conn *teradataConnection) (driver.Value, error) {
	basicType := getTdBasicType(meta.getDataType())
	switch basicType {
	case tdInteger:
		v := r.u32()
		if isNull {
			return nil, nil
		}
		return int32(v), nil
	case tdBigInt:
		v := r.u64()
		if isNull {
			return nil, nil
		}
		return int64(v), nil
	case tdSmallInt:
		v := r.u16()
		if isNull {
			return nil, nil
		}
		return int16(v), nil
	case tdByteInt:
		v := r.u8()
		if isNull {
			return nil, nil
		}
		return int8(v), nil
	case tdVarchar, tdLongVarchar, tdVarGraphic, tdLongVarGraphic:
		n := int(r.u16())
		if isNull {
			r.skip(n)
			return nil, nil
		}
		if n == 0 {
			return "", nil
		}
		return r.asciiString(n), nil
	case tdChar, tdGraphic:
		n := int(meta.maxDataLengthInBytes)
		if isNull {
			r.skip(n)
			return nil, nil
		}
		if n == 0 {
			return "", nil
		}
		return r.asciiString(n), nil
	case tdFloat:
		v := r.f64()
		if isNull {
			return nil, nil
		}
		return v, nil
	case tdDecimal:
		precision := int(meta.totalNumberOfDigits)
		scale := int(meta.numberOfFractionalDigits)
		var raw *big.Int
		switch {
		case precision <= 2:
			raw = big.NewInt(int64(int8(r.u8())))
		case precision <= 4:
			raw = big.NewInt(int64(int16(r.u16())))
		case precision <= 9:
			raw = big.NewInt(int64(int32(r.u32())))
		case precision <= 18:
			raw = big.NewInt(int64(r.u64()))
		case precision <= 38:
			raw = r.bigInt16()
		default:
			return nil, fmt.Errorf("decimal precision %d unsupported", precision)
		}
		if isNull {
			return nil, nil
		}
		return decimalString(raw, scale), nil
	case tdNumber:
		n := int(int8(r.u8()))
		if n <= 0 {
			if isNull {
				return nil, nil
			}
			return "0", nil
		}
		scale := int(int16(r.u16()))
		raw := r.bigIntN(n - 2)
		if isNull {
			return nil, nil
		}
		return decimalString(raw, scale), nil
	case tdVarByte, tdLongVarByte:
		n := int(r.u16())
		if n == 0 {
			if isNull {
				return nil, nil
			}
			return []byte{}, nil
		}
		b := r.bytes(n)
		if isNull {
			return nil, nil
		}
		return b, nil
	case tdIntervalYear, tdIntervalYearToMo, tdIntervalMonth, tdIntervalDay,
		tdIntervalDayToHr, tdIntervalDayToMin, tdIntervalDayToSec, tdIntervalHour,
		tdIntervalHrToMin, tdIntervalHrToSec, tdIntervalMinute, tdIntervalSecond:
		n := int(meta.maxDataLengthInBytes)
		if isNull {
			r.skip(n)
			return nil, nil
		}
		if n == 0 {
			return "", nil
		}
		return r.asciiString(n), nil
	case tdByte:
		n := int(meta.maxDataLengthInBytes)
		if n == 0 {
			if isNull {
				return nil, nil
			}
			return []byte{}, nil
		}
		b := r.bytes(n)
		if isNull {
			return nil, nil
		}
		return b, nil
	case tdDateAnsi, tdDateInteger:
		// (year-1900)*10000 + month*100 + day
		v := r.u32()
		if isNull {
			return nil, nil
		}
		iv := int32(v) + 19000000
		return fmt.Sprintf("%04d-%02d-%02d", iv/10000, iv%10000/100, iv%100), nil
	case tdTime, tdTimeTZ, tdTimestamp, tdTimestampTZ:
		// ASCII-formatted ("23:59:59.999999-05:00")
		n := int(meta.maxDataLengthInBytes)
		if isNull {
			r.skip(n)
			return nil, nil
		}
		if n == 0 {
			return "", nil
		}
		return r.asciiString(n), nil
	case tdClobLocator, tdBlobLocator:
		locatorLen := r.u16()
		pos := r.position()
		if locatorLen >= 2 {
			lobLen := r.u64()
			r.seek(pos)
			locatorData := r.bytes(int(locatorLen))
			if isNull {
				return nil, nil
			}
			if basicType == tdClobLocator {
				return newTeradataClob(meta.getDataType(), lobLen, locatorData, conn), nil
			}
			return newTeradataBlob(meta.getDataType(), lobLen, locatorData, conn), nil
		}
		// TODO: If null still use clob locator?
		if isNull {
			return nil, nil
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported response data type %d", meta.getDataType())
	}
}

func decimalString(raw *big.Int, scale int) string {
	if scale == 0 {
		return raw.String()
	}
	if scale < 0 {
		if raw.Sign() == 0 {
			return "0"
		}
		return raw.String() + strings.Repeat("0", -scale)
	}

	neg := raw.Sign() < 0
	abs := new(big.Int).Abs(raw)
	digits := abs.String()

	if len(digits) <= scale {
		digits = strings.Repeat("0", scale-len(digits)+1) + digits
	}

	intPart := digits[:len(digits)-scale]
	fracPart := digits[len(digits)-scale:]

	var sb strings.Builder
	if neg {
		sb.WriteByte('-')
	}
	sb.WriteString(intPart)
	sb.WriteByte('.')
	sb.WriteString(fracPart)
	return sb.String()
}

func (r *tdRowData) log(msg string, args ...any) {
	r.statement.conn.config.Logger.Log(context.Background(), logLevelTrace, msg, args...)
}
