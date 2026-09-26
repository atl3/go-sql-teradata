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
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"
)

var (
	bigInt128    = new(big.Int).Lsh(big.NewInt(1), 128)
	bigIntMax128 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1))
	bigIntMin128 = new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 127))
)

type paramDescriptor struct {
	dataType       uint16
	length         uint64
	precision      int16
	intervalDigits int16
	scale          int16
	isNull         bool
	encoded        []byte
}

func createParamParcels(capabilities *connectionCapabilities, dataTypes []uint16, dataValues []driver.Value, paramMetas []statementInfoMetaItem) ([]parcel, error) {
	// Create Descriptors
	descs := make([]*paramDescriptor, len(paramMetas))
	for i, m := range paramMetas {
		d, err := describeParam(dataValues[i], m)
		if err != nil {
			return nil, err
		}
		descs[i] = d
	}

	parcelLen := 2
	if capabilities.statementInfoRequestSupport {
		parcelLen = 3
	}
	parcels := make([]parcel, parcelLen)

	if capabilities.statementInfoRequestSupport {
		parcels[0] = &statementInfoRequestParcel{params: descs}
		parcels[1] = &statementInfoEndRequestParcel{}
		parcels[2] = &indicDataParcel{params: descs}
	} else {
		parcels[0] = &dataInfoParcel{params: descs}
		parcels[1] = &indicDataParcel{params: descs}
	}
	return parcels, nil
}

func describeParam(val driver.Value, meta statementInfoMetaItem) (*paramDescriptor, error) {
	d := &paramDescriptor{dataType: meta.getDataType() | 1, isNull: val == nil}
	switch getTdBasicType(meta.getDataType()) {
	case tdInteger:
		d.length = 4
	case tdSmallInt:
		d.length = 2
	case tdByteInt:
		d.length = 1
	case tdBigInt, tdFloat:
		d.length = 8
	case tdVarchar, tdLongVarchar, tdVarGraphic, tdLongVarGraphic, tdVarByte, tdLongVarByte:
		// TODO: 32000 bump to length?
	case tdDateAnsi, tdDateInteger:
		d.length = 4
	case tdTime, tdTimeTZ, tdTimestamp, tdTimestampTZ:
		// Scale is the fractional-seconds digits (TDPreparedStatement.setTimestamp/internalSetTime);
		// with scale 0 the server expects no ".ffffff" and rejects the value (6760)
		d.length = meta.getMaxLength()
		d.scale = int16(meta.getScale())
	case tdIntervalYear, tdIntervalYearToMo, tdIntervalMonth, tdIntervalDay,
		tdIntervalDayToHr, tdIntervalDayToMin, tdIntervalDayToSec, tdIntervalHour,
		tdIntervalHrToMin, tdIntervalHrToSec, tdIntervalMinute, tdIntervalMinToSec,
		tdIntervalSecond:
		// TODO: Java's setIntervalParameter also sends intervalDigits and a fractional-seconds scale
		d.length = meta.getMaxLength()
	case tdDecimal:
		switch precision := meta.getPercision(); {
		case precision <= 2:
			d.length = 1
		case precision <= 4:
			d.length = 2
		case precision <= 9:
			d.length = 4
		case precision <= 18:
			d.length = 8
		case precision <= 38:
			d.length = 16
		}
		d.precision = int16(meta.getPercision())
		d.scale = int16(meta.getScale())
	case tdNumber:
		d.length = numberMaxByteLength
		d.precision = numberSipScaleAndPrec
		d.scale = numberSipScaleAndPrec
	}

	// Encode and set Length for dynamic length
	encd, err := encodeParamValue(val, meta)
	if err != nil {
		return nil, err
	}
	d.encoded = encd
	if d.length == 0 {
		d.length = uint64(len(encd))
		switch getTdBasicType(meta.getDataType()) {
		case tdVarByte, tdVarchar, tdVarGraphic, tdLongVarchar, tdLongVarGraphic, tdLongVarByte:
			d.length -= 2
		}
	}
	return d, nil

}

func encodeParamValue(val driver.Value, meta statementInfoMetaItem) ([]byte, error) {
	if val == nil {
		return encodeNullParamValue(meta)
	}
	switch getTdBasicType(meta.getDataType()) {
	case tdInteger:
		v, ok := toInt64(val)
		if !ok {
			return nil, errors.New("param expecting integer data type but provided value is not a integer")
		}
		return uint32Bytes(uint32(v)), nil
	case tdBigInt:
		v, ok := toInt64(val)
		if !ok {
			return nil, errors.New("param expecting bigint data type but provided value is not a integer")
		}
		return uint64Bytes(uint64(v)), nil
	case tdSmallInt:
		v, ok := toInt64(val)
		if !ok {
			return nil, errors.New("param expecting smallint data type but provided value is not a integer")
		}
		return uint16Bytes(uint16(v)), nil
	case tdByteInt:
		v, ok := toInt64(val)
		if !ok {
			return nil, errors.New("param expecting byteint data type but provided value is not a integer")
		}
		return uint8Bytes(uint8(v)), nil
	case tdFloat:
		v, ok := val.(float64)
		if !ok {
			return nil, errors.New("param expecting float data type but provided value is not a float64")
		}
		return uint64Bytes(math.Float64bits(v)), nil
	case tdVarchar, tdLongVarchar, tdVarGraphic, tdLongVarGraphic:
		// Variable-length character types are self-length-prefixed within
		// the IndicData stream, mirroring the read-side format in
		// produceColumnValue (u16 length + bytes).
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("param expecting character data type but provided value is not a string")
		}
		d := []byte(s)
		if len(d) > math.MaxUint16 {
			return nil, fmt.Errorf("character param too long: %d bytes", len(d))
		}
		res := make([]byte, 2+len(d))
		binary.BigEndian.PutUint16(res, uint16(len(d)))
		copy(res[2:], d)
		return res, nil
	case tdChar, tdGraphic:
		// Fixed-width character types: no length prefix, padded/truncated to the field's declared width.
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("param expecting character data type but provided value is not a string")
		}
		return fixedWidthBytes([]byte(s), int(meta.getMaxLength()), ' '), nil
	case tdVarByte, tdLongVarByte:
		b, ok := val.([]byte)
		if !ok {
			return nil, fmt.Errorf("param expecting byte data type but provided value is not a []byte")
		}
		if len(b) > math.MaxUint16 {
			return nil, fmt.Errorf("varbyte param too long: %d bytes", len(b))
		}
		res := make([]byte, 2+len(b))
		binary.BigEndian.PutUint16(res, uint16(len(b)))
		copy(res[2:], b)
		return res, nil
	case tdByte:
		b, ok := val.([]byte)
		if !ok {
			return nil, fmt.Errorf("param expecting byte data type but provided value is not a []byte")
		}
		return fixedWidthBytes(b, int(meta.getMaxLength()), 0), nil
	case tdDateAnsi, tdDateInteger:
		// DATE integer format: (year-1900)*10000 + month*100 + day.
		switch v := val.(type) {
		case time.Time:
			y, m, d := v.Date()
			return uint32Bytes(uint32((y-1900)*10000 + int(m)*100 + d)), nil
		case int64:
			return uint32Bytes(uint32(v)), nil
		default:
			return nil, fmt.Errorf("param expecting date data type but provided value is not a time.Time")
		}
	case tdTime, tdTimeTZ, tdTimestamp, tdTimestampTZ,
		tdIntervalYear, tdIntervalYearToMo, tdIntervalMonth, tdIntervalDay,
		tdIntervalDayToHr, tdIntervalDayToMin, tdIntervalDayToSec, tdIntervalHour,
		tdIntervalHrToMin, tdIntervalHrToSec, tdIntervalMinute, tdIntervalMinToSec,
		tdIntervalSecond:
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("param expecting a formatted string for data type %d", meta.getDataType())
		}
		return fixedWidthBytes([]byte(s), int(meta.getMaxLength()), ' '), nil
	case tdDecimal:
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("param expecting decimal data type but provided value is not a string")
		}
		raw, err := decimalToScaledInt(s, int(meta.getScale()))
		if err != nil {
			return nil, err
		}
		switch {
		case meta.getPercision() <= 2:
			return []byte{uint8(int8(raw.Int64()))}, nil
		case meta.getPercision() <= 4:
			return uint16Bytes(uint16(int16(raw.Int64()))), nil
		case meta.getPercision() <= 9:
			return uint32Bytes(uint32(int32(raw.Int64()))), nil
		case meta.getPercision() <= 18:
			return uint64Bytes(uint64(raw.Int64())), nil
		case meta.getPercision() <= 38:
			return bigIntToBE16(raw)
		}
		return nil, fmt.Errorf("decimal precision %d unsupported", meta.getPercision())
	case tdNumber:
		unscaled, scale, err := numberFromValue(val)
		if err != nil {
			return nil, err
		}
		return encodeNumber(unscaled, scale)
	default:
		return nil, fmt.Errorf("unsupported data type: %d", meta.getDataType())
	}
}

func encodeNullParamValue(meta statementInfoMetaItem) ([]byte, error) {
	switch getTdBasicType(meta.getDataType()) {
	case tdInteger:
		return make([]byte, 4), nil
	case tdBigInt:
		return make([]byte, 8), nil
	case tdSmallInt:
		return make([]byte, 2), nil
	case tdByteInt:
		return make([]byte, 1), nil
	case tdFloat:
		return make([]byte, 8), nil
	case tdVarchar, tdLongVarchar, tdVarGraphic, tdLongVarGraphic, tdVarByte, tdLongVarByte:
		return make([]byte, 2), nil
	case tdChar, tdGraphic:
		return make([]byte, meta.getMaxLength()), nil
	case tdByte:
		return make([]byte, meta.getMaxLength()), nil
	case tdDateAnsi, tdDateInteger:
		return make([]byte, 4), nil
	case tdTime, tdTimeTZ, tdTimestamp, tdTimestampTZ,
		tdIntervalYear, tdIntervalYearToMo, tdIntervalMonth, tdIntervalDay,
		tdIntervalDayToHr, tdIntervalDayToMin, tdIntervalDayToSec, tdIntervalHour,
		tdIntervalHrToMin, tdIntervalHrToSec, tdIntervalMinute, tdIntervalMinToSec,
		tdIntervalSecond:
		return make([]byte, meta.getMaxLength()), nil
	case tdDecimal:
		switch {
		case meta.getPercision() <= 2:
			return make([]byte, 1), nil
		case meta.getPercision() <= 4:
			return make([]byte, 2), nil
		case meta.getPercision() <= 9:
			return make([]byte, 4), nil
		case meta.getPercision() <= 18:
			return make([]byte, 8), nil
		case meta.getPercision() <= 38:
			return make([]byte, 16), nil
		default:
			return nil, fmt.Errorf("decimal precision %d unsupported", meta.getPercision())
		}
	case tdNumber:
		return make([]byte, 1), nil
	default:
		return nil, fmt.Errorf("unsupported data type: %d", meta.getDataType())
	}
}

func uint8Bytes(val uint8) []byte {
	return []byte{byte(val)}
}

func uint16Bytes(val uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, val)
	return buf
}

func uint32Bytes(val uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, val)
	return buf
}

func uint64Bytes(val uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, val)
	return buf
}

// bigIntToBE16 encodes v as a 16-byte big endian twos complement value
func bigIntToBE16(v *big.Int) ([]byte, error) {
	if v.Cmp(bigIntMin128) < 0 || v.Cmp(bigIntMax128) > 0 {
		return nil, fmt.Errorf("decimal value %s does not fit in 16 bytes", v)
	}
	out := make([]byte, 16)
	if v.Sign() >= 0 {
		return v.FillBytes(out), nil
	}
	return new(big.Int).Add(v, bigInt128).FillBytes(out), nil
}

/*
Param Parcels
*/
type dataInfoParcel struct {
	params []*paramDescriptor
}

func (p *dataInfoParcel) getFlavor() parcelFlavor {
	return flavorDataInfo
}

func (p *dataInfoParcel) getLength() int {
	return parcelHeaderLen + 2 + len(p.params)*4
}

func (p *dataInfoParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.u16(uint16(len(p.params)))
	for _, p := range p.params {
		w.u16(p.dataType)
		w.u16(uint16(p.length))
	}
	return nil
}

type indicDataParcel struct {
	params []*paramDescriptor
}

func (p *indicDataParcel) getFlavor() parcelFlavor {
	return flavorIndicData
}

func (p *indicDataParcel) getLength() int {
	nullmapLen := (len(p.params) + 7) / 8 // NullMap MSB First bitmap
	parcelLen := parcelHeaderLen + nullmapLen
	for _, p := range p.params {
		parcelLen += len(p.encoded)
	}
	return parcelLen
}

func (p *indicDataParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	// Null Bitmap - param 1 = bit 7, param 2 = bit 6
	nullmap := make([]byte, (len(p.params)+7)/8)
	for i, v := range p.params {
		if v.isNull {
			nullmap[i/8] |= 1 << (7 - uint(i%8))
		}
	}
	w.bytes(nullmap)
	for _, p := range p.params {
		w.bytes(p.encoded)
	}
	return nil
}

type statementInfoRequestParcel struct {
	params []*paramDescriptor
}

func (p *statementInfoRequestParcel) getFlavor() parcelFlavor {
	return flavorStatementInfo
}

func (p *statementInfoRequestParcel) getLength() int {
	// TODO: *16 will need to change when Array/UDT support is added
	return parcelHeaderLen + len(p.params)*6 + len(p.params)*16 + 6
}

func (p *statementInfoRequestParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	for _, p := range p.params {
		//TODO: if getTdParameterMode(m.getDataType()) == paramModeIn ?
		w.u16(2) //TODO: Needs to be 5 for UDT
		w.u16(8)
		w.u16(16) //TODO: Needs to change for UDT
		w.u16(p.dataType)
		w.u64(p.length)
		w.u16(uint16(p.precision))
		w.u16(uint16(p.intervalDigits))
		w.u16(uint16(p.scale))
		// TODO: Struct/Array
	}
	w.u16(4)
	w.u16(8)
	w.u16(0)
	return nil
}

type statementInfoEndRequestParcel struct{}

func newStatementInfoEndRequestParcel() *statementInfoEndRequestParcel {
	return &statementInfoEndRequestParcel{}
}

func (p *statementInfoEndRequestParcel) getFlavor() parcelFlavor {
	return flavorStementInfoEnd
}

func (p *statementInfoEndRequestParcel) getLength() int {
	return parcelHeaderLen
}

func (p *statementInfoEndRequestParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	return nil
}
