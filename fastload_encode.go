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
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
)

type fastLoadEncodeKind int

const (
	fastLoadEncByteInt fastLoadEncodeKind = iota
	fastLoadEncSmallInt
	fastLoadEncInteger
	fastLoadEncBigInt
	fastLoadEncFloat
	fastLoadEncDate
	fastLoadEncDecimal
	fastLoadEncNumber
	fastLoadEncVarchar
	fastLoadEncVarbyte
	fastLoadEncTime
	fastLoadEncTimeTZ
	fastLoadEncTimestamp
	fastLoadEncTimestampTZ
)

type fastLoadColumnEncoder struct {
	kind     fastLoadEncodeKind
	cast     string // column type
	rowBytes uint64 // max bytes
	maxLen   int
	width    int
	scale    int
	wide     bool
	nullText []byte
}

func fastLoadMaxRowBytes(encoders []*fastLoadColumnEncoder) int {
	n := (len(encoders)+1+7)/8 + 4
	for _, e := range encoders {
		n += e.maxWireBytes()
	}
	return n
}

func (e *fastLoadColumnEncoder) maxWireBytes() int {
	switch e.kind {
	case fastLoadEncByteInt:
		return 1
	case fastLoadEncSmallInt:
		return 2
	case fastLoadEncInteger, fastLoadEncDate:
		return 4
	case fastLoadEncBigInt, fastLoadEncFloat:
		return 8
	case fastLoadEncDecimal:
		if e.wide {
			return 16
		}
		return 8
	case fastLoadEncNumber:
		return 20 // u8 len + i16 scale + up to 17 bytes for 40 digits
	case fastLoadEncVarchar, fastLoadEncVarbyte:
		return 2 + e.maxLen
	default:
		return e.width
	}
}

func newFastLoadColumnEncoders(info *statementInfoResponseParcel, capabilities *connectionCapabilities) ([]*fastLoadColumnEncoder, error) {
	items := info.paramMarkerMetaItems()
	encoders := make([]*fastLoadColumnEncoder, len(items))
	for i, item := range items {
		e, err := newFastLoadColumnEncoder(item, capabilities)
		if err != nil {
			return nil, fmt.Errorf("%w: column %d: %w", ErrFastLoadUnsupported, i+1, err)
		}
		encoders[i] = e
	}
	return encoders, nil
}

func newFastLoadColumnEncoder(item statementInfoMetaItem, capabilities *connectionCapabilities) (*fastLoadColumnEncoder, error) {
	dataType := getTdBasicType(item.getDataType())
	maxLen := item.getMaxLength()
	scale := int(item.getScale())
	fracWidth := 0
	if scale > 0 {
		fracWidth = scale + 1
	}

	e := &fastLoadColumnEncoder{scale: scale}
	switch dataType {
	case tdByteInt, tdSmallInt, tdInteger, tdBigInt, tdFloat, tdDateAnsi, tdDateInteger:
		e.kind = map[uint16]fastLoadEncodeKind{
			tdByteInt:     fastLoadEncByteInt,
			tdSmallInt:    fastLoadEncSmallInt,
			tdInteger:     fastLoadEncInteger,
			tdBigInt:      fastLoadEncBigInt,
			tdFloat:       fastLoadEncFloat,
			tdDateAnsi:    fastLoadEncDate,
			tdDateInteger: fastLoadEncDate,
		}[dataType]
		e.cast = fastLoadTypeName(dataType)
		e.rowBytes = maxLen
	case tdByte, tdVarByte, tdLongVarByte:
		e.kind = fastLoadEncVarbyte
		e.cast = fmt.Sprintf("VARBYTE(%d)", maxLen)
		e.maxLen = int(maxLen)
		e.rowBytes = maxLen + 2
	case tdChar, tdVarchar, tdLongVarchar,
		tdIntervalYear, tdIntervalYearToMo, tdIntervalMonth, tdIntervalDay, tdIntervalDayToHr,
		tdIntervalDayToMin, tdIntervalDayToSec, tdIntervalHour, tdIntervalHrToMin,
		tdIntervalHrToSec, tdIntervalMinute, tdIntervalMinToSec, tdIntervalSecond:
		e.kind = fastLoadEncVarchar
		e.cast = fmt.Sprintf("VARCHAR(%d)", maxLen)
		e.maxLen = int(maxLen)
		e.rowBytes = maxLen + 2
	case tdNumber:
		e.kind = fastLoadEncNumber
		e.cast = "NUMBER"
		e.rowBytes = 20
	case tdDecimal:
		e.kind = fastLoadEncDecimal
		e.wide = capabilities.largeDecimalSupport
		if e.wide {
			e.cast = fmt.Sprintf("DECIMAL(38,%d)", scale)
			e.rowBytes = 16
		} else {
			e.cast = fmt.Sprintf("DECIMAL(18,%d)", scale)
			e.rowBytes = 8
		}
	case tdTime, tdTimeTZ:
		e.kind = fastLoadEncTime
		e.width = 8 + fracWidth
		if dataType == tdTimeTZ {
			e.kind = fastLoadEncTimeTZ
			e.width += 6
		}
		e.cast = fmt.Sprintf("CHAR(%d)", e.width)
		e.rowBytes = uint64(e.width)
	case tdTimestamp, tdTimestampTZ:
		e.kind = fastLoadEncTimestamp
		e.width = 19 + fracWidth
		if dataType == tdTimestampTZ {
			e.kind = fastLoadEncTimestampTZ
			e.width += 6
		}
		e.cast = fmt.Sprintf("CHAR(%d)", e.width)
		e.rowBytes = uint64(e.width)
	default:
		name := dbNameForDataType(item.getDataType())
		if name == "" {
			name = fmt.Sprintf("type %d", item.getDataType())
		}
		return nil, fmt.Errorf("data type %s is not supported", name)
	}
	if e.width > 0 {
		e.nullText = []byte(strings.Repeat(" ", e.width))
	}
	return e, nil
}

func fastLoadUsingType(item statementInfoMetaItem, capabilities *connectionCapabilities) (string, uint64, error) {
	e, err := newFastLoadColumnEncoder(item, capabilities)
	if err != nil {
		return "", 0, err
	}
	return e.cast, e.rowBytes, nil
}

func fastLoadTypeName(dataType uint16) string {
	if dataType == tdDateAnsi || dataType == tdDateInteger {
		return "DATE"
	}
	return dbNameForDataType(dataType)
}

func writeFastLoadRow(w *bufferWriter, encoders []*fastLoadColumnEncoder, values []driver.Value, rowNumber int32) error {
	if len(values) != len(encoders) {
		return fmt.Errorf("fastload row has %d values, expected %d", len(values), len(encoders))
	}
	bitmapStart := w.position()
	w.skip((len(encoders) + 1 + 7) / 8)
	for i, e := range encoders {
		if values[i] == nil {
			w.buff[bitmapStart+i/8] |= 1 << (7 - i%8)
			e.writeNull(w)
		} else if err := e.writeValue(w, values[i]); err != nil {
			return fmt.Errorf("fastload column %d: %w", i+1, err)
		}
	}
	w.u32(uint32(rowNumber))
	return nil
}

func (e *fastLoadColumnEncoder) writeNull(w *bufferWriter) {
	switch e.kind {
	case fastLoadEncNumber:
		w.byte(0)
	case fastLoadEncVarchar, fastLoadEncVarbyte:
		w.skip(2)
	case fastLoadEncTime, fastLoadEncTimeTZ, fastLoadEncTimestamp, fastLoadEncTimestampTZ:
		w.bytes(e.nullText)
	default:
		w.skip(e.maxWireBytes())
	}
}

func (e *fastLoadColumnEncoder) writeValue(w *bufferWriter, val driver.Value) error {
	switch e.kind {
	case fastLoadEncByteInt:
		v, err := fastLoadIntegral(val, math.MinInt8, math.MaxInt8)
		if err != nil {
			return err
		}
		w.byte(byte(v))
		return nil
	case fastLoadEncSmallInt:
		v, err := fastLoadIntegral(val, math.MinInt16, math.MaxInt16)
		if err != nil {
			return err
		}
		w.u16(uint16(v))
		return nil
	case fastLoadEncInteger:
		v, err := fastLoadIntegral(val, math.MinInt32, math.MaxInt32)
		if err != nil {
			return err
		}
		w.u32(uint32(v))
		return nil
	case fastLoadEncBigInt:
		v, err := fastLoadIntegral(val, math.MinInt64, math.MaxInt64)
		if err != nil {
			return err
		}
		w.u64(uint64(v))
		return nil
	case fastLoadEncFloat:
		v, err := fastLoadFloat(val)
		if err != nil {
			return err
		}
		w.u64(math.Float64bits(v))
		return nil
	case fastLoadEncDate:
		v, err := fastLoadDate(val)
		if err != nil {
			return err
		}
		w.u32(uint32(v))
		return nil
	case fastLoadEncDecimal:
		return e.writeDecimal(w, val)
	case fastLoadEncNumber:
		unscaled, scale, err := numberFromValue(fastLoadNumericValue(val))
		if err != nil {
			return err
		}
		b, err := encodeNumber(unscaled, scale)
		if err != nil {
			return err
		}
		w.bytes(b)
		return nil
	case fastLoadEncVarchar:
		if b, ok := val.([]byte); ok {
			return e.writeVar(w, b)
		}
		s, err := fastLoadString(val)
		if err != nil {
			return err
		}
		return e.writeVarString(w, s)
	case fastLoadEncVarbyte:
		b, ok := val.([]byte)
		if !ok {
			return fmt.Errorf("expecting []byte, got %T", val)
		}
		return e.writeVar(w, b)
	default:
		s, err := e.temporalText(val)
		if err != nil {
			return err
		}
		if len(s) != e.width {
			return fmt.Errorf("time value %q must be %d characters", s, e.width)
		}
		w.str(s)
		return nil
	}
}

func (e *fastLoadColumnEncoder) writeVar(w *bufferWriter, b []byte) error {
	if len(b) > e.maxLen {
		return fmt.Errorf("value is %d bytes, column allows %d", len(b), e.maxLen)
	}
	w.u16(uint16(len(b)))
	w.bytes(b)
	return nil
}

func (e *fastLoadColumnEncoder) writeVarString(w *bufferWriter, s string) error {
	if len(s) > e.maxLen {
		return fmt.Errorf("value is %d bytes, column allows %d", len(s), e.maxLen)
	}
	w.u16(uint16(len(s)))
	w.str(s)
	return nil
}

func (e *fastLoadColumnEncoder) writeDecimal(w *bufferWriter, val driver.Value) error {
	unscaled, scale, err := numberFromValue(fastLoadNumericValue(val))
	if err != nil {
		return err
	}
	unscaled = rescaleHalfUp(unscaled, scale, e.scale)
	if e.wide {
		b, err := bigIntToBE16(unscaled)
		if err != nil {
			return err
		}
		w.bytes(b)
		return nil
	}
	if !unscaled.IsInt64() {
		return fmt.Errorf("decimal value %s does not fit in 8 bytes", unscaled)
	}
	w.u64(uint64(unscaled.Int64()))
	return nil
}

func (e *fastLoadColumnEncoder) temporalText(val driver.Value) (string, error) {
	tz := e.kind == fastLoadEncTimeTZ || e.kind == fastLoadEncTimestampTZ
	switch v := val.(type) {
	case time.Time:
		layout := "15:04:05"
		if e.kind == fastLoadEncTimestamp || e.kind == fastLoadEncTimestampTZ {
			layout = "2006-01-02 15:04:05"
		}
		if e.scale > 0 {
			layout += "." + strings.Repeat("0", e.scale)
		}
		s := v.Format(layout)
		if tz {
			s += v.Format("-07:00")
		}
		return s, nil
	case string:
		s := strings.TrimSpace(v)
		offset := ""
		if tz {
			if len(s) < 6 || (s[len(s)-6] != '+' && s[len(s)-6] != '-') {
				return "", fmt.Errorf("time value %q is missing a +hh:mm offset", v)
			}
			s, offset = s[:len(s)-6], s[len(s)-6:]
		}
		base := 8
		if e.kind == fastLoadEncTimestamp || e.kind == fastLoadEncTimestampTZ {
			base = 19
		}
		if len(s) < base {
			return "", fmt.Errorf("time value %q is too short", v)
		}
		text := s[:base]
		if e.scale > 0 {
			frac := strings.TrimPrefix(s[base:], ".")
			if len(frac) > e.scale {
				frac = frac[:e.scale]
			}
			text += "." + frac + strings.Repeat("0", e.scale-len(frac))
		}
		return text + offset, nil
	}
	return "", fmt.Errorf("expecting time.Time or string, got %T", val)
}

func fastLoadIntegral(val driver.Value, lo, hi int64) (int64, error) {
	var n *big.Int
	switch v := val.(type) {
	case int64:
		n = big.NewInt(v)
	case int:
		n = big.NewInt(int64(v))
	case int32:
		n = big.NewInt(int64(v))
	case int16:
		n = big.NewInt(int64(v))
	case int8:
		n = big.NewInt(int64(v))
	case bool:
		if v {
			n = big.NewInt(1)
		} else {
			n = big.NewInt(0)
		}
	case float64, string, []byte:
		unscaled, scale, err := numberFromValue(v)
		if err != nil {
			return 0, err
		}
		n = rescaleTruncate(unscaled, scale, 0)
	default:
		return 0, fmt.Errorf("expecting an integer, got %T", val)
	}
	if !n.IsInt64() || n.Int64() < lo || n.Int64() > hi {
		return 0, fmt.Errorf("value %s out of range [%d, %d]", n, lo, hi)
	}
	return n.Int64(), nil
}

func fastLoadFloat(val driver.Value) (float64, error) {
	switch v := val.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case int:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(strings.TrimSpace(v), 64)
	}
	return 0, fmt.Errorf("expecting a float, got %T", val)
}

func fastLoadDate(val driver.Value) (int32, error) {
	var t time.Time
	switch v := val.(type) {
	case time.Time:
		t = v
	case string:
		p, err := time.Parse(time.DateOnly, strings.TrimSpace(v))
		if err != nil {
			return 0, err
		}
		t = p
	case int64:
		return int32(v), nil // already IntegerDate form
	default:
		return 0, fmt.Errorf("expecting time.Time or yyyy-mm-dd string, got %T", val)
	}
	y, m, d := t.Date()
	return int32((y-1900)*10000 + int(m)*100 + d), nil
}

func fastLoadString(val driver.Value) (string, error) {
	switch v := val.(type) {
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case int:
		return strconv.Itoa(v), nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(v), nil
	case time.Time:
		return v.Format("2006-01-02 15:04:05.999999999"), nil
	}
	return "", fmt.Errorf("expecting a string, got %T", val)
}

func fastLoadNumericValue(val driver.Value) driver.Value {
	switch v := val.(type) {
	case int:
		return int64(v)
	case int32:
		return int64(v)
	case int16:
		return int64(v)
	case int8:
		return int64(v)
	case float32:
		return float64(v)
	}
	return val
}

func rescaleHalfUp(unscaled *big.Int, from, to int) *big.Int {
	if to >= from {
		return new(big.Int).Mul(unscaled, pow10(to-from))
	}
	return quoRoundHalfUp(unscaled, pow10(from-to))
}

func rescaleTruncate(unscaled *big.Int, from, to int) *big.Int {
	if to >= from {
		return new(big.Int).Mul(unscaled, pow10(to-from))
	}
	return new(big.Int).Quo(unscaled, pow10(from-to))
}

func pow10(n int) *big.Int {
	return new(big.Int).Exp(numberBigTen, big.NewInt(int64(n)), nil)
}
