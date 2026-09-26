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
	"database/sql"
	"database/sql/driver"
	"fmt"
	"math/big"
	"reflect"
	"strings"
)

const (
	paramModeUnknown = 0
	paramModeIn      = 1
	paramModeInOut   = 2
	paramModeOut     = 4
)

const (
	tdBlob             uint16 = 400 // BLOB
	tdBlobDeferred     uint16 = 404 // BLOB DEFERRED
	tdBlobLocator      uint16 = 408 // BLOB LOCATOR
	tdClob             uint16 = 416 // CLOB
	tdClobDeferred     uint16 = 420 // CLOB DEFERRED
	tdClobLocator      uint16 = 424 // CLOB LOCATOR
	tdStruct           uint16 = 440 // STRUCT
	tdVarchar          uint16 = 448 // VARCHAR
	tdChar             uint16 = 452 // CHAR
	tdLongVarchar      uint16 = 456 // LONG VARCHAR
	tdVarGraphic       uint16 = 464 // VARGRAPHIC
	tdGraphic          uint16 = 468 // GRAPHIC
	tdLongVarGraphic   uint16 = 472 // LONG VARGRAPHIC
	tdFloat            uint16 = 480 // FLOAT
	tdDecimal          uint16 = 484 // DECIMAL
	tdInteger          uint16 = 496 // INTEGER
	tdSmallInt         uint16 = 500 // SMALLINT
	tdArray            uint16 = 504 // ARRAY (1-dimensional)
	tdArrayND          uint16 = 508 // ARRAY (N-dimensional)
	tdDatasetAvro      uint16 = 512 // DATASET STORAGE FORMAT AVRO
	tdDatasetCsv       uint16 = 516 // DATASET STORAGE FORMAT CSV
	tdBigInt           uint16 = 600 // BIGINT
	tdNumber           uint16 = 604 // NUMBER
	tdVarByte          uint16 = 688 // VARBYTE
	tdByte             uint16 = 692 // BYTE
	tdLongVarByte      uint16 = 696 // LONG VARBYTE
	tdDateAnsi         uint16 = 748 // DATE (ANSI)
	tdDateInteger      uint16 = 752 // DATE (integer format)
	tdByteInt          uint16 = 756 // BYTEINT
	tdTime             uint16 = 760 // TIME
	tdTimestamp        uint16 = 764 // TIMESTAMP
	tdTimeTZ           uint16 = 768 // TIME WITH TIME ZONE
	tdTimestampTZ      uint16 = 772 // TIMESTAMP WITH TIME ZONE
	tdIntervalYear     uint16 = 776 // INTERVAL YEAR
	tdIntervalYearToMo uint16 = 780 // INTERVAL YEAR TO MONTH
	tdIntervalMonth    uint16 = 784 // INTERVAL MONTH
	tdIntervalDay      uint16 = 788 // INTERVAL DAY
	tdIntervalDayToHr  uint16 = 792 // INTERVAL DAY TO HOUR
	tdIntervalDayToMin uint16 = 796 // INTERVAL DAY TO MINUTE
	tdIntervalDayToSec uint16 = 800 // INTERVAL DAY TO SECOND
	tdIntervalHour     uint16 = 804 // INTERVAL HOUR
	tdIntervalHrToMin  uint16 = 808 // INTERVAL HOUR TO MINUTE
	tdIntervalHrToSec  uint16 = 812 // INTERVAL HOUR TO SECOND
	tdIntervalMinute   uint16 = 816 // INTERVAL MINUTE
	tdIntervalMinToSec uint16 = 820 // INTERVAL MINUTE TO SECOND
	tdIntervalSecond   uint16 = 824 // INTERVAL SECOND
	tdPeriodDate       uint16 = 832 // PERIOD(DATE)
	tdPeriodTime       uint16 = 836 // PERIOD(TIME)
	tdPeriodTimeTZ     uint16 = 840 // PERIOD(TIME WITH TIME ZONE)
	tdPeriodTimestamp  uint16 = 844 // PERIOD(TIMESTAMP)
	tdPeriodTimestampT uint16 = 848 // PERIOD(TIMESTAMP WITH TIME ZONE)
	tdXmlText          uint16 = 852 // XML TEXT
	tdXmlTextDeferred  uint16 = 856 // XML TEXT DEFERRED
	tdXmlTextLocator   uint16 = 860 // XML TEXT LOCATOR
	tdXmlBinary        uint16 = 864 // XML BINARY
	tdXmlBinaryDeferre uint16 = 868 // XML BINARY DEFERRED
	tdXmlBinaryLocator uint16 = 872 // XML BINARY LOCATOR
	tdJsonInline       uint16 = 880 // JSON INLINE
	tdJsonLocator      uint16 = 884 // JSON LOCATOR
	tdJsonDeferred     uint16 = 888 // JSON DEFERRED
)

var tdTypeFamilyBases = []uint16{
	tdBlob, tdBlobDeferred, tdBlobLocator,
	tdClob, tdClobDeferred, tdClobLocator,
	tdStruct,
	tdVarchar,
	tdChar,
	tdLongVarchar,
	tdVarGraphic,
	tdGraphic,
	tdLongVarGraphic,
	tdFloat,
	tdDecimal,
	tdInteger,
	tdSmallInt,
	tdArray, tdArrayND,
	tdDatasetAvro, tdDatasetCsv,
	tdBigInt,
	tdNumber,
	tdVarByte,
	tdByte,
	tdLongVarByte,
	tdDateAnsi, tdDateInteger,
	tdByteInt,
	tdTime,
	tdTimestamp,
	tdTimeTZ,
	tdTimestampTZ,
	tdIntervalYear,
	tdIntervalYearToMo,
	tdIntervalMonth,
	tdIntervalDay,
	tdIntervalDayToHr,
	tdIntervalDayToMin,
	tdIntervalDayToSec,
	tdIntervalHour,
	tdIntervalHrToMin,
	tdIntervalHrToSec,
	tdIntervalMinute,
	tdIntervalMinToSec,
	tdIntervalSecond,
	tdPeriodDate,
	tdPeriodTime,
	tdPeriodTimeTZ,
	tdPeriodTimestamp,
	tdPeriodTimestampT,
	tdXmlText, tdXmlTextDeferred, tdXmlTextLocator,
	tdXmlBinary, tdXmlBinaryDeferre, tdXmlBinaryLocator,
	tdJsonInline, tdJsonLocator, tdJsonDeferred,
}

var (
	scanTypeFloat64    = reflect.TypeFor[float64]()
	scanTypeInt8       = reflect.TypeFor[int8]()
	scanTypeInt16      = reflect.TypeFor[int16]()
	scanTypeInt32      = reflect.TypeFor[int32]()
	scanTypeInt64      = reflect.TypeFor[int64]()
	scanTypeNullFloat  = reflect.TypeFor[sql.NullFloat64]()
	scanTypeNullInt8   = reflect.TypeFor[sql.Null[int8]]()
	scanTypeNullInt16  = reflect.TypeFor[sql.Null[int16]]()
	scanTypeNullInt32  = reflect.TypeFor[sql.Null[int32]]()
	scanTypeNullInt64  = reflect.TypeFor[sql.NullInt64]()
	scanTypeString     = reflect.TypeFor[string]()
	scanTypeNullString = reflect.TypeFor[sql.NullString]()
	scanTypeBytes      = reflect.TypeFor[[]byte]()
	scanTypeUnknown    = reflect.TypeFor[any]()
)

func getTdBasicType(dataType uint16) uint16 {
	for _, base := range tdTypeFamilyBases {
		if tdDataTypeInFamily(dataType, base) {
			return base
		}
	}
	return 0
}

func getTdParameterMode(dataType uint16) int {
	for _, base := range tdTypeFamilyBases {
		switch dataType {
		case base, base + 1:
			return paramModeUnknown
		case base + 500:
			return paramModeIn
		case base + 501:
			return paramModeInOut
		case base + 502:
			return paramModeOut
		}
	}
	return paramModeUnknown
}

func tdDataTypeInFamily(dataType, base uint16) bool {
	switch dataType {
	case base, base + 1, base + 500, base + 501, base + 502:
		return true
	}
	return false
}

func toInt64(val driver.Value) (int64, bool) {
	switch v := val.(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case big.Int:
		return v.Int64(), true
	}
	return 0, false
}

func fixedWidthBytes(d []byte, width int, fill byte) []byte {
	if width <= 0 || len(d) == width {
		return d
	}
	if len(d) > width {
		return d[:width]
	}
	out := make([]byte, width)
	copy(out, d)
	for i := len(d); i < width; i++ {
		out[i] = fill
	}
	return out
}

func decimalToScaledInt(s string, scale int) (*big.Int, error) {
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	} else if strings.HasPrefix(s, "+") {
		s = s[1:]
	}

	intPart, fracPart, _ := strings.Cut(s, ".")
	if len(fracPart) > scale {
		fracPart = fracPart[:scale] // TODO: round rather than truncate
	}
	for len(fracPart) < scale {
		fracPart += "0"
	}

	digits := intPart + fracPart
	if digits == "" {
		digits = "0"
	}

	raw, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		return nil, fmt.Errorf("invalid decimal value: %q", s)
	}
	if neg {
		raw.Neg(raw)
	}
	return raw, nil
}

func dbNameForDataType(dataType uint16) string {
	switch getTdBasicType(dataType) {
	case tdBlob:
		return "BLOB"
	case tdBlobDeferred:
		return "BLOB DEFERRED"
	case tdBlobLocator:
		return "BLOB LOCATOR"
	case tdClob:
		return "CLOB"
	case tdClobDeferred:
		return "CLOB DEFERRED"
	case tdClobLocator:
		return "CLOB LOCATOR"
	case tdStruct:
		return "STRUCT"
	case tdVarchar:
		return "VARCHAR"
	case tdChar:
		return "CHAR"
	case tdLongVarchar:
		return "LONG VARCHAR"
	case tdVarGraphic:
		return "VARGRAPHIC"
	case tdGraphic:
		return "GRAPHIC"
	case tdLongVarGraphic:
		return "LONG VARGRAPHIC"
	case tdFloat:
		return "FLOAT"
	case tdDecimal:
		return "DECIMAL"
	case tdInteger:
		return "INTEGER"
	case tdSmallInt:
		return "SMALLINT"
	case tdArray:
		return "ARRAY (1-dimensional)"
	case tdArrayND:
		return "ARRAY (N-dimensional)"
	case tdDatasetAvro:
		return "DATASET STORAGE FORMAT AVRO"
	case tdDatasetCsv:
		return "DATASET STORAGE FORMAT CSV"
	case tdBigInt:
		return "BIGINT"
	case tdNumber:
		return "NUMBER"
	case tdVarByte:
		return "VARBYTE"
	case tdByte:
		return "BYTE"
	case tdLongVarByte:
		return "LONG VARBYTE"
	case tdDateAnsi:
		return "DATE (ANSI)"
	case tdDateInteger:
		return "DATE (integer format)"
	case tdByteInt:
		return "BYTEINT"
	case tdTime:
		return "TIME"
	case tdTimestamp:
		return "TIMESTAMP"
	case tdTimeTZ:
		return "TIME WITH TIME ZONE"
	case tdTimestampTZ:
		return "TIMESTAMP WITH TIME ZONE"
	case tdIntervalYear:
		return "INTERVAL YEAR"
	case tdIntervalYearToMo:
		return "INTERVAL YEAR TO MONTH"
	case tdIntervalMonth:
		return "INTERVAL MONTH"
	case tdIntervalDay:
		return "INTERVAL DAY"
	case tdIntervalDayToHr:
		return "INTERVAL DAY TO HOUR"
	case tdIntervalDayToMin:
		return "INTERVAL DAY TO MINUTE"
	case tdIntervalDayToSec:
		return "INTERVAL DAY TO SECOND"
	case tdIntervalHour:
		return "INTERVAL HOUR"
	case tdIntervalHrToMin:
		return "INTERVAL HOUR TO MINUTE"
	case tdIntervalHrToSec:
		return "INTERVAL HOUR TO SECOND"
	case tdIntervalMinute:
		return "INTERVAL MINUTE"
	case tdIntervalMinToSec:
		return "INTERVAL MINUTE TO SECOND"
	case tdIntervalSecond:
		return "INTERVAL SECOND"
	case tdPeriodDate:
		return "PERIOD(DATE)"
	case tdPeriodTime:
		return "PERIOD(TIME)"
	case tdPeriodTimeTZ:
		return "PERIOD(TIME WITH TIME ZONE)"
	case tdPeriodTimestamp:
		return "PERIOD(TIMESTAMP)"
	case tdPeriodTimestampT:
		return "PERIOD(TIMESTAMP WITH TIME ZONE)"
	case tdXmlText:
		return "XML TEXT"
	case tdXmlTextDeferred:
		return "XML TEXT DEFERRED"
	case tdXmlTextLocator:
		return "XML TEXT LOCATOR"
	case tdXmlBinary:
		return "XML BINARY"
	case tdXmlBinaryDeferre:
		return "XML BINARY DEFERRED"
	case tdXmlBinaryLocator:
		return "XML BINARY LOCATOR"
	case tdJsonInline:
		return "JSON INLINE"
	case tdJsonLocator:
		return "JSON LOCATOR"
	case tdJsonDeferred:
		return "JSON DEFERRED"
	}
	return ""
}

func scanTypeForDataType(dataType uint16, nullable bool) reflect.Type {
	switch getTdBasicType(dataType) {
	case tdInteger:
		if nullable {
			return scanTypeNullInt32
		}
		return scanTypeInt32
	case tdBigInt:
		if nullable {
			return scanTypeNullInt64
		}
		return scanTypeInt64
	case tdSmallInt:
		if nullable {
			return scanTypeNullInt16
		}
		return scanTypeInt16
	case tdByteInt:
		if nullable {
			return scanTypeNullInt8
		}
		return scanTypeInt8
	case tdVarchar, tdLongVarchar, tdVarGraphic, tdLongVarGraphic, tdChar, tdGraphic:
		if nullable {
			return scanTypeNullString
		}
		return scanTypeString
	case tdFloat:
		if nullable {
			return scanTypeNullFloat
		}
		return scanTypeFloat64
	case tdDecimal, tdNumber:
		if nullable {
			return scanTypeNullString
		}
		return scanTypeString
	case tdVarByte, tdLongVarByte, tdByte:
		return scanTypeBytes
	case tdIntervalYear, tdIntervalYearToMo, tdIntervalMonth, tdIntervalDay,
		tdIntervalDayToHr, tdIntervalDayToMin, tdIntervalDayToSec, tdIntervalHour,
		tdIntervalHrToMin, tdIntervalHrToSec, tdIntervalMinute, tdIntervalSecond,
		tdDateAnsi, tdDateInteger, tdTime, tdTimeTZ, tdTimestamp, tdTimestampTZ:
		if nullable {
			return scanTypeNullString
		}
		return scanTypeString
	}
	return scanTypeUnknown
}
