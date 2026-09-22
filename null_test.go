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
	"testing"
)

func TestIndicDataParcelNullParams(t *testing.T) {
	dataTypes := []uint16{tdInteger, tdVarchar, tdChar, tdVarByte, tdByte, tdFloat, tdBigInt, tdSmallInt, tdByteInt}
	dataValues := []driver.Value{nil, nil, nil, nil, nil, nil, nil, nil, nil}
	metas := make([]statementInfoMetaItem, len(dataTypes))
	for i, dt := range dataTypes {
		metas[i] = &statementInfoMetaDataLimited{dataType: dt, maxDataBytes: 10}
	}

	p := newIndicDataParcel(dataTypes, dataValues, metas)

	w := newBufferWriter(make([]byte, p.getLength()))
	if err := p.write(w); err != nil {
		t.Fatalf("write() with all-NULL params: %v", err)
	}
	if w.position() != p.getLength() {
		t.Fatalf("write() consumed %d bytes, getLength() declared %d", w.position(), p.getLength())
	}
}

// check non-null params alongside NULL
func TestIndicDataParcelMixedNullParams(t *testing.T) {
	dataTypes := []uint16{tdInteger, tdVarchar, tdInteger}
	dataValues := []driver.Value{int64(42), nil, int64(7)}
	metas := []statementInfoMetaItem{
		&statementInfoMetaDataLimited{dataType: tdInteger},
		&statementInfoMetaDataLimited{dataType: tdVarchar},
		&statementInfoMetaDataLimited{dataType: tdInteger},
	}

	p := newIndicDataParcel(dataTypes, dataValues, metas)
	w := newBufferWriter(make([]byte, p.getLength()))
	if err := p.write(w); err != nil {
		t.Fatalf("write() with mixed NULL params: %v", err)
	}
	if w.position() != p.getLength() {
		t.Fatalf("write() consumed %d bytes, getLength() declared %d", w.position(), p.getLength())
	}
}

func TestNullParamDataInfoAndIndicDataAgree(t *testing.T) {
	dataTypes := []uint16{tdInteger, tdVarchar, tdChar, tdDecimal}
	dataValues := []driver.Value{nil, nil, nil, nil}
	metas := []statementInfoMetaItem{
		&statementInfoMetaDataLimited{dataType: tdInteger},
		&statementInfoMetaDataLimited{dataType: tdVarchar},
		&statementInfoMetaDataLimited{dataType: tdChar, maxDataBytes: 20},
		&statementInfoMetaDataLimited{dataType: tdDecimal, numDigits: 10, fractionalDigits: 2},
	}

	declared := calculateParamLengths(dataTypes, dataValues, metas)
	wire := calculateWireParamLengths(dataTypes, dataValues, metas)

	for i, dt := range dataTypes {
		switch getTdBasicType(dt) {
		case tdVarchar, tdLongVarchar, tdVarGraphic, tdLongVarGraphic, tdVarByte, tdLongVarByte:
			if wire[i] != declared[i]+2 {
				t.Errorf("field %d (type %d): wire len %d, declared len %d+2", i, dt, wire[i], declared[i])
			}
		default:
			if wire[i] != declared[i] {
				t.Errorf("field %d (type %d): wire len %d != declared len %d", i, dt, wire[i], declared[i])
			}
		}
	}
}

func TestProduceColumnValueNullVarchar(t *testing.T) {
	buf := []byte{0x00, 0x00}
	r := newBufferReader(buf, 0, len(buf))
	meta := &statementInfoMetaDataFull{dataType: tdVarchar}

	v, err := produceColumnValue(r, meta, true, nil)
	if err != nil {
		t.Fatalf("produceColumnValue: %v", err)
	}
	if v != nil {
		t.Fatalf("expected nil for NULL zero-length VARCHAR, got %#v", v)
	}
}

func TestProduceColumnValueEmptyVarchar(t *testing.T) {
	buf := []byte{0x00, 0x00}
	r := newBufferReader(buf, 0, len(buf))
	meta := &statementInfoMetaDataFull{dataType: tdVarchar}

	v, err := produceColumnValue(r, meta, false, nil)
	if err != nil {
		t.Fatalf("produceColumnValue: %v", err)
	}
	if v != "" {
		t.Fatalf("expected empty string for non-NULL zero-length VARCHAR, got %#v", v)
	}
}
