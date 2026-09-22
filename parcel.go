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
	"fmt"
)

const parcelHeaderLen = 4

type parcel interface {
	getFlavor() parcelFlavor
	getLength() int
	write(w *bufferWriter) error
}

type responseParcel interface {
	getFlavor() parcelFlavor
	fromBuffer(reader *bufferReader, length int) error
}

type parcelFlavor uint16

const (
	flavorRequest               parcelFlavor = 1
	flavorData                  parcelFlavor = 3
	flavorRespond               parcelFlavor = 4
	flavorKeepRespond           parcelFlavor = 5
	flavorCancel                parcelFlavor = 7
	flavorSuccess               parcelFlavor = 8
	flavorFailure               parcelFlavor = 9
	flavorRecord                parcelFlavor = 10
	flavorEndStatement          parcelFlavor = 11
	flavorEndRequest            parcelFlavor = 12
	flavorLogon                 parcelFlavor = 36
	flavorLogoff                parcelFlavor = 37
	flavorConfig                parcelFlavor = 42
	flavorConfigResponse        parcelFlavor = 43
	flavorError                 parcelFlavor = 49
	flavorIndicData             parcelFlavor = 68
	flavorIndicRequest          parcelFlavor = 69
	flavorDataInfo              parcelFlavor = 71
	flavorOptions               parcelFlavor = 85
	flavorPrepInfo              parcelFlavor = 86
	flavorConnect               parcelFlavor = 88
	flavorLSN                   parcelFlavor = 89
	flavorAssign                parcelFlavor = 100
	flavorAssignResponse        parcelFlavor = 101
	flavorSessionOptions        parcelFlavor = 114
	flavorSsoRequest            parcelFlavor = 132
	flavorSsoResponse           parcelFlavor = 134
	flavorMultiPartIndicData    parcelFlavor = 142
	flavorEndMultiPartIndicData parcelFlavor = 143
	flavorMultiPartRecord       parcelFlavor = 144
	flavorMultiPartEnd          parcelFlavor = 145
	flavorBigRespond            parcelFlavor = 153
	flavorBigKeepRespond        parcelFlavor = 154
	flavorGatewayConfig         parcelFlavor = 165
	flavorClientConfig          parcelFlavor = 166
	flavorAuthMech              parcelFlavor = 167
	flavorStatementInfo         parcelFlavor = 169
	flavorStementInfoEnd        parcelFlavor = 170
	flavorClientAttributes      parcelFlavor = 189
	flavorFetchRowCount         parcelFlavor = 190
	flavorStatementStatus       parcelFlavor = 205
	flavorSecurityPolicy        parcelFlavor = 206
	flavorSlobRespond           parcelFlavor = 215
	flavorStartSlobData         parcelFlavor = 220
	flavorSlobData              parcelFlavor = 221
	flavorEndSlobData           parcelFlavor = 222
)

var (
	tdGssVersion  = []byte{20, 0, 0, 58}
	driverVersion = []byte("TTU 20.00.00")
	staticBytes   = []byte{1}
)

func readParcelHeader(reader *bufferReader) (uint16, int, bool) {
	flavor := reader.u16()
	if flavor&0x8000 != 0 {
		// Alt Header
		reader.u16()
		return flavor ^ 0x8000, int(reader.u32()), true
	}
	return flavor, int(reader.u16()), false
}

func findParcel[T responseParcel](parcels []responseParcel) (T, bool) {
	for _, p := range parcels {
		if t, ok := p.(T); ok {
			return t, true
		}
	}
	var zero T
	return zero, false
}

func checkErrorParcel(reader *bufferReader) error {
	ps := reader.position()
	for {
		parcelStart := reader.position()
		flavor, parcelLen, _ := readParcelHeader(reader)
		if flavor == uint16(flavorFailure) || flavor == uint16(flavorError) {
			p := &errorResponseParcel{}
			p.fromBuffer(reader, parcelLen)
			return p.asTeradataError()
		}
		reader.seek(parcelStart + int(parcelLen))
		if reader.isDone() {
			break
		}
	}
	reader.seek(ps)
	return nil
}

func responseParcelFactory(flavor uint16) (responseParcel, error) {
	switch flavor {
	case uint16(flavorError), uint16(flavorFailure):
		return &errorResponseParcel{}, nil
	case uint16(flavorConfigResponse):
		return &configResponseParcel{}, nil
	case uint16(flavorGatewayConfig):
		return &gatewayConfigParcel{}, nil
	case uint16(flavorAuthMech):
		return &authMechParcel{}, nil
	case uint16(flavorSsoResponse):
		return &ssoResponseParcel{}, nil
	case uint16(flavorAssignResponse):
		return &assignResponseParcel{}, nil
	case uint16(flavorSuccess):
		return &successResponseParcel{}, nil
	case uint16(flavorEndRequest):
		return &endRequstParcel{}, nil
	case uint16(flavorStatementInfo):
		return &statementInfoResponseParcel{}, nil
	case uint16(flavorStementInfoEnd):
		return &statementInfoEndResponseParcel{}, nil
	case uint16(flavorEndStatement):
		return &endStatementReponseParcel{}, nil
	case uint16(flavorStatementStatus):
		return &statementStatusParcel{}, nil
	case uint16(flavorSecurityPolicy):
		return &securityPolicyParcel{}, nil
	case uint16(flavorStartSlobData):
		return &startSlobDataParcel{}, nil
	case uint16(flavorSlobData):
		return &slobDataParcel{}, nil
	case uint16(flavorEndSlobData):
		return &endSlobdataParcel{}, nil
	//case uint16(flavorMultiPartRecord):
	//	return &multiPartRecordParcel{}, nil
	case uint16(flavorMultiPartEnd):
		return &multiPartRecordEndParcel{}, nil
	}
	return nil, fmt.Errorf("unknown parcel, flavor=%d", flavor)
}

// For testing
func marshalParcel(p parcel, b *writeBuffer) ([]byte, error) {
	buffer_len := p.getLength()
	buff := b.take(buffer_len)
	_ = buff[buffer_len-1]
	w := newBufferWriter(buff)
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(buffer_len))
	p.write(w)
	return buff, nil
}
