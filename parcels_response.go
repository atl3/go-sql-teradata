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
	"encoding/asn1"
	"fmt"
	"strings"
)

type endRequstParcel struct{}

func (p *endRequstParcel) getFlavor() parcelFlavor {
	return flavorEndRequest
}

func (p *endRequstParcel) String() string {
	return "endRequstParcel{}"
}

func (p *endRequstParcel) fromBuffer(reader *bufferReader, length int) error {
	return nil
}

type successResponseParcel struct {
	statementNumber uint16
	activityCount   int
	lastWarning     uint16
	fieldCount      uint16
	activityType    uint16
}

func (p *successResponseParcel) getFlavor() parcelFlavor {
	return flavorSuccess
}

func (p *successResponseParcel) String() string {
	return fmt.Sprintf("successResponseParcel{statementNo: %d, activityCount %d, lastWarning: %d, fieldCount: %d, activityType: %d}",
		p.statementNumber, p.activityCount, p.lastWarning, p.fieldCount, p.activityType)
}

func (p *successResponseParcel) fromBuffer(reader *bufferReader, length int) error {
	p.statementNumber = reader.u16()
	p.activityCount = int(reader.u32())
	p.lastWarning = reader.u16()
	p.fieldCount = reader.u16()
	p.activityType = reader.u16()
	return nil
}

type errorResponseParcel struct {
	statementNumber uint16
	info            uint16
	code            uint16
	messageLen      uint16
	message         string
}

func (p *errorResponseParcel) Error() string {
	return fmt.Sprintf("sql error code: %d, message: %s", p.code, p.message)
}

func (p *errorResponseParcel) getFlavor() parcelFlavor {
	return flavorError
}

func (p *errorResponseParcel) String() string {
	return fmt.Sprintf("errorResponseParcel{statementNo: %d, info %d, code: %d, message: %s}", p.statementNumber, p.info, p.code, p.message)
}

func (p *errorResponseParcel) fromBuffer(reader *bufferReader, length int) error {
	p.statementNumber = reader.u16()
	p.info = reader.u16()
	p.code = reader.u16()
	p.messageLen = reader.u16()
	msgData := reader.bytes(int(p.messageLen))
	p.message = string(msgData)
	return nil
}

type gatewayConfigParcel struct {
}

func (p *gatewayConfigParcel) getFlavor() parcelFlavor {
	return flavorGatewayConfig
}

func (p *gatewayConfigParcel) String() string {
	return "gatewayConfigParcel{}"
}

func (p *gatewayConfigParcel) fromBuffer(reader *bufferReader, length int) error {
	return nil
}

type securityPolicyParcel struct {
	securityRequired        bool
	confidentialityRequired bool
	securityLevel           int
}

func (p *securityPolicyParcel) getFlavor() parcelFlavor {
	return flavorSecurityPolicy
}

func (p *securityPolicyParcel) String() string {
	return fmt.Sprintf("securityPolicyParcel{securityRequired=%t,confidentialityRequired=%t,securityLevel=%d}", p.securityRequired, p.confidentialityRequired, p.securityLevel)
}

func (p *securityPolicyParcel) fromBuffer(reader *bufferReader, length int) error {
	p.securityRequired = reader.u8() >= 1
	p.confidentialityRequired = reader.u8() >= 1
	p.securityLevel = int(reader.skip(2).u32())
	return nil
}

type authMechParcel struct {
	ok                 bool
	oid                string
	defaultMech        bool
	defaultNegoMech    bool
	cidBypassSupported bool
	rank               int
}

func (p *authMechParcel) getFlavor() parcelFlavor {
	return flavorAuthMech
}

func (p *authMechParcel) String() string {
	return fmt.Sprintf("authMechParcel{oid=%s,cidBypassSupported=%t,defaultMech=%t}", p.oid, p.cidBypassSupported, p.defaultMech)
}

func (p *authMechParcel) getAuthMechFlag() authMechFlag {
	return decodeAuthMetch(p.oid)
}

func (p *authMechParcel) fromBuffer(reader *bufferReader, length int) error {
	startPos := reader.position()
	if reader.u32() == 1 {
		oidLen := reader.u32()
		oidParts := reader.bytes(int(oidLen))
		derData := append([]byte{0x06, byte(len(oidParts))}, oidParts...)
		var oid asn1.ObjectIdentifier
		_, err := asn1.Unmarshal(derData, &oid)
		if err != nil {
			p.ok = false
			return nil //swallow err here - revist later
		}
		p.oid = oid.String()

		for reader.position()-startPos+8 < length {
			pos := reader.position()
			typ := reader.u16()
			len := reader.u16()
			reader.skip(4)
			switch typ {
			case 16:
				p.defaultMech = reader.u32() != 0
			case 17:
				p.rank = int(reader.u32())
			case 112:
				p.defaultNegoMech = reader.u32() != 0
			case 129:
				p.cidBypassSupported = reader.u32() != 0
			}
			reader.seek(pos + int(len))
		}
	}
	return nil
}

// Assign Response Parcel
type assignResponseParcel struct {
	dbmsVersion string
	dbmsRelease string
	hostId      uint16
}

func (p *assignResponseParcel) getFlavor() parcelFlavor {
	return flavorAssignResponse
}

func (p *assignResponseParcel) String() string {
	return fmt.Sprintf("assignResponseParcel{dbmsVersion=%s, dbmsRelease=%s, hostId=%d}", p.dbmsVersion, p.dbmsRelease, p.hostId)
}

func (p *assignResponseParcel) fromBuffer(reader *bufferReader, length int) error {
	flavorPosition := reader.position() - parcelHeaderLen
	reader.seek(flavorPosition + 76)
	p.dbmsRelease = string(reader.bytes(6))
	p.dbmsVersion = string(reader.bytes(14))
	p.hostId = reader.u16()
	return nil
}

// SSO Response Parcel
type ssoResponseParcel struct {
	method     byte
	trip       byte
	code       byte
	authData   []byte
	mustBeZero byte
}

func (p *ssoResponseParcel) getFlavor() parcelFlavor {
	return flavorSsoResponse
}

func (p *ssoResponseParcel) String() string {
	return fmt.Sprintf("ssoResponseParcel{method=%d, trip=%d, code=%d}", p.method, p.trip, p.code)
}

func (p *ssoResponseParcel) fromBuffer(reader *bufferReader, length int) error {
	p.method = reader.u8()
	p.code = reader.u8()
	p.trip = reader.u8()
	p.mustBeZero = reader.u8()
	authLen := reader.u16()
	p.authData = reader.bytes(int(authLen))
	return nil
}

// Record Parcel
type recordParcel struct {
	stmtInfo       *statementInfoResponseParcel
	numColumns     int
	columnNmaes    []string
	nullIndicators []byte
}

func (p *recordParcel) getFlavor() parcelFlavor {
	return flavorRecord
}

func (p *recordParcel) String() string {
	return "recordParcel{}"
}

func (p *recordParcel) fromBuffer(reader *bufferReader, length int) error {
	p.nullIndicators = reader.bytes((p.numColumns + 7) / 8)
	return nil
}

type multiPartRecordParcel struct {
	*recordParcel
}

func (p *multiPartRecordParcel) getFlavor() parcelFlavor {
	return flavorMultiPartRecord
}

func (p *multiPartRecordParcel) String() string {
	return "multiPartRecordParcel{}"
}

type multiPartRecordEndParcel struct {
}

func (p *multiPartRecordEndParcel) getFlavor() parcelFlavor {
	return flavorMultiPartEnd
}

func (p *multiPartRecordEndParcel) String() string {
	return "multiPartRecordEndParcel{}"
}

func (p *multiPartRecordEndParcel) fromBuffer(reader *bufferReader, length int) error {
	return nil
}

// StatementStatus Parcel
type statementStatusParcel struct {
	status           byte
	responseMode     byte
	statementNumber  uint32
	code             uint16
	activityType     uint16
	activityCount    uint64
	fieldCount       uint32
	warnings         []*statementStatusWarning
	mergeInsertCount uint64
	mergeUpdateCount uint64
	mergeDeleteCount uint64
}

func (p *statementStatusParcel) getFlavor() parcelFlavor {
	return flavorStatementStatus
}

func (p *statementStatusParcel) String() string {
	if len(p.warnings) > 0 {
		var warnBuilder strings.Builder
		for _, w := range p.warnings {
			warnBuilder.WriteString(w.String())
		}
		warnings := warnBuilder.String()
		return fmt.Sprintf("statementStatusParcel{status=%d,responseMode=%d,statementNumber=%d,code=%d,activityCount=%d,warnings=[%s]}", p.status, p.responseMode, p.statementNumber, p.code, p.activityCount, warnings)
	}
	return fmt.Sprintf("statementStatusParcel{status=%d,responseMode=%d,statementNumber=%d,code=%d,activityCount=%d,warnings=NONE}", p.status, p.responseMode, p.statementNumber, p.code, p.activityCount)
}

func (p *statementStatusParcel) fromBuffer(reader *bufferReader, length int) error {
	startPos := reader.position()
	p.status = reader.u8()
	p.responseMode = reader.u8()
	reader.skip(2) // pad
	p.statementNumber = reader.u32()
	p.code = reader.u16()
	p.activityType = reader.u16()
	p.activityCount = reader.u64()
	p.fieldCount = reader.u32()
	reader.skip(4)
	p.warnings = make([]*statementStatusWarning, 0)
	for reader.position()-startPos+6 < length {
		typ := reader.u16()
		len := reader.u32()
		pos := reader.position()
		switch typ {
		case 1:
			warnCode := reader.u16()
			warnComp := reader.u16()
			warnMsg := reader.asciiString(int(reader.u32()))
			p.warnings = append(p.warnings, &statementStatusWarning{
				code:      warnCode,
				component: warnComp,
				message:   warnMsg,
			})
		case 10:
			if len >= 24 {
				// Merge Counts
				p.mergeInsertCount = reader.u64()
				p.mergeUpdateCount = reader.u64()
				p.mergeDeleteCount = reader.u64()
			}
		}
		reader.seek(pos + int(len))
	}
	return nil
}

type statementStatusWarning struct {
	code      uint16
	component uint16
	message   string
}

func (w *statementStatusWarning) String() string {
	return fmt.Sprintf("statementStatusWarning{code=%d, comp=%d, msg=%s}", w.code, w.component, w.message)
}

// StatementInfoEnd Parcel
type statementInfoEndResponseParcel struct{}

func (p *statementInfoEndResponseParcel) getFlavor() parcelFlavor {
	return flavorStementInfoEnd
}

func (p *statementInfoEndResponseParcel) String() string {
	return "statementInfoEndResponseParcel{}"
}

func (p *statementInfoEndResponseParcel) fromBuffer(reader *bufferReader, length int) error {
	return nil
}

// EndStatement Parcel
type endStatementReponseParcel struct {
	statementNumber uint16
}

func (p *endStatementReponseParcel) getFlavor() parcelFlavor {
	return flavorEndStatement
}

func (p *endStatementReponseParcel) String() string {
	return fmt.Sprintf("endStatementReponseParcel{statementNumber=%d}", p.statementNumber)
}

func (p *endStatementReponseParcel) fromBuffer(reader *bufferReader, length int) error {
	p.statementNumber = reader.u16()
	return nil
}

// StatementInfo Response Parcel
type statementInfoMetaItem interface {
	read(reader *bufferReader, contentType uint16, contentLen uint16) error
	getDataType() uint16
	getPercision() uint16
	getScale() uint16
	getMaxLength() uint64
	setReceiveItemNumber(i int)
	setTransmitItemNumber(i int)
	String() string
}

type statementInfoResponseParcel struct {
	metaItems        [6][]statementInfoMetaItem
	containsFullMeta bool
}

func (p *statementInfoResponseParcel) getFlavor() parcelFlavor {
	return flavorStatementInfo
}

func (p *statementInfoResponseParcel) String() string {
	return fmt.Sprintf("statementInfoResponseParcel{containsFullMeta=%t}", p.containsFullMeta)
}

func (p *statementInfoResponseParcel) debugString() string {
	var sb strings.Builder
	for i, ml := range p.metaItems {
		switch i {
		case 0:
			sb.WriteString("ParamMarkers:\n")
		case 1:
			sb.WriteString("ResultSetColumns:\n")
		case 2:
			sb.WriteString("ResultSetSummary:\n")
		case 3:
			sb.WriteString("AGKColumns:\n")
		case 4:
			sb.WriteString("ProcParams:\n")
		case 5:
			sb.WriteString("ProcColumns:\n")
		}
		for _, m := range ml {
			sb.WriteString(m.String())
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

func (p *statementInfoResponseParcel) fromBuffer(reader *bufferReader, length int) error {
	rnum := 1
	tnum := 1
	for i := 0; i < len(p.metaItems); i++ {
		p.metaItems[i] = make([]statementInfoMetaItem, 0)
	}
	var metaItem statementInfoMetaItem
	stack := make([]*statementInfoMetaDataFull, 0)
	for length > 0 {
		startPos := reader.position()
		metaLayoutType := reader.u16()
		metaContentType := reader.u16()
		metaContentLen := reader.u16()
		switch metaLayoutType {
		case 1:
			metaItem = &statementInfoMetaDataFull{}
			p.containsFullMeta = true
		case 2:
			metaItem = &statementInfoMetaDataLimited{}
		default:
			metaItem = &statementInfoMetaData{}
		}
		metaItem.read(reader, metaContentType, metaContentLen)
		if metaLayoutType == 1 || metaLayoutType == 2 {
			if getTdParameterMode(metaItem.getDataType()) != paramModeIn {
				metaItem.setReceiveItemNumber(rnum)
				rnum += 1
			}
			if getTdParameterMode(metaItem.getDataType()) != paramModeOut {
				metaItem.setTransmitItemNumber(tnum)
				tnum += 1
			}
		}

		// Move buffer to end of meta if not there
		metaLen := int(metaContentLen) + 6
		if startPos+metaLen != reader.position() {
			reader.seek(startPos + metaLen)
		}

		if metaLayoutType != 4 {
			fullItem, isFullItem := metaItem.(*statementInfoMetaDataFull)

			// Pop step
			for len(stack) > 0 && isFullItem && stack[len(stack)-1].structDepth >= fullItem.structDepth {
				stack = stack[:len(stack)-1]
			}

			// Attach-or-route step:
			if len(stack) > 0 && isFullItem {
				stack[len(stack)-1].addAttributeItem(fullItem)
			} else if metaContentType >= 1 && metaContentType <= 6 {
				p.metaItems[metaContentType-1] = append(p.metaItems[metaContentType-1], metaItem)
			} else if metaContentType != 7 {
				return fmt.Errorf("invalid meta content type: %d", metaContentType)
			}

			// Push step:
			if isFullItem && (fullItem.isStructType() || fullItem.isArrayType()) {
				stack = append(stack, fullItem)
			}
		} else {
			stack = stack[:0]
			rnum = 1
			tnum = 1
		}

		length -= metaLen
	}

	return nil
}

func (p *statementInfoResponseParcel) paramMarkerMetaItems() []statementInfoMetaItem {
	return p.metaItems[0]
}

func (p *statementInfoResponseParcel) resultSetColumnMetaItems() []statementInfoMetaItem {
	return p.metaItems[1]
}

func (p *statementInfoResponseParcel) resultSetSummaryMetaItems() []statementInfoMetaItem {
	return p.metaItems[2]
}

func (p *statementInfoResponseParcel) agkColumnMetaItems() []statementInfoMetaItem {
	return p.metaItems[3]
}

func (p *statementInfoResponseParcel) procParamMetaItems() []statementInfoMetaItem {
	return p.metaItems[4]
}

func (p *statementInfoResponseParcel) procColumnMetaItems() []statementInfoMetaItem {
	return p.metaItems[5]
}

type statementInfoMetaDataLimited struct {
	itemNumberRcv    int
	itemNumberTrn    int
	dataType         uint16
	maxDataBytes     uint64
	numDigits        uint16
	intervalDigits   uint16
	fractionalDigits uint16
}

func (m *statementInfoMetaDataLimited) String() string {
	return fmt.Sprintf("statementInfoMetaDataLimited{dataType=%d,maxBytes=%d}", m.dataType, m.maxDataBytes)
}

type statementInfoMetaDataFull struct {
	itemNumberRcv            int
	itemNumberTrn            int
	databaseName             string
	procOrTableName          string
	columnOrParamName        string
	columnPosition           uint16
	asClauseName             string
	title                    string
	format                   string
	defaultValue             string
	isIdentityColumn         byte
	isDefinitelyWritable     byte
	isNullable               byte
	mayBeNull                byte
	isSearchable             byte
	isWritable               byte
	dataType                 uint16
	udtIndicator             uint16
	udtTypeName              string
	dataTypeMiscInfo         string
	maxDataLengthInBytes     uint64
	totalNumberOfDigits      uint16
	numberOfIntervalDigits   uint16
	numberOfFractionalDigits uint16
	charsetCode              byte
	maxNumberOfCharacters    uint64
	isCaseSensitive          byte
	isSigned                 byte
	isKeyColumn              byte
	isUnique                 byte
	isExpression             byte
	isSortable               byte
	sprocParameterDirection  byte

	structDepth    uint16
	isTemporal     byte
	attributeName  string
	serverDataType uint16

	attributes []*statementInfoMetaDataFull

	arrayNumDimensions    uint16
	arrayMaxCardinalities []int
	arrayLowerBounds      []int

	catalogName string
}

func (m *statementInfoMetaDataFull) String() string {
	return fmt.Sprintf("statementInfoMetaDataFull{dataType=%d,columnOrParamName=%s,asClauseName=%s}", m.dataType, m.columnOrParamName, m.asClauseName)

}

type statementInfoMetaData struct{}

func (m *statementInfoMetaData) String() string {
	return "statementInfoMetaData{}"
}

func (m *statementInfoMetaDataLimited) read(reader *bufferReader, contentType uint16, contentLen uint16) error {
	m.dataType = reader.u16()
	m.maxDataBytes = reader.u64()
	m.numDigits = reader.u16()
	m.intervalDigits = reader.u16()
	m.fractionalDigits = reader.u16()
	return nil
}

func (m *statementInfoMetaDataLimited) getDataType() uint16 {
	return m.dataType
}

func (m *statementInfoMetaDataLimited) setReceiveItemNumber(i int) {
	m.itemNumberRcv = i
}

func (m *statementInfoMetaDataLimited) setTransmitItemNumber(i int) {
	m.itemNumberTrn = i
}

func (m *statementInfoMetaDataLimited) getPercision() uint16 {
	return m.numDigits
}

func (m *statementInfoMetaDataLimited) getScale() uint16 {
	return m.fractionalDigits
}

func (m *statementInfoMetaDataLimited) getMaxLength() uint64 {
	return m.maxDataBytes
}

func (m *statementInfoMetaDataFull) read(r *bufferReader, contentType uint16, contentLen uint16) error {
	startPos := r.position()
	endPos := startPos + int(contentLen)
	m.databaseName = r.asciiString(int(r.u16()))
	m.procOrTableName = r.asciiString(int(r.u16()))
	m.columnOrParamName = r.asciiString(int(r.u16()))
	m.columnPosition = r.u16()
	m.asClauseName = r.asciiString(int(r.u16()))
	m.title = r.asciiString(int(r.u16()))
	m.format = r.asciiString(int(r.u16()))
	m.defaultValue = r.asciiString(int(r.u16()))
	m.isIdentityColumn = r.u8()
	m.isDefinitelyWritable = r.u8()
	m.isNullable = r.u8()
	m.mayBeNull = r.u8()
	m.isSearchable = r.u8()
	m.isWritable = r.u8()
	m.dataType = r.u16()
	m.udtIndicator = r.u16()
	m.udtTypeName = r.asciiString(int(r.u16()))
	m.dataTypeMiscInfo = r.asciiString(int(r.u16()))
	m.maxDataLengthInBytes = r.u64()
	m.totalNumberOfDigits = r.u16()
	m.numberOfIntervalDigits = r.u16()
	m.numberOfFractionalDigits = r.u16()
	m.charsetCode = r.u8()
	m.maxNumberOfCharacters = r.u64()
	m.isCaseSensitive = r.u8()
	m.isSigned = r.u8()
	m.isKeyColumn = r.u8()
	m.isUnique = r.u8()
	m.isExpression = r.u8()
	m.isSortable = r.u8()
	m.sprocParameterDirection = r.u8()

	left := endPos - r.position()
	if left >= 7 {
		m.structDepth = r.u16()
		m.isTemporal = r.u8()
		m.attributeName = r.asciiString(int(r.u16()))
		m.serverDataType = r.u16()
	}

	left = endPos - r.position()
	if left >= 2 {
		m.arrayNumDimensions = r.u16()
		maxCard := make([]int, m.arrayNumDimensions)
		lowerBounds := make([]int, m.arrayNumDimensions)
		for i := 0; i < int(m.arrayNumDimensions); i++ {
			maxCard[i] = int(r.u32())
		}
		for i := 0; i < int(m.arrayNumDimensions); i++ {
			lowerBounds[i] = int(r.u32())
		}
		m.arrayMaxCardinalities = maxCard
		m.arrayLowerBounds = lowerBounds
	}

	left = endPos - r.position()
	if left >= 2 {
		m.catalogName = r.asciiString(int(r.u16()))
	}
	// TODO: Addl SP Logic
	return nil
}

func (m *statementInfoMetaDataFull) getDataType() uint16 {
	return m.dataType
}
func (m *statementInfoMetaDataFull) setReceiveItemNumber(i int) {
	m.itemNumberRcv = i
}
func (m *statementInfoMetaDataFull) setTransmitItemNumber(i int) {
	m.itemNumberTrn = i
}
func (m *statementInfoMetaDataFull) getPercision() uint16 {
	return m.totalNumberOfDigits
}
func (m *statementInfoMetaDataFull) getScale() uint16 {
	return m.numberOfFractionalDigits
}
func (m *statementInfoMetaDataFull) getMaxLength() uint64 {
	return m.maxDataLengthInBytes
}

func (m *statementInfoMetaData) read(reader *bufferReader, contentType uint16, contentLen uint16) error {
	return nil
}

func (m *statementInfoMetaData) getDataType() uint16 {
	return 0
}

func (m *statementInfoMetaData) setReceiveItemNumber(i int) {

}

func (m *statementInfoMetaData) setTransmitItemNumber(i int) {

}

func (m *statementInfoMetaData) getPercision() uint16 {
	return 0
}

func (m *statementInfoMetaData) getScale() uint16 {
	return 0
}

func (m *statementInfoMetaData) getMaxLength() uint64 {
	return 0
}

func (m *statementInfoMetaDataFull) isStructType() bool {
	return getTdBasicType(m.dataType) == 440
}
func (m *statementInfoMetaDataFull) isArrayType() bool {
	bt := getTdBasicType(m.dataType)
	return bt == 504 || bt == 508
}

func (m *statementInfoMetaDataFull) addAttributeItem(child *statementInfoMetaDataFull) {
	m.attributes = append(m.attributes, child)
}

func (m *statementInfoMetaDataFull) getColumnName() string {
	if m.asClauseName != "" {
		return m.asClauseName
	}
	return m.columnOrParamName
}

type configResponseParcel struct {
	length int

	defaultTransactionSemantics byte
	defaultTDCharSetCode        byte
	ampCount                    uint16
	charSetNameToCode           map[string]byte

	maximumNumberOfSegments uint16
	maximumSegmentSize      uint32

	lobSupport                     byte
	aphSupport                     byte
	extendedRspSupport             byte
	positioningSupport             byte
	msrPositioningSupport          byte
	udtSupport                     byte
	enhancedStatementStatusSupport byte
	aphResponseSupport             byte
	arraySupport                   byte
	outParamArgSupport             byte
	generatedKeysSupport           byte
	trustedSessionsSupport         byte
	largeDecimalBIGINT             byte
	statementInfoSupport           byte
	dynamicResultSetsSupport       byte
	statementInfoRequestSupport    byte
	udtTransformOffSupport         byte
	trustedSQLSupport              byte
	fastExportNoSpoolSupport       byte
	checkWorkloadSupport           byte
	extNamesOnDisk                 byte
	extNamesInViews                byte
	extNamesInDbs                  byte
	extNamesInParcels              byte
	fetchRowCountSupport           byte
	statementIndependenceSupport   byte
	numberDataTypeSupport          byte
	periodDataTypeSupport          byte
	elicitByNameSupport            byte
	clientAttributesSupport        byte
	arrayDataTypeSupport           byte
	xmlSupport                     byte
	statementStatusLevel           byte
	failFastSupport                byte
	unityClientAttributesSupport   byte
	jsonSupport                    byte
	recoverableNPSupport           byte
	redriveSupport                 byte
	controlDataSupport             byte
	monitorAsyncAbortSupport       byte
	slobClientToServerSupport      byte
	slobServerToClientSupport      byte
	dataSetAvroSupport             byte
	dataSetCSVSupport              byte
	queryableViewColumnInfoSupport byte
	odbcScalarFunctionLevel        byte
	otfSupport                     byte
	vsdSupport                     byte

	dbsRelease string
	dbsVersion string

	maxBinLiteralChars                  uint32
	maxCharLiteralChars                 uint32
	maxColNameChars                     uint32
	maxColGrpBy                         uint32
	maxColOrdrBy                        uint32
	maxColInSel                         uint32
	maxColinTbl                         uint32
	maxSchemaNameChars                  uint32
	maxProcedureNameChars               uint32
	maxRowBytes                         uint32
	maxRequestBytes                     uint32
	maxResponseBytes                    uint32
	maxTblNameChars                     uint32
	maxTblinSel                         uint32
	maxUsrNameChars                     uint32
	maxJsonByteCount                    uint32
	maxLobBytes                         uint64
	maxSPParams                         uint32
	maxObjectNameChars                  uint32
	maxFieldsUsingRow                   uint32
	maxUsingDataBytes                   uint32
	maxDecimal                          uint32
	maxColBytes                         uint32
	maxVarcharChars                     uint32
	maxCharChars                        uint32
	maxGraphicChars                     uint32
	maxVargraphicChars                  uint32
	maxVarbyteBytes                     uint32
	maxByteBytes                        uint32
	maxParamsInRequest                  uint32
	maxTimeScale                        uint32
	maxTimeStampScale                   uint32
	maxIntervalToSecondScale            uint32
	maxCatalogNameChars                 uint32
	maxDeferredByNameFileNameBytes      uint32
	maxAvailableBytesInResponseRow      uint32
	supportedTransactionIsolationLevels int
}

func (p *configResponseParcel) getFlavor() parcelFlavor {
	return flavorConfigResponse
}

func (p *configResponseParcel) String() string {
	return fmt.Sprintf("configResponseParcel{dbsRelease=%s, dbsVersion=%s, defaultTransactionSemantics=%d, lobSupport=%b, maxRowBytes=%d}", p.dbsRelease, p.dbsVersion, p.defaultTransactionSemantics, p.lobSupport, p.maxRowBytes)
}

func (p *configResponseParcel) fromBuffer(reader *bufferReader, length int) error {
	p.charSetNameToCode = make(map[string]byte)

	flavorPosition := reader.position() - parcelHeaderLen
	p.length = length

	reader.seek(flavorPosition + 14)

	ifpRecCount := reader.u16()
	reader.skip(int(ifpRecCount) * 4)

	p.ampCount = reader.u16()
	reader.skip(int(p.ampCount) * 2)

	p.defaultTDCharSetCode = reader.u8()
	reader.skip(1)

	charSetCount := reader.u16()
	for i := 0; i < int(charSetCount); i++ {
		code := reader.u8()
		reader.skip(1)
		name := strings.TrimSpace(reader.asciiString(30))
		p.charSetNameToCode[name] = code
	}

	p.defaultTransactionSemantics = reader.byteAt(reader.position() + 6)
	reader.skip(7)

	p.determineFeatureSupport(reader, flavorPosition)

	return nil
}

func (p *configResponseParcel) determineFeatureSupport(reader *bufferReader, flavorPosition int) {
	for reader.position()+4 < flavorPosition+p.length {
		tag := reader.u16()
		tagLen := int(reader.u16())
		pos := reader.position()

		switch tag {
		case 7:
			p.maximumNumberOfSegments = reader.u16At(pos + 2)
			p.maximumSegmentSize = reader.u32At(pos + 4)
			if tagLen > 116 {
				p.maxRowBytes = reader.u32At(pos + 8)
				p.maxLobBytes = reader.u64At(pos + 12)
				p.maxRequestBytes = reader.u32At(pos + 20)
				p.maxResponseBytes = reader.u32At(pos + 24)
				p.maxSPParams = reader.u32At(pos + 28)
				p.maxColGrpBy = reader.u32At(pos + 32)
				p.maxColOrdrBy = reader.u32At(pos + 36)
				p.maxColInSel = reader.u32At(pos + 40)
				p.maxColinTbl = reader.u32At(pos + 44)
				p.maxObjectNameChars = reader.u32At(pos + 48)
				p.maxTblinSel = reader.u32At(pos + 52)
				p.maxFieldsUsingRow = reader.u32At(pos + 56)
				p.maxUsingDataBytes = reader.u32At(pos + 60)
				p.maxBinLiteralChars = reader.u32At(pos + 64)
				p.maxCharLiteralChars = reader.u32At(pos + 68)
				p.maxDecimal = reader.u32At(pos + 72)
				p.maxColBytes = reader.u32At(pos + 76)
				p.maxVarcharChars = reader.u32At(pos + 80)
				p.maxCharChars = reader.u32At(pos + 84)
				p.maxGraphicChars = reader.u32At(pos + 88)
				p.maxVargraphicChars = reader.u32At(pos + 92)
				p.maxVarbyteBytes = reader.u32At(pos + 96)
				p.maxByteBytes = reader.u32At(pos + 100)
				p.maxParamsInRequest = reader.u32At(pos + 104)
				p.maxTimeScale = reader.u32At(pos + 108)
				p.maxTimeStampScale = reader.u32At(pos + 112)
				p.maxIntervalToSecondScale = reader.u32At(pos + 116)
				p.maxColNameChars = p.maxObjectNameChars
				p.maxProcedureNameChars = p.maxObjectNameChars
				p.maxSchemaNameChars = p.maxObjectNameChars
				p.maxTblNameChars = p.maxObjectNameChars
				p.maxUsrNameChars = p.maxObjectNameChars
				p.maxCatalogNameChars = p.maxObjectNameChars
			}
			if tagLen > 120 {
				p.maxDeferredByNameFileNameBytes = reader.u32At(pos + 120)
			}
			if tagLen > 124 {
				p.maxAvailableBytesInResponseRow = reader.u32At(pos + 124)
			}
			if tagLen > 128 {
				p.maxJsonByteCount = reader.u32At(pos + 128)
			}
		case 10:
			p.arraySupport = reader.byteAt(pos + 1)
			p.outParamArgSupport = reader.byteAt(pos + 3)
			p.largeDecimalBIGINT = reader.byteAt(pos + 4)
			p.generatedKeysSupport = reader.byteAt(pos + 5)
			p.trustedSessionsSupport = reader.byteAt(pos + 11)
			if tagLen > 13 {
				p.trustedSQLSupport = reader.byteAt(pos + 13)
			}
			if tagLen > 16 {
				p.xmlSupport = reader.byteAt(pos + 16)
			}
			if tagLen > 21 {
				p.jsonSupport = reader.byteAt(pos + 21)
			}
			if tagLen > 24 {
				p.dataSetAvroSupport = reader.byteAt(pos + 24)
			}
			if tagLen > 25 {
				p.dataSetCSVSupport = reader.byteAt(pos + 25)
			}
			if tagLen > 27 {
				p.odbcScalarFunctionLevel = reader.byteAt(pos + 27)
			}
			if tagLen > 28 {
				p.otfSupport = reader.byteAt(pos + 28)
			}
			if tagLen > 29 {
				p.vsdSupport = reader.byteAt(pos + 29)
			}
		case 11:
			p.lobSupport = reader.byteAt(pos)
			p.aphSupport = reader.byteAt(pos + 1)
			p.extendedRspSupport = reader.byteAt(pos + 2)
			if tagLen > 3 {
				p.positioningSupport = reader.byteAt(pos + 3)
			}
			if tagLen > 4 {
				p.udtSupport = reader.byteAt(pos + 4)
			}
			if tagLen > 5 {
				p.enhancedStatementStatusSupport = reader.byteAt(pos + 5)
			}
			if tagLen > 6 {
				p.aphResponseSupport = reader.byteAt(pos + 6)
			}
			if tagLen > 7 {
				p.statementInfoSupport = reader.byteAt(pos + 7)
			}
			if tagLen > 9 {
				p.dynamicResultSetsSupport = reader.byteAt(pos + 9)
			}
			if tagLen > 10 {
				p.msrPositioningSupport = reader.byteAt(pos + 10)
			}
			if tagLen > 11 {
				p.statementInfoRequestSupport = reader.byteAt(pos + 11)
			}
			if tagLen > 12 {
				p.udtTransformOffSupport = reader.byteAt(pos + 12)
			}
			if tagLen > 13 {
				p.periodDataTypeSupport = reader.byteAt(pos + 13)
			}
			if tagLen > 14 {
				p.elicitByNameSupport = reader.byteAt(pos + 14)
			}
			if tagLen > 15 {
				p.clientAttributesSupport = reader.byteAt(pos + 15)
			}
			if tagLen > 16 {
				p.fetchRowCountSupport = reader.byteAt(pos + 16)
			}
			if tagLen > 17 {
				p.statementIndependenceSupport = reader.byteAt(pos + 17)
			}
			if tagLen > 18 {
				p.recoverableNPSupport = reader.byteAt(pos + 18)
			}
			if tagLen > 19 {
				p.arrayDataTypeSupport = reader.byteAt(pos + 19)
			}
			if tagLen > 21 {
				p.redriveSupport = reader.byteAt(pos + 21)
			}
			if tagLen > 22 {
				p.controlDataSupport = reader.byteAt(pos + 22)
			}
			if tagLen > 24 {
				p.numberDataTypeSupport = reader.byteAt(pos + 24)
			}
			if tagLen > 25 {
				p.statementStatusLevel = reader.byteAt(pos + 25)
			}
			if tagLen > 26 {
				p.failFastSupport = reader.byteAt(pos + 26)
			}
			if tagLen > 27 {
				p.unityClientAttributesSupport = reader.byteAt(pos + 27)
			}
			if tagLen > 30 {
				p.slobClientToServerSupport = reader.byteAt(pos + 30)
			}
			if tagLen > 31 {
				p.slobServerToClientSupport = reader.byteAt(pos + 31)
			}
			if tagLen > 33 {
				p.queryableViewColumnInfoSupport = reader.byteAt(pos + 33)
			}
		case 12:
			if tagLen > 1 {
				p.fastExportNoSpoolSupport = reader.byteAt(pos + 1)
			}
			if tagLen > 2 {
				p.checkWorkloadSupport = reader.byteAt(pos + 2)
			}
			if tagLen > 4 {
				p.monitorAsyncAbortSupport = reader.byteAt(pos + 4)
			}
		case 13:
			p.dbsRelease = strings.TrimSpace(reader.asciiStringAt(pos, 30))
			p.dbsVersion = strings.TrimSpace(reader.asciiStringAt(pos+30, 32))
		case 14:
			p.extNamesOnDisk = reader.byteAt(pos)
			p.extNamesInViews = reader.byteAt(pos + 1)
			p.extNamesInDbs = reader.byteAt(pos + 2)
			p.extNamesInParcels = reader.byteAt(pos + 3)
		}

		reader.seek(pos + tagLen)
	}

	if p.dbsRelease == "" {
		p.supportedTransactionIsolationLevels = 8
	} else {
		p.supportedTransactionIsolationLevels = 9
	}
}
