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
	"net"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"time"
)

/***********************
	Handshake Parcels
************************/

// Client Config Parcel
type clientConfigParcel struct {
	redriveLevel int
}

func newClientConfigParcel(redriveLevel int) *clientConfigParcel {
	return &clientConfigParcel{
		redriveLevel: redriveLevel,
	}
}

func (p *clientConfigParcel) getFlavor() parcelFlavor {
	return flavorClientConfig
}

func (p *clientConfigParcel) getLength() int {
	length := parcelHeaderLen +
		4 +
		4 +
		len(tdGssVersion) +
		4 +
		len(driverVersion) +
		4 +
		len(staticBytes) +
		4 +
		len(staticBytes) +
		4 +
		4
	if p.redriveLevel >= 1 {
		length += 8 + len(staticBytes)
	}
	if p.redriveLevel >= 2 {
		length += 4
	}
	if p.redriveLevel >= 3 {
		length += 4
	}
	return length
}

func (p *clientConfigParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.u32(uint32(1))
	w.tlv16(uint16(2), tdGssVersion)
	w.tlv16(uint16(1), driverVersion)
	if p.redriveLevel >= 1 {
		w.tz16(4)
		w.tlv16(uint16(8), staticBytes)
	}
	if p.redriveLevel >= 2 {
		w.tz16(3)
	}
	if p.redriveLevel >= 3 {
		w.tz16(5)
	}
	w.tlv16(uint16(9), staticBytes)
	w.tlv16(uint16(11), staticBytes)
	w.tz16(14)
	w.tz16(15)
	return nil
}

// SSO Request Parcel
type ssoRequestParcel struct {
	method   byte
	trip     byte
	authData []byte
}

func newSSORequestParcel(trip byte, method byte, authData []byte) *ssoRequestParcel {
	return &ssoRequestParcel{
		method:   method,
		trip:     trip,
		authData: authData,
	}
}

func (p *ssoRequestParcel) getFlavor() parcelFlavor {
	return flavorSsoRequest
}

func (p *ssoRequestParcel) getLength() int {
	if p.authData == nil {
		return parcelHeaderLen + 4
	}
	return parcelHeaderLen + 4 + len(p.authData)
}

func (p *ssoRequestParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.byte(p.method)
	w.byte(p.trip)
	w.u16(uint16(len(p.authData)))
	w.bytes(p.authData)
	return nil
}

// Assign Parcel
type assignParcel struct {
	username []byte
}

func newAssignParcel(username string) *assignParcel {
	paddedUsername := fmt.Sprintf("%-32s", username)
	return &assignParcel{
		username: []byte(paddedUsername),
	}
}

func (p *assignParcel) getFlavor() parcelFlavor {
	return flavorAssign
}

func (p *assignParcel) getLength() int {
	return parcelHeaderLen + len(p.username)
}

func (p *assignParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.bytes(p.username)
	return nil
}

/***********************
	Logon Parcels
************************/

// Logon Parcel
type logonParcel struct {
	username string
	password string
}

func newLogonParcel(username string, password string) *logonParcel {
	return &logonParcel{
		username: username,
		password: password,
	}
}

func (p *logonParcel) getFlavor() parcelFlavor {
	return flavorLogon
}

func (p *logonParcel) getEncodedLogonString() []byte {
	return fmt.Appendf(nil, "\"%s\",\"%s\"", p.username, p.password)
}

func (p *logonParcel) getLength() int {
	bodyLen := len(p.getEncodedLogonString())
	return parcelHeaderLen + bodyLen
}

func (p *logonParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.bytes(p.getEncodedLogonString())
	return nil
}

// Logoff Parcel
type logoffParcel struct {
}

func newLogoffParcel() *logoffParcel {
	return &logoffParcel{}
}

func (p *logoffParcel) getFlavor() parcelFlavor {
	return flavorLogoff
}

func (p *logoffParcel) getLength() int {
	return parcelHeaderLen
}

func (p *logoffParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	return nil
}

// SessionOptionsParcel
type sessionOptionsParcel struct {
	body []byte
}

func newSessionOptionsParcel(config *Config, capabilities *connectionCapabilities) *sessionOptionsParcel {
	var tmode byte = 'D'
	switch config.TMode {
	case "TERA":
		tmode = 'T'
	case "ANSI":
		tmode = 'A'
	}

	if capabilities.statementStatusLevel >= 1 {
		// ESS Flag and Level
		return &sessionOptionsParcel{
			body: []byte{tmode, 'N', 'N', 'D', 'E', 0, 0, 0, 1, 0},
		}
	}
	return &sessionOptionsParcel{
		body: []byte{tmode, 'N', 'N', 'D', 0, 0, 0, 0, 0, 0},
	}
}

func (p *sessionOptionsParcel) getFlavor() parcelFlavor {
	return flavorSessionOptions
}

func (p *sessionOptionsParcel) getLength() int {
	return parcelHeaderLen + len(p.body)
}

func (p *sessionOptionsParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.bytes(p.body)
	return nil
}

// ConnectParcel
type connectParcel struct {
	partitionName string
	logonSeqNum   int
	function      int
}

func newConnectParcel(config *Config, logonSeqNum int) *connectParcel {
	return &connectParcel{
		logonSeqNum:   logonSeqNum,
		function:      config.ConnectFunction,
		partitionName: config.Partition,
	}
}

func (p *connectParcel) getFlavor() parcelFlavor {
	return flavorConnect
}

func (p *connectParcel) getLength() int {
	return parcelHeaderLen + 24
}

func (p *connectParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.bytes([]byte(fmt.Sprintf("%-16s", p.partitionName)))
	w.u32(uint32(p.logonSeqNum))
	w.u16(uint16(p.function))
	w.u16(0)
	return nil
}

// LogonData Parcel
type logonDataParcel struct {
	logonData string
}

func newLogonDataParcel(remoteHost string, remotePort int, lssType string, connectionId string) *logonDataParcel {
	parcel := &logonDataParcel{}
	var username string
	u, err := user.Current()
	if err != nil {
		username = "unknown"
	} else {
		username = truncateString(u.Username, 20)
	}
	driverVersion := "GoTeradatasql0.0.1"
	driverInfo := truncateString(fmt.Sprintf("Go%s%s;%s", lssType, driverVersion, runtime.Version()), 26)
	logonData := fmt.Sprintf(" CID=%s %s %s 01 LSS", connectionId, username, driverInfo)
	remain := 97 - len(logonData)
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	parcel.logonData = truncateString(fmt.Sprintf("%s;/%s:%d", hostname, remoteHost, remotePort), remain) + logonData
	return parcel
}

func (p *logonDataParcel) getFlavor() parcelFlavor {
	return flavorData
}

func (p *logonDataParcel) getLength() int {
	return parcelHeaderLen + len(p.logonData)
}

func (p *logonDataParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.bytes([]byte(p.logonData))
	return nil
}

/***********************
	Query Parcels
************************/

const (
	requestModeBatch          = 66
	requestModeExec           = 69
	requestModeInline         = 73
	requestModeMultipartIndic = 77
	requestModePrepare        = 80
	requestModeStatic         = 83

	dbcFunctionExecute         = 'B' // B_MODE
	dbcFunctionExecutePrepared = 'E' // E_MODE
	dbcFunctionPrepare         = 'P' // P_MODE
	dbcFunctionCall            = 'S' // S_MODE

	resultSetReturnSender   = 0
	resultSetReturnClient   = 1
	resultSetReturnCaller   = 2
	resultSetReturnClientSP = 3
	resultSetReturnCallerSP = 4
)

// Request Parcel
type requestParcel struct {
	statement []byte
}

func newRequestParcel(statement string) *requestParcel {
	return &requestParcel{
		statement: []byte(normalizeStatementText(statement)),
	}
}

func (p *requestParcel) getFlavor() parcelFlavor {
	return flavorRequest
}

func (p *requestParcel) getLength() int {
	return parcelHeaderLen + len(p.statement)
}

func (p *requestParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.bytes([]byte(p.statement))
	return nil
}

type indicRequestParcel struct {
	*requestParcel
}

func newIndicRequestParcel(statement string) *indicRequestParcel {
	return &indicRequestParcel{
		requestParcel: newRequestParcel(statement),
	}
}

func (p *indicRequestParcel) getFlavor() parcelFlavor {
	return flavorIndicRequest
}

// EndRequest Parcel
/*func newEndRequestParcel(statement string) *endRequstParcel {
	return &endRequstParcel{}
}

func (p *endRequstParcel) getLength() int {
	return parcelHeaderLen
}

func (p *endRequstParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	return nil
}*/

// FetchRowCountParcel
type fetchRowCountParcel struct {
	rowCount uint32
}

func newFetchRowCountParcel(rowCount int) *fetchRowCountParcel {
	return &fetchRowCountParcel{rowCount: uint32(rowCount)}
}

func (p *fetchRowCountParcel) getFlavor() parcelFlavor {
	return flavorFetchRowCount
}

func (p *fetchRowCountParcel) getLength() int {
	return 9
}

func (p *fetchRowCountParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.u32(p.rowCount)
	w.byte(1)
	return nil
}

// Options Parcel
type optionsParcel struct {
	requestMode              byte
	dBCFunction              byte
	lobSelect                bool
	lobMode                  byte
	returnStatementInfo      bool
	dynamicResultSetsAllowed bool
	returnExtendedNames      bool
	returnPeriodStructs      bool
	trustMode                bool
	xmlSupport               bool
	xmlFormat                byte
	failFast                 bool
	vdsSupport               bool
	arraySupport             bool
	largeResponseSupport     bool
	includeCatalogName       bool
	aphSupport               bool
}

func (p *optionsParcel) String() string {
	return fmt.Sprintf(
		"optionsParcel{requestMode: 0x%02x, dBCFunction: 0x%02x, lobSelect: %t, "+
			"returnStatementInfo: %t, dynamicResultSetsAllowed: %t, returnExtendedNames: %t, "+
			"returnPeriodStructs: %t, trustMode: %t, xmlSupport: %t, xmlFormat: 0x%02x, "+
			"failFast: %t, vdsSupport: %t, arraySupport: %t, largeResponseSupport: %t, "+
			"includeCatalogName: %t, aphSupport: %t}",
		p.requestMode,
		p.dBCFunction,
		p.lobSelect,
		p.returnStatementInfo,
		p.dynamicResultSetsAllowed,
		p.returnExtendedNames,
		p.returnPeriodStructs,
		p.trustMode,
		p.xmlSupport,
		p.xmlFormat,
		p.failFast,
		p.vdsSupport,
		p.arraySupport,
		p.largeResponseSupport,
		p.includeCatalogName,
		p.aphSupport,
	)
}

func newOptionsParcelInline(con *teradataConnection) *optionsParcel {
	requestMode := requestModeInline
	if con.capabilities.lobSupport {
		requestMode = requestModeMultipartIndic
	}
	return newOptionsParcel(con, requestMode, dbcFunctionExecute, 'S')
}

func newOptionsParcelPrepare(con *teradataConnection) *optionsParcel {
	requestMode := requestModeInline
	if con.capabilities.lobSupport {
		requestMode = requestModeMultipartIndic
	}
	return newOptionsParcel(con, requestMode, dbcFunctionCall, 'S')
}

func newOptionsParcelExecute(con *teradataConnection) *optionsParcel {
	requestMode := requestModeInline
	if con.capabilities.lobSupport {
		requestMode = requestModeMultipartIndic
	}
	return newOptionsParcel(con, requestMode, dbcFunctionExecutePrepared, 'S')
}

func newOptionsParcelLobSelect(con *teradataConnection) *optionsParcel {
	requestMode := requestModeInline
	if con.capabilities.lobSupport {
		requestMode = requestModeMultipartIndic
	}
	return newOptionsParcel(con, requestMode, dbcFunctionExecutePrepared, 'I')
}

func newOptionsParcel(con *teradataConnection, requestMode int, dbcFunction int, lobMode byte) *optionsParcel {
	return &optionsParcel{
		requestMode:              byte(requestMode),
		dBCFunction:              byte(dbcFunction),
		lobSelect:                con.config.LOBSupport && con.capabilities.lobSupport,
		lobMode:                  lobMode,
		returnStatementInfo:      true,
		dynamicResultSetsAllowed: con.capabilities.dynamicResultSetsSupport,
		returnExtendedNames:      con.capabilities.extNamesInParcels,
		returnPeriodStructs:      con.capabilities.periodDataTypeSupport,
		trustMode:                con.capabilities.trustedSQLSupport,
		xmlSupport:               con.capabilities.xmlSupport,
		xmlFormat:                'C', //TODO
		failFast:                 con.capabilities.failFastSupport,
		vdsSupport:               false, //con.capabilities.vsdSupport,
		arraySupport:             con.capabilities.arraySupport,
		largeResponseSupport:     con.capabilities.maxAvailableBytesInResponseRow > 64768,
		includeCatalogName:       con.capabilities.otfSupport,
		aphSupport:               con.capabilities.aphSupport, //TODO: Only set if using alt header and server supports it (con.capabilities.aphSupport)
	}
}

func (p *optionsParcel) getFlavor() parcelFlavor {
	return flavorOptions
}

func (p *optionsParcel) getLength() int {
	len := 10
	if p.dynamicResultSetsAllowed {
		len = 11
	}
	if p.returnExtendedNames || p.returnPeriodStructs || p.trustMode {
		len = 15
	}
	if p.arraySupport {
		len = 16
	}
	if p.xmlSupport || p.failFast {
		len = 18
	}
	if p.largeResponseSupport {
		len = 21
	}
	if p.vdsSupport {
		len = 22
	}
	return parcelHeaderLen + len
}

func (p *optionsParcel) write(w *bufferWriter) error {
	len := p.getLength()
	startPos := w.position()
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(len))
	w.byte(p.requestMode)
	w.byte(p.dBCFunction)
	if p.lobSelect {
		w.byte(p.lobMode) //lobSelect
		w.byte('U')       //clobTranslate
	} else {
		w.skip(2)
	}
	if p.aphSupport {
		w.byte('Y')
	} else {
		w.byte(0)
	}
	w.byte(boolOptionByteZero(p.returnStatementInfo))
	w.byte('Y') // UDTTransformsOff
	w.byte(38)  // maxDecimalPrecision
	w.byte(0)   //generatedKeys
	w.byte(boolOptionByteZero(p.dynamicResultSetsAllowed))

	if w.position()-startPos < len {
		w.byte(0) //spReturnResult TODO for storedProcedure work
	}
	if w.position()-startPos < len {
		w.byte(0) //boolOptionByteZero(p.returnPeriodStructs)
	}
	if w.position()-startPos < len {
		if p.returnExtendedNames {
			w.byte(1)
		} else {
			w.byte(0)
		}
	}
	if w.position()-startPos < len {
		w.byte(boolOptionByteNo(p.trustMode))
	}
	if w.position()-startPos < len {
		w.byte(boolOptionByteNo(false)) //StatementIndependence
	}
	if w.position()-startPos < len {
		w.byte(boolOptionByteZero(p.arraySupport))
	}
	if w.position()-startPos < len {
		if p.xmlSupport {
			w.byte(p.xmlFormat)
		} else {
			w.byte(0)
		}
	}
	if w.position()-startPos < len {
		w.byte(boolOptionByteNo(p.failFast))
	}
	if w.position()-startPos < len {
		w.byte('N') //UnityTDWM
	}
	if w.position()-startPos < len {
		w.byte('N') //SendSPSQLToUnity
	}
	if w.position()-startPos < len {
		w.byte(1) //LargeRows
	}
	if w.position()-startPos < len {
		w.byte(boolOptionByteZero(p.includeCatalogName))
	}

	w.skip(startPos + len - w.position())

	return nil
}

func boolOptionByteZero(b bool) byte {
	if b {
		return 'Y'
	}
	return 0
}
func boolOptionByteNo(b bool) byte {
	if b {
		return 'Y'
	}
	return 'N'
}

// Cancel Parcel
type cancelParcel struct{}

func newCancelParcel() *cancelParcel {
	return &cancelParcel{}
}

func (p *cancelParcel) getFlavor() parcelFlavor {
	return flavorCancel
}

func (p *cancelParcel) getLength() int {
	return parcelHeaderLen
}

func (p *cancelParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	return nil
}

// Respond Parcel
type respondParcel struct {
	maxMessageSize uint16
}

func newRespondParcel(capabilities *connectionCapabilities, config *Config) *respondParcel {
	maxRow := config.MaxMessageSize
	if capabilities.maxAvailableBytesInResponseRow < maxRow {
		maxRow = capabilities.maxAvailableBytesInResponseRow
	}
	return &respondParcel{
		maxMessageSize: uint16(maxRow),
	}
}

func (p *respondParcel) getFlavor() parcelFlavor {
	return flavorRespond
}

func (p *respondParcel) getLength() int {
	return parcelHeaderLen + 2
}

func (p *respondParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.u16(p.maxMessageSize)
	return nil
}

type keepRespondParcel struct {
	*respondParcel
}

func newKeepRespondParcel(capabilities *connectionCapabilities, config *Config) *keepRespondParcel {
	return &keepRespondParcel{
		newRespondParcel(capabilities, config),
	}
}

func (p *keepRespondParcel) getFlavor() parcelFlavor {
	return flavorKeepRespond
}

func (p *keepRespondParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.u16(p.maxMessageSize)
	return nil
}

type bigRespondParcel struct {
	maxMessageSize uint32
}

func newBigRespondParcel(capabilities *connectionCapabilities, config *Config) *bigRespondParcel {
	maxRow := config.MaxMessageSize
	if capabilities.maxAvailableBytesInResponseRow < maxRow {
		maxRow = capabilities.maxAvailableBytesInResponseRow
	}
	return &bigRespondParcel{
		maxMessageSize: uint32(maxRow),
	}
}

func (p *bigRespondParcel) getFlavor() parcelFlavor {
	return flavorBigRespond
}

func (p *bigRespondParcel) getLength() int {
	return parcelHeaderLen + 4
}

func (p *bigRespondParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.u32(p.maxMessageSize)
	return nil
}

type bigKeepRespondParcel struct {
	*bigRespondParcel
}

func newBigKeepRespondParcel(capabilities *connectionCapabilities, config *Config) *bigKeepRespondParcel {
	return &bigKeepRespondParcel{
		newBigRespondParcel(capabilities, config),
	}
}

func (p *bigKeepRespondParcel) getFlavor() parcelFlavor {
	return flavorBigKeepRespond
}

func (p *bigKeepRespondParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.u32(p.maxMessageSize)
	return nil
}

type slobRespondParcel struct {
	maxSingleLobBytes uint64
	maxRowLobBytes    uint64
}

func newSlobRespondParcel(capabilities *connectionCapabilities, config *Config) *slobRespondParcel {
	maxRow := config.MaxMessageSize
	if capabilities.maxAvailableBytesInResponseRow < maxRow {
		maxRow = capabilities.maxAvailableBytesInResponseRow
	}
	return &slobRespondParcel{
		maxSingleLobBytes: uint64(config.LOBRecieveThreshold),
		maxRowLobBytes:    uint64(maxRow),
	}
}

func (p *slobRespondParcel) getFlavor() parcelFlavor {
	return flavorSlobRespond
}

func (p *slobRespondParcel) getLength() int {
	return parcelHeaderLen + 16
}

func (p *slobRespondParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.u64(p.maxSingleLobBytes)
	w.u64(p.maxRowLobBytes)
	return nil
}

// Data Parcel
type dataParcel struct {
	data          []byte
	includeLength bool
}

func newDataParcel(data []byte, includeLength bool) *dataParcel {
	return &dataParcel{
		data:          data,
		includeLength: includeLength,
	}
}

func (p *dataParcel) getFlavor() parcelFlavor {
	return flavorData
}

func (p *dataParcel) getLength() int {
	if p.includeLength {
		return parcelHeaderLen + len(p.data) + 2
	}
	return parcelHeaderLen + len(p.data)
}

func (p *dataParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	if p.includeLength {
		w.u16(uint16(len(p.data)))
	}
	w.bytes(p.data)
	return nil
}

type dataInfoParcel struct {
	dataTypes  []uint16
	dataValues []driver.Value
	metas      []statementInfoMetaItem
}

func newDataInfoParcel(dataTypes []uint16, dataValues []driver.Value, paramMetas []statementInfoMetaItem) *dataInfoParcel {
	return &dataInfoParcel{
		dataTypes:  dataTypes,
		dataValues: dataValues,
		metas:      paramMetas,
	}
}

func (p *dataInfoParcel) getFlavor() parcelFlavor {
	return flavorDataInfo
}

func (p *dataInfoParcel) getLength() int {
	return parcelHeaderLen + 2 + len(p.dataTypes)*4
}

func (p *dataInfoParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.u16(uint16(len(p.dataTypes)))
	for i, l := range calculateParamLengths(p.dataTypes, p.dataValues, p.metas) {
		w.u16(p.dataTypes[i])
		w.u16(l)
	}
	return nil
}

// IndicData Parcel
type indicDataParcel struct {
	dataTypes  []uint16
	dataValues []driver.Value
	metas      []statementInfoMetaItem
}

func newIndicDataParcel(dataTypes []uint16, dataValues []driver.Value, paramMetas []statementInfoMetaItem) *indicDataParcel {
	return &indicDataParcel{
		dataTypes:  dataTypes,
		dataValues: dataValues,
		metas:      paramMetas,
	}
}

func (p *indicDataParcel) getFlavor() parcelFlavor {
	return flavorIndicData
}

func (p *indicDataParcel) getLength() int {
	nullmapLen := (len(p.dataTypes) + 7) / 8 // MSB First bitmap
	parcelLen := parcelHeaderLen + nullmapLen
	for _, l := range calculateWireParamLengths(p.dataTypes, p.dataValues, p.metas) {
		parcelLen += int(l)
	}
	return parcelLen
}

func (p *indicDataParcel) write(w *bufferWriter) error {
	return p.writeWithFlavor(p.getFlavor(), w)
}

func (p *indicDataParcel) writeWithFlavor(flvr parcelFlavor, w *bufferWriter) error {
	w.u16(uint16(flvr))
	w.u16(uint16(p.getLength()))
	// Null Bitmap - param 1 = bit 7, param 2 = bit 6
	nullmap := make([]byte, (len(p.dataTypes)+7)/8)
	for i, v := range p.dataValues {
		if v == nil {
			nullmap[i/8] |= 1 << (7 - uint(i%8))
		}
	}
	w.bytes(nullmap)

	for i, v := range p.dataValues {
		err := writeParamValue(v, w, p.metas[i])
		if err != nil {
			return err
		}
	}

	return nil
}

type multipartIindicDataParcel struct {
	*indicDataParcel
}

func newMultipartIndicDataParcel(dataTypes []uint16, dataValues []driver.Value, paramMetas []statementInfoMetaItem) *multipartIindicDataParcel {
	return &multipartIindicDataParcel{
		indicDataParcel: newIndicDataParcel(dataTypes, dataValues, paramMetas),
	}
}

func (p *multipartIindicDataParcel) getFlavor() parcelFlavor {
	return flavorMultiPartIndicData
}

func (p *multipartIindicDataParcel) write(w *bufferWriter) error {
	return p.writeWithFlavor(p.getFlavor(), w)
}

type endMultipartIindicDataParcel struct{}

func newEndMultipartIindicDataParcel() *endMultipartIindicDataParcel {
	return &endMultipartIindicDataParcel{}
}

func (p *endMultipartIindicDataParcel) getFlavor() parcelFlavor {
	return flavorIndicData
}

func (p *endMultipartIindicDataParcel) getLength() int {
	return parcelHeaderLen
}

func (p *endMultipartIindicDataParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	return nil
}

// ClientAttributes Parcel
type clientAttributesParcel struct {
	attributeData []byte
}

const (
	pclcliattHostname              = 7
	pclcliattProcThrID             = 8
	pclcliattSysUserID             = 9
	pclcliattProgName              = 10
	pclcliattOSName                = 11
	pclcliattEnvName               = 14
	pclcliattVMName                = 22
	pclcliattGrpSecProd            = 16
	pclcliattSessDesc              = 25
	pclcliattJobData               = 27
	pclcliattClientKind            = 28
	pclcliattClientVersion         = 29
	pclcliattClientAttributesEx    = 30
	pclcliattClientIPAddrByClient  = 31
	pclcliattClientPortByClient    = 32
	pclcliattServerIPAddrByClient  = 33
	pclcliattServerPortByClient    = 34
	pclcliattCOPSuffixedHostName   = 45
	pclcliattClientConfidentiality = 58
	pclcliattEnd                   = 32767
)

const clientAttrCharSet = 0xff

func appendClientAttrString(buf []byte, tag uint16, value string) []byte {
	if value == "" {
		return buf
	}
	v := []byte(value)
	buf = append(buf, byte(tag>>8), byte(tag))
	length := uint16(1 + len(v))
	buf = append(buf, byte(length>>8), byte(length))
	buf = append(buf, clientAttrCharSet)
	return append(buf, v...)
}

func appendClientAttrU16(buf []byte, tag uint16, value uint16) []byte {
	buf = append(buf, byte(tag>>8), byte(tag))
	buf = append(buf, 0, 2)
	return append(buf, byte(value>>8), byte(value))
}

func appendClientAttrEnd(buf []byte, tag uint16) []byte {
	buf = append(buf, byte(tag>>8), byte(tag))
	return append(buf, 0, 0)
}

func appendClientAttrByte(buf []byte, tag uint16, value byte) []byte {
	buf = append(buf, byte(tag>>8), byte(tag))
	buf = append(buf, 0, 1)
	return append(buf, value)
}

func newClientAttributesParcel(con *teradataConnection) *clientAttributesParcel {
	unitySupported := con.capabilities != nil && con.capabilities.unityClientAttributesSupport >= 1

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}

	var username string
	if u, err := user.Current(); err == nil {
		username = u.Username
	} else {
		username = "unknown"
	}

	progName, err := os.Executable()
	if err != nil || progName == "" {
		progName = os.Args[0]
	}

	osInfo := fmt.Sprintf("%s %s", runtime.GOOS, runtime.GOARCH)
	vmInfo := fmt.Sprintf("Go %s", runtime.Version())

	driverVersion := "GoTeradatasql0.0.1"

	lobSupport := "N"
	if con.capabilities != nil && con.capabilities.lobSupport {
		lobSupport = "Y"
	}
	statementInfoSupport := "N"
	if con.capabilities != nil && con.capabilities.statementInfoSupport >= 1 {
		statementInfoSupport = "Y"
	}

	_, tzOffset := time.Now().Zone()
	tzSign := "+"
	if tzOffset < 0 {
		tzSign = "-"
		tzOffset = -tzOffset
	}
	tz := fmt.Sprintf("%s%02d:%02d", tzSign, tzOffset/3600, (tzOffset%3600)/60)

	ex := "" +
		"BA=N;" +
		"CCS=ASCII;" +
		"CERT=U;" +
		"CF=0;" +
		"CID=" + con.connectionID + ";" +
		"CRC=DEFAULT;" +
		"CRL=Y;" +
		fmt.Sprintf("DP=%d;", con.remotePort) +
		"ENC=N;" +
		fmt.Sprintf("ES=%d;", con.sessionNo) +
		"FIPS=N;" +
		"GOV=N;" +
		"HP=443;" +
		"HR=0,0;" +
		fmt.Sprintf("GO=%s;", runtime.Version()) +
		"LM=TD2;" +
		"LOB=" + lobSupport + ";" +
		fmt.Sprintf("MEM=%d;", readMemLimit()) +
		"OA=0;" +
		"OCSP=Y;" +
		"OP=N;" +
		"OSL=3;" +
		"OSM=DEFAULT;" +
		"PART=DBC/SQL;" +
		"RED=0,0;" +
		"SC=1,0;" +
		"SCS=ASCII;" +
		"SE=N;" +
		"SIP=" + statementInfoSupport + ";" +
		"SSL=0;" +
		"SSLM=DEFAULT;" +
		"SSLP=DEFAULT;" +
		"TM=T;" +
		"TVD=plain;" +
		"TYPE=DEFAULT;" +
		"TZ=" + tz + ";"
	buf := make([]byte, 0, 662)
	hostAttr := hostname
	if !unitySupported {
		hostAttr = fmt.Sprintf("%s;%s:%d", hostname, con.remoteHost, con.remotePort)
	}
	buf = appendClientAttrString(buf, pclcliattHostname, hostAttr)
	buf = appendClientAttrString(buf, pclcliattProcThrID, fmt.Sprintf("%d", os.Getpid()))
	buf = appendClientAttrString(buf, pclcliattSysUserID, username)
	buf = appendClientAttrString(buf, pclcliattProgName, progName)
	buf = appendClientAttrString(buf, pclcliattOSName, osInfo)
	buf = appendClientAttrString(buf, pclcliattVMName, vmInfo)
	buf = appendClientAttrString(buf, pclcliattGrpSecProd, "unavailable")
	buf = appendClientAttrString(buf, pclcliattSessDesc, "C=N;")
	buf = appendClientAttrString(buf, pclcliattClientKind, "G")
	buf = appendClientAttrString(buf, pclcliattClientVersion, driverVersion)
	buf = appendClientAttrString(buf, pclcliattClientAttributesEx, ex)

	if unitySupported {
		buf = appendClientAttrString(buf, pclcliattClientIPAddrByClient, localAddrOrEmpty(con))
		buf = appendClientAttrU16(buf, pclcliattClientPortByClient, uint16(localPortOrZero(con)))
		buf = appendClientAttrString(buf, pclcliattServerIPAddrByClient, con.remoteHost)
		buf = appendClientAttrU16(buf, pclcliattServerPortByClient, uint16(con.remotePort))
	}

	buf = appendClientAttrByte(buf, pclcliattClientConfidentiality, con.config.getClientConfidentialityType(con.isTlsConn))
	buf = appendClientAttrEnd(buf, pclcliattEnd)
	return &clientAttributesParcel{
		attributeData: buf,
	}
}

func readMemLimit() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Sys
}

func localAddrOrEmpty(con *teradataConnection) string {
	if con.netConn == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(con.netConn.LocalAddr().String())
	if err != nil {
		return ""
	}
	return host
}

func localPortOrZero(con *teradataConnection) int {
	if con.netConn == nil {
		return 0
	}
	_, port, err := net.SplitHostPort(con.netConn.LocalAddr().String())
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return p
}

func (p *clientAttributesParcel) getFlavor() parcelFlavor {
	return flavorClientAttributes
}

func (p *clientAttributesParcel) getLength() int {
	return parcelHeaderLen + len(p.attributeData)
}

func (p *clientAttributesParcel) write(w *bufferWriter) error {
	w.u16(uint16(p.getFlavor()))
	w.u16(uint16(p.getLength()))
	w.bytes(p.attributeData)
	return nil
}
