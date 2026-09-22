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
	"crypto/tls"
	"database/sql/driver"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
)

type transactionMode int

const (
	teraMode transactionMode = iota
	ansiMode
)

type teradataConnection struct {
	connectionID string
	netConn      net.Conn
	rawConn      net.Conn
	config       *Config
	buffer       readBuffer  // read side: incoming messages
	writeBuffer  writeBuffer // write side: outgoing message framing
	requestNo    int
	authNonce    uint64
	sessionNo    uint32
	isTlsConn    bool

	remoteHost string
	remotePort int

	gss          gssContext
	capabilities *connectionCapabilities

	closed atomic.Bool

	transactionMode       transactionMode
	transactionInProgress bool
	currentTransaction    *teradataTransaction

	polSecurityRequired        bool
	polConfidentialityRequired bool
	polSecurityLevel           int

	//openKeepStatement bool
}

type teradataTransaction struct {
	conn *teradataConnection
}

// Hold server capabilities we care about returned in the ConfigResponse Parcel
type connectionCapabilities struct {
	defaultTransactionSemantics    rune
	statementStatusLevel           int
	clientAttributesSupport        byte
	lobSupport                     bool
	dynamicResultSetsSupport       bool
	extNamesInParcels              bool
	periodDataTypeSupport          bool
	trustedSQLSupport              bool
	xmlSupport                     bool
	failFastSupport                bool
	vsdSupport                     bool
	arraySupport                   bool
	maxAvailableBytesInResponseRow int
	otfSupport                     bool
	statementInfoSupport           byte
	unityClientAttributesSupport   byte
	aphSupport                     bool
	maxResponseMessageBodySize     int
	slobClientToServerSupport      byte
}

func (c *connectionCapabilities) String() string {
	return fmt.Sprintf(
		"connectionCapabilities{"+
			"defaultTransactionSemantics: %q, "+
			"statementStatusLevel: %d, "+
			"clientAttributesSupport: %d, "+
			"lobSupport: %t, "+
			"dynamicResultSetsSupport: %t, "+
			"extNamesInParcels: %t, "+
			"periodDataTypeSupport: %t, "+
			"trustedSQLSupport: %t, "+
			"xmlSupport: %t, "+
			"failFastSupport: %t, "+
			"vsdSupport: %t, "+
			"arraySupport: %t, "+
			"maxAvailableBytesInResponseRow: %d, "+
			"otfSupport: %t, "+
			"statementInfoSupport: %d, "+
			"unityClientAttributesSupport: %d, "+
			"maxResponseMessageBodySize: %d,"+
			"slobClientToServerSupport: %d, "+
			"aphSupport: %t"+
			"}",
		c.defaultTransactionSemantics,
		c.statementStatusLevel,
		c.clientAttributesSupport,
		c.lobSupport,
		c.dynamicResultSetsSupport,
		c.extNamesInParcels,
		c.periodDataTypeSupport,
		c.trustedSQLSupport,
		c.xmlSupport,
		c.failFastSupport,
		c.vsdSupport,
		c.arraySupport,
		c.maxAvailableBytesInResponseRow,
		c.otfSupport,
		c.statementInfoSupport,
		c.unityClientAttributesSupport,
		c.maxResponseMessageBodySize,
		c.slobClientToServerSupport,
		c.aphSupport,
	)
}

func newConnectionCapabilities(cnfg *configResponseParcel) *connectionCapabilities {
	c := &connectionCapabilities{
		defaultTransactionSemantics:    rune(cnfg.defaultTransactionSemantics),
		statementStatusLevel:           int(cnfg.statementStatusLevel),
		clientAttributesSupport:        cnfg.clientAttributesSupport,
		lobSupport:                     cnfg.lobSupport == 1,
		dynamicResultSetsSupport:       cnfg.dynamicResultSetsSupport&1 == 1,
		extNamesInParcels:              cnfg.extNamesInParcels&1 == 1,
		periodDataTypeSupport:          cnfg.periodDataTypeSupport&1 == 1,
		trustedSQLSupport:              cnfg.trustedSQLSupport&1 == 1,
		xmlSupport:                     cnfg.xmlSupport&1 == 1,
		failFastSupport:                cnfg.failFastSupport&1 == 1,
		vsdSupport:                     cnfg.vsdSupport&1 == 1,
		arraySupport:                   cnfg.arraySupport&1 == 1,
		otfSupport:                     cnfg.otfSupport&1 == 1,
		maxAvailableBytesInResponseRow: int(cnfg.maxAvailableBytesInResponseRow),
		statementInfoSupport:           cnfg.statementInfoSupport,
		unityClientAttributesSupport:   cnfg.unityClientAttributesSupport,
		aphSupport:                     cnfg.aphSupport >= 1,
		maxResponseMessageBodySize:     int(cnfg.maxResponseBytes),
		slobClientToServerSupport:      cnfg.slobClientToServerSupport,
	}
	if c.maxResponseMessageBodySize == 0 {
		c.maxResponseMessageBodySize = 1048500
	}
	return c
}

func (c *teradataConnection) Begin() (driver.Tx, error) {
	if c.currentTransaction == nil {
		// We only have to worry about TERA mode here
		if c.transactionMode == teraMode && !c.transactionInProgress {
			err := c.execSessionSQL("BT")
			if err != nil {
				return nil, err
			}
		}
		t := &teradataTransaction{conn: c}
		c.currentTransaction = t
		return t, nil
	}
	return nil, ErrTransactionInProgress
}

func (c *teradataConnection) Prepare(query string) (driver.Stmt, error) {
	return c.prepare(query)
}

func (c *teradataConnection) prepare(query string) (*teradataStatement, error) {
	if c.closed.Load() {
		return nil, driver.ErrBadConn
	}

	// TODO: if connection has an openKeepStatement cancel it

	// Write the query with PREPARE options parcel:
	err := c.writeLanMessage(
		c.newLanHeaderStart(),
		newOptionsParcelPrepare(c),
		newIndicRequestParcel(query),
		newRespondParcel(c.capabilities, c.config),
	)
	if err != nil {
		return nil, err
	}

	parcels, _, err := c.readLanMessage()
	if err != nil {
		return nil, err
	}
	statementInfo, ok := findParcel[*statementInfoResponseParcel](parcels)
	if !ok {
		return nil, ErrInvalidResponse
	}

	// Check that we got all the "end" parcels expected for success:
	statementInfoEnd := false
	endRequest := false
	endStatement := false
	for _, p := range parcels {
		switch p.getFlavor() {
		case flavorStementInfoEnd:
			statementInfoEnd = true
		case flavorEndRequest:
			endRequest = true
		case flavorEndStatement:
			endStatement = true
		}
	}

	if !statementInfoEnd || !endRequest || !endStatement {
		return nil, ErrInvalidResponse
	}

	return &teradataStatement{
		conn:          c,
		query:         query,
		statementInfo: statementInfo,
	}, nil
}

// Helper for executing inline SQL on the open connection (Begin Transaction, Commit, Rollback, etc)
func (c *teradataConnection) execSessionSQL(query string) error {
	if c.closed.Load() {
		return driver.ErrBadConn
	}
	err := c.writeLanMessage(
		c.newLanHeaderStart(),
		newOptionsParcelInline(c),
		newIndicRequestParcel(query),
		newRespondParcel(c.capabilities, c.config),
	)
	if err != nil {
		return err
	}
	_, _, err = c.readLanMessage()
	return err
}

func (c *teradataConnection) Close() (err error) {
	if c.closed.Swap(true) {
		return
	}
	if c.netConn != nil {
		err := c.writeLanMessage(
			c.newLanHeaderLogoff(),
			newLogoffParcel(),
		)
		if err != nil {
			return err
		}
		// TODO: Check response
		_, _, err = c.readLanMessage()
		if err != nil {
			return err
		}

		err = c.netConn.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *teradataConnection) Ping(ctx context.Context) (err error) {
	if c.closed.Load() {
		return driver.ErrBadConn
	}
	err = c.execSessionSQL("--isValid")
	if err != nil && isConnectionError(err) {
		c.closed.Store(true)
		return driver.ErrBadConn
	}
	return nil
}

func (c *teradataConnection) handshake() (bool, error) {
	// Config
	capabailities, authMech, authMechMap, err := c.configHandshake()
	if err != nil {
		return false, err
	}
	c.capabilities = newConnectionCapabilities(capabailities)
	c.config.Logger.Log(context.Background(), logLevelTrace, c.capabilities.String())

	// Dechipher session transaction mode:
	switch c.config.TMode {
	case "DEFAULT":
		// Dechpiher transaction mode from server default:
		if c.capabilities.defaultTransactionSemantics == 'A' {
			c.transactionMode = ansiMode
		} else {
			c.transactionMode = teraMode
		}
	case "TERA":
		c.transactionMode = teraMode
	case "ANSI":
		c.transactionMode = ansiMode
	default:
		c.transactionMode = teraMode
	}

	// Check auth mechs
	if authMech&authMechTd2 == authMechTd2 {
		ciBypass := false
		if td2Mech, ok := authMechMap[authMechTd2Oid]; ok {
			ciBypass = td2Mech.cidBypassSupported
		}

		if c.isTlsConn && ciBypass {
			c.config.Logger.Log(context.Background(), logLevelTrace, "using simplified TD2 over TLS auth")
			c.gss = newTd2TlsGssContext(c.config.Logger)
		} else {
			c.config.Logger.Log(context.Background(), logLevelTrace, "using full TD2 auth")
			c.gss = newTd2GssContext(c.config.Logger)
		}

	} else {
		return false, ErrNoSupportAuth
	}

	// For Non-TLS / TD2 Auth we setup the secure channel
	err = c.gss.establishSecureChannel(c)
	if err != nil {
		c.config.Logger.Log(context.Background(), logLevelTrace, "establishSecureChannel failed", "error", err)
		return false, err
	}

	// Authenticate:
	err = c.authenticate()
	if err != nil {
		return false, err
	}

	return true, nil
}

func (c *teradataConnection) authenticate() error {
	header := c.newLanHeaderConnect()
	binary.BigEndian.PutUint64(header.authNonce[:], uint64(c.nextAuthNonce()))
	if c.connectionID == "" {
		c.connectionID = strings.TrimPrefix(fmt.Sprintf("%p", c), "0x")
	}
	parcels := []parcel{
		newLogonParcel(c.config.User, c.config.Password),
		newSessionOptionsParcel(c.config, c.capabilities),
		newConnectParcel(c.config, 0),
	}
	support := c.capabilities.clientAttributesSupport
	if support <= 1 {
		parcels = append(parcels, newLogonDataParcel(c.remoteHost, c.remotePort, "", c.connectionID))
	}
	if support >= 1 {
		parcels = append(parcels, newClientAttributesParcel(c))
	}

	err := c.writeLanMessage(header, parcels...)
	if err != nil {
		return err
	}

	respParcels, _, err := c.readLanMessage()
	if err != nil {
		return err
	}

	// If we get Success or EndRequest parcels then we consider it Good:
	_, ok := findParcel[*successResponseParcel](respParcels)
	if ok {
		return nil
	}
	_, ok = findParcel[*endRequstParcel](respParcels)
	if ok {
		return nil
	}

	return ErrInternal

}

func (con *teradataConnection) configHandshake() (*configResponseParcel, authMechFlag, map[string]*authMech, error) {
	// Send Client Config:
	err := con.writeLanMessage(
		&lanHeader{
			version:     3,
			kind:        lanHeaderTypeCfg,
			byteVar:     7,
			hostCharSet: 0xFF,
			requestNo:   0,
		},
		newClientConfigParcel(con.config.redriveLevel),
	)
	if err != nil {
		return nil, 0, nil, err
	}

	// Read response
	parcels, _, err := con.readLanMessage()
	if err != nil {
		return nil, 0, nil, err
	}

	authMechMap := make(map[string]*authMech)
	var cnfgResp *configResponseParcel
	var authMechs authMechFlag
	if len(parcels) > 0 {
		for _, p := range parcels {
			switch parcel := p.(type) {
			case *configResponseParcel:
				cnfgResp = parcel
			case *authMechParcel:
				authMechs |= parcel.getAuthMechFlag()
				authMechMap[parcel.oid] = &authMech{
					isDefault:          parcel.defaultMech,
					rank:               parcel.rank,
					cidBypassSupported: parcel.cidBypassSupported,
				}
			}

		}
	}
	if cnfgResp == nil {
		return nil, 0, nil, ErrInvalidResponse
	}

	return cnfgResp, authMechs, authMechMap, nil
}

func (c *teradataConnection) nextAuthNonce() uint64 {
	c.authNonce += 1
	return c.authNonce
}

func (c *teradataConnection) nextRequestNumber() uint32 {
	c.requestNo += 1
	return uint32(c.requestNo)
}

func (c *teradataConnection) sameRequestNumber() uint32 {
	return uint32(c.requestNo)
}

func (c *teradataConnection) isTlsConnection() bool {
	if _, ok := c.netConn.(*tls.Conn); ok {
		return c.isTlsConn
	}
	return false
}

func (t *teradataTransaction) Commit() error {
	if t.conn.transactionMode == teraMode {
		for t.conn.transactionInProgress {
			err := t.conn.execSessionSQL("ET")
			if err != nil {
				return err
			}
		}
	} else {
		err := t.conn.execSessionSQL("COMMIT WORK")
		if err != nil {
			return err
		}
	}
	t.conn.currentTransaction = nil
	return nil
}

func (t *teradataTransaction) Rollback() error {
	var err error
	if t.conn.transactionMode == teraMode {
		err = t.conn.execSessionSQL("ABORT")
	} else {
		err = t.conn.execSessionSQL("ROLLBACK WORK")
	}

	if err != nil {
		// Ignore "no transaction to abort" errors
		if !isTeradataErrorCode(err, 3514) {
			return err
		}
	}
	t.conn.currentTransaction = nil
	return nil
}
