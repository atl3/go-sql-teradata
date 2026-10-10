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
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"
)

type fastLoadConnection struct {
	connector          *teradataConnector
	controlSession     *teradataConnection
	diagnosticSession  *teradataConnection
	currentTransaction *fastLoadTx
	logonSeqNum        int
	opened             atomic.Bool
}

// Create new Fast Load connection to bulk import data
func NewFastLoadConnection(cfg *Config) (FastLoadConnection, error) {
	return &fastLoadConnection{
		connector: newConnector(cfg),
	}, nil
}

// Create new Fast Load connection to bulk import data
func (c *teradataConnector) NewFastLoadConnection() (FastLoadConnection, error) {
	return &fastLoadConnection{
		connector: c,
	}, nil
}

// Abort any load in progress and close control and diagnostic sessions
func (c *fastLoadConnection) Close() error {
	var errs []error
	if c.currentTransaction != nil {
		if err := c.currentTransaction.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	errs = append(errs, c.closeSessions())
	return errors.Join(errs...)
}

func (c *fastLoadConnection) closeSessions() error {
	var errs []error
	for _, s := range []*teradataConnection{c.diagnosticSession, c.controlSession} {
		if s != nil {
			if err := s.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	c.diagnosticSession = nil
	c.controlSession = nil
	c.opened.Store(false)
	return errors.Join(errs...)
}

// Opens control and diagnostic sessions
func (c *fastLoadConnection) Open(ctx context.Context) error {
	// Make control connection
	c.log(ctx, logLevelTrace, "Attempting to open control session")
	cc, err := c.openFastLoadConnection(ctx, fastLoadConnControl, 0)
	if err != nil {
		return err
	}
	c.controlSession = cc
	lsn := c.controlSession.logonSequenceNumber

	// Make diag connection
	c.log(ctx, logLevelTrace, "Attempting to open diagnostic session")
	dc, err := c.openFastLoadConnection(ctx, fastLoadConnDiag, lsn)
	if err != nil {
		return err
	}
	c.diagnosticSession = dc
	c.logonSeqNum = lsn
	c.opened.Store(true)
	return nil
}

func (c *fastLoadConnection) openFastLoadConnection(ctx context.Context, ctype fastConnectionType, lsn int) (*teradataConnection, error) {
	conn, err := c.connector.connect(ctx, false)
	if err != nil {
		return nil, err
	}
	if ok, err := conn.handshake(); !ok || err != nil {
		return nil, err
	}
	switch ctype {
	case fastLoadConnControl:
		err = conn.fastLoadControlAuthenticate()
	case fastLoadConnDiag:
		err = conn.fastLoadDiagAuthenticate(lsn)
	case fastLoadConnData:
		err = conn.fastLoadDataAuthenticate(lsn)
	}
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Initiate Fast Load
func (c *fastLoadConnection) BeginFastLoad(ctx context.Context, database string, table string, columns ...string) (FastLoadTx, error) {
	if len(columns) == 0 {
		return nil, ErrFastLoadNoColumns
	}
	if c.currentTransaction != nil {
		return nil, ErrFastLoadNotClosed
	}
	// Open control session if this is the first load:
	if !c.opened.Load() {
		err := c.Open(ctx)
		if err != nil {
			return nil, err
		}
	}
	if c.controlSession == nil {
		return nil, ErrFastConnectFailed
	}

	// Prepare a basic insert statement so we can get the datatypes and sizes:
	insertStatement := buildFastLoadInsertStatement(database, table, columns)
	stmt, err := c.controlSession.prepare(insertStatement)
	if err != nil {
		return nil, err
	}
	statementInfo := stmt.statementInfo
	stmt.Close()

	// -
	// Prepare "begin load" statement
	errorTable1 := fmt.Sprintf("%s.%s_ERR_1", database, table)
	errorTable2 := fmt.Sprintf("%s.%s_ERR_2", database, table)
	c.log(ctx, logLevelTrace, "FastLoad Error Tables", "errorTable1", errorTable1, "errorTable2", errorTable2)
	beginLoadStatment := fmt.Sprintf("BEGIN LOADING %s.%s ERRORFILES %s, %s WITH INTERVAL", database, table, errorTable1, errorTable2)
	c.log(ctx, logLevelTrace, "FastLoad", "beginLoadStatment", beginLoadStatment)

	// -
	// Determine number of data connections to open
	dataSessionCount := 0
	if c.controlSession.capabilities.checkWorkloadSupported {
		checkWorkloadStatement := fmt.Sprintf("CHECK WORKLOAD FOR %s", beginLoadStatment)
		c.log(ctx, logLevelTrace, "FastLoad Check Workload", "statement", checkWorkloadStatement)
		_, err := c.controlSession.execSessionSQL(checkWorkloadStatement)
		if err != nil {
			return nil, err
		}
		rowData, err := c.controlSession.execSessionQuery("CHECK WORKLOAD END")
		if err != nil {
			return nil, err
		}
		if len(rowData) >= 2 {
			if flg, ok := rowData[0].(string); ok {
				if flg == "Y" {
					if val, ok := rowData[1].(int); ok {
						dataSessionCount = val
					}
				} else {
					c.log(ctx, logLevelTrace, "CHECK WORKLOAD Session Count skipped, using default")
				}
			}
		}
	}
	// If not from CheckWorkload use Amp count from session:
	if dataSessionCount == 0 {
		dataSessionCount = c.controlSession.capabilities.ampCount
	}
	// Limit connections to config max
	if dataSessionCount <= 0 || dataSessionCount > c.connector.config.MaxFastLoadSessions {
		c.log(ctx, logLevelTrace, "FastLoad Init dataSessionCount", "Was", dataSessionCount, "Using", c.connector.config.MaxFastLoadSessions)
		dataSessionCount = c.connector.config.MaxFastLoadSessions
	}

	// -
	// Create param encoders
	encoders, err := newFastLoadColumnEncoders(statementInfo, c.controlSession.capabilities)
	if err != nil {
		return nil, err
	}

	// -
	// Create Data Channels
	dataChannels, err := c.openDataChannels(ctx, dataSessionCount, encoders)
	if err != nil {
		return nil, err
	}
	tx := &fastLoadTx{
		conn:          c,
		dataChannels:  dataChannels,
		encoders:      encoders,
		sessionCount:  dataSessionCount,
		statementInfo: statementInfo,
		target:        database + "." + table,
		errorTable1:   errorTable1,
		errorTable2:   errorTable2,
		beginLoading:  beginLoadStatment,
	}
	ok, loading := false, false
	// Abort if we executed begin load but failed later in init phase:
	defer func() {
		if ok {
			return
		}
		if loading {
			abortCtx, cancel := fastLoadCleanupContext(ctx)
			defer cancel()
			if abortErr := tx.Abort(abortCtx); abortErr != nil {
				c.log(ctx, logLevelTrace, "FastLoad Begin: abort after failed setup", "error", abortErr)
			}
		} else {
			closeDataChannels(ctx, tx.dataChannels)
		}
	}()

	// -
	// Prepare FastLoad Begin
	usingInsertStatement, err := buildFastLoadUsingInsert(database, table, columns, statementInfo, c.controlSession.capabilities)
	if err != nil {
		return nil, err
	}

	// -
	// Release anything a previous, unfinished load left behind
	if err := tx.clearStaleLoad(ctx); err != nil {
		return nil, err
	}

	// -
	// Begin Load (FastLoadManagerPreparedStatement.beginFastLoad())
	if err := tx.controlExec(ctx, "SET SESSION DateForm = IntegerDate"); err != nil {
		return nil, err
	}
	if err := tx.controlExec(ctx, beginLoadStatment); err != nil {
		return nil, err
	}
	loading = true
	// Begin Transaction
	if err := fastLoadBegin(c.controlSession); err != nil {
		return nil, err
	}
	if err := tx.controlExec(ctx, usingInsertStatement); err != nil {
		return nil, err
	}

	ok = true
	c.currentTransaction = tx

	return tx, nil
}

// Open all data connections
func (c *fastLoadConnection) openDataChannels(ctx context.Context, n int, encoders []*fastLoadColumnEncoder) ([]*fastLoadDataChannel, error) {
	c.log(ctx, logLevelTrace, "Opening data sessions", "dataSessionCount", n)
	channels := make([]*fastLoadDataChannel, 0, n)
	for range n {
		conn, err := c.openFastLoadConnection(ctx, fastLoadConnData, c.logonSeqNum)
		if err != nil {
			closeDataChannels(ctx, channels)
			return nil, err
		}
		ch, err := newFastLoadDataChannel(conn, encoders, c.connector.config)
		if err != nil {
			conn.Close()
			closeDataChannels(ctx, channels)
			return nil, err
		}
		channels = append(channels, ch)
	}
	return channels, nil
}

func closeDataChannels(ctx context.Context, channels []*fastLoadDataChannel) error {
	var errs []error
	for _, ch := range channels {
		if err := ch.close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *fastLoadConnection) log(ctx context.Context, level slog.Level, msg string, args ...any) {
	c.connector.config.Logger.Log(ctx, level, msg, args...)
}

/*
Fastload TX
*/
type fastLoadTx struct {
	conn          *fastLoadConnection
	dataChannels  []*fastLoadDataChannel
	encoders      []*fastLoadColumnEncoder
	sessionCount  int
	rowNumber     int32
	statementInfo *statementInfoResponseParcel
	target        string // database.table
	errorTable1   string
	errorTable2   string
	beginLoading  string // BEGIN LOADING statement, re-sent by Abort
	done          bool   // the tx can't be used again if ended or aborted
}

func (t *fastLoadTx) AddRow(ctx context.Context, values ...driver.Value) (int, error) {
	if t.done {
		return 0, ErrFastLoadFinished
	}
	ch := t.dataChannels[int(t.rowNumber)%len(t.dataChannels)]
	rowNumber := t.rowNumber + 1
	if err := ch.pushRow(ctx, rowNumber, values); err != nil {
		return 0, err
	}
	t.rowNumber = rowNumber
	return int(rowNumber), nil
}

// Sends pending rows and wait for server response
func (t *fastLoadTx) Flush(ctx context.Context) error {
	if t.done {
		return ErrFastLoadFinished
	}
	for _, ch := range t.dataChannels {
		if err := ch.dispatch(ctx); err != nil {
			return err
		}
	}
	var errs []error
	for i, ch := range t.dataChannels {
		if err := ch.wait(ctx); err != nil {
			errs = append(errs, fmt.Errorf("data session %d: %w", i+1, err))
		}
	}
	return errors.Join(errs...)
}

// Completes the load by flushing, committing and checking error tables
func (t *fastLoadTx) End(ctx context.Context) (*FastLoadResult, error) {
	if t.done {
		return nil, ErrFastLoadFinished
	}
	res := &FastLoadResult{RowsSent: int64(t.rowNumber)}
	if err := t.endLoading(ctx, res); err != nil {
		abortCtx, cancel := fastLoadCleanupContext(ctx)
		defer cancel()
		if abortErr := t.Abort(abortCtx); abortErr != nil {
			err = errors.Join(err, fmt.Errorf("abort after failed end: %w", abortErr))
		}
		return nil, err
	}
	defer t.finish(ctx)

	control := t.conn.controlSession
	var errs []error
	var err error
	if res.Errors, err = readFastLoadErrorTable1(ctx, control, t.errorTable1); err != nil {
		errs = append(errs, fmt.Errorf("reading %s: %w", t.errorTable1, err))
	}
	if res.UniqueViolations, err = countFastLoadErrorTable(control, t.errorTable2); err != nil {
		errs = append(errs, fmt.Errorf("reading %s: %w", t.errorTable2, err))
	}
	if err = t.dropErrorTables(ctx); err != nil {
		errs = append(errs, err)
	}
	return res, errors.Join(errs...)
}

func (t *fastLoadTx) endLoading(ctx context.Context, res *FastLoadResult) error {
	if err := t.Flush(ctx); err != nil {
		return err
	}
	control := t.conn.controlSession
	if err := t.controlExec(ctx, "CHECKPOINT LOADING END"); err != nil {
		return err
	}
	if err := fastLoadCommit(control); err != nil {
		return err
	}
	// Begin Transaction
	if err := fastLoadBegin(control); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	t.conn.log(ctx, logLevelTrace, "FastLoad End", "ExecuteStatement", "END LOADING")
	loaded, err := control.execSessionUpdate("END LOADING")
	if err != nil {
		return err
	}
	if err := fastLoadCommit(control); err != nil {
		return err
	}
	res.RowsAccepted = loaded
	return nil
}

// Abort and rollback the load
func (t *fastLoadTx) Abort(ctx context.Context) error {
	if t.done {
		return ErrFastLoadFinished
	}
	defer t.finish(ctx)
	c := t.conn

	closeDataChannels(ctx, t.dataChannels)
	t.dataChannels = nil
	c.closeSessions()

	if err := c.Open(ctx); err != nil {
		return err
	}
	channels, err := c.openDataChannels(ctx, t.sessionCount, t.encoders)
	if err != nil {
		return err
	}
	t.dataChannels = channels

	if err := t.releaseLoad(ctx); err != nil {
		return err
	}
	return t.dropErrorTables(ctx)
}

// Check if table is locked from a failed Fast Load and release it
func (t *fastLoadTx) clearStaleLoad(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	probe := "SELECT 1 FROM " + t.target + " WHERE 1=2"
	t.conn.log(ctx, logLevelTrace, "FastLoad", "ExecuteStatement", probe)
	_, err := t.conn.controlSession.execSessionQuery(probe)
	switch {
	case err == nil:
	case isTeradataErrorCode(err, 2652):
		t.conn.log(ctx, logLevelTrace, "FastLoad: releasing stale load", "table", t.target)
		if err := t.releaseLoad(ctx); err != nil {
			return fmt.Errorf("releasing stale load of %s: %w", t.target, err)
		}
	default:
		return err
	}
	return t.dropErrorTables(ctx)
}

func (t *fastLoadTx) releaseLoad(ctx context.Context) error {
	control := t.conn.controlSession
	if err := fastLoadCommit(control); err != nil {
		return err
	}
	if err := t.controlExec(ctx, t.beginLoading); err != nil {
		return err
	}
	if err := fastLoadBegin(control); err != nil {
		return err
	}
	if err := t.controlExec(ctx, "END LOADING"); err != nil {
		return err
	}
	if err := fastLoadCommit(control); err != nil {
		return err
	}
	return t.controlExec(ctx, "DELETE "+t.target+" ALL")
}

// Closes the transaction (Aborting if not succesfully ended)
func (t *fastLoadTx) Close() error {
	if t.done {
		return nil
	}
	return t.Abort(context.Background())
}

func (t *fastLoadTx) finish(ctx context.Context) {
	closeDataChannels(ctx, t.dataChannels)
	t.dataChannels = nil
	t.done = true
	t.conn.currentTransaction = nil
}

func (t *fastLoadTx) controlExec(ctx context.Context, stmt string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t.conn.log(ctx, logLevelTrace, "FastLoad", "ExecuteStatement", stmt)
	_, err := t.conn.controlSession.execSessionSQL(stmt)
	return err
}

func (t *fastLoadTx) dropErrorTables(ctx context.Context) error {
	//NOTE: If 2631 (deadlock) retry up to 5 times
	var errs []error
	for _, table := range []string{t.errorTable1, t.errorTable2} {
		for attempt := 1; ; attempt++ {
			err := t.controlExec(ctx, "DROP TABLE "+table)
			if err == nil || isTeradataErrorCode(err, 3807) {
				break
			}
			if !isTeradataErrorCode(err, 2631) || attempt == 5 {
				errs = append(errs, fmt.Errorf("dropping %s: %w", table, err))
				break
			}
			select {
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
				return errors.Join(append(errs, ctx.Err())...)
			}
		}
	}
	return errors.Join(errs...)
}

func fastLoadCleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx.Err() == nil {
		return ctx, func() {}
	}
	return context.WithTimeout(context.WithoutCancel(ctx), fastLoadCleanupTimeout)
}

func fastLoadBegin(conn *teradataConnection) error {
	if conn.transactionInProgress {
		return nil
	}
	_, err := conn.execSessionSQL("BT")
	return err
}

func fastLoadCommit(conn *teradataConnection) error {
	for conn.transactionInProgress {
		if _, err := conn.execSessionSQL("ET"); err != nil {
			return err
		}
	}
	return nil
}
