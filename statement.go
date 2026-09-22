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
)

type teradataStatement struct {
	conn       *teradataConnection
	paramCount int
	query      string
	requestNo  uint32

	isOpenKeep    bool
	statementInfo *statementInfoResponseParcel
}

func (stmt *teradataStatement) Close() error {
	if stmt.isOpenKeep {
		err := stmt.sendCancelAndDrain()
		if err != nil {
			return err
		}
	}
	return nil
}

func (stmt *teradataStatement) NumInput() int {
	if stmt.statementInfo == nil {
		return 0
	}
	return len(stmt.statementInfo.paramMarkerMetaItems())
}

func (stmt *teradataStatement) ColumnConverter(idx int) driver.ValueConverter {
	return driver.DefaultParameterConverter
}

func (stmt *teradataStatement) CheckNamedValue(nv *driver.NamedValue) (err error) {
	nv.Value, err = driver.DefaultParameterConverter.ConvertValue(nv.Value)
	if err != nil {
		return err
	}
	return nil
}

func (stmt *teradataStatement) Exec(args []driver.Value) (driver.Result, error) {
	err := stmt.execute(args)
	if err != nil {
		return nil, err
	}
	parcels, _, err := stmt.conn.readLanMessage()
	if err != nil {
		return nil, err
	}
	if stmtStatusParcel, ok := findParcel[*statementStatusParcel](parcels); ok {
		return &teradataResult{
			lastInsertId: 0,
			rowsAffected: stmtStatusParcel.activityCount + stmtStatusParcel.mergeInsertCount + stmtStatusParcel.mergeUpdateCount + stmtStatusParcel.mergeDeleteCount,
		}, nil
	}
	if succParcel, ok := findParcel[*successResponseParcel](parcels); ok {
		return &teradataResult{
			lastInsertId: 0,
			rowsAffected: uint64(succParcel.activityCount),
		}, nil
	}

	return nil, ErrInvalidResponse //TODO: Handle other responses to provide a meaningful error
}

func (stmt *teradataStatement) Query(args []driver.Value) (driver.Rows, error) {
	err := stmt.execute(args)
	if err != nil {
		return nil, err
	}
	// Get our own buffer here to read it across multiple Next() calls which could trigger more IO (fetchMore, deferred LOB fetch, etc)
	parcelData, parcelStart, parcelEnd, _, err := stmt.conn.readLanMessageRawOwned()
	if err != nil {
		return nil, err
	}
	return newTdRowData(stmt, stmt.statementInfo, parcelData, parcelStart, parcelEnd)
}

func (stmt *teradataStatement) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	vals, err := namedValuesToValues(args)
	if err != nil {
		return nil, err
	}
	var result driver.Result
	err = stmt.conn.runCancelable(ctx, func() error {
		var execErr error
		result, execErr = stmt.Exec(vals)
		return execErr
	})
	return result, err
}

func (stmt *teradataStatement) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	vals, err := namedValuesToValues(args)
	if err != nil {
		return nil, err
	}
	var rows driver.Rows
	err = stmt.conn.runCancelable(ctx, func() error {
		var queryErr error
		rows, queryErr = stmt.Query(vals)
		return queryErr
	})
	if err != nil {
		return nil, err
	}
	rows.(*tdRowData).startCtxWatcher(ctx)
	return rows, nil
}

func namedValuesToValues(args []driver.NamedValue) ([]driver.Value, error) {
	vals := make([]driver.Value, len(args))
	for _, a := range args {
		if a.Name != "" {
			return nil, fmt.Errorf("named parameters are not supported")
		}
		if a.Ordinal < 1 || a.Ordinal > len(args) {
			return nil, fmt.Errorf("invalid parameter ordinal %d", a.Ordinal)
		}
		vals[a.Ordinal-1] = a.Value
	}
	return vals, nil
}

func (stmt *teradataStatement) execute(args []driver.Value) error {
	parmLen := len(stmt.statementInfo.paramMarkerMetaItems())
	argsLen := len(args)
	if parmLen != argsLen {
		return fmt.Errorf("query expects %d params, %d provided", parmLen, argsLen)
	}
	parcelLen := 3
	if parmLen > 0 {
		parcelLen = 5
	}
	if stmt.conn.isLobReceivable() {
		parcelLen += 1
	}

	parcels := make([]parcel, parcelLen)
	parcels[0] = newOptionsParcelExecute(stmt.conn)
	parcels[1] = newIndicRequestParcel(stmt.query)
	if parmLen > 0 {
		paramMetas := stmt.statementInfo.paramMarkerMetaItems()
		dataTypes := make([]uint16, parmLen)
		for i, p := range paramMetas {
			dataTypes[i] = p.getDataType()
		}
		parcels[2] = newDataInfoParcel(dataTypes, args, paramMetas)
		parcels[3] = newIndicDataParcel(dataTypes, args, paramMetas)
	}

	if stmt.conn.isLobReceivable() {
		parcels[parcelLen-2] = newSlobRespondParcel(stmt.conn.capabilities, stmt.conn.config)
	}
	parcels[parcelLen-1] = stmt.conn.getRespondParcel()

	if stmt.conn.isLobReceivable() && stmt.conn.isKeepResponses() {
		stmt.isOpenKeep = true
	} else {
		stmt.isOpenKeep = false
	}

	err := stmt.conn.writeLanMessage(
		stmt.conn.newLanHeaderStart(),
		parcels...,
	)
	if err != nil {
		return err
	}
	stmt.requestNo = stmt.conn.sameRequestNumber()
	return nil
}

type teradataResult struct {
	lastInsertId uint64
	rowsAffected uint64
}

func (r *teradataResult) LastInsertId() (int64, error) {
	return int64(r.lastInsertId), nil
}

func (r *teradataResult) RowsAffected() (int64, error) {
	return int64(r.rowsAffected), nil
}
