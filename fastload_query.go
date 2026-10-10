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
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func buildFastLoadInsertStatement(database, table string, columns []string) string {
	var cols, params strings.Builder
	for i, c := range columns {
		if i > 0 {
			cols.WriteRune(',')
			params.WriteRune(',')
		}
		cols.WriteString(c)
		params.WriteRune('?')
	}
	return fmt.Sprintf("INSERT INTO %s.%s (%s) VALUES (%s)", database, table, cols.String(), params.String())
}

func buildFastLoadUsingInsert(database, table string, columns []string, info *statementInfoResponseParcel, capabilities *connectionCapabilities) (string, error) {
	if info == nil {
		return "", fmt.Errorf("%w: no statement info for prepared insert", ErrFastLoadUnsupported)
	}
	items := info.paramMarkerMetaItems()
	if len(items) != len(columns) {
		return "", fmt.Errorf("%w: expected %d parameter markers, got %d", ErrFastLoadUnsupported, len(columns), len(items))
	}

	var using, insert, values strings.Builder

	// Rows will all include null indicator for each column + rownumber int + rownumber null ind
	rowBytes := uint64((len(items)+1+7)/8 + 4)

	for i, item := range items {
		columnName := columns[i]
		dbType, size, err := fastLoadUsingType(item, capabilities)
		if err != nil {
			return "", fmt.Errorf("%w: column %d: %w", ErrFastLoadUnsupported, i+1, err)
		}
		rowBytes += size

		if full, ok := item.(*statementInfoMetaDataFull); ok {
			if full.columnOrParamName != "" {
				columnName = full.columnOrParamName
			}
		}

		if i > 0 {
			using.WriteRune(',')
			insert.WriteRune(',')
			values.WriteRune(',')
		}
		using.WriteString(fmt.Sprintf("\"F_%s\" (%s)", columnName, dbType))
		insert.WriteString(fmt.Sprintf("\"%s\"", columnName))
		values.WriteString(fmt.Sprintf(":\"F_%s\"", columnName))
	}
	using.WriteString(", \"RowNumber\" (INTEGER)")

	// Force 64K max until we implement APH request parcels (TODO)
	if /*!capabilities.largeIndicDataSupport &&*/ rowBytes > 64000 {
		return "", fmt.Errorf("%w: potential row data size of %d bytes exceeds 64000 bytes", ErrFastLoadUnsupported, rowBytes)
	}

	return fmt.Sprintf("USING %s INSERT INTO %s.%s (%s) VALUES (%s)", using.String(), database, table, insert.String(), values.String()), nil
}

// Read rows rejected by server into ET1
func readFastLoadErrorTable1(ctx context.Context, conn *teradataConnection, table string) ([]FastLoadErrorRow, error) {
	query := "LOCKING " + table + " FOR ACCESS SELECT ErrorCode, ErrorFieldName" +
		", CAST(SUBSTRING(DataParcel FROM BYTES(DataParcel) - 3 FOR 4) AS BYTE(4)) AS RowNumber" +
		" FROM " + table + " ORDER BY RowNumber"
	stmt, err := conn.prepare(query)
	if err != nil {
		if isTeradataErrorCode(err, 3807) {
			return nil, nil // no error table, no errors
		}
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FastLoadErrorRow
	dest := make([]driver.Value, 3)
	for {
		if err := rows.Next(dest); err != nil {
			if err == io.EOF {
				return out, nil
			}
			return out, err
		}
		row := FastLoadErrorRow{}
		if code, ok := fastLoadInt64(dest[0]); ok {
			row.ErrorCode = int(code)
		}
		if field, ok := dest[1].(string); ok {
			row.Column = strings.TrimPrefix(strings.TrimSpace(field), "F_")
		}
		if rn, ok := dest[2].([]byte); ok && len(rn) == 4 {
			row.RowNumber = int(int32(binary.BigEndian.Uint32(rn)))
		}
		out = append(out, row)
	}
}

// Count errors from ET2
func countFastLoadErrorTable(conn *teradataConnection, table string) (int64, error) {
	row, err := conn.execSessionQuery("LOCKING " + table + " FOR ACCESS SELECT COUNT(*) FROM " + table)
	if err != nil {
		if isTeradataErrorCode(err, 3807) {
			return 0, nil
		}
		return 0, err
	}
	if len(row) == 0 {
		return 0, nil
	}
	n, _ := fastLoadInt64(row[0])
	return n, nil
}

func fastLoadInt64(v driver.Value) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int32:
		return int64(n), true
	case int16:
		return int64(n), true
	case int8:
		return int64(n), true
	case int:
		return int64(n), true
	case string:
		i, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64)
		return i, err == nil
	}
	return 0, false
}
