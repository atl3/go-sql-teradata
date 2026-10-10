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
	"math"
	"time"
)

type fastConnectionType int

const (
	fastLoadConnControl fastConnectionType = iota
	fastLoadConnDiag
	fastLoadConnData
)
const (
	fastLoadCleanupTimeout        = 2 * time.Minute
	fastLoadParcelHeaderLen       = 4
	fastLoadMaxParcelLen          = math.MaxUint16
	fastLoadBuffersPerSession     = 2
	fastLoadRespondMaxMessageSize = 65104
)

type FastLoadConnection interface {
	// Teardown Connections and Abort Open Transactions
	Close() error
	// Begin a Load
	BeginFastLoad(ctx context.Context, database string, table string, columns ...string) (FastLoadTx, error)
}

type FastLoadTx interface {
	// Add row to queue
	AddRow(ctx context.Context, values ...driver.Value) (int, error)
	// Send all queued rows to server, blocks until ackd
	Flush(ctx context.Context) error
	// End loading
	End(ctx context.Context) (*FastLoadResult, error)
	// Abort load and rollback
	Abort(ctx context.Context) error
	// Close underlying data connections
	Close() error
}

type FastLoadResult struct {
	RowsSent         int64
	RowsAccepted     int64
	Errors           []FastLoadErrorRow
	UniqueViolations int64
}

type FastLoadErrorRow struct {
	RowNumber int
	ErrorCode int
	Column    string
}
