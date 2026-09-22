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
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

var (
	username string
	password string
	host     string
	caPath   string

	//db *sql.DB // For non TLS/no-TLS and TERA/ANSI tests
)

func TestMain(m *testing.M) {
	username = os.Getenv("TERASQL_USER")
	password = os.Getenv("TERASQL_PASS")
	host = os.Getenv("TERASQL_HOST")
	caPath = os.Getenv("TERASQL_CA_PEM")

	/*connector, err := NewConnector(&Config{
		User:     username,
		Password: password,
		Host:     host,
		CopMode:  false,
	})
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	db = sql.OpenDB(connector)
	defer db.Close()*/

	code := m.Run()
	os.Exit(code)
}

func TestConnectionNoTls(t *testing.T) {
	isTlsCon := testConnect(t, &Config{
		User:     username,
		Password: password,
		Host:     host,
		CopMode:  false,
		SSLMode:  "DISABLE",
	})
	if isTlsCon {
		t.Fatal("connection is tls")
	}
}

func TestConnectionNoTlsEncOn(t *testing.T) {
	isTlsCon := testConnect(t, &Config{
		User:        username,
		Password:    password,
		Host:        host,
		CopMode:     false,
		SSLMode:     "DISABLE",
		EncryptData: true,
	})
	if isTlsCon {
		t.Fatal("connection is tls")
	}
}

func TestConnectionTlsPrefer(t *testing.T) {
	testConnect(t, &Config{
		User:     username,
		Password: password,
		Host:     host,
		CopMode:  false,
		SSLMode:  "PREFER",
	})
}

func TestConnectionTlsVerify(t *testing.T) {
	isTlsCon := testConnect(t, &Config{
		User:     username,
		Password: password,
		Host:     host,
		CopMode:  false,
		SSLMode:  "VERIFY-CA",
		SSLCA:    caPath,
	})
	if !isTlsCon {
		t.Fatal("connection is not tls")
	}
}

func testConnect(t *testing.T, cfg *Config) bool {
	connector, err := NewConnector(cfg)
	if err != nil {
		t.Fatalf("new connector: %s", err.Error())
	}
	db := sql.OpenDB(connector)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if cfg.SSLMode == "VERIFY-CA" {
		c, err := db.Conn(ctx)
		if err != nil {
			t.Fatalf("database unreachable: %s", err.Error())
		}
		err = c.Raw(func(driverConn any) error {
			if c, ok := driverConn.(*teradataConnection); ok {
				if !c.isTlsConnection() {
					return errors.New("sslmode is VERIFY-CA but connection is not tls")
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("tls mode failed: %s", err.Error())
		}
	}

	// Ping
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("database unreachable: %s", err.Error())
	}

	// Test Query
	rows, err := db.QueryContext(ctx, "select 630")
	if err != nil {
		t.Fatalf("test query execution failed: %s", err.Error())
	}
	if rows.Err() != nil {
		t.Fatalf("test query execution failed: %s", rows.Err().Error())
	}
	defer rows.Close()

	var i int
	for rows.Next() {
		rows.Scan(&i)
	}
	if i != 630 {
		t.Fatalf("test query execution failed (bad result): %d", i)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("conn failed: %s", err.Error())
	}
	defer conn.Close()
	var isTls bool = false
	err = conn.Raw(func(driverConn any) error {
		if tcon, ok := driverConn.(*teradataConnection); ok {
			//tcon.isTlsConn
			_, ok := tcon.netConn.(*tls.Conn)
			isTls = ok && tcon.isTlsConn
			return nil
		}
		return errors.New("invalid connection type")
	})
	if err != nil {
		t.Fatalf("tls checked failed: %s", err.Error())
	}
	return isTls
}

func TestTransactionsTeraMode(t *testing.T) {
	testTransactions(t, &Config{
		User:     username,
		Password: password,
		Host:     host,
		CopMode:  false,
		TMode:    "TERA",
	})
}

func TestTransactionsAnsiMode(t *testing.T) {
	testTransactions(t, &Config{
		User:     username,
		Password: password,
		Host:     host,
		CopMode:  false,
		TMode:    "ANSI",
	})
}

func testTransactions(t *testing.T, cfg *Config) {
	connector, err := NewConnector(cfg)
	if err != nil {
		t.Fatalf("new connector: %s", err.Error())
	}
	db := sql.OpenDB(connector)
	defer func() {
		dropTransactionTestTable(db, cfg)
		dropTestDatabase(db, cfg)
		db.Close()
	}()

	err = dropTestDatabase(db, cfg) // Drop database if already exists (ignore err if not exists)
	if err != nil {
		t.Logf("drop db error: %s", err.Error())
	}
	err = createTestDatabase(db, cfg)
	if err != nil {
		t.Fatalf("transaction test db create failed: %s", err.Error())
	}
	err = createTransactionTestTable(db, cfg)
	if err != nil {
		t.Fatalf("transaction test failed: %s", err.Error())
	}

	txCtx, txCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer txCancel()
	err = runTransactionTest(txCtx, db)
	if err != nil {
		t.Fatalf("transaction test failed: %s", err.Error())
	}
}

func createTransactionTestTable(db *sql.DB, cfg *Config) error {
	return execDDL(db, cfg, "create table teragolang.trans_test (id integer, val varchar(30))")
}

func dropTransactionTestTable(db *sql.DB, cfg *Config) error {
	return execDDL(db, cfg, "drop table teragolang.trans_test")
}

func runTransactionTest(ctx context.Context, db *sql.DB) error {
	const rollbackMinID, rollbackMaxID = 800001, 800003
	const commitMinID, commitMaxID = 800101, 800103
	const insertQuery = "insert into teragolang.trans_test (id, val) values (?, ?)"

	// Test Rollback
	rollbackTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for id := rollbackMinID; id <= rollbackMaxID; id++ {
		if _, err := rollbackTx.ExecContext(ctx, insertQuery, id, "Rollback Test"); err != nil {
			return err
		}
	}
	if err := rollbackTx.Rollback(); err != nil {
		return err
	}
	count, err := transactionCountInRange(ctx, db, rollbackMinID, rollbackMaxID)
	if err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("expected 0 rows after rollback, found %d", count)
	}

	// Test Commit
	commitTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for id := commitMinID; id <= commitMaxID; id++ {
		if _, err := commitTx.ExecContext(ctx, insertQuery, id, "Commit Test"); err != nil {
			return err
		}
	}
	if err := commitTx.Commit(); err != nil {
		return err
	}
	wantCount := commitMaxID - commitMinID + 1
	count, err = transactionCountInRange(ctx, db, commitMinID, commitMaxID)
	if err != nil {
		return err
	}
	if count != wantCount {
		return fmt.Errorf("expected %d rows after rollback, found %d", wantCount, count)
	}
	return nil
}

func transactionCountInRange(ctx context.Context, db *sql.DB, minID, maxID int) (int, error) {
	const query = `select count(*) from teragolang.trans_test where id between ? and ?`
	var count int
	err := db.QueryRowContext(ctx, query, minID, maxID).Scan(&count)
	return count, err
}

func createTestDatabase(db *sql.DB, cfg *Config) error {
	return execDDL(db, cfg, "create database teragolang from dbc AS PERM = 1000000")
}

func execDDL(db *sql.DB, cfg *Config, query string) error {
	if _, err := db.Exec(query); err != nil {
		return err
	}
	if cfg.TMode == "ANSI" {
		if _, err := db.Exec("COMMIT WORK"); err != nil {
			return err
		}
	}
	return nil
}

func execDDLIgnoreErr(db *sql.DB, cfg *Config, query string) {
	db.Exec(query)
	if cfg.TMode == "ANSI" {
		db.Exec("COMMIT WORK")
	}
}

func dropTestDatabase(db *sql.DB, cfg *Config) error {
	execDDLIgnoreErr(db, cfg, "delete database teragolang ALL")
	execDDLIgnoreErr(db, cfg, "MODIFY DATABASE teragolang AS DROP DEFAULT JOURNAL TABLE")
	execDDLIgnoreErr(db, cfg, "drop database teragolang")
	return nil //Ignoring errs
}

/*
Connection Timeout

func TestQueryTimeout(t *testing.T) {
	const longQuery = `
		select count(*)
		from sys_calendar.calendar a,
			 sys_calendar.calendar b
		where a.calendar_date between '1999-01-01' and '2024-01-01'
			and  b.calendar_date between '1999-01-01' and '2024-01-01'
	`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	rows, err := db.QueryContext(ctx, longQuery)
	if err != nil {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("timeout failed with wrong error: %s", err.Error())
		}
	} else {
		rows.Close()
		t.Fatalf("timeout not triggered failed: %s", err.Error())
	}
}*/

/*
const longQuery = `
		select calendar_date
		from sys_calendar.calendar
		where calendar_date between '1999-01-01' and '2024-01-01'
	`
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rows, err := db.QueryContext(ctx, longQuery)
	if err != nil {
		t.Fatalf("timeout query executing failed: %s", err.Error())
	}
	defer rows.Close()

	var cnt = 0
	var dt interface{}
	for rows.Next() {
		rows.Scan(&dt)
		cnt += 1
		if cnt >= 10 {
			cancel()
		}
	}
*/
