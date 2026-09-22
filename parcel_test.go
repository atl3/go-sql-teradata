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
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestOptionsParcel(t *testing.T) {
	cfg := &Config{
		User:     username,
		Password: password,
		Host:     host,
		CopMode:  false,
		TMode:    "TERA",
	}
	connector, err := NewConnector(cfg)
	if err != nil {
		t.Fatalf("new connector: %s", err.Error())
	}
	db := sql.OpenDB(connector)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("conn failed: %s", err.Error())
	}
	defer conn.Close()
	err = conn.Raw(func(driverConn any) error {
		if tcon, ok := driverConn.(*teradataConnection); ok {
			parcel := newOptionsParcelExecute(tcon)
			b := newWriteBuffer()
			buf := b.take(parcel.getLength() + 4)
			bwriter := newBufferWriter(buf)
			parcel.write(bwriter)
			str := bytesToHex(buf)
			fmt.Println(str)
			return nil
		}
		return errors.New("invalid connection type")
	})

}

func bytesToHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	var sb strings.Builder
	for i, b := range data {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", b)
	}
	return sb.String()
}
