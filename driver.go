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
	"database/sql/driver"
)

type TeradataDriver struct {
}

func (d TeradataDriver) Open(dsn string) (driver.Conn, error) {
	cfg, err := ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	c := newConnector(cfg)
	return c.Connect(context.Background())
}

func init() {
	sql.Register("teradata", &TeradataDriver{})
}

func NewConnector(cfg *Config) (driver.Connector, error) {
	return newConnector(cfg), nil
}

func (d TeradataDriver) OpenConnector(dsn string) (driver.Connector, error) {
	config, err := ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	return newConnector(config), nil
}
