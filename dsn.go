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
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Host     string // Hostname / IP
	Port     int    // Port Number
	Database string // Database Name
	User     string // Username
	Password string // Password

	// Base Options
	TMode           string        // TMODE allowed="TERA,ANSI,DEFAULT"
	CopMode         bool          // COP default="ON" allowed="ON,OFF"
	CopLast         bool          // COPLAST default="ON" allowed="ON,OFF"
	Timeout         time.Duration // TIMEOUT default="60"
	Partition       string        // PARTITION default="DBC/SQL"
	ConnectFunction int           // CONNECT_FUNCTION default="0" allowed="0,1,2"
	MaxMessageSize  int           // MAX_MESSAGE_BODY default=2097152
	EncryptData     bool          // ENCRYPTDATA default="OFF" allowed="ON,OFF"

	// TLS Options
	SSLMode       string // SSLMODE default="PREFER" allowed="DISABLE,ALLOW,PREFER,REQUIRE,VERIFY-CA,VERIFY-FULL"
	SSLProtocol   string // SSLPROTOCOL default="TLSv1.3"
	SSLCipher     string // SSLCIPHER default=""
	SSLServerName string // SSLSERVERNAME default=""
	SSLCA         string // SSLCA
	SSLCAPath     string // SSLCAPATH
	SSLBase64     string // SSLBASE64
	SSLPort       int    // HTTPS_PORT

	// LOB Options
	LOBSupport          bool // LOB_SUPPORT default="OFF" allowed="ON,OFF"
	LOBRecieveThreshold int  // SLOB_RECEIVE_THRESHOLD default=1000
	LOBPrefetch         bool // LOB_PREFETCH  default="OFF" allowed="ON,OFF"

	Logger *slog.Logger

	// Settings
	redriveLevel int
	sslLevel     int
}

func NewTeradataConfig(host, user, pass string) *Config {
	cfg := &Config{
		Host:                host,
		Port:                1025,
		User:                user,
		Password:            pass,
		CopMode:             true,
		CopLast:             true,
		SSLMode:             "PREFER",
		SSLProtocol:         "TLSv1.3",
		Timeout:             60 * time.Second,
		TMode:               "DEFAULT",
		SSLPort:             443,
		redriveLevel:        3,
		LOBSupport:          true,
		LOBRecieveThreshold: 1000,
		LOBPrefetch:         false,
		Partition:           "DBC/SQL",
		ConnectFunction:     0,
	}
	cfg.normalize()
	return cfg
}

func ParseDSN(dsn string) (*Config, error) {
	if !strings.HasPrefix(dsn, "teradatasql://") {
		dsn = "teradatasql://" + dsn
	}
	parsedURL, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DSN: %w", err)
	}
	logger := newNoopLogger()

	config := &Config{
		redriveLevel: 3,      //TODO
		Logger:       logger, //Logger(log.New(os.Stderr, "[teradatasql] ", log.Ldate|log.Ltime)),
	}
	config.Host = parsedURL.Hostname()
	if portStr := parsedURL.Port(); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %w", err)
		}
		config.Port = port
	} else {
		config.Port = 1025
	}

	config.Database = strings.TrimPrefix(parsedURL.Path, "/")
	config.User = parsedURL.User.Username()
	if pass, ok := parsedURL.User.Password(); ok {
		config.Password = pass
	}

	queryParams := parsedURL.Query()
	err = parseUrlArgs(config, &queryParams)
	if err != nil {
		return nil, err
	}
	config.normalize()
	return config, nil
}

func (c *Config) ToDSN() (string, error) {
	if c == nil {
		return "", errors.New("Invalid Config")
	}
	c.normalize()
	var dsnBuilder strings.Builder
	if c.User != "" {
		dsnBuilder.WriteString(c.User)
		if c.Password != "" {
			dsnBuilder.WriteRune(':')
			dsnBuilder.WriteString(c.Password)
		}
		dsnBuilder.WriteRune('@')
	}
	dsnBuilder.WriteString(c.Host)
	dsnBuilder.WriteRune('/')
	if c.Database != "" {
		dsnBuilder.WriteString(c.Database)
	}
	dsnBuilder.WriteRune('?')
	dsnBuilder.WriteString(generateDsnParamString(c))
	return dsnBuilder.String(), nil
}

func (c *Config) normalize() {
	if c.redriveLevel < 1 || c.redriveLevel > 3 {
		c.redriveLevel = 3
	}
	if c.Logger == nil {
		c.Logger = newNoopLogger()
	}
	if c.Port == 0 {
		c.Port = 1025
	}
	if c.SSLPort == 0 {
		c.SSLPort = 443
	}
	if c.TMode == "" {
		c.TMode = "DEFAULT"
	}
	if c.Timeout.Seconds() == 0 {
		c.Timeout = time.Duration(60) * time.Second
	}
	if c.SSLProtocol == "" {
		c.SSLProtocol = "TLSv1.3"
	}
	if c.SSLMode == "" {
		c.SSLMode = "PREFER"
	}
	if c.MaxMessageSize == 0 {
		c.MaxMessageSize = 2097152
	}
	if c.LOBRecieveThreshold == 0 {
		c.LOBRecieveThreshold = 1000
	}
	if c.Partition == "" {
		c.Partition = "DBC/SQL"
	}
	c.sslLevel = decodeSslMode(c.SSLMode)
}

func (c *Config) useTls() bool {
	if c.sslLevel <= sslLevelAllow {
		return false
	}
	return true
}

func (c *Config) getClientConfidentialityType(isTlsConn bool) byte {
	if isTlsConn {
		switch c.SSLMode {
		case sslModeVerifyFull:
			return 'V'
		case sslModeVerifyCA:
			return 'C'
		}
		return 'R'
	}

	switch c.SSLMode {
	case sslModeDisable, sslModeAllow:
		if c.EncryptData {
			return 'E'
		}
		return 'U'
	case sslModePrefer, sslModeRequire:
		if c.EncryptData {
			return 'F'
		}
		return 'H'
	}
	return 'U'
}

func (c *Config) allowTlsFallback() bool {
	return c.sslLevel < sslLevelRequire
}

func generateDsnParamString(config *Config) string {
	var paramBuilder strings.Builder
	var paramCount int = 0
	paramCount = writeDsnParam(&paramBuilder, paramCount, "TMODE", config.TMode, config.TMode != "DEFAULT")
	paramCount = writeDsnParam(&paramBuilder, paramCount, "COP", boolToDsnParam(config.CopMode), !config.CopMode)
	paramCount = writeDsnParam(&paramBuilder, paramCount, "COPLAST", boolToDsnParam(config.CopLast), !config.CopLast)
	paramCount = writeDsnParam(&paramBuilder, paramCount, "TIMEOUT", strconv.FormatFloat(config.Timeout.Seconds(), 'f', 0, 64), config.Timeout.Seconds() != 60)
	paramCount = writeDsnParam(&paramBuilder, paramCount, "SSLMODE", config.SSLMode, config.SSLMode != "PREFER")
	paramCount = writeDsnParam(&paramBuilder, paramCount, "SSLPROTOCOL", config.SSLProtocol, config.SSLProtocol != "TLSv1.3")
	paramCount = writeDsnParam(&paramBuilder, paramCount, "SSLCIPHER", config.SSLCipher, config.SSLCipher != "")
	paramCount = writeDsnParam(&paramBuilder, paramCount, "SSLCA", config.SSLCA, config.SSLCA != "")
	paramCount = writeDsnParam(&paramBuilder, paramCount, "SSLCAPATH", config.SSLCAPath, config.SSLCAPath != "")
	paramCount = writeDsnParam(&paramBuilder, paramCount, "SSLBASE64", config.SSLBase64, config.SSLBase64 != "")
	paramCount = writeDsnParam(&paramBuilder, paramCount, "SSLSERVERNAME", config.SSLServerName, config.SSLServerName != "")
	paramCount = writeDsnParam(&paramBuilder, paramCount, "HTTPS_PORT", strconv.Itoa(config.SSLPort), config.SSLPort != 443)
	paramCount = writeDsnParam(&paramBuilder, paramCount, "ENCRYPTDATA", boolToDsnParam(config.EncryptData), config.EncryptData)
	paramCount = writeDsnParam(&paramBuilder, paramCount, "LOB_SUPPORT", boolToDsnParam(config.LOBSupport), !config.LOBSupport)
	paramCount = writeDsnParam(&paramBuilder, paramCount, "MAX_MESSAGE_BODY", strconv.Itoa(config.MaxMessageSize), config.MaxMessageSize != 2097152)
	paramCount = writeDsnParam(&paramBuilder, paramCount, "SLOB_RECEIVE_THRESHOLD", strconv.Itoa(config.LOBRecieveThreshold), config.LOBRecieveThreshold != 1000)
	paramCount = writeDsnParam(&paramBuilder, paramCount, "CONNECT_FUNCTION", strconv.Itoa(config.ConnectFunction), config.ConnectFunction != 0)
	writeDsnParam(&paramBuilder, paramCount, "PARTITION", config.Partition, config.Partition != "")
	return paramBuilder.String()
}

func writeDsnParam(builder *strings.Builder, count int, name string, val string, write bool) int {
	if write {
		if count > 0 {
			builder.WriteRune('&')
		}
		builder.WriteString(name)
		builder.WriteRune('=')
		builder.WriteString(val)
		return count + 1
	}
	return count
}

func parseUrlArgs(config *Config, params *url.Values) error {

	config.TMode = validateParam(params.Get("TMODE"), "DEFAULT", "DEFAULT", "TERA", "ANSI")
	config.CopMode = parseBooleanArg(params.Get("COP"), true)
	config.CopLast = parseBooleanArg(params.Get("COPLAST"), true)
	if timeout := params.Get("TIMEOUT"); timeout != "" {
		config.Timeout = parseTimeArg(timeout)
	} else {
		config.Timeout = parseTimeArg("60")
	}

	// SSL Options
	config.SSLMode = validateParam(params.Get("SSLMODE"), "PREFER", "DISABLE", "ALLOW", "PREFER", "REQUIRE", "VERIFY-CA", "VERIFY-FULL")
	config.SSLProtocol = validateParam(params.Get("SSLPROTOCOL"), "TLSv1.3", "TLSv1.3", "TLSv1.2")
	config.SSLCipher = params.Get("SSLCIPHER")
	config.SSLCA = params.Get("SSLCA")
	config.SSLCAPath = params.Get("SSLCAPATH")
	config.SSLBase64 = params.Get("SSLBASE64")
	config.SSLServerName = params.Get("SSLSERVERNAME")
	if sslPort := params.Get("HTTPS_PORT"); sslPort != "" {
		port, err := strconv.Atoi(sslPort)
		if err != nil {
			return fmt.Errorf("invalid ssl port: %w", err)
		}
		config.SSLPort = port
	} else {
		config.SSLPort = 443
	}

	config.EncryptData = parseBooleanArg(params.Get("ENCRYPTDATA"), false)
	config.LOBSupport = parseBooleanArg(params.Get("LOB_SUPPORT"), true)
	config.MaxMessageSize = parseIntArg(params.Get("MAX_MESSAGE_BODY"))
	config.LOBRecieveThreshold = parseIntArg(params.Get("SLOB_RECEIVE_THRESHOLD"))

	config.Partition = params.Get("PARTITION")
	config.ConnectFunction = parseIntArg(params.Get("CONNECT_FUNCTION"))
	return nil
}

func validateParam(val string, def string, allowed ...string) string {
	if slices.Contains(allowed, val) {
		return val
	}
	return def
}

func parseBooleanArg(val string, def bool) bool {
	if val == "" {
		return def
	}
	if strings.ToUpper(val) == "ON" || strings.ToUpper(val) == "TRUE" {
		return true
	}
	return false
}

func boolToDsnParam(val bool) string {
	if val {
		return "ON"
	}
	return "OFF"
}

func parseTimeArg(val string) time.Duration {
	intval := parseIntArg(val)
	if intval == 0 {
		intval = 60
	}
	return time.Duration(intval) * time.Second
}

func parseIntArg(val string) int {
	i, err := strconv.Atoi(val)
	if err != nil {
		return 0
	}
	return i
}

func validateTranMode(tmode string) bool {
	if tmode == "TERA" || tmode == "ANSI" || tmode == "DEFAULT" {
		return true
	}
	return false
}
